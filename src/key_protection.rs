//! Java's password protection of private keys in JKS and JCEKS keystores:
//! recovering a key to protect it again under another password. A recovered
//! key lives only in memory, in a buffer that is wiped when dropped.
use crown::{
    asn1::{
        der::{self, Reader},
        oid::ObjectIdentifier,
    },
    block::des::TripleDes,
    hash::md5::sum_md5,
    modes::{
        BlockMode,
        cbc::{CbcDecryptor, CbcEncryptor},
    },
    rng::Rng,
    x509::{
        algorithm::AlgorithmIdentifier,
        keys::EncryptedPrivateKeyInfo,
        pbe::{pkcs7_pad, pkcs7_unpad},
    },
};
use sha1::{Digest, Sha1};
use zeroize::{Zeroize, Zeroizing};

/// `sun.security.provider.KeyProtector`, the JKS scheme: the key XORed with
/// a SHA-1 keystream, between a salt and a check digest.
const JKS_PROTECTOR: &[u64] = &[1, 3, 6, 1, 4, 1, 42, 2, 17, 1, 1];
/// `PBEWithMD5AndTripleDES`, the JCEKS scheme.
const JCEKS_PROTECTOR: &[u64] = &[1, 3, 6, 1, 4, 1, 42, 2, 19, 1];
const SHA1_SIZE: usize = 20;
/// What Java uses to protect new JCEKS keys.
const JCEKS_ITERATIONS: u32 = 200_000;
/// Java refuses larger counts too.
const MAX_JCEKS_ITERATIONS: u32 = 5_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The password does not recover the key.
    Password,
    /// The key is not protected in a way the app can read.
    Unsupported,
    /// JCEKS only protects keys with printable ASCII passwords.
    PasswordNotAscii,
}

/// Recovers the PKCS #8 key from a JKS or JCEKS entry's protected key.
pub fn recover(protected: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let info = EncryptedPrivateKeyInfo::parse(protected).map_err(|_| Error::Unsupported)?;
    if info.algorithm.oid.matches(JKS_PROTECTOR) {
        recover_jks(&info.encrypted_data, password)
    } else if info.algorithm.oid.matches(JCEKS_PROTECTOR) {
        recover_jceks(&info, password)
    } else {
        Err(Error::Unsupported)
    }
}

/// Protects a PKCS #8 key as Java does for the keystore's format, with a
/// fresh salt from `rng`.
pub fn protect(
    key: &[u8],
    password: &str,
    jceks: bool,
    rng: &mut impl Rng,
) -> Result<Vec<u8>, Error> {
    let info = if jceks {
        let mut salt = [0; 8];
        rng.fill_bytes(&mut salt);
        let (cipher_key, iv) = jceks_key(password, salt, JCEKS_ITERATIONS)?;
        let mut data = pkcs7_pad(key, 8);
        let cipher = TripleDes::new(&cipher_key[..]).map_err(|_| Error::Unsupported)?;
        cipher.to_cbc_enc(&iv).encrypt(&mut data);
        let parameters = der::sequence(
            &[
                der::octet_string(&salt),
                der::integer(&JCEKS_ITERATIONS.to_be_bytes()),
            ]
            .concat(),
        );
        EncryptedPrivateKeyInfo {
            algorithm: AlgorithmIdentifier::new(object_id(JCEKS_PROTECTOR), Some(parameters)),
            encrypted_data: data,
        }
    } else {
        let mut salt = [0; SHA1_SIZE];
        rng.fill_bytes(&mut salt);
        let password = jks_password(password);
        let mut data = salt.to_vec();
        data.extend_from_slice(key);
        jks_keystream(&password, &salt, &mut data[SHA1_SIZE..]);
        data.extend_from_slice(&jks_digest(&password, key));
        EncryptedPrivateKeyInfo {
            algorithm: AlgorithmIdentifier::with_null(object_id(JKS_PROTECTOR)),
            encrypted_data: data,
        }
    };
    Ok(info.encode())
}

fn object_id(arcs: &[u64]) -> ObjectIdentifier {
    ObjectIdentifier::new(arcs).expect("static oid")
}

/// The password as Java hashes it: its UTF-16 units, big-endian.
fn jks_password(password: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(password.encode_utf16().flat_map(u16::to_be_bytes).collect())
}

/// XORs `data` with the keystream: SHA-1 of the password and the salt, then
/// of the password and each previous block.
fn jks_keystream(password: &[u8], salt: &[u8], data: &mut [u8]) {
    let mut block: [u8; SHA1_SIZE] = Sha1::new()
        .chain_update(password)
        .chain_update(salt)
        .finalize()
        .into();
    for chunk in data.chunks_mut(SHA1_SIZE) {
        for (byte, mask) in chunk.iter_mut().zip(block) {
            *byte ^= mask;
        }
        block = Sha1::new()
            .chain_update(password)
            .chain_update(block)
            .finalize()
            .into();
    }
    block.zeroize();
}

fn jks_digest(password: &[u8], key: &[u8]) -> [u8; SHA1_SIZE] {
    Sha1::new()
        .chain_update(password)
        .chain_update(key)
        .finalize()
        .into()
}

fn recover_jks(data: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let key_len = data
        .len()
        .checked_sub(2 * SHA1_SIZE)
        .ok_or(Error::Unsupported)?;
    let (salt, rest) = data.split_at(SHA1_SIZE);
    let (encrypted, digest) = rest.split_at(key_len);
    let password = jks_password(password);
    let mut key = Zeroizing::new(encrypted.to_vec());
    jks_keystream(&password, salt, &mut key);
    if jks_digest(&password, &key)[..] == *digest {
        Ok(key)
    } else {
        Err(Error::Password)
    }
}

/// The Triple DES key and IV that `PBEWithMD5AndTripleDES` derives: each
/// half of the salt, hashed with the password `iterations` times, gives 16
/// of the 32 bytes.
fn jceks_key(
    password: &str,
    mut salt: [u8; 8],
    iterations: u32,
) -> Result<(Zeroizing<[u8; 24]>, [u8; 8]), Error> {
    // Java's PBE keys hold printable ASCII only.
    if !password.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
        return Err(Error::PasswordNotAscii);
    }
    // Java inverts the first half when both halves are the same.
    if salt[..4] == salt[4..] {
        salt[..4].reverse();
    }
    let mut derived = Zeroizing::new([0; 32]);
    let mut input = Zeroizing::new(Vec::with_capacity(16 + password.len()));
    for (half, output) in salt.chunks(4).zip(derived.chunks_mut(16)) {
        let mut hashed = Zeroizing::new(half.to_vec());
        for _ in 0..iterations {
            input.clear();
            input.extend_from_slice(&hashed);
            input.extend_from_slice(password.as_bytes());
            *hashed = sum_md5(&input).to_vec();
        }
        output.copy_from_slice(&hashed);
    }
    let mut key = Zeroizing::new([0; 24]);
    key.copy_from_slice(&derived[..24]);
    let mut iv = [0; 8];
    iv.copy_from_slice(&derived[24..]);
    Ok((key, iv))
}

fn recover_jceks(
    info: &EncryptedPrivateKeyInfo,
    password: &str,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let parameters = info
        .algorithm
        .parameters
        .as_deref()
        .ok_or(Error::Unsupported)?;
    let (salt, iterations) = (|| {
        let mut reader = Reader::new(parameters);
        let mut sequence = reader.read_sequence()?;
        let salt = sequence.read_octet_string()?.to_vec();
        let iterations = sequence.read_integer_i64()?;
        Ok::<_, crown::error::CryptoError>((salt, iterations))
    })()
    .map_err(|_| Error::Unsupported)?;
    let salt: [u8; 8] = salt.try_into().map_err(|_| Error::Unsupported)?;
    let iterations = u32::try_from(iterations)
        .ok()
        .filter(|count| (1..=MAX_JCEKS_ITERATIONS).contains(count))
        .ok_or(Error::Unsupported)?;
    let data = &info.encrypted_data;
    if data.is_empty() || !data.len().is_multiple_of(8) {
        return Err(Error::Unsupported);
    }
    // A password Java could not have used cannot be the right one.
    let (cipher_key, iv) = jceks_key(password, salt, iterations).map_err(|_| Error::Password)?;
    let mut key = Zeroizing::new(data.clone());
    let cipher = TripleDes::new(&cipher_key[..]).map_err(|_| Error::Unsupported)?;
    cipher.to_cbc_dec(&iv).encrypt(&mut key);
    let key = pkcs7_unpad(&mut key, 8)
        .map(Zeroizing::new)
        .map_err(|_| Error::Password)?;
    // About 1 wrong password in 256 leaves valid padding.
    if crate::pkcs12::is_private_key_info(&key) {
        Ok(key)
    } else {
        Err(Error::Password)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TestRng, synthetic_pkcs8};

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn jks_protection_matches_java_and_recovers_only_with_the_password() {
        // Salt 01..14, the key XORed with the keystream, then the digest.
        let protected = protect(b"synthetic", "pä😀", false, &mut TestRng(0)).unwrap();
        assert_eq!(
            protected,
            hex(
                "3043300e060a2b060104012a02110101050004310102030405060708090a0b0c0d0e\
                 0f1011121314a12492ce49c83a1b959589440d8e07cb2600835443ec065339df3d31e7"
            )
        );
        assert_eq!(*recover(&protected, "pä😀").unwrap(), b"synthetic");
        for password in ["", "pä", "pä😁"] {
            assert_eq!(recover(&protected, password), Err(Error::Password));
        }
        // A key longer than one keystream block, and an empty one.
        let long = [7; 50];
        let protected = protect(&long, "", false, &mut TestRng(9)).unwrap();
        assert_eq!(*recover(&protected, "").unwrap(), long);
        let empty = protect(b"", "x", false, &mut TestRng(9)).unwrap();
        assert!(recover(&empty, "x").unwrap().is_empty());
        // Any changed byte of the key or digest fails the check.
        let mut changed = protected.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert_eq!(recover(&changed, ""), Err(Error::Password));
    }

    #[test]
    fn jceks_key_derivation_matches_java() {
        // Checked against Java's PBEWithMD5AndTripleDES cipher.
        let (key, iv) = jceks_key("changeit", [1, 2, 3, 4, 5, 6, 7, 8], 5).unwrap();
        assert_eq!(
            key[..],
            hex("95418e423b8f41ef5e25df1ff82ca16053a46ded03888aa6")
        );
        assert_eq!(iv[..], hex("8f80e8123b591dd0"));
        // Equal salt halves: the first is inverted.
        let (key, iv) = jceks_key("changeit", [1, 2, 3, 4, 1, 2, 3, 4], 5).unwrap();
        assert_eq!(
            key[..],
            hex("873efd9d9c05cdea21860a61b968d44995418e423b8f41ef")
        );
        assert_eq!(iv[..], hex("5e25df1ff82ca160"));
        for password in ["pä", "tab\t", "😀"] {
            assert_eq!(
                jceks_key(password, [0; 8], 1).err(),
                Some(Error::PasswordNotAscii)
            );
        }
    }

    #[test]
    fn jceks_protection_recovers_only_with_the_password() {
        let key = synthetic_pkcs8(b"synthetic, not a private key");
        let protected = protect(&key, "changeit", true, &mut TestRng(0)).unwrap();
        let info = EncryptedPrivateKeyInfo::parse(&protected).unwrap();
        assert!(info.algorithm.oid.matches(JCEKS_PROTECTOR));
        assert!(!protected.windows(9).any(|window| window == b"synthetic"));
        assert_eq!(*recover(&protected, "changeit").unwrap(), key);
        for password in ["", "changeit ", "chängeit"] {
            assert_eq!(recover(&protected, password), Err(Error::Password));
        }
        assert_eq!(
            protect(&key, "pä", true, &mut TestRng(0)),
            Err(Error::PasswordNotAscii)
        );
        // Content that decrypts but is not a key means a wrong password.
        let not_a_key = protect(
            b"decrypts, but is not a key",
            "changeit",
            true,
            &mut TestRng(0),
        );
        assert_eq!(
            recover(&not_a_key.unwrap(), "changeit"),
            Err(Error::Password)
        );
    }

    #[test]
    fn rejects_protection_it_cannot_read() {
        let info = |arcs: &[u64], parameters: Option<Vec<u8>>, data: &[u8]| {
            EncryptedPrivateKeyInfo {
                algorithm: AlgorithmIdentifier::new(object_id(arcs), parameters),
                encrypted_data: data.to_vec(),
            }
            .encode()
        };
        let parameters = |salt: &[u8], iterations: u32| {
            Some(der::sequence(
                &[
                    der::octet_string(salt),
                    der::integer(&iterations.to_be_bytes()),
                ]
                .concat(),
            ))
        };
        for protected in [
            b"not DER".to_vec(),
            // Another algorithm, and a JKS key too short for salt and digest.
            info(&[1, 2, 3, 4], None, &[0; 48]),
            info(JKS_PROTECTOR, None, &[0; 39]),
            // JCEKS without parameters, with a bad salt size, iteration
            // count, or ciphertext length.
            info(JCEKS_PROTECTOR, None, &[0; 16]),
            info(JCEKS_PROTECTOR, Some(der::null()), &[0; 16]),
            info(JCEKS_PROTECTOR, parameters(&[0; 7], 5), &[0; 16]),
            info(JCEKS_PROTECTOR, parameters(&[0; 8], 0), &[0; 16]),
            info(JCEKS_PROTECTOR, parameters(&[0; 8], 5_000_001), &[0; 16]),
            info(JCEKS_PROTECTOR, parameters(&[0; 8], 5), &[0; 15]),
            info(JCEKS_PROTECTOR, parameters(&[0; 8], 5), &[]),
        ] {
            assert_eq!(recover(&protected, "changeit"), Err(Error::Unsupported));
        }
    }
}
