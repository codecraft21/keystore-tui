//! Secret keys as JCEKS and PKCS12 keystores hold them. JCEKS seals a
//! serialized `SecretKeySpec` in a serialized `SealedObject`, encrypted with
//! `PBEWithMD5AndTripleDES`; PKCS12 wraps the key in a PKCS #8 structure
//! named by its algorithm. A key read here lives only in memory, in a buffer
//! that is wiped when dropped.
use crown::{
    asn1::{
        der::{self, Reader},
        oid::ObjectIdentifier,
    },
    rng::Rng,
};
use zeroize::Zeroizing;

use crate::{
    java_serialization,
    key_protection::{self, Error},
};

/// The class of the object that seals a JCEKS secret key.
pub const SEALED_CLASS: &[u8] = b"com.sun.crypto.provider.SealedObjectForKeyProtector";
const KEY_CLASS: &str = "javax.crypto.spec.SecretKeySpec";
const SEAL_ALGORITHM: &str = "PBEWithMD5AndTripleDES";
/// The first bytes of a serialization stream: its magic number and version.
const STREAM_HEADER: [u8; 4] = [0xac, 0xed, 0x00, 0x05];

/// The largest key that is generated, imported, or exported.
pub const MAX_KEY_SIZE: usize = 1024;

/// A secret key: its raw bytes, and its algorithm as Java names it.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey {
    pub algorithm: String,
    pub key: Zeroizing<Vec<u8>>,
}

/// The algorithms offered for new keys, with their PKCS12 object
/// identifiers. An HMAC key is as long as its hash.
const ALGORITHMS: [(&str, &[u64], usize); 5] = [
    ("AES", &[2, 16, 840, 1, 101, 3, 4, 1], 0),
    ("HmacSHA1", &[1, 2, 840, 113549, 2, 7], 160),
    ("HmacSHA256", &[1, 2, 840, 113549, 2, 9], 256),
    ("HmacSHA384", &[1, 2, 840, 113549, 2, 10], 384),
    ("HmacSHA512", &[1, 2, 840, 113549, 2, 11], 512),
];
/// Other algorithms Java names in PKCS12, which are read and kept.
const OTHER_ALGORITHMS: [(&str, &[u64]); 3] = [
    ("HmacSHA224", &[1, 2, 840, 113549, 2, 8]),
    ("DESede", &[1, 2, 840, 113549, 3, 7]),
    ("DES", &[1, 3, 14, 3, 2, 7]),
];
const AES_BITS: [usize; 3] = [128, 192, 256];

/// An algorithm and key size offered for a secret key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Choice {
    pub algorithm: &'static str,
    pub bits: usize,
}

impl Choice {
    pub fn label(self) -> String {
        format!("{} ({} bits)", self.algorithm, self.bits)
    }

    /// A new key of this algorithm and size.
    pub fn generate(self, rng: &mut impl Rng) -> SecretKey {
        let mut key = Zeroizing::new(vec![0; self.bits / 8]);
        rng.fill_bytes(&mut key);
        SecretKey {
            algorithm: self.algorithm.into(),
            key,
        }
    }
}

/// What a new key can be: AES in its three sizes, then each HMAC.
pub fn generated() -> Vec<Choice> {
    let aes = AES_BITS.map(|bits| Choice {
        algorithm: "AES",
        bits,
    });
    let hmac = ALGORITHMS[1..]
        .iter()
        .map(|&(algorithm, _, bits)| Choice { algorithm, bits });
    aes.into_iter().chain(hmac).collect()
}

/// What a key of `length` bytes can be: AES when it has one of its sizes,
/// and any HMAC.
pub fn fitting(length: usize) -> Vec<Choice> {
    let bits = length * 8;
    ALGORITHMS
        .iter()
        .filter(|(algorithm, ..)| *algorithm != "AES" || AES_BITS.contains(&bits))
        .map(|&(algorithm, ..)| Choice { algorithm, bits })
        .collect()
}

fn utf(text: &str) -> Vec<u8> {
    [&(text.len() as u16).to_be_bytes()[..], text.as_bytes()].concat()
}

fn byte_array(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new([&(bytes.len() as u32).to_be_bytes()[..], bytes].concat())
}

/// A new `byte[]` object's start, up to its length: its class description
/// with Java's serial version.
const NEW_BYTE_ARRAY: [u8; 19] = [
    0x75, 0x72, 0x00, 0x02, b'[', b'B', 0xac, 0xf3, 0x17, 0xf8, 0x06, 0x08, 0x54, 0xe0, 0x02, 0x00,
    0x00, 0x78, 0x70,
];

/// The key as the serialized `SecretKeySpec` Java seals.
fn serialized(key: &SecretKey) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        [
            &STREAM_HEADER[..],
            &[0x73, 0x72],
            &utf(KEY_CLASS),
            // The serial version, the flags, and the two fields.
            &[
                0x5b, 0x47, 0x0b, 0x66, 0xe2, 0x30, 0x61, 0x4d, 0x02, 0x00, 0x02, b'L',
            ],
            &utf("algorithm"),
            &[0x74],
            &utf("Ljava/lang/String;"),
            b"[",
            &utf("key"),
            &[0x74],
            &utf("[B"),
            &[0x78, 0x70, 0x74],
            &utf(&key.algorithm),
            &NEW_BYTE_ARRAY,
            &byte_array(&key.key),
        ]
        .concat(),
    )
}

/// The serialized `SealedObject` Java stores a JCEKS secret key as: the key
/// encrypted under `password`, with a fresh salt from `rng`.
pub fn seal(key: &SecretKey, password: &str, rng: &mut impl Rng) -> Result<Vec<u8>, Error> {
    let (parameters, encrypted) = key_protection::jceks_encrypt(&serialized(key), password, rng)?;
    Ok([
        &STREAM_HEADER[..],
        &[0x73, 0x72],
        &utf(std::str::from_utf8(SEALED_CLASS).expect("an ASCII class name")),
        &[
            0xcd, 0x57, 0xca, 0x59, 0xe7, 0x30, 0xbb, 0x53, 0x02, 0x00, 0x00, 0x78, 0x72,
        ],
        &utf("javax.crypto.SealedObject"),
        &[
            0x3e, 0x36, 0x3d, 0xa6, 0xc3, 0xb7, 0x54, 0x70, 0x02, 0x00, 0x04, b'[',
        ],
        &utf("encodedParams"),
        &[0x74],
        &utf("[B"),
        b"[",
        &utf("encryptedContent"),
        // The class name again, by reference.
        &[0x71, 0x00, 0x7e, 0x00, 0x02, b'L'],
        &utf("paramsAlg"),
        &[0x74],
        &utf("Ljava/lang/String;"),
        b"L",
        &utf("sealAlg"),
        &[0x71, 0x00, 0x7e, 0x00, 0x03, 0x78, 0x70],
        &NEW_BYTE_ARRAY,
        &byte_array(&parameters),
        // A second array, of the class described for the first.
        &[0x75, 0x71, 0x00, 0x7e, 0x00, 0x05],
        &byte_array(&encrypted),
        &[0x74],
        &utf(SEAL_ALGORITHM),
        &[0x74],
        &utf(SEAL_ALGORITHM),
    ]
    .concat())
}

/// Recovers the key from the serialized `SealedObject` of a JCEKS entry.
pub fn unseal(sealed: &[u8], password: &str) -> Result<SecretKey, Error> {
    let object = java_serialization::read_object(sealed).map_err(|_| Error::Unsupported)?;
    let field = |name| object.field(name).ok_or(Error::Unsupported);
    if object.class != SEALED_CLASS || field("sealAlg")? != SEAL_ALGORITHM.as_bytes() {
        return Err(Error::Unsupported);
    }
    let plain = key_protection::jceks_decrypt(
        field("encodedParams")?,
        field("encryptedContent")?,
        password,
    )?;
    // About 1 wrong password in 256 leaves valid padding, but not a stream.
    if !plain.starts_with(&STREAM_HEADER) {
        return Err(Error::Password);
    }
    let key = java_serialization::read_object(&plain).map_err(|_| Error::Unsupported)?;
    // Java also seals other kinds of keys, which are not read.
    if key.class != KEY_CLASS.as_bytes() {
        return Err(Error::Unsupported);
    }
    let (Some(algorithm), Some(bytes)) = (key.field("algorithm"), key.field("key")) else {
        return Err(Error::Unsupported);
    };
    Ok(SecretKey {
        algorithm: String::from_utf8(algorithm.to_vec()).map_err(|_| Error::Unsupported)?,
        key: Zeroizing::new(bytes.to_vec()),
    })
}

fn identifier(algorithm: &str) -> Option<&'static [u64]> {
    let offered = ALGORITHMS.iter().map(|&(name, arcs, _)| (name, arcs));
    offered
        .chain(OTHER_ALGORITHMS)
        .find(|(name, _)| name.eq_ignore_ascii_case(algorithm))
        .map(|(_, arcs)| arcs)
}

/// The key in the PKCS #8 structure a PKCS12 keystore encrypts: a version,
/// the algorithm, and the key's bytes. `None` for an algorithm that PKCS12
/// has no name for.
pub fn to_pkcs8(key: &SecretKey) -> Option<Zeroizing<Vec<u8>>> {
    let arcs = identifier(&key.algorithm)?;
    let algorithm = ObjectIdentifier::new(arcs).expect("a constant object identifier");
    let wrapped = Zeroizing::new(der::octet_string(&key.key));
    let content = Zeroizing::new(
        [
            &der::integer(&[0])[..],
            &der::sequence(&der::oid(&algorithm)),
            &wrapped[..],
        ]
        .concat(),
    );
    Some(Zeroizing::new(der::sequence(&content)))
}

/// The key in the PKCS #8 structure of a PKCS12 secret key. An algorithm
/// without a Java name here is named by its object identifier.
pub fn from_pkcs8(pkcs8: &[u8]) -> Option<SecretKey> {
    let mut reader = Reader::new(pkcs8);
    let mut info = reader.read_sequence().ok()?;
    info.read_integer().ok()?;
    let algorithm = info.read_sequence().ok()?.read_oid().ok()?;
    let key = info.read_octet_string().ok()?;
    let offered = ALGORITHMS.iter().map(|&(name, arcs, _)| (name, arcs));
    let name = offered
        .chain(OTHER_ALGORITHMS)
        .find(|(_, arcs)| algorithm.matches(arcs))
        .map_or_else(|| algorithm.to_dotted_string(), |(name, _)| name.into());
    Some(SecretKey {
        algorithm: name,
        key: Zeroizing::new(key.to_vec()),
    })
}

/// The key in the content of a file: the bytes that hex digits spell, with
/// or without spaces, colons, and line breaks, or else the content as it
/// is. `None` for no key, and for one longer than `MAX_KEY_SIZE`.
pub fn from_file(content: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let digits: Option<Vec<u8>> = content
        .iter()
        .filter(|byte| !byte.is_ascii_whitespace() && **byte != b':')
        .map(|&byte| char::from(byte).to_digit(16).map(|digit| digit as u8))
        .collect();
    let key = match digits {
        Some(digits) if !digits.is_empty() && digits.len() % 2 == 0 => {
            let key = digits
                .chunks(2)
                .map(|pair| pair[0] << 4 | pair[1])
                .collect();
            // The digits spell the key.
            drop(Zeroizing::new(digits));
            key
        }
        _ => content.to_vec(),
    };
    let key = Zeroizing::new(key);
    (1..=MAX_KEY_SIZE).contains(&key.len()).then_some(key)
}

/// The key as a line of hex digits.
pub fn hex(key: &[u8]) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::with_capacity(key.len() * 2 + 1));
    for byte in key {
        text.push_str(&format!("{byte:02x}"));
    }
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TestRng, sealed_secret_key};

    fn key(algorithm: &str, bytes: &[u8]) -> SecretKey {
        SecretKey {
            algorithm: algorithm.into(),
            key: Zeroizing::new(bytes.to_vec()),
        }
    }

    #[test]
    fn a_sealed_key_is_recovered_with_its_password_only() {
        let aes = key("AES", &[7; 16]);
        let sealed = seal(&aes, "changeit", &mut TestRng(1)).unwrap();
        assert!(unseal(&sealed, "changeit") == Ok(aes.clone()));
        assert!(unseal(&sealed, "other") == Err(Error::Password));
        // A password Java could not have used.
        assert!(unseal(&sealed, "pässword") == Err(Error::Password));
        assert!(seal(&aes, "pässword", &mut TestRng(1)) == Err(Error::PasswordNotAscii));
        // The stream is laid out as Java lays it out, which the keystore
        // parser walks to find the next entry.
        let object = java_serialization::read_object(&sealed).unwrap();
        assert_eq!(object.class, SEALED_CLASS);
        assert_eq!(object.rest, b"");
        assert_eq!(object.field("paramsAlg"), Some(SEAL_ALGORITHM.as_bytes()));
        let template = sealed_secret_key();
        let fields = template.windows(2).position(|w| w == [0x78, 0x70]).unwrap();
        assert_eq!(sealed[..fields], template[..fields]);
        // Each seal has its own salt.
        assert_ne!(sealed, seal(&aes, "changeit", &mut TestRng(2)).unwrap());
        let hmac = key("HmacSHA256", &[9; 32]);
        let sealed = seal(&hmac, "", &mut TestRng(1)).unwrap();
        assert!(unseal(&sealed, "") == Ok(hmac));
    }

    #[test]
    fn only_a_sealed_secret_key_spec_is_read() {
        let unsupported = |sealed: &[u8]| unseal(sealed, "changeit") == Err(Error::Unsupported);
        assert!(unsupported(b"junk"));
        // Synthetic parameters, which are not the algorithm's.
        assert!(unsupported(&sealed_secret_key()));
        let aes = key("AES", &[7; 16]);
        let sealed = seal(&aes, "changeit", &mut TestRng(1)).unwrap();
        // Another class, and another algorithm.
        let mut other = sealed.clone();
        other[8] = b'd';
        assert!(unsupported(&other));
        let mut other = sealed.clone();
        let last = other.len() - 1;
        other[last] = b'X';
        assert!(unsupported(&other));

        // What is sealed must be a `SecretKeySpec` with its two fields.
        let reseal = |plain: &[u8]| {
            let (parameters, encrypted) =
                key_protection::jceks_encrypt(plain, "changeit", &mut TestRng(1)).unwrap();
            let start = sealed.windows(2).position(|w| w == [0x78, 0x70]).unwrap() + 2;
            [
                &sealed[..start],
                &NEW_BYTE_ARRAY,
                &byte_array(&parameters),
                &[0x75, 0x71, 0x00, 0x7e, 0x00, 0x05],
                &byte_array(&encrypted),
                &[0x74],
                &utf(SEAL_ALGORITHM),
                &[0x74],
                &utf(SEAL_ALGORITHM),
            ]
            .concat()
        };
        let plain = serialized(&aes);
        assert!(unseal(&reseal(&plain), "changeit") == Ok(aes.clone()));
        assert!(unseal(&reseal(b"not a stream"), "changeit") == Err(Error::Password));
        assert!(unsupported(&reseal(&plain[..plain.len() - 1])));
        let mut renamed = plain.to_vec();
        renamed[8] = b'k';
        assert!(unsupported(&reseal(&renamed)));
        // A key under another field name, and an algorithm that is not text.
        let mut field = plain.to_vec();
        let at = field.windows(3).rposition(|w| w == b"key").unwrap();
        field[at] = b'K';
        assert!(unsupported(&reseal(&field)));
        let mut name = plain.to_vec();
        let at = name.windows(3).rposition(|w| w == b"AES").unwrap();
        name[at] = 0xff;
        assert!(unsupported(&reseal(&name)));
    }

    #[test]
    fn pkcs8_names_the_algorithm_by_its_object_identifier() {
        let aes = key("AES", &[7; 32]);
        let pkcs8 = to_pkcs8(&aes).unwrap();
        assert!(crate::pkcs12::is_private_key_info(&pkcs8));
        assert!(from_pkcs8(&pkcs8) == Some(aes));
        for (name, ..) in ALGORITHMS {
            let wrapped = to_pkcs8(&key(&name.to_lowercase(), &[1])).unwrap();
            assert_eq!(from_pkcs8(&wrapped).unwrap().algorithm, name);
        }
        for (name, _) in OTHER_ALGORITHMS {
            let wrapped = to_pkcs8(&key(name, &[1; 8])).unwrap();
            assert_eq!(from_pkcs8(&wrapped).unwrap().algorithm, name);
        }
        assert!(to_pkcs8(&key("Blowfish", &[1; 8])).is_none());
        // An algorithm without a name here keeps its identifier.
        let unknown = der::sequence(
            &[
                der::integer(&[0]),
                der::sequence(&der::oid(&ObjectIdentifier::new(&[1, 2, 3, 4]).unwrap())),
                der::octet_string(&[5; 4]),
            ]
            .concat(),
        );
        assert!(from_pkcs8(&unknown) == Some(key("1.2.3.4", &[5; 4])));
        assert!(from_pkcs8(b"junk").is_none());
        assert!(from_pkcs8(&der::sequence(&der::integer(&[0]))).is_none());
    }

    #[test]
    fn choices_are_aes_sizes_and_each_hmac() {
        let labels: Vec<_> = generated().into_iter().map(Choice::label).collect();
        assert_eq!(
            labels,
            [
                "AES (128 bits)",
                "AES (192 bits)",
                "AES (256 bits)",
                "HmacSHA1 (160 bits)",
                "HmacSHA256 (256 bits)",
                "HmacSHA384 (384 bits)",
                "HmacSHA512 (512 bits)",
            ]
        );
        for choice in generated() {
            let key = choice.generate(&mut TestRng(1));
            assert_eq!(
                (key.key.len() * 8, key.algorithm.as_str()),
                (choice.bits, choice.algorithm)
            );
            assert!(to_pkcs8(&key).is_some());
        }
        assert_ne!(
            generated()[0].generate(&mut TestRng(1)).key,
            generated()[0].generate(&mut TestRng(2)).key
        );
        // A key that is not of an AES size is an HMAC key.
        let names = |length| -> Vec<_> { fitting(length).iter().map(|c| c.label()).collect() };
        assert_eq!(names(24)[0], "AES (192 bits)");
        assert_eq!(names(24).len(), 5);
        assert_eq!(names(20)[0], "HmacSHA1 (160 bits)");
        assert_eq!(names(20).len(), 4);
    }

    #[test]
    fn a_file_holds_a_key_as_hex_digits_or_as_it_is() {
        let read = |content: &[u8]| from_file(content).map(|key| key.to_vec());
        assert_eq!(read(b"01a4\n"), Some(vec![1, 0xa4]));
        assert_eq!(read(b" 01:A4 0f\r\n"), Some(vec![1, 0xa4, 0x0f]));
        // An odd number of digits, and bytes that are not digits.
        assert_eq!(read(b"01a"), Some(b"01a".to_vec()));
        assert_eq!(read(&[0xff, 0x00, 0x30]), Some(vec![0xff, 0x00, 0x30]));
        assert_eq!(read(b""), None);
        assert_eq!(read(b" \n"), Some(b" \n".to_vec()));
        assert_eq!(
            read(&[1; MAX_KEY_SIZE]).map(|key| key.len()),
            Some(MAX_KEY_SIZE)
        );
        assert_eq!(read(&[1; MAX_KEY_SIZE + 1]), None);
        assert_eq!(hex(&[1, 0xa4]).as_str(), "01a4\n");
        assert_eq!(read(hex(&[0xab; 32]).as_bytes()), Some(vec![0xab; 32]));
    }
}
