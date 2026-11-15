use super::*;

/// Why an encrypted safe could not be read.
pub(super) enum SafeError {
    /// The safe is malformed, or uses unsupported or excessive parameters.
    Unreadable,
    /// Decryption failed, as it does for most wrong passwords.
    Decryption,
}

pub(super) fn decrypt_safe(content: &[u8], password: &[u8]) -> Result<Vec<u8>, SafeError> {
    let unreadable = |_| SafeError::Unreadable;
    let mut reader = Reader::new(content);
    let mut sequence = reader.read_sequence().map_err(unreadable)?;
    let _version = sequence.read_integer().map_err(unreadable)?;
    let mut info = sequence.read_sequence().map_err(unreadable)?;
    let _content_type = info.read_oid().map_err(unreadable)?;
    let algorithm = AlgorithmIdentifier::parse(&mut info).map_err(unreadable)?;
    let ciphertext = info.read_implicit(0, false).map_err(unreadable)?;
    pbe_decrypt(&algorithm, ciphertext, password)
}

/// The PKCS #8 private key `key` as an encoded `EncryptedPrivateKeyInfo`
/// under `password`.
pub(crate) fn encrypt_key(
    key: &[u8],
    password: &[u8],
    rng: &mut impl Rng,
) -> Result<Vec<u8>, WriteError> {
    let cipher = Pbes2Cipher::Aes256Cbc { iv: Vec::new() };
    encrypt_private_key(key, password, cipher, PBE_ITERATIONS, rng)
        .map(|encrypted| encrypted.encode())
        .map_err(|_| "the key could not be encrypted")
}

/// The PKCS #8 private key in the encoded `EncryptedPrivateKeyInfo`
/// `encrypted`, or `None` if `password` does not decrypt it.
pub(crate) fn decrypt_key(encrypted: &[u8], password: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    decrypt_info(&EncryptedPrivateKeyInfo::parse(encrypted).ok()?, password)
}

pub(super) fn decrypt_info(
    info: &EncryptedPrivateKeyInfo,
    password: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    pbe_decrypt(&info.algorithm, &info.encrypted_data, password)
        .ok()
        .map(Zeroizing::new)
        .filter(|key| is_private_key_info(key))
}

/// Decrypts `ciphertext` as its password-based encryption `algorithm` says.
pub(super) fn pbe_decrypt(
    algorithm: &AlgorithmIdentifier,
    ciphertext: &[u8],
    password: &[u8],
) -> Result<Vec<u8>, SafeError> {
    let unreadable = |_| SafeError::Unreadable;
    let check = |iterations, salt: &[u8], block_size| {
        if iterations == 0
            || iterations > MAX_ITERATIONS
            || salt.len() > MAX_SALT_SIZE
            || ciphertext.is_empty()
            || !ciphertext.len().is_multiple_of(block_size)
        {
            Err(SafeError::Unreadable)
        } else {
            Ok(())
        }
    };
    let decrypted = if algorithm.oid.matches(oid::OID_PBES2) {
        let pbe = Pbes2::parse(algorithm).map_err(unreadable)?;
        let block_size = match pbe.cipher {
            Pbes2Cipher::Aes128Cbc { .. }
            | Pbes2Cipher::Aes192Cbc { .. }
            | Pbes2Cipher::Aes256Cbc { .. } => 16,
            Pbes2Cipher::DesEde3Cbc { .. } => 8,
        };
        check(pbe.iterations, &pbe.salt, block_size)?;
        pbe.decrypt(ciphertext, password)
    } else {
        let mut pbe = LegacyPbe::parse(algorithm).map_err(unreadable)?;
        if algorithm.oid.matches(PBE_SHA1_128BIT_RC4) {
            pbe.kind = LegacyPbeKind::Rc4_128;
        } else if algorithm.oid.matches(PBE_SHA1_40BIT_RC4) {
            pbe.kind = LegacyPbeKind::Rc4_40;
        }
        let block_size = match pbe.kind {
            LegacyPbeKind::Rc4_40 | LegacyPbeKind::Rc4_128 => 1,
            LegacyPbeKind::DesEde3 | LegacyPbeKind::DesEde2 | LegacyPbeKind::Rc2_40 => 8,
        };
        check(pbe.iterations, &pbe.salt, block_size)?;
        pbe.decrypt(ciphertext, password)
    };
    // An unsupported parameter is not a wrong password; any other failure can be.
    decrypted.map_err(|error| match error {
        CryptoError::UnsupportedOperation(_) => SafeError::Unreadable,
        _ => SafeError::Decryption,
    })
}

pub(super) const OTHER_KEY_PASSWORD: WriteError = "A key in this keystore is protected by another password, so the keystore password was not changed.";
pub(super) const UNSUPPORTED_KEY: WriteError = "A key in this keystore uses encryption that is not supported, so the keystore password was not changed.";

/// The value of a key bag, as its `[0]` element, with the key decrypted
/// with `old` and encrypted again with `new`. The decrypted key exists only
/// in memory and is wiped. A secret key is handled as Java stores it: an
/// encrypted PKCS #8 structure inside the secret bag.
pub(super) fn reencrypt_key(
    bag: &Bag,
    old: &[u8],
    new: &[u8],
    rng: &mut impl Rng,
) -> Result<Vec<u8>, WriteError> {
    let secret;
    let (info, is_secret) = match bag {
        Bag::ShroudedKey(info) => (info, false),
        Bag::Secret { oid: kind, value } => {
            secret = secret_info(kind, value).ok_or(UNSUPPORTED_KEY)?;
            (&secret, true)
        }
        _ => return Err(UNSUPPORTED_KEY),
    };
    let key = pbe_decrypt(&info.algorithm, &info.encrypted_data, old)
        .map(Zeroizing::new)
        .map_err(|error| match error {
            SafeError::Unreadable => UNSUPPORTED_KEY,
            SafeError::Decryption => OTHER_KEY_PASSWORD,
        })?;
    // About 1 wrong password in 256 leaves valid padding, and RC4 has none.
    if !is_private_key_info(&key) {
        return Err(OTHER_KEY_PASSWORD);
    }
    let encrypted = encrypt_private_key(
        &key,
        new,
        Pbes2Cipher::Aes256Cbc { iv: Vec::new() },
        PBE_ITERATIONS,
        rng,
    )
    .map_err(|_| UNSUPPORTED_KEY)?
    .encode();
    Ok(if is_secret {
        der::explicit(0, &secret_value(&encrypted))
    } else {
        der::explicit(0, &encrypted)
    })
}

/// The encrypted PKCS #8 structure in a secret bag of type `kind` with
/// `value`, as Java stores a secret key. `None` for any other secret.
pub(super) fn secret_info(
    kind: &ObjectIdentifier,
    value: &[u8],
) -> Option<EncryptedPrivateKeyInfo> {
    if !kind.matches(oid::OID_PKCS12_SHROUDED_KEY_BAG) {
        return None;
    }
    Reader::new(value)
        .read_explicit(0)
        .and_then(|mut value| value.read_octet_string_owned())
        .and_then(|der| EncryptedPrivateKeyInfo::parse(&der))
        .ok()
}

/// A secret bag's value around the encoded, encrypted PKCS #8 structure
/// `encrypted`.
pub(super) fn secret_value(encrypted: &[u8]) -> Vec<u8> {
    der::sequence(
        &[
            der::oid(&object_id(oid::OID_PKCS12_SHROUDED_KEY_BAG)),
            der::explicit(0, &der::octet_string(encrypted)),
        ]
        .concat(),
    )
}

/// Whether `content` has the shape of a PKCS #8 `PrivateKeyInfo`: a version,
/// an algorithm, and the key octets, with optional fields after them.
pub(crate) fn is_private_key_info(content: &[u8]) -> bool {
    let mut reader = Reader::new(content);
    let Ok(mut info) = reader.read_sequence() else {
        return false;
    };
    info.read_integer().is_ok()
        && info.read_sequence().is_ok()
        && info.read_octet_string().is_ok()
        && reader.expect_end().is_ok()
}

/// The bag `raw` with `value` as its `[0]` value element. The bag's type and
/// attributes keep their bytes.
pub(super) fn with_value(raw: &[u8], value: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut reader = Reader::new(raw);
    let mut bag = reader.read_sequence()?;
    let id = bag.read_raw_tlv()?;
    bag.read_raw_tlv()?;
    let attributes = if bag.is_empty() {
        &[][..]
    } else {
        bag.read_raw_tlv()?
    };
    Ok(der::sequence(&[id, value, attributes].concat()))
}

/// Whether `content` is a single SafeContents sequence of bags.
pub(super) fn is_safe_contents(content: &[u8]) -> bool {
    let mut reader = Reader::new(content);
    let Ok(mut bags) = reader.read_sequence() else {
        return false;
    };
    while !bags.is_empty() {
        if bags.read_sequence().is_err() {
            return false;
        }
    }
    reader.expect_end().is_ok()
}
