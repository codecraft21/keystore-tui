//! OpenSSL's legacy PEM private-key format (`RSA PRIVATE KEY` and
//! `EC PRIVATE KEY`), plain or encrypted with RFC 1421 `Proc-Type` and
//! `DEK-Info` headers (`EVP_BytesToKey` with MD5).
use crown::{
    asn1::{Reader, der, oid, oid::ObjectIdentifier},
    block::{
        aes::Aes,
        des::{Des, TripleDes},
    },
    hash::md5::sum_md5,
    modes::{
        BlockMode,
        cbc::{CbcDecryptor, CbcEncryptor},
    },
    rng::Rng,
    rsa::der::parse_rsa_private_key,
    x509::keys::PrivateKeyInfo,
};
use zeroize::Zeroizing;

/// A private key as PKCS #8 `PrivateKeyInfo`, wiped when dropped.
pub type Pkcs8Key = Zeroizing<Vec<u8>>;

/// Which traditional OpenSSL private-key type a PEM block holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Rsa,
    Ec,
}

impl KeyKind {
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "RSA PRIVATE KEY" => Some(Self::Rsa),
            "EC PRIVATE KEY" => Some(Self::Ec),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Rsa => "RSA PRIVATE KEY",
            Self::Ec => "EC PRIVATE KEY",
        }
    }
}

/// Supported legacy OpenSSL PEM CBC block ciphers (`DEK-Info`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    Aes128,
    Aes192,
    Aes256,
    DesEde3,
    Des,
}

impl Cipher {
    pub fn from_dek_name(name: &str) -> Option<Self> {
        match name.to_ascii_uppercase().as_str() {
            "AES-128-CBC" => Some(Self::Aes128),
            "AES-192-CBC" => Some(Self::Aes192),
            "AES-256-CBC" => Some(Self::Aes256),
            "DES-EDE3-CBC" => Some(Self::DesEde3),
            "DES-CBC" => Some(Self::Des),
            _ => None,
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
            Self::DesEde3 => 24,
            Self::Des => 8,
        }
    }

    fn block_size(self) -> usize {
        match self {
            Self::Aes128 | Self::Aes192 | Self::Aes256 => 16,
            Self::DesEde3 | Self::Des => 8,
        }
    }

    fn dek_name(self) -> &'static str {
        match self {
            Self::Aes128 => "AES-128-CBC",
            Self::Aes192 => "AES-192-CBC",
            Self::Aes256 => "AES-256-CBC",
            Self::DesEde3 => "DES-EDE3-CBC",
            Self::Des => "DES-CBC",
        }
    }
}

/// A parsed `... PRIVATE KEY` PEM block with its RFC 1421 headers.
pub struct PemKeyBlock {
    pub label: String,
    pub headers: Vec<(String, String)>,
    pub data: Zeroizing<Vec<u8>>,
}

impl PemKeyBlock {
    /// Whether the block carries a `Proc-Type: 4,ENCRYPTED` header.
    pub fn is_encrypted(&self) -> bool {
        self.header("Proc-Type").is_some_and(|value| {
            let mut parts = value.split(',').map(str::trim);
            parts.next() == Some("4")
                && parts
                    .next()
                    .is_some_and(|kind| kind.eq_ignore_ascii_case("ENCRYPTED"))
                && parts.next().is_none()
        })
    }

    /// Whether the block carries any RFC 1421 header (such as `Proc-Type` or `DEK-Info`).
    pub fn has_headers(&self) -> bool {
        !self.headers.is_empty()
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// An encrypted legacy OpenSSL PEM key (`RSA PRIVATE KEY` or `EC PRIVATE KEY`),
/// validated and ready to decrypt once the user supplies its password.
pub struct EncryptedLegacyKey {
    kind: KeyKind,
    cipher: Cipher,
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl EncryptedLegacyKey {
    /// Validates the headers and ciphertext framing of an encrypted legacy PEM block.
    pub fn parse(block: PemKeyBlock) -> Result<Self, String> {
        let Some(kind) = KeyKind::from_label(&block.label) else {
            return Err(format!(
                "holds an encrypted '{}' block, which is not supported; convert the key to PKCS #8 first",
                block.label
            ));
        };
        let dek_info = block
            .header("DEK-Info")
            .ok_or_else(|| "holds a malformed encrypted private key".to_owned())?;
        let Some((cipher_name, iv_hex)) = dek_info.split_once(',') else {
            return Err("holds a malformed encrypted private key".into());
        };
        let cipher_name = cipher_name.trim();
        let Some(cipher) = Cipher::from_dek_name(cipher_name) else {
            return Err(format!(
                "uses an unsupported legacy PEM cipher '{cipher_name}'; convert the key to PKCS #8 first"
            ));
        };
        let iv = decode_hex(iv_hex.trim())
            .filter(|iv| iv.len() == cipher.block_size())
            .ok_or_else(|| "holds a malformed encrypted private key".to_owned())?;
        if block.data.is_empty() || !block.data.len().is_multiple_of(cipher.block_size()) {
            return Err("holds a malformed encrypted private key".into());
        }
        Ok(Self {
            kind,
            cipher,
            iv,
            ciphertext: block.data.to_vec(),
        })
    }

    /// Decrypts the key with `password` and returns it as PKCS #8 `PrivateKeyInfo`.
    /// Returns `None` if decryption, padding, or key validation fails (wrong password).
    pub fn decrypt(&self, password: &[u8]) -> Option<Pkcs8Key> {
        let key = evp_bytes_to_key(password, &self.iv[..8], self.cipher.key_len());
        let mut plaintext = Zeroizing::new(self.ciphertext.clone());
        // `crown`'s CBC decryptors implement `CryptBlocks` via `BlockMode::encrypt`.
        match self.cipher {
            Cipher::Aes128 | Cipher::Aes192 | Cipher::Aes256 => {
                Aes::new(&key)
                    .ok()?
                    .to_cbc_dec(&self.iv)
                    .encrypt(&mut plaintext);
            }
            Cipher::DesEde3 => {
                TripleDes::new(&key)
                    .ok()?
                    .to_cbc_dec(&self.iv)
                    .encrypt(&mut plaintext);
            }
            Cipher::Des => {
                Des::new(&key)
                    .ok()?
                    .to_cbc_dec(&self.iv)
                    .encrypt(&mut plaintext);
            }
        }
        if !pkcs7_unpad(&mut plaintext, self.cipher.block_size()) {
            return None;
        }
        match self.kind {
            KeyKind::Rsa => {
                parse_rsa_private_key(&plaintext).ok()?;
                Some(wrap_pkcs8(
                    oid::OID_RSA_ENCRYPTION,
                    &der::null(),
                    &plaintext,
                ))
            }
            KeyKind::Ec => {
                let curve = ec_curve(&plaintext)?;
                let wrapped = wrap_pkcs8(oid::OID_EC_PUBLIC_KEY, curve, &plaintext);
                PrivateKeyInfo::parse(&wrapped).ok()?.decode().ok()?;
                Some(wrapped)
            }
        }
    }
}

/// Why [`parse_key_blocks`] could not read a PEM text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// A `... PRIVATE KEY` block is malformed: its END line is missing or
    /// mismatched, or its body is not valid base64.
    KeyBlock,
    /// Another block, or a BEGIN line, is malformed.
    OtherBlock,
}

/// Extracts every PEM block whose label ends with `PRIVATE KEY`, preserving its
/// RFC 1421 headers (including folded continuation lines) and decoding its
/// body into a wiping buffer.
pub fn parse_key_blocks(text: &str) -> Result<Vec<PemKeyBlock>, ParseError> {
    let mut blocks = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("-----BEGIN ") else {
            continue;
        };
        let Some(label) = rest.strip_suffix("-----") else {
            return Err(ParseError::OtherBlock);
        };
        let is_key = label.ends_with("PRIVATE KEY");
        let malformed = if is_key {
            ParseError::KeyBlock
        } else {
            ParseError::OtherBlock
        };
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut body: Option<Zeroizing<String>> = None;
        let mut in_body = false;
        let mut closed = false;
        while let Some(line) = lines.next() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("-----END ") {
                let end_label = rest.strip_suffix("-----").ok_or(malformed)?;
                if end_label != label {
                    return Err(malformed);
                }
                closed = true;
                break;
            }
            if !is_key {
                continue;
            }
            if !in_body {
                if trimmed.is_empty() {
                    if !headers.is_empty() {
                        in_body = true;
                    }
                    continue;
                }
                if line.starts_with([' ', '\t'])
                    && let Some((_, value)) = headers.last_mut()
                {
                    value.push(' ');
                    value.push_str(trimmed);
                    continue;
                }
                if let Some((name, value)) = trimmed.split_once(':') {
                    headers.push((name.trim().to_owned(), value.trim().to_owned()));
                    continue;
                }
                in_body = true;
            }
            let body = body.get_or_insert_with(|| {
                let mut capacity = non_whitespace_len(trimmed);
                for rest_line in lines.clone() {
                    let rest_trimmed = rest_line.trim();
                    if rest_trimmed.starts_with("-----END ") {
                        break;
                    }
                    capacity += non_whitespace_len(rest_trimmed);
                }
                Zeroizing::new(String::with_capacity(capacity))
            });
            if trimmed.chars().any(char::is_whitespace) {
                for ch in trimmed.chars() {
                    if !ch.is_whitespace() {
                        body.push(ch);
                    }
                }
            } else {
                body.push_str(trimmed);
            }
        }
        if !closed {
            return Err(malformed);
        }
        if is_key {
            let body_text = match &body {
                Some(body) => {
                    debug_assert_eq!(body.len(), body.capacity());
                    body.as_str()
                }
                None => "",
            };
            let data = base64_decode(body_text).ok_or(malformed)?;
            blocks.push(PemKeyBlock {
                label: label.to_owned(),
                headers,
                data,
            });
        }
    }
    Ok(blocks)
}

fn non_whitespace_len(trimmed: &str) -> usize {
    if !trimmed.chars().any(char::is_whitespace) {
        trimmed.len()
    } else {
        trimmed
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .map(char::len_utf8)
            .sum()
    }
}

/// The legacy OpenSSL PEM label for `pkcs8_der` (`RSA PRIVATE KEY` or
/// `EC PRIVATE KEY`), or `None` when the key cannot be written in that format,
/// such as a key of another algorithm or an EC key that names no curve.
pub fn legacy_label(pkcs8_der: &[u8]) -> Option<&'static str> {
    from_pkcs8(pkcs8_der).ok().map(|(label, _)| label)
}

/// Converts a PKCS #8 `PrivateKeyInfo` into its traditional OpenSSL PEM label
/// and DER (`RSAPrivateKey` or RFC 5915 `ECPrivateKey` with its named curve).
pub fn from_pkcs8(pkcs8_der: &[u8]) -> Result<(&'static str, Zeroizing<Vec<u8>>), &'static str> {
    let info = PrivateKeyInfo::parse(pkcs8_der).map_err(|_| "the private key is malformed")?;
    let oid = info.algorithm.oid;
    let params = info.algorithm.parameters;
    let private_key = Zeroizing::new(info.private_key);
    if oid.matches(oid::OID_RSA_ENCRYPTION) {
        parse_rsa_private_key(&private_key).map_err(|_| "the RSA private key is malformed")?;
        Ok((KeyKind::Rsa.label(), private_key))
    } else if oid.matches(oid::OID_EC_PUBLIC_KEY) {
        if ec_curve(&private_key).is_some() {
            return Ok((KeyKind::Ec.label(), private_key));
        }
        let curve_tlv = params
            .as_deref()
            .filter(|bytes| {
                let mut reader = Reader::new(bytes);
                reader.read_oid().is_ok() && reader.expect_end().is_ok()
            })
            .ok_or("the EC private key does not name its curve")?;
        let ec_der =
            insert_ec_curve(&private_key, curve_tlv).ok_or("the EC private key is malformed")?;
        Ok((KeyKind::Ec.label(), ec_der))
    } else {
        Err("only RSA and EC keys can be exported in legacy OpenSSL PEM format")
    }
}

/// Encrypts `key_der` in OpenSSL's legacy PEM format with `AES-256-CBC` and
/// formats the PEM block (followed by `rest`), verifying that it decrypts back
/// to the same key.
pub fn encrypt_pem_block(
    label: &str,
    key_der: &[u8],
    password: &[u8],
    rng: &mut impl Rng,
    rest: &[u8],
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let block = encrypt_pem_with_cipher(label, key_der, password, Cipher::Aes256, rng, rest)?;
    // Verify the encrypted key decrypts back before returning it.
    let text = std::str::from_utf8(&block).map_err(|_| "the encrypted key is not UTF-8")?;
    let mut parsed =
        parse_key_blocks(text).map_err(|_| "the encrypted key would not parse again")?;
    let parsed_block = parsed
        .pop()
        .ok_or("the encrypted key would not parse again")?;
    let encrypted = EncryptedLegacyKey::parse(parsed_block)
        .map_err(|_| "the encrypted key would not parse again")?;
    let decrypted = encrypted
        .decrypt(password)
        .ok_or("the encrypted key would not decrypt again")?;
    let (_, roundtrip_der) =
        from_pkcs8(&decrypted).map_err(|_| "the encrypted key would not decrypt again")?;
    if roundtrip_der.as_slice() != key_der {
        return Err("the encrypted key would not decrypt again");
    }
    Ok(block)
}

/// Encrypts `key_der` with `cipher` and encodes the legacy PEM block.
fn encrypt_pem_with_cipher(
    label: &str,
    key_der: &[u8],
    password: &[u8],
    cipher: Cipher,
    rng: &mut impl Rng,
    rest: &[u8],
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let block_size = cipher.block_size();
    let mut iv = vec![0u8; block_size];
    rng.fill_bytes(&mut iv);
    let key = evp_bytes_to_key(password, &iv[..8], cipher.key_len());
    let mut buf = pkcs7_pad(key_der, block_size);
    match cipher {
        Cipher::Aes128 | Cipher::Aes192 | Cipher::Aes256 => {
            Aes::new(&key)
                .map_err(|_| "the key could not be encrypted")?
                .to_cbc_enc(&iv)
                .encrypt(&mut buf);
        }
        Cipher::DesEde3 => {
            TripleDes::new(&key)
                .map_err(|_| "the key could not be encrypted")?
                .to_cbc_enc(&iv)
                .encrypt(&mut buf);
        }
        Cipher::Des => {
            Des::new(&key)
                .map_err(|_| "the key could not be encrypted")?
                .to_cbc_enc(&iv)
                .encrypt(&mut buf);
        }
    }
    let headers = format!(
        "Proc-Type: 4,ENCRYPTED\nDEK-Info: {},{}\n\n",
        cipher.dek_name(),
        encode_hex_upper(&iv)
    );
    Ok(pem_block(label, &headers, &buf, rest))
}

/// `data` as a PEM block labelled `label` with optional `headers` (already
/// terminated with `\n\n` when non-empty), followed by `rest`, written into
/// one buffer sized up front so no unwiped copy of `data` is left behind.
pub fn pem_block(label: &str, headers: &str, data: &[u8], rest: &[u8]) -> Zeroizing<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let encoded = data.len().div_ceil(3) * 4;
    let lines = encoded.div_ceil(64);
    let armour = "-----BEGIN -----\n".len() + "-----END -----\n".len() + 2 * label.len();
    let mut out = Zeroizing::new(Vec::with_capacity(
        armour + headers.len() + encoded + lines + rest.len(),
    ));
    out.extend_from_slice(b"-----BEGIN ");
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(b"-----\n");
    out.extend_from_slice(headers.as_bytes());
    for (index, group) in data.chunks(3).enumerate() {
        let bytes = [
            group[0],
            *group.get(1).unwrap_or(&0),
            *group.get(2).unwrap_or(&0),
        ];
        let bits = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]);
        for position in 0..4 {
            out.push(if position <= group.len() {
                ALPHABET[(bits >> (18 - 6 * position) & 63) as usize]
            } else {
                b'='
            });
        }
        if index % 16 == 15 {
            out.push(b'\n');
        }
    }
    if !encoded.is_multiple_of(64) {
        out.push(b'\n');
    }
    out.extend_from_slice(b"-----END ");
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(b"-----\n");
    out.extend_from_slice(rest);
    debug_assert_eq!(out.len(), out.capacity());
    out
}

/// The curve named inside an RFC 5915 `ECPrivateKey`, as an encoded OID TLV.
pub fn ec_curve(key: &[u8]) -> Option<&[u8]> {
    let mut key = Reader::new(key).read_sequence().ok()?;
    key.read_integer().ok()?;
    key.read_octet_string().ok()?;
    key.read_explicit(0).ok()?.read_raw_tlv().ok()
}

/// Wraps a key in its algorithm's own encoding into a PKCS #8 `PrivateKeyInfo`.
pub fn wrap_pkcs8(algorithm: &[u64], parameters: &[u8], key: &[u8]) -> Pkcs8Key {
    let algorithm = ObjectIdentifier::new(algorithm).expect("static oid");
    let octets = Zeroizing::new(der::octet_string(key));
    let mut content = Zeroizing::new(Vec::with_capacity(octets.len() + 64));
    content.extend(der::integer(&[0]));
    content.extend(der::sequence(
        &[der::oid(&algorithm), parameters.to_vec()].concat(),
    ));
    content.extend_from_slice(&octets);
    Zeroizing::new(der::sequence(&content))
}

/// Rebuilds an RFC 5915 `ECPrivateKey` that lacked `[0] parameters` by
/// inserting `[0] EXPLICIT <curve_tlv>` while preserving `[1] publicKey`.
fn insert_ec_curve(ec_der: &[u8], curve_tlv: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut reader = Reader::new(ec_der);
    let mut seq = reader.read_sequence().ok()?;
    let version = seq.read_integer().ok()?;
    let private_key = seq.read_octet_string().ok()?;
    let mut public_key_tlv = None;
    while !seq.is_empty() {
        let tag = seq.peek_tag().ok()?;
        if tag.class == der::Class::ContextSpecific && tag.number == 1 {
            public_key_tlv = Some(seq.read_raw_tlv().ok()?);
        } else {
            return None;
        }
    }
    reader.expect_end().ok()?;
    let mut content = Zeroizing::new(Vec::with_capacity(ec_der.len() + curve_tlv.len() + 16));
    content.extend_from_slice(&der::integer(version));
    content.extend_from_slice(&der::octet_string(private_key));
    content.extend_from_slice(&der::explicit(0, curve_tlv));
    if let Some(public_key) = public_key_tlv {
        content.extend_from_slice(public_key);
    }
    Some(Zeroizing::new(der::sequence(&content)))
}

/// OpenSSL `EVP_BytesToKey` with MD5 and 1 iteration (salt = first 8 bytes of IV).
fn evp_bytes_to_key(password: &[u8], salt: &[u8], key_len: usize) -> Zeroizing<Vec<u8>> {
    let mut derived = Zeroizing::new(Vec::with_capacity(key_len));
    let mut prev: Option<Zeroizing<[u8; 16]>> = None;
    while derived.len() < key_len {
        let mut input = Zeroizing::new(Vec::with_capacity(
            prev.as_ref().map_or(0, |d| d.len()) + password.len() + salt.len(),
        ));
        if let Some(digest) = &prev {
            input.extend_from_slice(&**digest);
        }
        input.extend_from_slice(password);
        input.extend_from_slice(salt);
        let digest = Zeroizing::new(sum_md5(&input));
        let needed = (key_len - derived.len()).min(digest.len());
        derived.extend_from_slice(&digest[..needed]);
        prev = Some(digest);
    }
    derived
}

fn pkcs7_pad(data: &[u8], block_size: usize) -> Zeroizing<Vec<u8>> {
    let pad = block_size - (data.len() % block_size);
    let mut out = Zeroizing::new(Vec::with_capacity(data.len() + pad));
    out.extend_from_slice(data);
    out.resize(data.len() + pad, pad as u8);
    out
}

fn pkcs7_unpad(data: &mut Zeroizing<Vec<u8>>, block_size: usize) -> bool {
    let Some(&last) = data.last() else {
        return false;
    };
    let pad = usize::from(last);
    if pad == 0 || pad > block_size || pad > data.len() {
        return false;
    }
    let start = data.len() - pad;
    if data[start..].iter().any(|&byte| byte != last) {
        return false;
    }
    data.truncate(start);
    true
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        out.push((high << 4) | low);
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn encode_hex_upper(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn base64_decode(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    fn value(byte: u8) -> Option<u32> {
        match byte {
            b'A'..=b'Z' => Some(u32::from(byte - b'A')),
            b'a'..=b'z' => Some(u32::from(byte - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(byte - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    // Padded base64 only: whole groups of four, with at most two `=` at the
    // end. The output then never outgrows the buffer, so no unwiped copy of
    // the decoded key is left behind by reallocation.
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let padding = bytes.iter().rev().take_while(|&&byte| byte == b'=').count();
    if padding > 2 {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len() / 4 * 3));
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &byte in &bytes[..bytes.len() - padding] {
        acc = (acc << 6) | value(byte)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if acc & ((1 << bits) - 1) != 0 {
        return None;
    }
    debug_assert!(out.len() <= out.capacity());
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        generate::{self, Algorithm},
        test_support::{TestRng, ed25519_pkcs8},
    };
    use crown::{asn1::pem, ec::CurveId};

    fn sample_rsa_pkcs8() -> Pkcs8Key {
        let mut rng = crate::save::OsRng::default();
        generate::key_pair(Algorithm::Rsa(1024), &mut rng).expect("rsa key")
    }

    fn sample_ec_pkcs8() -> Pkcs8Key {
        let mut rng = TestRng(22);
        generate::key_pair(Algorithm::Ec(CurveId::P256), &mut rng).expect("ec key")
    }

    #[test]
    fn round_trips_rsa_and_ec_across_all_ciphers() {
        let rsa = sample_rsa_pkcs8();
        let ec = sample_ec_pkcs8();
        let all_ciphers = [
            Cipher::Aes128,
            Cipher::Aes192,
            Cipher::Aes256,
            Cipher::DesEde3,
            Cipher::Des,
        ];
        let mut rng = TestRng(33);
        for (pkcs8, expected_label) in [(&rsa, "RSA PRIVATE KEY"), (&ec, "EC PRIVATE KEY")] {
            assert_eq!(legacy_label(pkcs8), Some(expected_label));
            let (label, raw) = from_pkcs8(pkcs8).expect("convert to legacy");
            assert_eq!(label, expected_label);
            for cipher in all_ciphers {
                let pem_bytes =
                    encrypt_pem_with_cipher(label, &raw, b"secret-pass", cipher, &mut rng, b"")
                        .expect("encrypt");
                let text = std::str::from_utf8(&pem_bytes).unwrap();
                assert!(text.contains("Proc-Type: 4,ENCRYPTED"));
                assert!(text.contains(&format!("DEK-Info: {},", cipher.dek_name())));
                let mut blocks = parse_key_blocks(text).expect("parse");
                assert_eq!(blocks.len(), 1);
                let block = blocks.pop().unwrap();
                assert!(block.is_encrypted());
                let encrypted = EncryptedLegacyKey::parse(block).expect("valid encrypted");
                assert!(encrypted.decrypt(b"wrong-pass").is_none());
                let decrypted = encrypted.decrypt(b"secret-pass").expect("decrypt");
                let (_, decoded_raw) = from_pkcs8(&decrypted).expect("re-extract");
                assert_eq!(decoded_raw.as_slice(), raw.as_slice());
            }
        }
    }

    #[test]
    fn encrypt_pem_block_verifies_and_appends_rest() {
        let ec = sample_ec_pkcs8();
        let (label, raw) = from_pkcs8(&ec).unwrap();
        let mut rng = TestRng(44);
        let cert = pem::encode("CERTIFICATE", b"cert-bytes");
        let out = encrypt_pem_block(label, &raw, b"pw", &mut rng, cert.as_bytes()).unwrap();
        let text = std::str::from_utf8(&out).unwrap();
        assert!(text.ends_with(&cert));
        let mut blocks = parse_key_blocks(text).unwrap();
        assert_eq!(blocks.len(), 1);
        let encrypted = EncryptedLegacyKey::parse(blocks.pop().unwrap()).unwrap();
        assert!(encrypted.decrypt(b"pw").is_some());
    }

    #[test]
    fn ec_pkcs8_without_embedded_curve_inserts_named_curve() {
        let ec = sample_ec_pkcs8();
        let info = PrivateKeyInfo::parse(&ec).unwrap();
        // Rebuild inner ECPrivateKey without [0] parameters, leaving the curve only in PKCS #8 AlgorithmIdentifier.
        let mut reader = Reader::new(&info.private_key);
        let mut seq = reader.read_sequence().unwrap();
        let version = seq.read_integer().unwrap();
        let scalar = seq.read_octet_string().unwrap();
        let _curve = seq.read_explicit(0).unwrap();
        let pub_tlv = if seq.is_empty() {
            None
        } else {
            Some(seq.read_raw_tlv().unwrap())
        };
        let mut stripped_inner = Vec::new();
        stripped_inner.extend_from_slice(&der::integer(version));
        stripped_inner.extend_from_slice(&der::octet_string(scalar));
        if let Some(pub_tlv) = pub_tlv {
            stripped_inner.extend_from_slice(pub_tlv);
        }
        let stripped_ec = der::sequence(&stripped_inner);
        assert!(ec_curve(&stripped_ec).is_none());
        let stripped_pkcs8 = PrivateKeyInfo {
            algorithm: info.algorithm,
            private_key: stripped_ec,
            attributes: None,
            public_key: None,
        }
        .encode();

        let (label, exported) = from_pkcs8(&stripped_pkcs8).expect("inserts curve");
        assert_eq!(label, "EC PRIVATE KEY");
        let curve = ec_curve(&exported).expect("curve is now embedded");
        let rewrapped = wrap_pkcs8(oid::OID_EC_PUBLIC_KEY, curve, &exported);
        assert!(PrivateKeyInfo::parse(&rewrapped).unwrap().decode().is_ok());
    }

    #[test]
    fn rejects_non_rsa_ec_and_malformed_headers() {
        let ed = ed25519_pkcs8(9);
        assert_eq!(legacy_label(&ed), None);
        assert!(from_pkcs8(&ed).is_err());

        // Unsupported cipher
        let bf = "-----BEGIN RSA PRIVATE KEY-----\r\nProc-Type: 4,ENCRYPTED\r\nDEK-Info: BF-CBC,0011223344556677\r\n\r\nAAAAAAAAAAAAAAAAAAAAAA==\r\n-----END RSA PRIVATE KEY-----\r\n";
        let mut blocks = parse_key_blocks(bf).unwrap();
        let err = EncryptedLegacyKey::parse(blocks.pop().unwrap())
            .err()
            .unwrap();
        assert!(err.contains("BF-CBC"));

        // Wrong IV length for AES-256-CBC (needs 16 bytes = 32 hex chars)
        let bad_iv = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,0011\n\nAAAAAAAAAAAAAAAAAAAAAA==\n-----END RSA PRIVATE KEY-----\n";
        let mut blocks = parse_key_blocks(bad_iv).unwrap();
        assert!(EncryptedLegacyKey::parse(blocks.pop().unwrap()).is_err());

        // Non-block-aligned ciphertext
        let bad_len = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00112233445566778899AABBCCDDEEFF\n\nAAAA\n-----END RSA PRIVATE KEY-----\n";
        let mut blocks = parse_key_blocks(bad_len).unwrap();
        assert!(EncryptedLegacyKey::parse(blocks.pop().unwrap()).is_err());

        // Unsupported encrypted label (PRIVATE KEY)
        let enc_pkcs8 = "-----BEGIN PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00112233445566778899AABBCCDDEEFF\n\nAAAAAAAAAAAAAAAAAAAAAA==\n-----END PRIVATE KEY-----\n";
        let mut blocks = parse_key_blocks(enc_pkcs8).unwrap();
        assert!(EncryptedLegacyKey::parse(blocks.pop().unwrap()).is_err());
    }

    #[test]
    fn legacy_label_needs_a_named_curve() {
        let ec = sample_ec_pkcs8();
        let info = PrivateKeyInfo::parse(&ec).unwrap();
        let mut reader = Reader::new(&info.private_key);
        let mut seq = reader.read_sequence().unwrap();
        let version = seq.read_integer().unwrap();
        let scalar = seq.read_octet_string().unwrap();
        let inner = der::sequence(&[der::integer(version), der::octet_string(scalar)].concat());
        // No curve in the `ECPrivateKey` and only NULL in the PKCS #8 parameters.
        let unnamed = wrap_pkcs8(oid::OID_EC_PUBLIC_KEY, &der::null(), &inner);
        assert!(from_pkcs8(&unnamed).is_err());
        assert_eq!(legacy_label(&unnamed), None);
    }

    #[test]
    fn base64_decode_requires_padded_groups() {
        assert_eq!(base64_decode("").unwrap().as_slice(), b"");
        assert_eq!(base64_decode("TWFu").unwrap().as_slice(), b"Man");
        assert_eq!(base64_decode("TWE=").unwrap().as_slice(), b"Ma");
        assert_eq!(base64_decode("TQ==").unwrap().as_slice(), b"M");
        for bad in [
            "TWE", "TQ", "TQ=", "TWFuTWE", "T===", "====", "TQ==TQ==", "TW=u", "TR==",
        ] {
            assert!(base64_decode(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn parse_key_blocks_reads_folded_headers_and_reports_where_it_failed() {
        let folded = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\
            DEK-Info: AES-128-CBC,\n 00112233445566778899AABBCCDDEEFF\n\n\
            AAAAAAAAAAAAAAAAAAAAAA==\n-----END RSA PRIVATE KEY-----\n";
        let mut blocks = parse_key_blocks(folded).unwrap();
        let block = blocks.pop().unwrap();
        assert_eq!(
            block.header("DEK-Info"),
            Some("AES-128-CBC, 00112233445566778899AABBCCDDEEFF")
        );
        let encrypted = EncryptedLegacyKey::parse(block).unwrap();
        assert_eq!(encrypted.cipher, Cipher::Aes128);

        let damaged_key = "-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----\n";
        assert_eq!(
            parse_key_blocks(damaged_key).err(),
            Some(ParseError::KeyBlock)
        );
        let unclosed_key = "-----BEGIN PRIVATE KEY-----\nAAAA\n";
        assert_eq!(
            parse_key_blocks(unclosed_key).err(),
            Some(ParseError::KeyBlock)
        );
        let unclosed_other = "-----BEGIN CERTIFICATE-----\nAAAA\n";
        assert_eq!(
            parse_key_blocks(unclosed_other).err(),
            Some(ParseError::OtherBlock)
        );
        let bad_begin = "-----BEGIN CERTIFICATE\n";
        assert_eq!(
            parse_key_blocks(bad_begin).err(),
            Some(ParseError::OtherBlock)
        );
    }

    #[test]
    fn parse_key_blocks_handles_empty_whitespace_and_multiline_bodies() {
        // Empty body (no allocation needed).
        let empty = "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n";
        let blocks = parse_key_blocks(empty).unwrap();
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].data.is_empty());

        // Multi-line body with internal whitespace, blank lines, and clean lines.
        let mixed =
            "-----BEGIN PRIVATE KEY-----\nTW Fu\n\n\tTW\tFu\nTWFu\n-----END PRIVATE KEY-----\n";
        let blocks = parse_key_blocks(mixed).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].data.as_slice(), b"ManManMan");

        // Malformed non-ASCII body is still sized accurately and rejected.
        let non_ascii = "-----BEGIN PRIVATE KEY-----\nä ö\n-----END PRIVATE KEY-----\n";
        assert_eq!(
            parse_key_blocks(non_ascii).err(),
            Some(ParseError::KeyBlock)
        );
    }
}
