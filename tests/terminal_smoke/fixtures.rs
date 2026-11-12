//! Generated public test data: committed fixtures, temporary directories, and
//! keystores and PEM files built from them at runtime.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use sha1::{Digest, Sha1};

pub const ROOT: &str = env!("CARGO_MANIFEST_DIR");

pub fn fixture(name: &str) -> PathBuf {
    Path::new(ROOT).join("tests/fixtures").join(name)
}

/// A directory under Cargo's target directory, removed when dropped.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let name = format!(
            "terminal-check-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Append the JKS integrity digest for an empty password.
pub fn with_empty_password_digest(mut body: Vec<u8>) -> Vec<u8> {
    let digest = Sha1::new()
        .chain_update(b"Mighty Aphrodite")
        .chain_update(&body)
        .finalize();
    body.extend_from_slice(&digest);
    body
}

/// `trusted-cert.jks` with its digest recomputed for an empty password.
pub fn empty_password_fixture() -> Vec<u8> {
    let mut data = fs::read(fixture("trusted-cert.jks")).unwrap();
    data.truncate(data.len() - 20);
    with_empty_password_digest(data)
}

/// The DER certificate stored in the public fixture under `root-cert`.
pub fn fixture_certificate() -> Vec<u8> {
    let data = fs::read(fixture("trusted-cert.jks")).unwrap();
    let offset = 12 + 4 + 2 + b"root-cert".len() + 8 + 2 + b"X.509".len();
    let length = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
    data[offset + 4..offset + 4 + length].to_vec()
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut encoded = String::new();
    for chunk in data.chunks(3) {
        let bits = chunk.iter().enumerate().fold(0_u32, |bits, (i, &byte)| {
            bits | u32::from(byte) << (16 - 8 * i)
        });
        for i in 0..4 {
            if i <= chunk.len() {
                encoded.push(char::from(BASE64[(bits >> (18 - 6 * i) & 63) as usize]));
            } else {
                encoded.push('=');
            }
        }
    }
    encoded
}

fn base64_decode(text: &str) -> Vec<u8> {
    let mut decoded = Vec::new();
    let (mut bits, mut count) = (0_u32, 0);
    for byte in text.bytes().take_while(|&byte| byte != b'=') {
        let value = BASE64
            .iter()
            .position(|&c| c == byte)
            .expect("invalid base64");
        bits = bits << 6 | value as u32;
        count += 6;
        if count >= 8 {
            count -= 8;
            decoded.push((bits >> count) as u8);
        }
    }
    decoded
}

pub fn certificate_pem(der: &[u8]) -> String {
    let body = base64_encode(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect();
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        lines.join("\n")
    )
}

/// The DER inside a single PEM block, whatever its label.
pub fn pem_der(text: &str) -> Vec<u8> {
    let body: String = text
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with("-----"))
        .collect();
    base64_decode(&body)
}

/// Build an empty-password JKS with three copies of the public fixture
/// certificate. One copy's notAfter is moved earlier to exercise sorting;
/// certificate signatures are never checked by the app.
pub fn triage_keystore() -> Vec<u8> {
    let certificate = fixture_certificate();
    let not_after = b"361009194829Z";
    let positions: Vec<usize> = certificate
        .windows(not_after.len())
        .enumerate()
        .filter(|(_, window)| window == not_after)
        .map(|(position, _)| position)
        .collect();
    assert_eq!(positions.len(), 1, "unexpected fixture expiry");
    let mut earlier = certificate.clone();
    earlier[positions[0]..positions[0] + not_after.len()].copy_from_slice(b"301009194829Z");

    fn utf(body: &mut Vec<u8>, text: &str) {
        body.extend_from_slice(&(text.len() as u16).to_be_bytes());
        body.extend_from_slice(text.as_bytes());
    }

    let entries = [
        ("alpha", &certificate),
        ("beta-quit", &certificate),
        ("zeta-soon", &earlier),
    ];
    let mut body = Vec::new();
    for value in [0xFEED_FEED, 2, entries.len() as u32] {
        body.extend_from_slice(&u32::to_be_bytes(value));
    }
    for (alias, der) in entries {
        body.extend_from_slice(&2_u32.to_be_bytes());
        utf(&mut body, alias);
        body.extend_from_slice(&0_u64.to_be_bytes());
        utf(&mut body, "X.509");
        body.extend_from_slice(&(der.len() as u32).to_be_bytes());
        body.extend_from_slice(der);
    }
    with_empty_password_digest(body)
}

/// Build an empty-password JKS with one private-key entry, `server`, whose
/// key is synthetic bytes protected by `key_password` as Java protects JKS
/// keys, and the public fixture certificate as its chain.
pub fn key_keystore(key_password: &str) -> Vec<u8> {
    let certificate = fixture_certificate();
    let key = b"synthetic bytes, not a private key";
    // The JKS protector: a salt, the key XORed with a SHA-1 keystream,
    // and a check digest, all keyed by the password's UTF-16 units.
    let password: Vec<u8> = key_password
        .encode_utf16()
        .flat_map(u16::to_be_bytes)
        .collect();
    let salt = [7_u8; 20];
    let mut protected = salt.to_vec();
    let mut block = Sha1::new()
        .chain_update(&password)
        .chain_update(salt)
        .finalize();
    for chunk in key.chunks(20) {
        protected.extend(chunk.iter().zip(block).map(|(byte, mask)| byte ^ mask));
        block = Sha1::new()
            .chain_update(&password)
            .chain_update(block)
            .finalize();
    }
    protected.extend(
        Sha1::new()
            .chain_update(&password)
            .chain_update(key)
            .finalize(),
    );
    // EncryptedPrivateKeyInfo with Sun's key protector algorithm.
    let mut info = b"\x30\x0e\x06\x0a\x2b\x06\x01\x04\x01\x2a\x02\x11\x01\x01\x05\x00".to_vec();
    info.extend([0x04, protected.len() as u8]);
    info.extend(protected);
    let mut encoded = vec![0x30, info.len() as u8];
    encoded.extend(info);

    let mut body = Vec::new();
    for value in [0xFEED_FEED, 2, 1, 1] {
        body.extend_from_slice(&u32::to_be_bytes(value));
    }
    body.extend_from_slice(b"\x00\x06server");
    body.extend_from_slice(&0_u64.to_be_bytes());
    body.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    body.extend_from_slice(&encoded);
    body.extend_from_slice(&1_u32.to_be_bytes());
    body.extend_from_slice(b"\x00\x05X.509");
    body.extend_from_slice(&(certificate.len() as u32).to_be_bytes());
    body.extend_from_slice(&certificate);
    with_empty_password_digest(body)
}

#[test]
fn base64_round_trips() {
    for data in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
        assert_eq!(base64_decode(&base64_encode(data)), data);
    }
    assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    assert_eq!(base64_encode(b"fo"), "Zm8=");
}
