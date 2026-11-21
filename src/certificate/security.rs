//! Weak-cryptography checks for the entry list and detail view. They flag
//! short public keys and weak signature hashes; they do not verify anything.
use std::fmt;

use crown::asn1::{Reader, der};

use super::OID_RSASSA_PSS;

/// RSA and DSA keys shorter than this are flagged, following NIST SP 800-131A.
pub const MINIMUM_RSA_DSA_BITS: u32 = 2048;
/// EC curves smaller than this are flagged.
pub const MINIMUM_EC_BITS: u32 = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Weakness {
    ShortKey {
        algorithm: String,
        bits: u32,
        minimum: u32,
    },
    /// The signature's hash function, such as `SHA-1`.
    WeakSignature(&'static str),
}

impl fmt::Display for Weakness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortKey {
                algorithm,
                bits,
                minimum,
            } => write!(
                f,
                "{bits}-bit {algorithm} key is shorter than the recommended {minimum} bits"
            ),
            Self::WeakSignature(hash) => write!(f, "signed with {hash}, which is no longer secure"),
        }
    }
}

const WEAK_SIGNATURES: &[(&[u64], &str)] = &[
    (&[1, 2, 840, 113549, 1, 1, 2], "MD2"),
    (&[1, 2, 840, 113549, 1, 1, 3], "MD4"),
    (&[1, 2, 840, 113549, 1, 1, 4], "MD5"),
    (&[1, 2, 840, 113549, 1, 1, 5], "SHA-1"),
    (&[1, 3, 14, 3, 2, 29], "SHA-1"),
    (&[1, 2, 840, 10045, 4, 1], "SHA-1"),
    (&[1, 2, 840, 10040, 4, 3], "SHA-1"),
    (&[1, 3, 14, 3, 2, 27], "SHA-1"),
];

const WEAK_HASHES: &[(&[u64], &str)] = &[
    (&[1, 2, 840, 113549, 2, 2], "MD2"),
    (&[1, 2, 840, 113549, 2, 4], "MD4"),
    (&[1, 2, 840, 113549, 2, 5], "MD5"),
    (&[1, 3, 14, 3, 2, 26], "SHA-1"),
];

/// The weak hash function of an encoded signature `AlgorithmIdentifier`, if any.
fn weak_signature_hash(algorithm_der: &[u8]) -> Option<&'static str> {
    let mut reader = Reader::new(algorithm_der);
    let mut algorithm = reader.read_sequence().ok()?;
    reader.expect_end().ok()?;
    let oid = algorithm.read_oid().ok()?;
    if oid.matches(OID_RSASSA_PSS) {
        return pss_weak_hash(&mut algorithm);
    }
    WEAK_SIGNATURES
        .iter()
        .find_map(|(arcs, hash)| oid.matches(arcs).then_some(*hash))
}

/// Checks the hash algorithm of RSASSA-PSS parameters. Per RFC 4055 section 3.1,
/// omitted parameters or an omitted `[0] hashAlgorithm` field defaults to SHA-1.
fn pss_weak_hash(algorithm: &mut Reader<'_>) -> Option<&'static str> {
    if algorithm.is_empty() {
        return Some("SHA-1");
    }
    let mut params = algorithm.read_sequence().ok()?;
    algorithm.expect_end().ok()?;
    if params.is_empty() {
        return Some("SHA-1");
    }
    if params.peek_tag().ok()? != der::Tag::context_constructed(0) {
        return Some("SHA-1");
    }
    let mut explicit = params.read_explicit(0).ok()?;
    let mut hash_alg = explicit.read_sequence().ok()?;
    explicit.expect_end().ok()?;
    let hash_oid = hash_alg.read_oid().ok()?;
    WEAK_HASHES
        .iter()
        .find_map(|(arcs, hash)| hash_oid.matches(arcs).then_some(*hash))
}

/// The weaknesses of a certificate's key and signature. A self-signed
/// certificate's signature is not checked: trust in a root comes from where
/// it is stored, not from its signature.
pub fn weaknesses(
    algorithm: &str,
    key_size: Option<u32>,
    signature_der: &[u8],
    self_signed: bool,
) -> Vec<Weakness> {
    let mut found: Vec<_> = key_weakness(algorithm, key_size).into_iter().collect();
    if !self_signed && let Some(hash) = weak_signature_hash(signature_der) {
        found.push(Weakness::WeakSignature(hash));
    }
    found
}

/// Whether a key of this algorithm and size is too short.
pub fn key_weakness(algorithm: &str, key_size: Option<u32>) -> Option<Weakness> {
    let minimum = match algorithm {
        "RSA" | "RSASSA-PSS" | "DSA" => MINIMUM_RSA_DSA_BITS,
        "EC" => MINIMUM_EC_BITS,
        _ => return None,
    };
    let bits = key_size.filter(|&bits| bits < minimum)?;
    Some(Weakness::ShortKey {
        algorithm: algorithm.into(),
        bits,
        minimum,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crown::asn1::oid::ObjectIdentifier;

    fn alg_id(arcs: &[u64], params: Option<&[u8]>) -> Vec<u8> {
        der::algorithm_identifier(&ObjectIdentifier::new(arcs).unwrap(), params)
    }

    #[test]
    fn flags_keys_below_the_minimum_size() {
        let sha256_rsa = alg_id(&[1, 2, 840, 113549, 1, 1, 11], Some(&der::null()));
        for (algorithm, bits, weak) in [
            ("RSA", Some(1024), true),
            ("RSA", Some(2047), true),
            ("RSA", Some(2048), false),
            ("RSASSA-PSS", Some(1024), true),
            ("DSA", Some(1024), true),
            ("DSA", Some(3072), false),
            ("EC", Some(192), true),
            ("EC", Some(224), true),
            ("EC", Some(256), false),
            ("EC", None, false),
            ("Ed25519", Some(255), false),
            ("1.2.3.4", Some(8), false),
        ] {
            let found = weaknesses(algorithm, bits, &sha256_rsa, false);
            assert_eq!(!found.is_empty(), weak, "{algorithm} {bits:?}");
        }
        assert_eq!(
            weaknesses("RSA", Some(1024), &sha256_rsa, true)[0].to_string(),
            "1024-bit RSA key is shorter than the recommended 2048 bits"
        );
    }

    #[test]
    fn flags_md5_and_sha1_signatures_except_on_self_signed_certificates() {
        for (arcs, hash) in WEAK_SIGNATURES {
            let sig = alg_id(arcs, None);
            let found = weaknesses("EC", Some(256), &sig, false);
            assert_eq!(found, [Weakness::WeakSignature(hash)]);
            assert!(weaknesses("EC", Some(256), &sig, true).is_empty());
        }
        assert_eq!(
            Weakness::WeakSignature("SHA-1").to_string(),
            "signed with SHA-1, which is no longer secure"
        );
        for arcs in [&[1, 2, 840, 10045, 4, 3, 2][..], &[1, 3, 101, 112]] {
            assert!(weaknesses("EC", Some(256), &alg_id(arcs, None), false).is_empty());
        }
    }

    #[test]
    fn flags_rsassa_pss_with_weak_or_default_sha1_hash() {
        let sha1_hash = alg_id(&[1, 3, 14, 3, 2, 26], Some(&der::null()));
        let sha256_hash = alg_id(&[2, 16, 840, 1, 101, 3, 4, 2, 1], Some(&der::null()));
        // Omitted parameters -> RFC 4055 default SHA-1.
        let omitted = alg_id(OID_RSASSA_PSS, None);
        // Empty RSASSA-PSS-params SEQUENCE -> RFC 4055 default SHA-1.
        let empty_params = alg_id(OID_RSASSA_PSS, Some(&der::sequence(&[])));
        // Omitted [0] hashAlgorithm with only [2] saltLength -> default SHA-1.
        let salt_only = alg_id(
            OID_RSASSA_PSS,
            Some(&der::sequence(&der::explicit(2, &der::integer_i64(20)))),
        );
        // Explicit [0] SHA-1 hashAlgorithm.
        let explicit_sha1 = alg_id(
            OID_RSASSA_PSS,
            Some(&der::sequence(&der::explicit(0, &sha1_hash))),
        );
        for sig in [omitted, empty_params, salt_only, explicit_sha1] {
            assert_eq!(
                weaknesses("RSA", Some(2048), &sig, false),
                [Weakness::WeakSignature("SHA-1")]
            );
            assert!(weaknesses("RSA", Some(2048), &sig, true).is_empty());
        }
        // Explicit [0] SHA-256 hashAlgorithm is not weak.
        let explicit_sha256 = alg_id(
            OID_RSASSA_PSS,
            Some(&der::sequence(&der::explicit(0, &sha256_hash))),
        );
        assert!(weaknesses("RSA", Some(2048), &explicit_sha256, false).is_empty());
        // Malformed parameters do not falsely flag weakness.
        let malformed = alg_id(OID_RSASSA_PSS, Some(&der::null()));
        assert!(weaknesses("RSA", Some(2048), &malformed, false).is_empty());
    }
}
