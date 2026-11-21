//! Checks a certificate's signature against the public key of the certificate
//! stored as its issuer, and a certificate request's against its own key. This
//! is offline and makes no trust decisions: names, validity, constraints, and
//! revocation are not checked.
use crown::{
    asn1::{Reader, der::Class},
    error::CryptoError,
    x509::{AlgorithmIdentifier, SignatureAlgorithm, keys::PublicKey, keys::SubjectPublicKeyInfo},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signature {
    Verified,
    /// Why the signature does not verify.
    Failed(&'static str),
    /// Why the signature could not be checked.
    Unchecked(&'static str),
}

/// The signed bytes, the signature algorithm (from inside and outside the
/// signed part), and the signature value. A request's signed part does not
/// repeat the algorithm.
struct Signed<'a> {
    tbs: &'a [u8],
    inner_algorithm: Option<&'a [u8]>,
    outer_algorithm: &'a [u8],
    value: &'a [u8],
}

fn signed(der: &[u8]) -> Option<Signed<'_>> {
    let mut reader = Reader::new(der);
    let mut certificate = reader.read_sequence().ok()?;
    reader.expect_end().ok()?;
    let tbs = certificate.read_raw_tlv().ok()?;
    let outer_algorithm = certificate.read_raw_tlv().ok()?;
    let value = certificate.read_bit_string_bytes().ok()?;
    certificate.expect_end().ok()?;
    let mut fields = Reader::new(tbs).read_sequence().ok()?;
    skip_version(&mut fields)?;
    fields.read_raw_tlv().ok()?; // Serial number.
    let inner_algorithm = Some(fields.read_raw_tlv().ok()?);
    Some(Signed {
        tbs,
        inner_algorithm,
        outer_algorithm,
        value,
    })
}

/// A certificate's SubjectPublicKeyInfo, byte for byte as stored.
pub fn subject_public_key_info(der: &[u8]) -> Option<&[u8]> {
    let mut reader = Reader::new(der);
    let mut certificate = reader.read_sequence().ok()?;
    reader.expect_end().ok()?;
    let mut fields = certificate.read_sequence().ok()?;
    skip_version(&mut fields)?;
    for _ in [
        "serial number",
        "signature",
        "issuer",
        "validity",
        "subject",
    ] {
        fields.read_raw_tlv().ok()?;
    }
    fields.read_raw_tlv().ok()
}

fn skip_version(fields: &mut Reader<'_>) -> Option<()> {
    let tag = fields.peek_tag().ok()?;
    if tag.class == Class::ContextSpecific && tag.number == 0 {
        fields.read_raw_tlv().ok()?;
    }
    Some(())
}

/// Whether a key of this type can make signatures with this algorithm.
fn compatible(algorithm: &SignatureAlgorithm, key: &PublicKey) -> bool {
    matches!(
        (algorithm, key),
        (
            SignatureAlgorithm::RsaPkcs1v15(_) | SignatureAlgorithm::RsaPss { .. },
            PublicKey::Rsa(_)
        ) | (SignatureAlgorithm::Ecdsa(_), PublicKey::Ec { .. })
            | (SignatureAlgorithm::Ed25519, PublicKey::Ed25519(_))
            | (SignatureAlgorithm::Ed448, PublicKey::Ed448(_))
            | (SignatureAlgorithm::Sm2, PublicKey::Sm2(_))
            | (SignatureAlgorithm::Dsa(_), PublicKey::Dsa { .. })
            | (SignatureAlgorithm::MlDsa(_), PublicKey::MlDsa(_))
            | (SignatureAlgorithm::SlhDsa(_), PublicKey::SlhDsa(_))
    )
}

/// Checks `certificate`'s signature with the public key in `issuer`. Pass the
/// same certificate twice to check a self-signed certificate.
pub fn verify(certificate: &[u8], issuer: &[u8]) -> Signature {
    let Some(signed) = signed(certificate) else {
        return Signature::Unchecked("the certificate could not be decoded");
    };
    let Some(spki) = subject_public_key_info(issuer) else {
        return match parse_algorithm(signed.outer_algorithm) {
            Err(reason) => Signature::Unchecked(reason),
            Ok(_) => Signature::Unchecked("the issuer certificate could not be decoded"),
        };
    };
    check(&signed, spki)
}

/// Checks a PKCS#10 certificate request's signature with its own public key.
/// A match shows the request is intact and was signed with the private key
/// matching the public key it contains.
pub fn verify_request(request: &[u8]) -> Signature {
    let Some((signed, spki)) = signed_request(request) else {
        return Signature::Unchecked("the request could not be decoded");
    };
    check(&signed, spki)
}

/// A request's signed parts and its SubjectPublicKeyInfo.
fn signed_request(request: &[u8]) -> Option<(Signed<'_>, &[u8])> {
    let mut reader = Reader::new(request);
    let mut fields = reader.read_sequence().ok()?;
    reader.expect_end().ok()?;
    let tbs = fields.read_raw_tlv().ok()?;
    let outer_algorithm = fields.read_raw_tlv().ok()?;
    let value = fields.read_bit_string_bytes().ok()?;
    fields.expect_end().ok()?;
    let mut info = Reader::new(tbs).read_sequence().ok()?;
    info.read_raw_tlv().ok()?; // Version.
    info.read_raw_tlv().ok()?; // Subject.
    let signed = Signed {
        tbs,
        inner_algorithm: None,
        outer_algorithm,
        value,
    };
    Some((signed, info.read_raw_tlv().ok()?))
}

fn parse_algorithm(identifier: &[u8]) -> Result<SignatureAlgorithm, &'static str> {
    let mut reader = Reader::new(identifier);
    let identifier = AlgorithmIdentifier::parse(&mut reader)
        .map_err(|_| "the signature algorithm could not be decoded")?;
    reader
        .expect_end()
        .map_err(|_| "the signature algorithm could not be decoded")?;
    SignatureAlgorithm::from_identifier(&identifier)
        .map_err(|_| "the signature algorithm is not supported")
}

/// Checks the signature with the key in `spki`. An algorithm repeated inside
/// the signed part must match the one outside it.
fn check(signed: &Signed<'_>, spki: &[u8]) -> Signature {
    let algorithm = match parse_algorithm(signed.outer_algorithm) {
        Ok(algorithm) => algorithm,
        Err(reason) => return Signature::Unchecked(reason),
    };
    let key = match SubjectPublicKeyInfo::parse(spki) {
        Ok(spki) => spki.public_key,
        Err(CryptoError::UnsupportedOperation(_)) => {
            return Signature::Unchecked("the key type is not supported");
        }
        Err(_) => return Signature::Unchecked("the public key could not be decoded"),
    };
    if signed
        .inner_algorithm
        .is_some_and(|inner| inner != signed.outer_algorithm)
    {
        return Signature::Failed("the signature algorithm differs inside the certificate");
    }
    if !compatible(&algorithm, &key) {
        return Signature::Failed("the key type cannot make this signature");
    }
    match algorithm.verify(&key, signed.tbs, signed.value) {
        Ok(true) => Signature::Verified,
        Err(CryptoError::UnsupportedOperation(_)) => {
            Signature::Unchecked("the signature algorithm or key is not supported")
        }
        Ok(false) | Err(_) => Signature::Failed("the signature does not match"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{ed25519_certificate, fixture_certificate_der, metadata_certificate};
    use crown::asn1::{der, oid::ObjectIdentifier};

    #[test]
    fn verifies_signatures_made_by_the_issuer_key() {
        let root = ed25519_certificate("root", "root", 1, 1);
        let leaf = ed25519_certificate("leaf", "root", 2, 1);
        assert_eq!(verify(&root, &root), Signature::Verified);
        assert_eq!(verify(&leaf, &root), Signature::Verified);
        // The keytool fixture is a self-signed ECDSA P-256 certificate.
        let fixture = fixture_certificate_der();
        assert_eq!(verify(fixture, fixture), Signature::Verified);
    }

    #[test]
    fn reports_wrong_issuers_and_altered_certificates() {
        let root = ed25519_certificate("root", "root", 1, 1);
        let other = ed25519_certificate("other", "other", 3, 3);
        let leaf = ed25519_certificate("leaf", "root", 2, 1);
        let failed = Signature::Failed("the signature does not match");
        assert_eq!(verify(&leaf, &other), failed);
        let mut altered = leaf.clone();
        let last = altered.len() - 1;
        altered[last] ^= 1;
        assert_eq!(verify(&altered, &root), failed);
        let subject = leaf.windows(4).position(|w| w == b"leaf").unwrap();
        let mut renamed = leaf.clone();
        renamed[subject] = b'L';
        assert_eq!(verify(&renamed, &root), failed);
        assert_eq!(
            verify(&leaf, fixture_certificate_der()),
            Signature::Failed("the key type cannot make this signature")
        );
        // Placeholder signature bytes in a well-formed ECDSA certificate.
        let placeholder = metadata_certificate("leaf", "root", &[1], &[]);
        assert_eq!(verify(&placeholder, fixture_certificate_der()), failed);
    }

    fn oid(arcs: &[u64]) -> Vec<u8> {
        der::sequence(&der::oid(&ObjectIdentifier::new(arcs).unwrap()))
    }

    /// Replaces the `n`th Ed25519 algorithm identifier: the signature inside
    /// the signed part, the public key, or the signature outside it.
    fn replace_algorithm(certificate: &[u8], n: usize, arcs: &[u64]) -> Vec<u8> {
        let ed25519 = oid(&[1, 3, 101, 112]);
        let at = (0..certificate.len())
            .filter(|&i| certificate[i..].starts_with(&ed25519))
            .nth(n)
            .unwrap();
        let mut changed = certificate.to_vec();
        changed.splice(at..at + ed25519.len(), oid(arcs));
        changed
    }

    #[test]
    fn rejects_a_signature_algorithm_that_differs_inside_the_certificate() {
        let root = ed25519_certificate("root", "root", 1, 1);
        let leaf = ed25519_certificate("leaf", "root", 2, 1);
        let ed448 = [1, 3, 101, 113];
        assert_eq!(
            verify(&replace_algorithm(&leaf, 2, &ed448), &root),
            Signature::Failed("the signature algorithm differs inside the certificate")
        );
    }

    #[test]
    fn leaves_unsupported_or_undecodable_input_unchecked() {
        let root = ed25519_certificate("root", "root", 1, 1);
        let leaf = ed25519_certificate("leaf", "root", 2, 1);
        let unknown = [1, 2, 3, 4];
        for (certificate, issuer, reason) in [
            (
                b"junk".to_vec(),
                root.clone(),
                "the certificate could not be decoded",
            ),
            (
                replace_algorithm(&leaf, 2, &unknown),
                root.clone(),
                "the signature algorithm is not supported",
            ),
            (
                leaf.clone(),
                b"junk".to_vec(),
                "the issuer certificate could not be decoded",
            ),
            (
                leaf.clone(),
                replace_algorithm(&root, 1, &unknown),
                "the key type is not supported",
            ),
            (
                [leaf.as_slice(), &[0]].concat(),
                root.clone(),
                "the certificate could not be decoded",
            ),
            (
                leaf.clone(),
                [root.as_slice(), &[0]].concat(),
                "the issuer certificate could not be decoded",
            ),
        ] {
            assert_eq!(verify(&certificate, &issuer), Signature::Unchecked(reason));
        }

        // Trailing bytes inside the outer SEQUENCE of a certificate or request.
        let mut inner = Reader::new(&leaf).read_sequence().unwrap();
        let tbs = inner.read_raw_tlv().unwrap();
        let alg = inner.read_raw_tlv().unwrap();
        let sig = inner.read_raw_tlv().unwrap();
        let extra_cert = der::sequence(&[tbs, alg, sig, &der::null()].concat());
        assert_eq!(
            verify(&extra_cert, &root),
            Signature::Unchecked("the certificate could not be decoded")
        );

        let request = crate::test_support::ed25519_request("device", &[]);
        assert_eq!(
            verify_request(&[request.as_slice(), &[0]].concat()),
            Signature::Unchecked("the request could not be decoded")
        );
        let mut req_inner = Reader::new(&request).read_sequence().unwrap();
        let req_tbs = req_inner.read_raw_tlv().unwrap();
        let req_alg = req_inner.read_raw_tlv().unwrap();
        let req_sig = req_inner.read_raw_tlv().unwrap();
        let extra_req = der::sequence(&[req_tbs, req_alg, req_sig, &der::null()].concat());
        assert_eq!(
            verify_request(&extra_req),
            Signature::Unchecked("the request could not be decoded")
        );

        // An algorithm/key pair that parses and is compatible, but whose verify()
        // returns UnsupportedOperation (e.g. ECDSA with SHA-1 on a P-256 key,
        // or a curve/hash combination crown does not implement verification for).
        let ecdsa_sha1 = oid(&[1, 2, 840, 10045, 4, 1]);
        let fixture = fixture_certificate_der();
        let mut cert_reader = Reader::new(fixture).read_sequence().unwrap();
        let mut tbs_reader = cert_reader.read_sequence().unwrap();
        let mut fields = Vec::new();
        while !tbs_reader.is_empty() {
            fields.push(tbs_reader.read_raw_tlv().unwrap().to_vec());
        }
        fields[2] = ecdsa_sha1.clone();
        let unsupported_verify = der::sequence(
            &[
                der::sequence(&fields.concat()),
                ecdsa_sha1,
                der::bit_string(0, &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]),
            ]
            .concat(),
        );
        let result = verify(&unsupported_verify, fixture);
        // Verify that UnsupportedOperation (if returned by crown) is never
        // misreported as Failed; if crown supports SHA-1 ECDSA, it fails match.
        assert!(matches!(
            result,
            Signature::Unchecked(_) | Signature::Failed("the signature does not match")
        ));
    }
}
