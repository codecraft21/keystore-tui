use super::*;
use crate::test_support::{TestRng, fixture_certificate_der, fixture_summary, synthetic_pkcs8};
use crown::{
    asn1::{der, oid::ObjectIdentifier},
    pkcs12::{SafeBag, encode_safe_contents},
    x509::{
        Certificate,
        algorithm::{AlgorithmIdentifier, Hash},
        attribute::{friendly_name, local_key_id},
        keys::EncryptedPrivateKeyInfo,
    },
};

const MODERN: &[u8] = include_bytes!("../../../tests/fixtures/trusted-cert.p12");
const LEGACY: &[u8] = include_bytes!("../../../tests/fixtures/trusted-cert-legacy.p12");
const UNICODE_ALIAS: &[u8] = include_bytes!("../../../tests/fixtures/unicode-alias.p12");
const EMPTY_PASSWORD: &[u8] = include_bytes!("../../../tests/fixtures/empty-password.p12");
const NUL_PASSWORD: &[u8] = include_bytes!("../../../tests/fixtures/nul-password.p12");
const EMPTY_PASSWORD_NO_MAC: &[u8] =
    include_bytes!("../../../tests/fixtures/empty-password-no-mac.p12");
const OPENSSL: &[u8] = include_bytes!("../../../tests/fixtures/openssl-cert.p12");
const OPENSSL_LEGACY: &[u8] = include_bytes!("../../../tests/fixtures/openssl-cert-legacy.p12");
const OPENSSL_NO_MAC_AES: &[u8] = include_bytes!("../../../tests/fixtures/openssl-no-mac-aes.p12");
const OPENSSL_NO_MAC: [&[u8]; 5] = [
    OPENSSL_NO_MAC_AES,
    include_bytes!("../../../tests/fixtures/openssl-no-mac-3des.p12"),
    include_bytes!("../../../tests/fixtures/openssl-no-mac-rc2.p12"),
    include_bytes!("../../../tests/fixtures/openssl-no-mac-rc4.p12"),
    include_bytes!("../../../tests/fixtures/openssl-no-mac-rc4-40.p12"),
];
/// A wrong password that passes the padding check of `OPENSSL_NO_MAC_AES`.
const VALID_PADDING_PASSWORD: &str = "wrong130";

fn synthetic(bags: Vec<SafeBag>) -> Vec<u8> {
    Pfx::build(bags, b"changeit", 100, &mut TestRng(0))
        .unwrap()
        .encode()
}

mod read;
mod write;

fn secret_bag() -> SafeBag {
    SafeBag {
        bag: Bag::Secret {
            oid: ObjectIdentifier::new(oid::OID_PKCS12_SECRET_BAG).unwrap(),
            value: der::octet_string(&[1, 2, 3]),
        },
        attributes: vec![friendly_name("secret")],
    }
}

fn legacy(kind: LegacyPbeKind) -> LegacyPbe {
    LegacyPbe {
        salt: vec![7; 8],
        iterations: 1,
        kind,
    }
}

fn raw_certificate(der: &[u8], attributes: Vec<crown::x509::attribute::Attribute>) -> SafeBag {
    SafeBag {
        bag: Bag::Other {
            oid: ObjectIdentifier::new(oid::OID_PKCS12_CERT_BAG).unwrap(),
            value: der::sequence(
                &[
                    der::oid(&ObjectIdentifier::new(oid::OID_X509_CERTIFICATE).unwrap()),
                    der::explicit(0, &der::octet_string(der)),
                ]
                .concat(),
            ),
        },
        attributes,
    }
}
