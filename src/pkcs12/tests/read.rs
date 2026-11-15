use super::*;

#[test]
fn reads_java_truststores_with_modern_and_legacy_crypto() {
    for data in [MODERN, LEGACY] {
        let store = parse(data).unwrap();
        assert!(matches!(store.verify("wrong"), Err(VerifyError::Password)));
        let verified = store.verify("changeit").unwrap();
        assert_eq!(
            verified.entries,
            vec![KeystoreEntry {
                alias: "root-cert".into(),
                certificate: Some(fixture_summary()),
                content: Content::Certificates {
                    kind: Kind::TrustedCertificate,
                    certificates: vec![fixture_certificate_der().to_vec()],
                },
                chain_warning: None,
            }]
        );
        assert!(!verified.incomplete);
    }
}

#[test]
fn reads_openssl_certificate_stores_without_java_attributes() {
    for data in [OPENSSL, OPENSSL_LEGACY] {
        let store = parse(data).unwrap();
        assert!(matches!(store.verify("wrong"), Err(VerifyError::Password)));
        let verified = store.verify("changeit").unwrap();
        assert_eq!(
            verified.entries,
            vec![KeystoreEntry {
                alias: "JKS TUI test fixture".into(),
                certificate: Some(fixture_summary()),
                content: Content::Certificates {
                    kind: Kind::Certificate,
                    certificates: vec![fixture_certificate_der().to_vec()],
                },
                chain_warning: None,
            }]
        );
        assert!(!verified.incomplete);
    }
}

#[test]
fn reads_a_java_unicode_alias() {
    let verified = parse(UNICODE_ALIAS).unwrap().verify("changeit").unwrap();
    assert_eq!(verified.entries[0].alias, "certificate-😀");
    assert!(!verified.incomplete);
}

#[test]
fn lists_keys_without_decrypting_them_and_warns_about_unknown_bags() {
    let key = SafeBag {
        bag: Bag::ShroudedKey(EncryptedPrivateKeyInfo {
            algorithm: AlgorithmIdentifier::with_null(
                ObjectIdentifier::new(oid::OID_PBES2).unwrap(),
            ),
            encrypted_data: vec![1, 2, 3],
        }),
        attributes: vec![friendly_name("private"), local_key_id(&[1])],
    };
    let secret = SafeBag {
        bag: Bag::Secret {
            oid: ObjectIdentifier::new(oid::OID_PKCS12_SECRET_BAG).unwrap(),
            value: der::octet_string(&[1, 2, 3]),
        },
        attributes: vec![friendly_name("secret")],
    };
    let unknown = SafeBag {
        bag: Bag::Other {
            oid: ObjectIdentifier::new(&[1, 2, 3, 4]).unwrap(),
            value: der::null(),
        },
        attributes: vec![friendly_name("other")],
    };
    let plaintext_key = SafeBag {
        bag: Bag::Other {
            oid: ObjectIdentifier::new(oid::OID_PKCS12_KEY_BAG).unwrap(),
            value: der::octet_string(&[1, 2, 3]),
        },
        attributes: vec![friendly_name("plaintext")],
    };
    let data = synthetic(vec![key, secret, unknown, plaintext_key]);
    let verified = parse(&data).unwrap().verify("changeit").unwrap();
    assert_eq!(
        verified.entries,
        vec![
            KeystoreEntry {
                alias: "private".into(),
                certificate: None,
                content: Content::Certificates {
                    kind: Kind::PrivateKey,
                    certificates: vec![],
                },
                chain_warning: None,
            },
            KeystoreEntry {
                alias: "secret".into(),
                certificate: None,
                content: Content::Certificates {
                    kind: Kind::SecretKey,
                    certificates: vec![],
                },
                chain_warning: None,
            },
        ]
    );
    assert!(verified.incomplete);
}

#[test]
fn summarizes_the_certificate_sharing_a_private_key_id() {
    let key = |alias, id: &[u8]| SafeBag {
        bag: Bag::ShroudedKey(EncryptedPrivateKeyInfo {
            algorithm: AlgorithmIdentifier::with_null(
                ObjectIdentifier::new(oid::OID_PBES2).unwrap(),
            ),
            encrypted_data: vec![1, 2, 3],
        }),
        attributes: vec![friendly_name(alias), local_key_id(id)],
    };
    let certificate = SafeBag {
        bag: Bag::Cert(Certificate::parse(fixture_certificate_der()).unwrap()),
        attributes: vec![friendly_name("matched"), local_key_id(&[2])],
    };
    let data = synthetic(vec![
        key("matched", &[2]),
        key("unmatched", &[3]),
        certificate,
    ]);
    let verified = parse(&data).unwrap().verify("changeit").unwrap();
    assert_eq!(verified.entries[0].alias, "matched");
    assert_eq!(verified.entries[0].certificate, Some(fixture_summary()));
    assert_eq!(verified.entries[1].alias, "unmatched");
    assert_eq!(verified.entries[1].certificate, None);
    assert!(!verified.incomplete);
}

#[test]
fn malformed_bag_does_not_hide_later_entries_in_a_verified_store() {
    let secret = |alias| SafeBag {
        bag: Bag::Secret {
            oid: ObjectIdentifier::new(oid::OID_PKCS12_SECRET_BAG).unwrap(),
            value: der::octet_string(&[1]),
        },
        attributes: vec![friendly_name(alias)],
    };
    let malformed = SafeBag {
        bag: Bag::Other {
            oid: ObjectIdentifier::new(oid::OID_PKCS12_CERT_BAG).unwrap(),
            value: der::null(),
        },
        attributes: vec![],
    };
    let data = synthetic(vec![secret("first"), malformed, secret("last")]);
    let verified = parse(&data).unwrap().verify("changeit").unwrap();
    assert_eq!(verified.entries.len(), 2);
    assert_eq!(verified.entries[0].alias, "first");
    assert_eq!(verified.entries[1].alias, "last");
    assert!(verified.incomplete);
}

#[test]
fn reads_passwordless_java_truststores_without_a_mac() {
    let data = include_bytes!("../../../tests/fixtures/passwordless.p12");
    assert!(Pfx::parse(data).unwrap().mac.is_none());
    for password in ["", "changeit"] {
        let verified = parse(data).unwrap().verify(password).unwrap();
        assert!(!verified.incomplete);
        assert_eq!(verified.entries.len(), 1);
        assert_eq!(verified.entries[0].alias, "root-cert");
        assert_eq!(verified.entries[0].kind(), "Trusted certificate");
        assert_eq!(verified.entries[0].certificate, Some(fixture_summary()));
        assert_eq!(
            verified.entries[0].certificates(),
            [fixture_certificate_der().to_vec()]
        );
    }
}

#[test]
fn encrypted_store_without_mac_still_requires_a_password() {
    let data = include_bytes!("../../../tests/fixtures/encrypted-no-mac.p12");
    assert!(Pfx::parse(data).unwrap().mac.is_none());
    let store = parse(data).unwrap();
    for password in ["", "wrong"] {
        assert!(matches!(store.verify(password), Err(VerifyError::Password)));
    }
    let verified = store.verify("changeit").unwrap();
    assert!(!verified.incomplete);
    assert_eq!(verified.entries.len(), 1);
    assert_eq!(verified.entries[0].alias, "root-cert");
    assert_eq!(verified.entries[0].certificate, Some(fixture_summary()));
    assert_eq!(
        verified.entries[0].certificates(),
        [fixture_certificate_der().to_vec()]
    );
}

fn pbes2(cipher: Pbes2Cipher) -> Pbes2 {
    Pbes2 {
        salt: vec![7; 8],
        iterations: 1,
        key_length: None,
        prf: Hash::Sha256,
        cipher,
    }
}

/// A store whose only safe is EncryptedData, with no MacData.
fn encrypted_without_mac(algorithm: AlgorithmIdentifier, ciphertext: &[u8]) -> Vec<u8> {
    let data = ObjectIdentifier::new(oid::OID_PKCS7_DATA).unwrap();
    let encrypted = der::sequence(
        &[
            der::integer(&[0]),
            der::sequence(
                &[
                    der::oid(&data),
                    algorithm.encode(),
                    der::implicit(0, false, ciphertext),
                ]
                .concat(),
            ),
        ]
        .concat(),
    );
    let safe = ContentInfo {
        content_type: ObjectIdentifier::new(oid::OID_PKCS7_ENCRYPTED_DATA).unwrap(),
        content: encrypted,
    };
    Pfx {
        version: 3,
        auth_safe: ContentInfo {
            content_type: data,
            content: der::octet_string(&der::sequence(&safe.encode())),
        },
        mac: None,
    }
    .encode()
}

#[test]
fn encrypted_stores_without_mac_reject_wrong_passwords_with_every_scheme() {
    let plaintext = encode_safe_contents(&[secret_bag()]);
    let mut stores = Vec::new();
    for cipher in [
        Pbes2Cipher::Aes128Cbc { iv: vec![1; 16] },
        Pbes2Cipher::Aes192Cbc { iv: vec![1; 16] },
        Pbes2Cipher::Aes256Cbc { iv: vec![1; 16] },
        Pbes2Cipher::DesEde3Cbc { iv: vec![1; 8] },
    ] {
        let pbe = pbes2(cipher);
        let ciphertext = pbe.encrypt(&plaintext, b"changeit").unwrap();
        stores.push(encrypted_without_mac(pbe.to_algorithm(), &ciphertext));
    }
    for kind in [
        LegacyPbeKind::Rc4_40,
        LegacyPbeKind::Rc4_128,
        LegacyPbeKind::DesEde3,
        LegacyPbeKind::DesEde2,
        LegacyPbeKind::Rc2_40,
    ] {
        let pbe = legacy(kind);
        let ciphertext = pbe.encrypt(&plaintext, b"changeit").unwrap();
        let mut algorithm = pbe.to_algorithm();
        // Crown writes the two RC4 OIDs swapped.
        let rfc_oid = match kind {
            LegacyPbeKind::Rc4_40 => Some(PBE_SHA1_40BIT_RC4),
            LegacyPbeKind::Rc4_128 => Some(PBE_SHA1_128BIT_RC4),
            _ => None,
        };
        if let Some(arcs) = rfc_oid {
            algorithm.oid = ObjectIdentifier::new(arcs).unwrap();
        }
        stores.push(encrypted_without_mac(algorithm, &ciphertext));
    }
    for data in stores {
        let store = parse(&data).unwrap();
        for password in ["", "\0", "wrong", "changeiT"] {
            assert!(matches!(store.verify(password), Err(VerifyError::Password)));
        }
        let verified = store.verify("changeit").unwrap();
        assert!(!verified.incomplete);
        assert_eq!(verified.entries.len(), 1);
        assert_eq!(verified.entries[0].alias, "secret");
    }
}

#[test]
fn wrong_password_with_valid_padding_is_rejected_without_a_mac() {
    let pbe = pbes2(Pbes2Cipher::Aes256Cbc { iv: vec![1; 16] });
    let ciphertext = pbe
        .encrypt(&encode_safe_contents(&[secret_bag()]), b"changeit")
        .unwrap();
    let store = parse(&encrypted_without_mac(pbe.to_algorithm(), &ciphertext)).unwrap();
    // About 1 wrong key in 256 decrypts to plaintext with valid padding.
    let password = (0..10_000)
        .map(|n| format!("wrong{n}"))
        .find(|password| pbe.decrypt(&ciphertext, password.as_bytes()).is_ok())
        .unwrap();
    assert!(matches!(
        store.verify(&password),
        Err(VerifyError::Password)
    ));
}

#[test]
fn unreadable_encryption_without_a_mac_is_incomplete_rather_than_a_wrong_password() {
    let plaintext = encode_safe_contents(&[secret_bag()]);
    let aes = pbes2(Pbes2Cipher::Aes256Cbc { iv: vec![1; 16] });
    let ciphertext = aes.encrypt(&plaintext, b"changeit").unwrap();
    let unknown = AlgorithmIdentifier::with_null(ObjectIdentifier::new(&[1, 2, 3, 4]).unwrap());
    let excessive = Pbes2 {
        iterations: MAX_ITERATIONS + 1,
        ..aes.clone()
    };
    let mismatched_key = Pbes2 {
        key_length: Some(16),
        ..aes.clone()
    };
    let triple_des = legacy(LegacyPbeKind::DesEde3);
    for data in [
        encrypted_without_mac(unknown, &ciphertext),
        encrypted_without_mac(excessive.to_algorithm(), &ciphertext),
        encrypted_without_mac(mismatched_key.to_algorithm(), &ciphertext),
        encrypted_without_mac(aes.to_algorithm(), &ciphertext[1..]),
        encrypted_without_mac(aes.to_algorithm(), &[]),
        encrypted_without_mac(triple_des.to_algorithm(), &[0; 15]),
    ] {
        let verified = parse(&data).unwrap().verify("").unwrap();
        assert!(verified.entries.is_empty());
        assert!(verified.incomplete);
    }
}

#[test]
fn reads_openssl_stores_without_a_mac_only_with_the_right_password() {
    for data in OPENSSL_NO_MAC {
        let store = parse(data).unwrap();
        assert!(store.0.mac.is_none());
        for password in ["", "wrong", VALID_PADDING_PASSWORD] {
            assert!(matches!(store.verify(password), Err(VerifyError::Password)));
        }
        let verified = store.verify("changeit").unwrap();
        assert_eq!(
            verified.entries,
            vec![KeystoreEntry {
                alias: "JKS TUI test fixture".into(),
                certificate: Some(fixture_summary()),
                content: Content::Certificates {
                    kind: Kind::Certificate,
                    certificates: vec![fixture_certificate_der().to_vec()],
                },
                chain_warning: None,
            }]
        );
        assert!(!verified.incomplete);
    }
}

#[test]
fn openssl_aes_fixture_has_a_wrong_password_with_valid_padding() {
    // tests/fixtures/README.md names this password for manual testing.
    let safe = Pfx::parse(OPENSSL_NO_MAC_AES)
        .unwrap()
        .authenticated_safe()
        .unwrap();
    let mut reader = Reader::new(&safe);
    let mut safes = reader.read_sequence().unwrap();
    let info = ContentInfo::parse_reader(&mut safes).unwrap();
    let plaintext = decrypt_safe(&info.content, VALID_PADDING_PASSWORD.as_bytes())
        .ok()
        .unwrap();
    assert!(!is_safe_contents(&plaintext));
}

#[test]
fn invalid_ciphertext_length_without_a_mac_is_incomplete() {
    let data = include_bytes!("../../../tests/fixtures/invalid-ciphertext-no-mac.p12");
    let store = parse(data).unwrap();
    for password in ["", "changeit"] {
        let verified = store.verify(password).unwrap();
        assert!(verified.entries.is_empty());
        assert!(verified.incomplete);
    }
}

#[test]
fn opens_empty_and_nul_password_stores_without_a_mac_with_an_empty_password() {
    let plaintext = encode_safe_contents(&[secret_bag()]);
    for password in [b"".as_slice(), b"\0".as_slice()] {
        let aes = pbes2(Pbes2Cipher::Aes256Cbc { iv: vec![1; 16] });
        let triple_des = legacy(LegacyPbeKind::DesEde3);
        for data in [
            encrypted_without_mac(
                aes.to_algorithm(),
                &aes.encrypt(&plaintext, password).unwrap(),
            ),
            encrypted_without_mac(
                triple_des.to_algorithm(),
                &triple_des.encrypt(&plaintext, password).unwrap(),
            ),
        ] {
            let store = parse(&data).unwrap();
            assert!(matches!(
                store.verify("changeit"),
                Err(VerifyError::Password)
            ));
            let verified = store.verify("").unwrap();
            assert!(!verified.incomplete);
            assert_eq!(verified.entries.len(), 1);
            assert_eq!(verified.entries[0].alias, "secret");
        }
    }
}

#[test]
fn rejects_failed_mac() {
    let mut pfx = Pfx::parse(MODERN).unwrap();
    pfx.mac.as_mut().unwrap().digest[0] ^= 1;
    assert!(matches!(
        parse(&pfx.encode()).unwrap().verify("changeit"),
        Err(VerifyError::Password)
    ));
}

#[test]
fn rejects_excessive_mac_work_before_prompting() {
    let mut pfx = Pfx::parse(MODERN).unwrap();
    pfx.mac.as_mut().unwrap().iterations = MAX_ITERATIONS + 1;
    assert!(parse(&pfx.encode()).is_err());
}

#[test]
fn opens_empty_password_stores_without_a_prompt() {
    for password in [b"".as_slice(), b"\0".as_slice()] {
        let data = Pfx::build(vec![], password, 100, &mut TestRng(0))
            .unwrap()
            .encode();
        let verified = parse(&data).unwrap().verify("").unwrap();
        assert!(verified.entries.is_empty());
        assert!(!verified.incomplete);
    }
}

#[test]
fn opens_java_empty_and_nul_password_stores_with_an_empty_password() {
    // Java's empty-password store only opens through the NUL fallback.
    assert!(parse(EMPTY_PASSWORD).unwrap().0.verify_mac(b"").is_err());
    assert!(parse(EMPTY_PASSWORD_NO_MAC).unwrap().0.mac.is_none());
    for data in [EMPTY_PASSWORD, NUL_PASSWORD, EMPTY_PASSWORD_NO_MAC] {
        let store = parse(data).unwrap();
        assert!(matches!(
            store.verify("changeit"),
            Err(VerifyError::Password)
        ));
        let verified = store.verify("").unwrap();
        assert_eq!(
            verified.entries,
            vec![KeystoreEntry {
                alias: "root-cert".into(),
                certificate: Some(fixture_summary()),
                content: Content::Certificates {
                    kind: Kind::TrustedCertificate,
                    certificates: vec![fixture_certificate_der().to_vec()],
                },
                chain_warning: None,
            }]
        );
        assert!(!verified.incomplete);
    }
}

#[test]
fn retains_exact_certificates_and_builds_key_chains_from_unnamed_ca_bags() {
    use crate::test_support::metadata_certificate;
    let leaf = metadata_certificate("leaf", "intermediate", &[0, 0, 1], &[]);
    let intermediate = metadata_certificate("intermediate", "root", &[2], &[]);
    let root = metadata_certificate("root", "root", &[3], &[]);
    let unrelated = metadata_certificate("other", "other", &[4], &[]);
    let key = SafeBag {
        bag: Bag::ShroudedKey(EncryptedPrivateKeyInfo {
            algorithm: AlgorithmIdentifier::with_null(
                ObjectIdentifier::new(oid::OID_PBES2).unwrap(),
            ),
            encrypted_data: vec![1, 2, 3],
        }),
        attributes: vec![friendly_name("key"), local_key_id(&[1])],
    };
    let data = synthetic(vec![
        key,
        raw_certificate(&root, vec![]),
        raw_certificate(&unrelated, vec![]),
        raw_certificate(&leaf, vec![local_key_id(&[1])]),
        raw_certificate(&intermediate, vec![]),
        raw_certificate(&root, vec![]),
    ]);
    let verified = parse(&data).unwrap().verify("changeit").unwrap();
    assert!(!verified.incomplete);
    // Chain members are not listed again, but an unrelated certificate is.
    assert_eq!(verified.entries.len(), 2);
    assert_eq!(
        verified.entries[0].certificates(),
        [leaf, intermediate, root]
    );
    assert_eq!(verified.entries[0].chain_warning, None);
    assert_eq!(verified.entries[1].alias, "other");
    assert_eq!(verified.entries[1].kind(), "Certificate");
    assert_eq!(verified.entries[1].certificates(), [unrelated]);
}

#[test]
fn names_unnamed_keys_and_lists_plain_certificates_like_openssl_writes_them() {
    use crate::test_support::metadata_certificate;
    let leaf = metadata_certificate("leaf", "ca", &[1], &[]);
    let ca = metadata_certificate("ca", "ca", &[2], &[]);
    let loose = metadata_certificate("loose", "loose", &[3], &[]);
    let key = |id: &[u8]| SafeBag {
        bag: Bag::ShroudedKey(EncryptedPrivateKeyInfo {
            algorithm: AlgorithmIdentifier::with_null(
                ObjectIdentifier::new(oid::OID_PBES2).unwrap(),
            ),
            encrypted_data: vec![1, 2, 3],
        }),
        attributes: vec![local_key_id(id)],
    };
    let data = synthetic(vec![
        key(&[1]),
        key(&[9]),
        raw_certificate(&leaf, vec![local_key_id(&[1])]),
        raw_certificate(&ca, vec![]),
        raw_certificate(&loose, vec![friendly_name("named")]),
        raw_certificate(b"unreadable", vec![]),
    ]);
    let verified = parse(&data).unwrap().verify("changeit").unwrap();
    assert!(!verified.incomplete);
    let listed: Vec<_> = verified
        .entries
        .iter()
        .map(|entry| {
            (
                entry.alias.as_str(),
                entry.kind(),
                entry.certificates().len(),
            )
        })
        .collect();
    assert_eq!(
        listed,
        [
            ("Certificate 1", "Certificate", 1),
            ("Private key 1", "Private key", 0),
            ("leaf", "Private key", 2),
            ("named", "Certificate", 1),
        ]
    );
}

#[test]
fn trusted_certificates_with_colliding_aliases_remain_visible() {
    use crate::test_support::metadata_certificate;
    use crown::x509::attribute::Attribute;

    let first = metadata_certificate("first", "first", &[1], &[]);
    let second = metadata_certificate("second", "second", &[2], &[]);
    let trusted = |der: &[u8], alias| {
        raw_certificate(
            der,
            vec![
                friendly_name(alias),
                Attribute::new(
                    ObjectIdentifier::new(TRUSTED_KEY_USAGE).unwrap(),
                    vec![der::oid(
                        &ObjectIdentifier::new(&[2, 5, 29, 37, 0]).unwrap(),
                    )],
                ),
            ],
        )
    };
    for alias in ["shared", "SHARED"] {
        let data = synthetic(vec![trusted(&first, "shared"), trusted(&second, alias)]);
        let verified = parse(&data).unwrap().verify("changeit").unwrap();
        assert!(!verified.incomplete);
        assert_eq!(verified.entries.len(), 2);
        let mut expected = vec![("shared", first.clone()), (alias, second.clone())];
        expected.sort_by(|a, b| a.0.cmp(b.0));
        for (entry, (alias, der)) in verified.entries.iter().zip(expected) {
            assert_eq!(entry.alias, alias);
            assert_eq!(entry.kind(), "Trusted certificate");
            assert_eq!(entry.certificates(), [der]);
        }

        // A name shared with a key must not hide a trusted certificate either.
        let key = SafeBag {
            bag: Bag::ShroudedKey(EncryptedPrivateKeyInfo {
                algorithm: AlgorithmIdentifier::with_null(
                    ObjectIdentifier::new(oid::OID_PBES2).unwrap(),
                ),
                encrypted_data: vec![1, 2, 3],
            }),
            attributes: vec![friendly_name("shared")],
        };
        let mut secret = secret_bag();
        secret.attributes = vec![friendly_name("shared")];
        for other in [key, secret] {
            let kind = if matches!(other.bag, Bag::ShroudedKey(_)) {
                "Private key"
            } else {
                "Secret key"
            };
            let data = synthetic(vec![other, trusted(&second, alias)]);
            let verified = parse(&data).unwrap().verify("changeit").unwrap();
            assert!(!verified.incomplete);
            assert_eq!(verified.entries.len(), 2);
            assert!(verified.entries.iter().any(|entry| entry.kind() == kind));
            let certificate = verified
                .entries
                .iter()
                .find(|entry| entry.kind() == "Trusted certificate")
                .unwrap();
            assert_eq!(certificate.alias, alias);
            assert_eq!(certificate.certificates(), std::slice::from_ref(&second));
        }
    }
}

#[test]
fn identical_trusted_certificates_are_listed_once() {
    use crate::test_support::metadata_certificate;
    use crown::x509::attribute::Attribute;

    let der = metadata_certificate("ca", "ca", &[1], &[]);
    let trusted = |alias| {
        raw_certificate(
            &der,
            vec![
                friendly_name(alias),
                Attribute::new(
                    ObjectIdentifier::new(TRUSTED_KEY_USAGE).unwrap(),
                    vec![der::oid(
                        &ObjectIdentifier::new(&[2, 5, 29, 37, 0]).unwrap(),
                    )],
                ),
            ],
        )
    };
    let data = synthetic(vec![trusted("ca"), trusted("ca")]);
    let verified = parse(&data).unwrap().verify("changeit").unwrap();
    assert!(!verified.incomplete);
    assert_eq!(verified.entries.len(), 1);
    assert_eq!(verified.entries[0].alias, "ca");

    // The same certificate under names differing in case stays separate.
    let data = synthetic(vec![trusted("ca"), trusted("CA")]);
    let verified = parse(&data).unwrap().verify("changeit").unwrap();
    assert_eq!(verified.entries.len(), 2);
}

#[test]
fn malformed_and_negative_serial_certificates_remain_inspectable() {
    use crate::test_support::metadata_certificate;
    use crown::x509::attribute::Attribute;
    let negative = metadata_certificate("negative", "negative", &[0xff], &[]);
    let trusted = |name| {
        vec![
            friendly_name(name),
            Attribute::new(
                ObjectIdentifier::new(TRUSTED_KEY_USAGE).unwrap(),
                vec![der::oid(
                    &ObjectIdentifier::new(&[2, 5, 29, 37, 0]).unwrap(),
                )],
            ),
        ]
    };
    let data = synthetic(vec![
        raw_certificate(b"unreadable", trusted("malformed")),
        raw_certificate(&negative, trusted("negative")),
    ]);
    let verified = parse(&data).unwrap().verify("changeit").unwrap();
    assert!(!verified.incomplete);
    assert_eq!(verified.entries.len(), 2);
    assert_eq!(verified.entries[0].certificates(), [b"unreadable".to_vec()]);
    assert!(verified.entries[0].certificate.is_none());
    assert_eq!(verified.entries[1].certificates(), [negative]);
    assert_eq!(
        certificate::details::Details::parse(&verified.entries[1].certificates()[0])
            .unwrap()
            .serial_decimal,
        "-1"
    );
}
