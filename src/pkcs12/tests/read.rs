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
    let mut budget = MAX_TOTAL_ITERATIONS;
    let (plaintext, _) = decrypt_safe(
        &info.content,
        VALID_PADDING_PASSWORD.as_bytes(),
        &mut budget,
    )
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

#[test]
fn decrypts_ber_constructed_encrypted_content_definite_and_indefinite() {
    let plaintext = encode_safe_contents(&[secret_bag()]);
    let aes = pbes2(Pbes2Cipher::Aes256Cbc { iv: vec![3; 16] });
    let ciphertext = aes.encrypt(&plaintext, b"changeit").unwrap();
    let (first, second) = ciphertext.split_at(ciphertext.len() / 2);
    let data_oid = ObjectIdentifier::new(oid::OID_PKCS7_DATA).unwrap();

    let build_store = |encrypted_content_tlv: Vec<u8>| {
        let encrypted_data = der::sequence(
            &[
                der::integer(&[0]),
                der::sequence(
                    &[
                        der::oid(&data_oid),
                        aes.to_algorithm().encode(),
                        encrypted_content_tlv,
                    ]
                    .concat(),
                ),
            ]
            .concat(),
        );
        let safe = ContentInfo {
            content_type: ObjectIdentifier::new(oid::OID_PKCS7_ENCRYPTED_DATA).unwrap(),
            content: encrypted_data,
        };
        Pfx {
            version: 3,
            auth_safe: ContentInfo {
                content_type: data_oid.clone(),
                content: der::octet_string(&der::sequence(&safe.encode())),
            },
            mac: None,
        }
        .encode()
    };

    // Definite-length BER constructed [0] (0xA0) holding two OCTET STRING chunks.
    let chunks = [der::octet_string(first), der::octet_string(second)].concat();
    let definite = der::implicit(0, true, &chunks);
    assert_eq!(definite[0], 0xA0);

    // Indefinite-length BER constructed [0] (0xA0 0x80 ... 0x00 0x00), with a
    // nested constructed OCTET STRING (0x24 0x80 ... 0x00 0x00) for the second chunk.
    let mut nested = vec![0x24, 0x80];
    nested.extend(der::octet_string(second));
    nested.extend([0x00, 0x00]);
    let mut indefinite = vec![0xA0, 0x80];
    indefinite.extend(der::octet_string(first));
    indefinite.extend(nested);
    indefinite.extend([0x00, 0x00]);

    for tlv in [definite, indefinite] {
        let store = parse(&build_store(tlv)).unwrap();
        let verified = store.verify("changeit").unwrap();
        assert!(!verified.incomplete);
        assert_eq!(verified.entries.len(), 1);
        assert_eq!(verified.entries[0].alias, "secret");
        assert!(matches!(store.verify("wrong"), Err(VerifyError::Password)));
    }

    // Non-OCTET-STRING inside constructed [0] is rejected as unreadable/incomplete.
    let bad = der::implicit(0, true, &der::integer(&[1]));
    let verified = parse(&build_store(bad))
        .unwrap()
        .verify("changeit")
        .unwrap();
    assert!(verified.entries.is_empty());
    assert!(verified.incomplete);
}

#[test]
fn cumulative_kdf_iteration_budget_stops_excessive_multi_safe_stores() {
    let data_oid = ObjectIdentifier::new(oid::OID_PKCS7_DATA).unwrap();
    let enc_oid = ObjectIdentifier::new(oid::OID_PKCS7_ENCRYPTED_DATA).unwrap();

    let make_safe = |alias: &str, iterations: u32| {
        let mut bag = secret_bag();
        bag.attributes = vec![friendly_name(alias)];
        let plaintext = encode_safe_contents(&[bag]);
        let pbe = Pbes2 {
            salt: vec![7; 8],
            iterations,
            key_length: None,
            prf: Hash::Sha256,
            cipher: Pbes2Cipher::Aes256Cbc { iv: vec![1; 16] },
        };
        let ciphertext = pbe.encrypt(&plaintext, b"changeit").unwrap();
        let encrypted = der::sequence(
            &[
                der::integer(&[0]),
                der::sequence(
                    &[
                        der::oid(&data_oid),
                        pbe.to_algorithm().encode(),
                        der::implicit(0, false, &ciphertext),
                    ]
                    .concat(),
                ),
            ]
            .concat(),
        );
        ContentInfo {
            content_type: enc_oid.clone(),
            content: encrypted,
        }
        .encode()
    };

    // Build a store with a 100-iteration MAC and 3 encrypted safes of 100 iterations each.
    let safes_der = der::sequence(
        &[
            make_safe("safe-1", 100),
            make_safe("safe-2", 100),
            make_safe("safe-3", 100),
        ]
        .concat(),
    );
    let salt = vec![5u8; 20];
    let mac_pw = pkcs12_password(b"changeit");
    let mac_key = pkcs12kdf::derive(Hash::Sha256.factory(), &mac_pw, &salt, 3, 100, 32).unwrap();
    let mut hmac = EvpHash::new_sha256_hmac(&mac_key).unwrap();
    hmac.write_all(&safes_der).unwrap();
    let pfx = Pfx {
        version: 3,
        auth_safe: ContentInfo::data(&safes_der),
        mac: Some(MacData {
            digest_algorithm: AlgorithmIdentifier::with_null(object_id(Hash::Sha256.oid())),
            digest: hmac.sum(),
            salt,
            iterations: 100,
        }),
    };
    let store = parse(&pfx.encode()).unwrap();

    // Budget of 400 covers MAC (100) + 3 safes (300): complete and writable.
    let (verified, writable) = store.open_with_budget("changeit", 400).unwrap();
    assert!(!verified.incomplete);
    assert!(writable.is_some());
    assert_eq!(verified.entries.len(), 3);

    // Budget of 250 covers MAC (100) + safe-1 (100), leaving 50: safe-2 and safe-3
    // exceed remaining budget and are skipped without running their KDFs.
    let (verified, writable) = store.open_with_budget("changeit", 250).unwrap();
    assert!(verified.incomplete);
    assert!(writable.is_none());
    assert_eq!(verified.entries.len(), 1);
    assert_eq!(verified.entries[0].alias, "safe-1");
}

#[test]
fn trusted_cert_with_local_key_id_and_named_chain_certs_have_clean_ownership() {
    use crate::test_support::metadata_certificate;
    use crown::x509::attribute::Attribute;

    let leaf = metadata_certificate("leaf", "ca", &[1], &[]);
    let other_leaf = metadata_certificate("other-leaf", "ca", &[2], &[]);
    let ca = metadata_certificate("ca", "ca", &[3], &[]);
    let trusted_attr = || {
        Attribute::new(
            ObjectIdentifier::new(TRUSTED_KEY_USAGE).unwrap(),
            vec![der::oid(
                &ObjectIdentifier::new(ANY_EXTENDED_KEY_USAGE).unwrap(),
            )],
        )
    };
    let key_bag = |alias: &str, id: &[u8]| SafeBag {
        bag: Bag::ShroudedKey(EncryptedPrivateKeyInfo {
            algorithm: AlgorithmIdentifier::with_null(
                ObjectIdentifier::new(oid::OID_PBES2).unwrap(),
            ),
            encrypted_data: vec![1, 2, 3],
        }),
        attributes: vec![friendly_name(alias), local_key_id(id)],
    };

    // 1. A trusted certificate sharing a key's localKeyId must NOT be claimed
    //    as the key's leaf; the key claims its own non-trusted leaf instead.
    let data = synthetic(vec![
        raw_certificate(
            &other_leaf,
            vec![
                friendly_name("trusted-cert"),
                local_key_id(&[1]),
                trusted_attr(),
            ],
        ),
        raw_certificate(&leaf, vec![friendly_name("my-key"), local_key_id(&[1])]),
        raw_certificate(&ca, vec![friendly_name("named-ca")]),
        key_bag("my-key", &[1]),
    ]);
    let verified = parse(&data).unwrap().verify("changeit").unwrap();
    assert!(!verified.incomplete);
    let by_alias = |name: &str| verified.entries.iter().find(|e| e.alias == name).unwrap();
    assert_eq!(verified.entries.len(), 3);
    assert_eq!(by_alias("my-key").kind(), "Private key");
    assert_eq!(
        by_alias("my-key").certificates(),
        &[leaf.clone(), ca.clone()]
    );
    assert_eq!(by_alias("trusted-cert").kind(), "Trusted certificate");
    assert_eq!(
        by_alias("trusted-cert").certificates(),
        &[other_leaf.clone(), ca.clone()]
    );
    // Standalone named Certificate stays visible even though it appears in my-key's chain.
    assert_eq!(by_alias("named-ca").kind(), "Certificate");
    assert_eq!(
        by_alias("named-ca").certificates(),
        std::slice::from_ref(&ca)
    );

    // 2. First-match localKeyId hijacking: two keys sharing the same localKeyId
    //    match their own friendlyName cert rather than both grabbing the first cert.
    let data = synthetic(vec![
        raw_certificate(
            &other_leaf,
            vec![friendly_name("key-b"), local_key_id(&[9])],
        ),
        raw_certificate(&leaf, vec![friendly_name("key-a"), local_key_id(&[9])]),
        key_bag("key-a", &[9]),
        key_bag("key-b", &[9]),
    ]);
    let verified = parse(&data).unwrap().verify("changeit").unwrap();
    assert!(!verified.incomplete);
    assert_eq!(verified.entries.len(), 2);
    assert_eq!(verified.entries[0].alias, "key-a");
    assert_eq!(
        verified.entries[0].certificates(),
        std::slice::from_ref(&leaf)
    );
    assert_eq!(verified.entries[1].alias, "key-b");
    assert_eq!(
        verified.entries[1].certificates(),
        std::slice::from_ref(&other_leaf)
    );

    // 3. Two keys sharing the same localKeyId with only one cert bag: the cert
    //    is claimed by at most one key (no dual ownership).
    let data = synthetic(vec![
        raw_certificate(&leaf, vec![local_key_id(&[9])]),
        key_bag("key-a", &[9]),
        key_bag("key-b", &[9]),
    ]);
    let (verified, writable) = parse(&data).unwrap().open("changeit").unwrap();
    assert!(!verified.incomplete);
    assert_eq!(verified.entries.len(), 2);
    assert_eq!(
        verified.entries[0].certificates(),
        std::slice::from_ref(&leaf)
    );
    assert!(verified.entries[1].certificates().is_empty());
    let writable = writable.unwrap();
    assert_eq!(writable.sources[0].len(), 2);
    assert_eq!(writable.sources[1].len(), 1);
}
