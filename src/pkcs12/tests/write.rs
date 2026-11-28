use super::*;

fn open(data: &[u8], password: &str) -> (Vec<KeystoreEntry>, Writable) {
    let (verified, writable) = parse(data).unwrap().open(password).unwrap();
    (verified.entries, writable.unwrap())
}

fn contains(data: &[u8], needle: &[u8]) -> bool {
    data.windows(needle.len()).any(|window| window == needle)
}

fn shrouded_key(attributes: Vec<crown::x509::attribute::Attribute>) -> SafeBag {
    SafeBag {
        bag: Bag::ShroudedKey(EncryptedPrivateKeyInfo {
            algorithm: AlgorithmIdentifier::with_null(
                ObjectIdentifier::new(oid::OID_PBES2).unwrap(),
            ),
            encrypted_data: b"synthetic, not a private key".to_vec(),
        }),
        attributes,
    }
}

#[test]
fn written_stores_read_back_with_the_same_entries_and_protection() {
    let passwordless = include_bytes!("../../../tests/fixtures/passwordless.p12");
    for (name, data, password) in [
        ("modern", MODERN, "changeit"),
        ("legacy", LEGACY, "changeit"),
        ("unicode alias", UNICODE_ALIAS, "changeit"),
        ("openssl", OPENSSL, "changeit"),
        ("openssl legacy", OPENSSL_LEGACY, "changeit"),
        ("openssl no mac", OPENSSL_NO_MAC_AES, "changeit"),
        ("empty password", EMPTY_PASSWORD, ""),
        ("nul password", NUL_PASSWORD, ""),
        ("empty password no mac", EMPTY_PASSWORD_NO_MAC, ""),
        ("passwordless", &passwordless[..], ""),
    ] {
        let original = parse(data).unwrap();
        let (entries, writable) = open(data, password);
        let saved = writable.encode(&mut TestRng(0)).unwrap();
        let store = parse(&saved).unwrap();
        let verified = store.verify(password).unwrap();
        assert_eq!(verified.entries, entries, "{name}");
        assert!(!verified.incomplete, "{name}");
        // A store keeps its MAC, or its lack of one, and certificates
        // that were encrypted stay hidden.
        assert_eq!(store.0.mac.is_some(), original.0.mac.is_some(), "{name}");
        assert_eq!(
            contains(&saved, fixture_certificate_der()),
            contains(data, fixture_certificate_der()),
            "{name}"
        );
        if original.0.mac.is_some() || !contains(data, fixture_certificate_der()) {
            assert!(
                matches!(store.verify("wrong"), Err(VerifyError::Password)),
                "{name}"
            );
            // Fresh salts make every protected save differ.
            assert_ne!(saved, writable.encode(&mut TestRng(7)).unwrap(), "{name}");
        }
    }
}

#[test]
fn stores_that_were_not_read_completely_are_not_writable() {
    let unknown = SafeBag {
        bag: Bag::Other {
            oid: ObjectIdentifier::new(&[1, 2, 3, 4]).unwrap(),
            value: der::null(),
        },
        attributes: vec![friendly_name("other")],
    };
    let data = synthetic(vec![shrouded_key(vec![friendly_name("key")]), unknown]);
    let (verified, writable) = parse(&data).unwrap().open("changeit").unwrap();
    assert!(verified.incomplete);
    assert!(writable.is_none());
}

#[test]
fn removing_a_key_takes_its_certificate_and_unshared_chain() {
    use crate::test_support::metadata_certificate;
    let leaf = metadata_certificate("leaf", "intermediate", &[1], &[]);
    let other_leaf = metadata_certificate("other-leaf", "root", &[5], &[]);
    let intermediate = metadata_certificate("intermediate", "root", &[2], &[]);
    let root = metadata_certificate("root", "root", &[3], &[]);
    let loose = metadata_certificate("loose", "loose", &[4], &[]);
    let data = synthetic(vec![
        shrouded_key(vec![friendly_name("a-key"), local_key_id(&[1])]),
        shrouded_key(vec![friendly_name("b-key"), local_key_id(&[2])]),
        raw_certificate(&leaf, vec![local_key_id(&[1])]),
        raw_certificate(&other_leaf, vec![local_key_id(&[2])]),
        raw_certificate(&intermediate, vec![]),
        raw_certificate(&root, vec![]),
        raw_certificate(&loose, vec![friendly_name("loose")]),
    ]);
    let aliases = |entries: &[KeystoreEntry]| -> Vec<String> {
        entries.iter().map(|entry| entry.alias.clone()).collect()
    };
    let (entries, mut writable) = open(&data, "changeit");
    assert_eq!(aliases(&entries), ["a-key", "b-key", "loose"]);
    assert_eq!(entries[0].certificates().len(), 3);

    // The intermediate goes with its key; the root is still b-key's.
    let entries = writable.remove(0);
    assert_eq!(aliases(&entries), ["b-key", "loose"]);
    assert_eq!(entries[1].kind(), "Certificate");
    assert_eq!(
        entries[0].certificates(),
        [other_leaf.clone(), root.clone()]
    );
    let saved = writable.encode(&mut TestRng(0)).unwrap();
    assert_eq!(
        parse(&saved).unwrap().verify("changeit").unwrap().entries,
        entries
    );
    assert!(!contains(&saved, &leaf) && !contains(&saved, &intermediate));
    assert!(contains(&saved, &root) && contains(&saved, &loose));

    // Then a plain certificate, then the last key with its root.
    let entries = writable.remove(1);
    assert_eq!(aliases(&entries), ["b-key"]);
    assert!(writable.remove(0).is_empty());
    let saved = writable.encode(&mut TestRng(0)).unwrap();
    let verified = parse(&saved).unwrap().verify("changeit").unwrap();
    assert!(verified.entries.is_empty() && !verified.incomplete);
    assert!(!contains(&saved, &root));
}

#[test]
fn renaming_names_the_key_and_its_certificate_and_keeps_the_rest() {
    use crate::test_support::metadata_certificate;
    let leaf = metadata_certificate("leaf", "leaf", &[1], &[]);
    let data = synthetic(vec![
        shrouded_key(vec![friendly_name("old"), local_key_id(&[7, 7])]),
        raw_certificate(&leaf, vec![friendly_name("old"), local_key_id(&[7, 7])]),
        shrouded_key(vec![local_key_id(&[9])]),
    ]);
    let (entries, mut writable) = open(&data, "changeit");
    assert_eq!(entries[0].alias, "Private key 1");
    assert_eq!(entries[1].alias, "old");

    let entries = writable.rename(1, "new-ü😀").unwrap();
    assert_eq!(entries[1].alias, "new-ü😀");
    assert_eq!(entries[1].certificates(), std::slice::from_ref(&leaf));
    // A key without a name gets one.
    let entries = writable.rename(0, "named").unwrap();
    assert_eq!(entries[0].alias, "named");
    assert_eq!(entries[0].kind(), "Private key");

    let saved = writable.encode(&mut TestRng(0)).unwrap();
    let store = parse(&saved).unwrap();
    assert_eq!(store.verify("changeit").unwrap().entries, entries);
    let bags = store.read_bags(b"changeit").unwrap().bags;
    // Both bags of the entry carry the name once, as a BMPString, and
    // still share their key ID; the key itself is untouched.
    for bag in &bags[..2] {
        assert_eq!(bag.friendly_name().as_deref(), Some("new-ü😀"));
        assert_eq!(bag.local_key_id(), Some(vec![7, 7]));
        assert_eq!(bag.attributes.len(), 2);
        assert!(contains(&bag.raw, &[0x1e, 14, 0, b'n', 0, b'e', 0, b'w']));
    }
    for bag in [&bags[0], &bags[2]] {
        let Bag::ShroudedKey(key) = &bag.bag else {
            panic!("a key bag");
        };
        assert_eq!(key.encrypted_data, b"synthetic, not a private key");
    }
}

#[test]
fn inserted_certificates_are_trusted_entries_stored_like_the_others() {
    use crate::test_support::metadata_certificate;
    let added = metadata_certificate("added", "added", &[9], &[]);
    // Java's store encrypts certificates, so the new one is encrypted.
    let (_, mut writable) = open(MODERN, "changeit");
    let entries = writable
        .insert_trusted_certificate("added", &added)
        .unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        entries[0],
        KeystoreEntry {
            alias: "added".into(),
            certificate: certificate::summarize(&added),
            content: Content::Certificates {
                kind: Kind::TrustedCertificate,
                certificates: vec![added.clone()],
            },
            chain_warning: None,
        }
    );
    let saved = writable.encode(&mut TestRng(0)).unwrap();
    assert!(!contains(&saved, &added));
    assert_eq!(
        parse(&saved).unwrap().verify("changeit").unwrap().entries,
        entries
    );

    // A passwordless truststore stays readable without a password.
    let passwordless = include_bytes!("../../../tests/fixtures/passwordless.p12");
    let (_, mut writable) = open(passwordless, "");
    let entries = writable
        .insert_trusted_certificate("added", &added)
        .unwrap();
    let saved = writable.encode(&mut TestRng(0)).unwrap();
    assert!(contains(&saved, &added));
    let store = parse(&saved).unwrap();
    assert!(store.0.mac.is_none());
    assert_eq!(store.verify("").unwrap().entries, entries);

    // A new store has a MAC and encrypts its certificates.
    let mut writable = Writable::empty("secret");
    let empty = writable.encode(&mut TestRng(0)).unwrap();
    let verified = parse(&empty).unwrap().verify("secret").unwrap();
    assert!(verified.entries.is_empty() && !verified.incomplete);
    assert!(matches!(
        parse(&empty).unwrap().verify("wrong"),
        Err(VerifyError::Password)
    ));
    let entries = writable
        .insert_trusted_certificate("added", &added)
        .unwrap();
    let saved = writable.encode(&mut TestRng(0)).unwrap();
    assert!(!contains(&saved, &added));
    assert_eq!(
        parse(&saved).unwrap().verify("secret").unwrap().entries,
        entries
    );
}

#[test]
fn the_password_changes_only_where_nothing_else_depends_on_it() {
    let (entries, mut writable) = open(MODERN, "changeit");
    assert!(
        writable
            .set_password("", &mut TestRng(0))
            .unwrap_err()
            .contains("not empty")
    );
    writable.set_password("new-päss", &mut TestRng(0)).unwrap();
    let saved = writable.encode(&mut TestRng(0)).unwrap();
    let store = parse(&saved).unwrap();
    assert!(matches!(
        store.verify("changeit"),
        Err(VerifyError::Password)
    ));
    assert_eq!(store.verify("new-päss").unwrap().entries, entries);

    let passwordless = include_bytes!("../../../tests/fixtures/passwordless.p12");
    let (_, mut writable) = open(passwordless, "");
    let error = writable
        .set_password("secret", &mut TestRng(0))
        .unwrap_err();
    assert!(error.contains("not protected by a password"), "{error}");

    // A key that is not really encrypted cannot be re-encrypted.
    let data = synthetic(vec![shrouded_key(vec![friendly_name("key")])]);
    let (_, mut writable) = open(&data, "changeit");
    let error = writable
        .set_password("secret", &mut TestRng(0))
        .unwrap_err();
    assert!(error.contains("not supported"), "{error}");
    let saved = writable.encode(&mut TestRng(0)).unwrap();
    assert!(parse(&saved).unwrap().verify("changeit").is_ok());
}

fn encrypted_key(pkcs8: &[u8], password: &[u8], legacy: bool) -> EncryptedPrivateKeyInfo {
    if legacy {
        let pbe = LegacyPbe {
            salt: vec![7; 8],
            iterations: 50,
            kind: LegacyPbeKind::DesEde3,
        };
        EncryptedPrivateKeyInfo {
            algorithm: pbe.to_algorithm(),
            encrypted_data: pbe.encrypt(pkcs8, password).unwrap(),
        }
    } else {
        encrypt_private_key(
            pkcs8,
            password,
            Pbes2Cipher::Aes256Cbc { iv: Vec::new() },
            50,
            &mut TestRng(3),
        )
        .unwrap()
    }
}

/// The content of every key and secret bag that `password` decrypts,
/// in bag order.
fn decrypted_keys(data: &[u8], password: &str) -> Vec<Vec<u8>> {
    let bags = parse(data)
        .unwrap()
        .read_bags(password.as_bytes())
        .unwrap()
        .bags;
    bags.iter()
        .filter_map(|bag| match &bag.bag {
            Bag::ShroudedKey(info) => Some(info.clone()),
            Bag::Secret { value, .. } => {
                let der = Reader::new(value)
                    .read_explicit(0)
                    .unwrap()
                    .read_octet_string_owned()
                    .unwrap();
                Some(EncryptedPrivateKeyInfo::parse(&der).unwrap())
            }
            _ => None,
        })
        .filter_map(|info| {
            pbe_decrypt(&info.algorithm, &info.encrypted_data, password.as_bytes())
                .ok()
                .map(|(key, _)| key)
        })
        .collect()
}

#[test]
fn changing_the_password_re_encrypts_keys_without_changing_them() {
    use crate::test_support::metadata_certificate;
    let leaf = metadata_certificate("leaf", "leaf", &[1], &[]);
    let modern = synthetic_pkcs8(b"first synthetic key");
    let legacy = synthetic_pkcs8(b"second synthetic key");
    let secret = synthetic_pkcs8(b"synthetic secret");
    let secret_bag = |password: &[u8]| SafeBag {
        bag: Bag::Secret {
            oid: ObjectIdentifier::new(oid::OID_PKCS12_SHROUDED_KEY_BAG).unwrap(),
            value: der::explicit(
                0,
                &der::octet_string(&encrypted_key(&secret, password, false).encode()),
            ),
        },
        attributes: vec![friendly_name("secret")],
    };
    let bags = |other_password: &[u8]| {
        vec![
            SafeBag {
                bag: Bag::ShroudedKey(encrypted_key(&modern, b"changeit", false)),
                attributes: vec![friendly_name("modern"), local_key_id(&[1])],
            },
            raw_certificate(&leaf, vec![local_key_id(&[1])]),
            SafeBag {
                bag: Bag::ShroudedKey(encrypted_key(&legacy, b"changeit", true)),
                attributes: vec![friendly_name("legacy")],
            },
            secret_bag(other_password),
        ]
    };
    let data = synthetic(bags(b"changeit"));
    let (entries, mut writable) = open(&data, "changeit");
    assert_eq!(entries.len(), 3);
    writable.set_password("new-päss", &mut TestRng(0)).unwrap();
    let saved = writable.encode(&mut TestRng(0)).unwrap();
    let store = parse(&saved).unwrap();
    assert!(matches!(
        store.verify("changeit"),
        Err(VerifyError::Password)
    ));
    // The listing, names, and key IDs are as before.
    assert_eq!(store.verify("new-päss").unwrap().entries, entries);
    // Each key decrypts with the new password to the same bytes, and
    // is now encrypted with PBES2.
    assert_eq!(
        decrypted_keys(&saved, "new-päss"),
        [modern.clone(), legacy.clone(), secret.clone()]
    );
    for bag in store.read_bags("new-päss".as_bytes()).unwrap().bags {
        if let Bag::ShroudedKey(info) = &bag.bag {
            assert!(info.algorithm.oid.matches(oid::OID_PBES2));
            assert!(
                pbe_decrypt(&info.algorithm, &info.encrypted_data, b"changeit")
                    .ok()
                    .is_none_or(|(key, _)| !is_private_key_info(&key))
            );
        }
    }
    // The keys are not left in the file unencrypted.
    for key in [&modern, &legacy, &secret] {
        assert!(!contains(&saved, key));
    }

    // One key under another password stops the change, and nothing moves.
    let data = synthetic(bags(b"other"));
    let (_, mut writable) = open(&data, "changeit");
    let error = writable
        .set_password("new-päss", &mut TestRng(0))
        .unwrap_err();
    assert!(error.contains("another password"), "{error}");
    let saved = writable.encode(&mut TestRng(0)).unwrap();
    assert_eq!(decrypted_keys(&saved, "changeit"), [modern, legacy]);
}

#[test]
fn keys_that_cannot_be_re_encrypted_stop_the_password_change() {
    let secret = |kind: &[u64], value: Vec<u8>| SafeBag {
        bag: Bag::Secret {
            oid: ObjectIdentifier::new(kind).unwrap(),
            value,
        },
        attributes: vec![friendly_name("secret")],
    };
    let not_a_key = encrypted_key(b"decrypts, but is not a key", b"changeit", false);
    for (bag, reason) in [
        // A secret that is not an encrypted PKCS #8 structure.
        (
            secret(&[1, 2, 3, 4], der::explicit(0, &der::octet_string(b"raw"))),
            "not supported",
        ),
        (
            secret(
                oid::OID_PKCS12_SHROUDED_KEY_BAG,
                der::explicit(0, &der::octet_string(b"not encrypted key info")),
            ),
            "not supported",
        ),
        // Content that decrypts with valid padding but is not a key
        // means the password was wrong.
        (
            SafeBag {
                bag: Bag::ShroudedKey(not_a_key),
                attributes: vec![friendly_name("key")],
            },
            "another password",
        ),
    ] {
        let data = synthetic(vec![bag]);
        let (entries, mut writable) = open(&data, "changeit");
        let error = writable
            .set_password("secret", &mut TestRng(0))
            .unwrap_err();
        assert!(error.contains(reason), "{error}");
        let saved = writable.encode(&mut TestRng(0)).unwrap();
        assert_eq!(
            parse(&saved).unwrap().verify("changeit").unwrap().entries,
            entries
        );
    }
}

#[test]
fn recognizes_the_shape_of_a_private_key() {
    assert!(is_private_key_info(&synthetic_pkcs8(b"key")));
    for content in [
        &b""[..],
        b"not DER",
        &der::sequence(&der::integer(&[0])),
        &der::octet_string(b"key"),
        &[synthetic_pkcs8(b"key"), vec![0]].concat(),
    ] {
        assert!(!is_private_key_info(content));
    }
}

#[test]
fn empty_password_encodings_refuse_new_keys_without_changing_the_store() {
    let key = synthetic_pkcs8(b"synthetic key");
    for data in [EMPTY_PASSWORD, NUL_PASSWORD] {
        let (entries, mut writable) = open(data, "");
        let mut rng = TestRng(0);
        let message =
            "a key needs a keystore password that is not empty; change the password first (p)";
        assert_eq!(
            writable.insert_private_key("private", &key, &[], &mut rng),
            Err(message)
        );
        assert_eq!(
            writable.insert_secret_key("secret", &key, 0, &mut rng),
            Err(message)
        );
        assert_eq!(open(&writable.encode(&mut rng).unwrap(), "").0, entries);
        writable.set_password("changeit", &mut rng).unwrap();
        writable
            .insert_private_key("private", &key, &[], &mut rng)
            .unwrap();
        writable
            .insert_secret_key("secret", &key, 0, &mut rng)
            .unwrap();
    }
}

#[test]
fn inserted_secret_keys_are_stored_as_java_stores_them() {
    let wrapped = synthetic_pkcs8(b"synthetic secret");
    let mut writable = Writable::empty("changeit");
    // A store whose only safe is encrypted gets a plain one for keys.
    writable.safes = vec![Some(PBE_ITERATIONS)];
    let mut rng = TestRng(0);
    let entries = writable
        .insert_secret_key("aes", &wrapped, 1_700_000_000_000, &mut rng)
        .unwrap();
    assert_eq!(writable.safes, [Some(PBE_ITERATIONS), None]);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        (entries[0].alias.as_str(), entries[0].kind()),
        ("aes", "Secret key")
    );
    assert_eq!(writable.secret_key(0).unwrap().as_slice(), wrapped);
    assert!(writable.private_key(0).is_none());
    // Java names the key and gives it the time as its local key ID.
    let data = writable.encode(&mut rng).unwrap();
    assert!(contains(&data, b"Time 1700000000000"));
    let (entries, read) = open(&data, "changeit");
    assert_eq!(entries[0].kind(), "Secret key");
    assert_eq!(read.secret_key(0).unwrap().as_slice(), wrapped);

    // Another kind of secret, a key under another password, and a
    // private key are not secret keys to read.
    let secret = |kind: &[u64], value: Vec<u8>| SafeBag {
        bag: Bag::Secret {
            oid: ObjectIdentifier::new(kind).unwrap(),
            value,
        },
        attributes: vec![friendly_name("secret")],
    };
    let other_password = encrypted_key(&wrapped, b"other", false).encode();
    let bags = vec![
        secret(&[1, 2, 3, 4], der::explicit(0, &der::octet_string(b"raw"))),
        secret(
            oid::OID_PKCS12_SHROUDED_KEY_BAG,
            der::explicit(0, &der::octet_string(&other_password)),
        ),
        shrouded_key(vec![friendly_name("key")]),
    ];
    let (entries, read) = open(&synthetic(bags), "changeit");
    assert_eq!(entries.len(), 3);
    for index in 0..3 {
        assert!(read.secret_key(index).is_none(), "{index}");
    }
}

#[test]
fn inserted_private_keys_share_issuers_and_decrypt_again() {
    use crate::test_support::metadata_certificate;
    let ca = metadata_certificate("ca", "ca", &[1], &[]);
    let first = metadata_certificate("first", "ca", &[2], &[]);
    let second = metadata_certificate("second", "ca", &[3], &[]);
    let key = synthetic_pkcs8(b"synthetic, not a private key");
    let mut writable = Writable::empty("changeit");
    // A store whose only safe is encrypted gets a plain one for keys.
    writable.safes = vec![Some(PBE_ITERATIONS)];
    let mut rng = TestRng(0);
    for leaf in [&first, &second] {
        let chain = [leaf.clone(), ca.clone()];
        writable
            .insert_private_key("key", &key, &chain, &mut rng)
            .unwrap();
    }
    let entries = writable
        .insert_private_key("bare", &key, &[], &mut rng)
        .unwrap();
    assert_eq!(writable.safes, [Some(PBE_ITERATIONS), None]);
    // The second chain reuses the issuer the first one stored.
    let held = |certificate: &Vec<u8>| {
        writable
            .bags
            .iter()
            .filter(|bag| bag.certificate_der.as_ref() == Some(certificate))
            .count()
    };
    assert_eq!((held(&ca), held(&first), held(&second)), (1, 1, 1));
    for index in 0..entries.len() {
        assert_eq!(writable.private_key(index).unwrap().as_slice(), key);
    }
    // An entry without a key has none to decrypt.
    let entries = writable.insert_trusted_certificate("trusted", &ca).unwrap();
    let trusted = entries.iter().position(|entry| entry.alias == "trusted");
    assert!(writable.private_key(trusted.unwrap()).is_none());
}

#[test]
fn removing_or_renaming_key_preserves_standalone_named_and_trusted_certs() {
    use crate::test_support::metadata_certificate;
    use crown::x509::attribute::Attribute;

    let leaf = metadata_certificate("leaf", "ca", &[1], &[]);
    let ca = metadata_certificate("ca", "ca", &[2], &[]);
    let trusted_attr = Attribute::new(
        ObjectIdentifier::new(TRUSTED_KEY_USAGE).unwrap(),
        vec![der::oid(
            &ObjectIdentifier::new(ANY_EXTENDED_KEY_USAGE).unwrap(),
        )],
    );
    let data = synthetic(vec![
        shrouded_key(vec![friendly_name("my-key"), local_key_id(&[1])]),
        raw_certificate(&leaf, vec![friendly_name("my-key"), local_key_id(&[1])]),
        raw_certificate(
            &leaf,
            vec![
                friendly_name("trusted-leaf"),
                local_key_id(&[1]),
                trusted_attr,
            ],
        ),
        raw_certificate(&ca, vec![friendly_name("named-ca")]),
    ]);
    let (entries, mut writable) = open(&data, "changeit");
    let aliases = |entries: &[KeystoreEntry]| -> Vec<String> {
        entries.iter().map(|e| e.alias.clone()).collect()
    };
    assert_eq!(aliases(&entries), ["my-key", "named-ca", "trusted-leaf"]);

    // Renaming my-key must not touch trusted-leaf or named-ca.
    let entries = writable.rename(0, "renamed-key").unwrap();
    assert_eq!(
        aliases(&entries),
        ["named-ca", "renamed-key", "trusted-leaf"]
    );

    // Deleting renamed-key must NOT delete named-ca or trusted-leaf.
    let entries = writable.remove(1);
    assert_eq!(aliases(&entries), ["named-ca", "trusted-leaf"]);
    let saved = writable.encode(&mut TestRng(0)).unwrap();
    let verified = parse(&saved).unwrap().verify("changeit").unwrap();
    assert!(!verified.incomplete);
    assert_eq!(verified.entries, entries);
}

#[test]
fn set_chain_and_insert_private_key_are_atomic_on_error() {
    use crate::test_support::metadata_certificate;

    let leaf = metadata_certificate("leaf", "leaf", &[1], &[]);
    let new_leaf = metadata_certificate("new-leaf", "new-leaf", &[2], &[]);
    let key = synthetic_pkcs8(b"synthetic key");

    let mut writable = Writable::empty("changeit");
    let entries = writable
        .insert_private_key("key", &key, std::slice::from_ref(&leaf), &mut TestRng(0))
        .unwrap();
    let bags_before = writable.bags.len();
    let safes_before = writable.safes.clone();
    let sources_before = writable.sources.clone();

    // Out-of-bounds index and empty chain leave writable untouched.
    assert!(
        writable
            .set_chain(99, "key", std::slice::from_ref(&new_leaf))
            .is_err()
    );
    assert!(writable.set_chain(0, "key", &[]).is_err());
    assert_eq!(writable.bags.len(), bags_before);
    assert_eq!(writable.safes, safes_before);
    assert_eq!(writable.sources, sources_before);

    // Corrupted raw key bag makes set_chain fail without dropping the entry.
    let key_bag_idx = writable.sources[0][0];
    let saved_raw = writable.bags[key_bag_idx].raw.clone();
    writable.bags[key_bag_idx].raw = vec![0x00];
    assert!(
        writable
            .set_chain(0, "key", std::slice::from_ref(&new_leaf))
            .is_err()
    );
    writable.bags[key_bag_idx].raw = saved_raw;
    assert_eq!(writable.bags.len(), bags_before);
    assert_eq!(writable.sources, sources_before);
    let encoded = writable.encode(&mut TestRng(0)).unwrap();
    assert_eq!(
        parse(&encoded).unwrap().verify("changeit").unwrap().entries,
        entries
    );
}

#[test]
fn preserves_higher_kdf_iterations_on_save_password_change_and_key_insert() {
    use crate::test_support::metadata_certificate;

    let leaf = metadata_certificate("leaf", "leaf", &[1], &[]);
    let priv_key = synthetic_pkcs8(b"synthetic private key");
    let sec_key = synthetic_pkcs8(b"synthetic secret key");
    let extra_key = synthetic_pkcs8(b"extra private key");

    let mac_iters: u32 = 25_000;
    let safe_iters: u32 = 20_000;
    let priv_iters: u32 = 15_000;
    let sec_iters: u32 = 18_000;

    let priv_enc = encrypt_private_key(
        &priv_key,
        b"changeit",
        Pbes2Cipher::Aes256Cbc { iv: Vec::new() },
        priv_iters,
        &mut TestRng(1),
    )
    .unwrap();
    let sec_enc = encrypt_private_key(
        &sec_key,
        b"changeit",
        Pbes2Cipher::Aes256Cbc { iv: Vec::new() },
        sec_iters,
        &mut TestRng(2),
    )
    .unwrap();

    let cert_safe_contents = encode_safe_contents(&[raw_certificate(
        &leaf,
        vec![friendly_name("my-key"), local_key_id(&[1])],
    )]);
    let safe_pbe = Pbes2 {
        salt: vec![9; 20],
        iterations: safe_iters,
        key_length: None,
        prf: Hash::Sha256,
        cipher: Pbes2Cipher::Aes256Cbc { iv: vec![4; 16] },
    };
    let cert_ciphertext = safe_pbe.encrypt(&cert_safe_contents, b"changeit").unwrap();
    let data_oid = ObjectIdentifier::new(oid::OID_PKCS7_DATA).unwrap();
    let enc_safe = ContentInfo {
        content_type: ObjectIdentifier::new(oid::OID_PKCS7_ENCRYPTED_DATA).unwrap(),
        content: der::sequence(
            &[
                der::integer(&[0]),
                der::sequence(
                    &[
                        der::oid(&data_oid),
                        safe_pbe.to_algorithm().encode(),
                        der::implicit(0, false, &cert_ciphertext),
                    ]
                    .concat(),
                ),
            ]
            .concat(),
        ),
    };
    let key_safe_contents = encode_safe_contents(&[
        SafeBag {
            bag: Bag::ShroudedKey(priv_enc),
            attributes: vec![friendly_name("my-key"), local_key_id(&[1])],
        },
        SafeBag {
            bag: Bag::Secret {
                oid: ObjectIdentifier::new(oid::OID_PKCS12_SHROUDED_KEY_BAG).unwrap(),
                value: der::explicit(0, &der::octet_string(&sec_enc.encode())),
            },
            attributes: vec![friendly_name("my-secret")],
        },
    ]);
    let key_safe = ContentInfo::data(&key_safe_contents);
    let auth_safe_der = der::sequence(&[enc_safe.encode(), key_safe.encode()].concat());
    let mac_salt = vec![7u8; 20];
    let mac_pw = pkcs12_password(b"changeit");
    let mac_key = pkcs12kdf::derive(
        Hash::Sha256.factory(),
        &mac_pw,
        &mac_salt,
        3,
        u64::from(mac_iters),
        32,
    )
    .unwrap();
    let mut hmac = EvpHash::new_sha256_hmac(&mac_key).unwrap();
    hmac.write_all(&auth_safe_der).unwrap();
    let original_bytes = Pfx {
        version: 3,
        auth_safe: ContentInfo::data(&auth_safe_der),
        mac: Some(MacData {
            digest_algorithm: AlgorithmIdentifier::with_null(object_id(Hash::Sha256.oid())),
            digest: hmac.sum(),
            salt: mac_salt,
            iterations: mac_iters,
        }),
    }
    .encode();

    // Helper to inspect encrypted safe PBES2 iterations in a PFX.
    let encrypted_safe_iterations = |bytes: &[u8]| -> Vec<u32> {
        let pfx = Pfx::parse(bytes).unwrap();
        let auth = pfx.authenticated_safe().unwrap();
        let mut reader = Reader::new(&auth);
        let mut seq = reader.read_sequence().unwrap();
        let mut out = Vec::new();
        while !seq.is_empty() {
            let info = ContentInfo::parse_reader(&mut seq).unwrap();
            if info.content_type.matches(oid::OID_PKCS7_ENCRYPTED_DATA) {
                let mut r = Reader::new(&info.content);
                let mut s = r.read_sequence().unwrap();
                let _ = s.read_integer().unwrap();
                let mut eci = s.read_sequence().unwrap();
                let _ = eci.read_oid().unwrap();
                let alg = AlgorithmIdentifier::parse(&mut eci).unwrap();
                out.push(Pbes2::parse(&alg).unwrap().iterations);
            }
        }
        out
    };

    // 1. Open and re-save: MAC and encrypted safe iterations are preserved.
    let (_, mut writable) = open(&original_bytes, "changeit");
    let resaved = writable.encode(&mut TestRng(3)).unwrap();
    assert_eq!(
        Pfx::parse(&resaved).unwrap().mac.unwrap().iterations,
        mac_iters
    );
    assert_eq!(encrypted_safe_iterations(&resaved), vec![safe_iters]);

    // 2. Change password and insert a new private key: higher counts are preserved
    //    on MAC, safe, re-encrypted keys, and new key.
    writable.set_password("newpass", &mut TestRng(4)).unwrap();
    writable
        .insert_private_key("extra", &extra_key, &[], &mut TestRng(5))
        .unwrap();
    let changed = writable.encode(&mut TestRng(6)).unwrap();
    let store = parse(&changed).unwrap();
    assert_eq!(store.0.mac.as_ref().unwrap().iterations, mac_iters);
    assert_eq!(encrypted_safe_iterations(&changed), vec![safe_iters]);

    let bags = store.read_bags(b"newpass").unwrap().bags;
    let key_iters = |alias: &str| -> u32 {
        let bag = bags
            .iter()
            .find(|b| b.friendly_name().as_deref() == Some(alias) && b.certificate_der.is_none())
            .unwrap();
        match &bag.bag {
            Bag::ShroudedKey(info) => Pbes2::parse(&info.algorithm).unwrap().iterations,
            Bag::Secret { oid, value } => {
                let info = secret_info(oid, value).unwrap();
                Pbes2::parse(&info.algorithm).unwrap().iterations
            }
            _ => panic!("expected key bag"),
        }
    };
    assert_eq!(key_iters("my-key"), priv_iters);
    assert_eq!(key_iters("my-secret"), sec_iters);
    assert_eq!(key_iters("extra"), mac_iters);
}

#[test]
fn bulk_add_helpers_match_insert_without_relisting() {
    use crate::test_support::metadata_certificate;

    let root = metadata_certificate("root", "root", &[1], &[]);
    let leaf_a = metadata_certificate("leaf-a", "root", &[2], &[]);
    let leaf_b = metadata_certificate("leaf-b", "root", &[3], &[]);
    let trusted = metadata_certificate("trusted", "trusted", &[4], &[]);
    let key_a = synthetic_pkcs8(b"synthetic key a");
    let key_b = synthetic_pkcs8(b"synthetic key b");
    let secret = crate::secret_key::to_pkcs8(&crate::secret_key::SecretKey {
        algorithm: "AES".into(),
        key: Zeroizing::new(vec![0x11; 16]),
    })
    .unwrap();

    let mut bulk = Writable::empty("changeit");
    let mut bulk_rng = TestRng(7);
    bulk.add_trusted_certificate("trusted", &trusted).unwrap();
    bulk.add_private_key(
        "key-a",
        &key_a,
        &[leaf_a.clone(), root.clone(), root.clone()],
        &mut bulk_rng,
    )
    .unwrap();
    bulk.add_private_key(
        "key-b",
        &key_b,
        &[leaf_b.clone(), root.clone()],
        &mut bulk_rng,
    )
    .unwrap();
    bulk.add_secret_key("secret", &secret, 1_700_000_000_000, &mut bulk_rng)
        .unwrap();
    // Bulk construction never runs relist().
    assert!(bulk.sources.is_empty());

    let mut incremental = Writable::empty("changeit");
    let mut inc_rng = TestRng(7);
    incremental
        .insert_trusted_certificate("trusted", &trusted)
        .unwrap();
    incremental
        .insert_private_key(
            "key-a",
            &key_a,
            &[leaf_a, root.clone(), root.clone()],
            &mut inc_rng,
        )
        .unwrap();
    incremental
        .insert_private_key("key-b", &key_b, &[leaf_b, root], &mut inc_rng)
        .unwrap();
    let expected_entries = incremental
        .insert_secret_key("secret", &secret, 1_700_000_000_000, &mut inc_rng)
        .unwrap();

    assert_eq!(bulk.safes, incremental.safes);
    assert_eq!(bulk.bags.len(), incremental.bags.len());
    let bulk_encoded = bulk.encode(&mut TestRng(99)).unwrap();
    let inc_encoded = incremental.encode(&mut TestRng(99)).unwrap();
    assert_eq!(bulk_encoded, inc_encoded);

    let verified = parse(&bulk_encoded).unwrap().verify("changeit").unwrap();
    assert!(!verified.incomplete);
    assert_eq!(verified.entries, expected_entries);
}
