//! Bounded, offline checks of the stored path, not RFC 5280 path validation.
use crown::asn1::{Reader, der};

use super::{details::Details, extensions::printable, signature::Signature};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Info,
    Pass,
    Problem,
    Unknown,
}

pub struct Finding {
    pub status: Status,
    pub message: String,
}

fn add(out: &mut Vec<Finding>, status: Status, message: impl Into<String>) {
    out.push(Finding {
        status,
        message: message.into(),
    });
}

/// Missing is distinct from malformed or duplicate. Never interpret display text.
fn extension<'a>(info: &'a Details, oid: &[u64]) -> Result<Option<&'a [u8]>, ()> {
    let mut found = info
        .extensions
        .iter()
        .filter(|e| e.oid.as_ref().is_some_and(|id| id.matches(oid)));
    let value = found.next().map(|e| e.value.as_slice());
    if found.next().is_some() || info.extensions.iter().any(|e| e.oid.is_none()) {
        Err(())
    } else {
        Ok(value)
    }
}

fn sequence(value: &[u8]) -> Result<Reader<'_>, ()> {
    let mut reader = Reader::new(value);
    let result = reader.read_sequence().map_err(|_| ())?;
    reader.expect_end().map_err(|_| ())?;
    Ok(result)
}

fn constraints(value: &[u8]) -> Result<(bool, Option<i64>), ()> {
    let mut reader = sequence(value)?;
    let ca = if !reader.is_empty() && reader.peek_tag().map_err(|_| ())? == der::BOOLEAN {
        reader.read_boolean().map_err(|_| ())?
    } else {
        false
    };
    let length = if reader.is_empty() {
        None
    } else {
        Some(reader.read_integer_i64().map_err(|_| ())?)
    };
    reader.expect_end().map_err(|_| ())?;
    if length.is_some_and(|n| n < 0 || !ca) {
        return Err(());
    }
    Ok((ca, length))
}

fn signing_usage(value: &[u8]) -> Result<bool, ()> {
    let mut reader = Reader::new(value);
    let (_, bits) = reader.read_bit_string().map_err(|_| ())?;
    reader.expect_end().map_err(|_| ())?;
    if bits.is_empty() {
        return Err(());
    }
    Ok(bits[0] & 4 != 0)
}

fn key_id(value: &[u8], authority: bool) -> Result<Option<Vec<u8>>, ()> {
    if !authority {
        let mut reader = Reader::new(value);
        let id = reader.read_octet_string().map_err(|_| ())?;
        reader.expect_end().map_err(|_| ())?;
        return if id.is_empty() {
            Err(())
        } else {
            Ok(Some(id.to_vec()))
        };
    }
    let mut reader = sequence(value)?;
    let mut id = None;
    let mut seen = Vec::new();
    while !reader.is_empty() {
        let (tag, value) = reader.read_tlv().map_err(|_| ())?;
        if seen.contains(&tag) || value.is_empty() {
            return Err(());
        }
        seen.push(tag);
        if tag == der::Tag::context(0) {
            id = Some(value.to_vec());
        } else if tag != der::Tag::context_constructed(1) && tag != der::Tag::context(2) {
            return Err(());
        }
    }
    Ok(id)
}

fn identifier(info: &Details, authority: bool) -> Result<Option<Vec<u8>>, ()> {
    extension(
        info,
        if authority {
            &[2, 5, 29, 35]
        } else {
            &[2, 5, 29, 14]
        },
    )?
    .map(|value| key_id(value, authority))
    .unwrap_or(Ok(None))
}

/// Report each stored certificate, leaf first. No network or trust-store access.
pub fn check(
    metadata: &[Option<Details>],
    signatures: &[Option<Signature>],
    warning: Option<&str>,
    now: i64,
) -> Vec<Finding> {
    use Status::*;
    let mut out = Vec::new();
    if let Some(warning) = warning {
        add(&mut out, Unknown, warning);
    }
    if metadata.is_empty() {
        add(&mut out, Unknown, "No certificates are stored.");
    }
    for (index, info) in metadata.iter().enumerate() {
        let label = format!("Certificate {}", index + 1);
        let Some(info) = info else {
            add(
                &mut out,
                Unknown,
                format!("{label}: cannot decode certificate; checks unavailable."),
            );
            continue;
        };
        add(
            &mut out,
            Info,
            format!("{label}: {}", printable(&info.subject.to_string())),
        );
        let validity = if info.not_before.to_unix() > info.not_after.to_unix() {
            (Problem, "Validity: invalid interval.")
        } else if now < info.not_before.to_unix() {
            (Problem, "Validity: not yet valid.")
        } else if now > info.not_after.to_unix() {
            (Problem, "Validity: expired.")
        } else {
            (Pass, "Validity: within validity period.")
        };
        add(&mut out, validity.0, validity.1);
        match signatures.get(index).copied().flatten() {
            Some(Signature::Verified) => add(
                &mut out,
                Pass,
                "Signature: verified (does not establish trust).",
            ),
            Some(Signature::Failed(reason)) => {
                add(&mut out, Problem, format!("Signature: {reason}."))
            }
            Some(Signature::Unchecked(reason)) => {
                add(&mut out, Unknown, format!("Signature: {reason}."))
            }
            None => add(&mut out, Unknown, "Signature: issuer unavailable."),
        }
        match metadata.get(index + 1) {
            Some(Some(issuer)) => {
                add(
                    &mut out,
                    if info.issuer == issuer.subject {
                        Pass
                    } else {
                        Problem
                    },
                    if info.issuer == issuer.subject {
                        "Issuer name: matches next stored certificate."
                    } else {
                        "Issuer name: does not match next stored certificate."
                    },
                );
                match (identifier(info, true), identifier(issuer, false)) {
                    (Ok(Some(a)), Ok(Some(b))) => add(
                        &mut out,
                        if a == b { Pass } else { Problem },
                        if a == b {
                            "Issuer key identifiers: match."
                        } else {
                            "Issuer key identifiers: AKI/SKI conflict."
                        },
                    ),
                    (Err(_), _) | (_, Err(_)) => add(
                        &mut out,
                        Unknown,
                        "Issuer key identifiers: malformed or duplicate extension.",
                    ),
                    _ => add(
                        &mut out,
                        Unknown,
                        "Issuer key identifiers: AKI or SKI absent.",
                    ),
                }
            }
            Some(None) => add(
                &mut out,
                Unknown,
                "Issuer relationship: next certificate cannot be decoded.",
            ),
            None if info.issuer == info.subject => add(
                &mut out,
                Unknown,
                "Chain endpoint: self-issued; trust not checked.",
            ),
            None => add(
                &mut out,
                Unknown,
                "Issuer certificate: missing from stored chain.",
            ),
        }
        // Only certificates acting as issuers need CA constraints. The target
        // (index 0) is excluded from pathLen, as are self-issued intermediates.
        if index > 0 {
            match extension(info, &[2, 5, 29, 19]).and_then(|v| v.map(constraints).transpose()) {
                Ok(Some((true, limit))) => {
                    add(&mut out, Pass, "Basic Constraints: issuer is a CA.");
                    if let Some(limit) = limit {
                        if metadata[1..index].iter().any(Option::is_none) {
                            add(
                                &mut out,
                                Unknown,
                                "Path length: an intermediate cannot be decoded.",
                            );
                        } else {
                            let count = metadata[1..index]
                                .iter()
                                .flatten()
                                .filter(|c| c.subject != c.issuer)
                                .count();
                            add(
                                &mut out,
                                if count as u64 > limit as u64 {
                                    Problem
                                } else {
                                    Pass
                                },
                                format!(
                                    "Path length: {count} non-self-issued intermediates; limit {limit}."
                                ),
                            );
                        }
                    }
                }
                Ok(_) => add(
                    &mut out,
                    Problem,
                    "Basic Constraints: issuer lacks CA status.",
                ),
                Err(_) => add(
                    &mut out,
                    Unknown,
                    "Basic Constraints: malformed or duplicate extension.",
                ),
            }
            match extension(info, &[2, 5, 29, 15]).and_then(|v| v.map(signing_usage).transpose()) {
                Ok(Some(true)) => add(&mut out, Pass, "Key Usage: certificate signing permitted."),
                Ok(Some(false)) => add(
                    &mut out,
                    Problem,
                    "Key Usage: certificate signing not permitted.",
                ),
                Ok(None) => add(
                    &mut out,
                    Unknown,
                    "Key Usage: absent (no usage restriction declared).",
                ),
                Err(_) => add(
                    &mut out,
                    Unknown,
                    "Key Usage: malformed or duplicate extension.",
                ),
            }
        }
        for ext in &info.extensions {
            let Some(oid) = &ext.oid else {
                add(
                    &mut out,
                    Unknown,
                    "Malformed extension: additional checks unavailable.",
                );
                continue;
            };
            // Only issuer Basic Constraints and Key Usage have their complete
            // semantics checked here. Decoding an extension does not validate it.
            if ext.critical && !(index > 0 && [15, 19].iter().any(|n| oid.matches(&[2, 5, 29, *n])))
            {
                add(
                    &mut out,
                    Unknown,
                    format!("Critical extension {oid}: semantics not fully checked."),
                );
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::metadata_certificate;
    use crown::asn1::oid::ObjectIdentifier;

    fn ext(n: u64, value: &[u8]) -> Vec<u8> {
        der::sequence(
            &[
                der::oid(&ObjectIdentifier::new(&[2, 5, 29, n]).unwrap()),
                der::octet_string(value),
            ]
            .concat(),
        )
    }
    fn cert(subject: &str, issuer: &str, extensions: &[Vec<u8>]) -> Option<Details> {
        Some(Details::parse(&metadata_certificate(subject, issuer, &[1], extensions)).unwrap())
    }
    fn ca(limit: i64) -> Vec<Vec<u8>> {
        vec![
            ext(
                19,
                &der::sequence(&[der::boolean(true), der::integer_i64(limit)].concat()),
            ),
            ext(15, &der::bit_string(2, &[4])),
        ]
    }
    fn has(findings: &[Finding], status: Status, text: &str) -> bool {
        findings
            .iter()
            .any(|f| f.status == status && f.message.contains(text))
    }
    fn run(chain: &[Option<Details>]) -> Vec<Finding> {
        check(
            chain,
            &vec![Some(Signature::Verified); chain.len()],
            None,
            chain.iter().flatten().next().unwrap().not_before.to_unix(),
        )
    }

    #[test]
    fn valid_chain_and_inclusive_validity_boundaries() {
        let chain = vec![
            cert("leaf", "ca", &[]),
            cert("ca", "root", &ca(0)),
            cert("root", "root", &ca(1)),
        ];
        let report = run(&chain);
        assert!(!report.iter().any(|f| f.status == Status::Problem));
        assert!(has(
            &report,
            Status::Pass,
            "1 non-self-issued intermediates; limit 1"
        ));
        let info = chain[0].as_ref().unwrap();
        for time in [info.not_before.to_unix(), info.not_after.to_unix()] {
            assert!(has(
                &check(&chain, &[], None, time),
                Status::Pass,
                "within validity period"
            ));
        }
        assert!(has(
            &check(&chain, &[], None, info.not_before.to_unix() - 1),
            Status::Problem,
            "not yet valid"
        ));
        assert!(has(
            &check(&chain, &[], None, info.not_after.to_unix() + 1),
            Status::Problem,
            "expired"
        ));
    }

    #[test]
    fn checks_all_members_constraints_and_self_issued_path_length() {
        let mut chain = vec![
            cert("leaf", "ca", &[]),
            cert("ca", "root", &ca(0)),
            cert("root", "root", &ca(0)),
        ];
        assert!(has(
            &run(&chain),
            Status::Problem,
            "1 non-self-issued intermediates; limit 0"
        ));
        chain[1] = cert("root", "root", &ca(0));
        assert!(has(
            &run(&chain),
            Status::Pass,
            "0 non-self-issued intermediates; limit 0"
        ));
        chain[1] = cert(
            "ca",
            "root",
            &[
                ext(19, &der::sequence(&[])),
                ext(15, &der::bit_string(7, &[0x80])),
            ],
        );
        let report = run(&chain);
        assert!(has(&report, Status::Problem, "lacks CA status"));
        assert!(has(&report, Status::Problem, "signing not permitted"));
        chain[1].as_mut().unwrap().not_after = chain[0].as_ref().unwrap().not_before;
        let time = chain[0].as_ref().unwrap().not_before.to_unix() + 1;
        assert!(has(
            &check(&chain, &[], None, time),
            Status::Problem,
            "expired"
        ));
    }

    #[test]
    fn issuer_names_identifiers_and_missing_issuers() {
        let aki = ext(35, &der::sequence(&der::implicit(0, false, &[1])));
        let ski = ext(14, &der::octet_string(&[2]));
        let chain = vec![cert("leaf", "wrong", &[aki]), cert("ca", "root", &[ski])];
        let report = run(&chain);
        assert!(has(&report, Status::Problem, "does not match"));
        assert!(has(&report, Status::Problem, "AKI/SKI conflict"));
        assert!(has(&report, Status::Unknown, "missing from stored chain"));
        let matched = vec![
            cert(
                "leaf",
                "ca",
                &[ext(35, &der::sequence(&der::implicit(0, false, &[2])))],
            ),
            chain[1].clone(),
        ];
        assert!(has(&run(&matched), Status::Pass, "identifiers: match"));
    }

    #[test]
    fn malformed_duplicate_and_unsupported_checks_remain_unknown() {
        let duplicate = ca(0)[0].clone();
        let chain = vec![
            cert("leaf", "ca", &[ext(35, &[0xff])]),
            cert(
                "ca",
                "ca",
                &[duplicate.clone(), duplicate, ext(15, &[0xff])],
            ),
        ];
        let report = run(&chain);
        for text in [
            "Basic Constraints: malformed",
            "Key Usage: malformed",
            "identifiers: malformed",
        ] {
            assert!(has(&report, Status::Unknown, text));
        }
        let mut chain = chain;
        chain[1] = None;
        assert!(has(
            &run(&chain),
            Status::Unknown,
            "next certificate cannot be decoded"
        ));
        let report = check(
            &chain,
            &[Some(Signature::Unchecked("unsupported algorithm"))],
            Some("cycle"),
            0,
        );
        assert!(has(&report, Status::Unknown, "unsupported algorithm"));
        assert!(has(&report, Status::Unknown, "cycle"));
        assert!(has(
            &check(&chain, &[Some(Signature::Failed("bad signature"))], None, 0),
            Status::Problem,
            "bad signature"
        ));
        assert!(has(
            &check(&[], &[], None, 0),
            Status::Unknown,
            "No certificates"
        ));
    }

    #[test]
    fn unsupported_critical_extensions_and_unreadable_path_are_unknown() {
        let critical = der::sequence(
            &[
                der::oid(&ObjectIdentifier::new(&[2, 5, 29, 30]).unwrap()),
                der::boolean(true),
                der::octet_string(&der::sequence(&[])),
            ]
            .concat(),
        );
        let chain = vec![
            cert("leaf", "ca", &[critical]),
            None,
            cert("root", "root", &ca(0)),
        ];
        let report = run(&chain);
        assert!(has(
            &report,
            Status::Unknown,
            "Critical extension 2.5.29.30"
        ));
        assert!(has(
            &report,
            Status::Unknown,
            "Path length: an intermediate cannot be decoded"
        ));
    }

    #[test]
    fn strict_constraint_decoding_rejects_invalid_and_trailing_data() {
        for value in [
            der::sequence(&[der::boolean(true), der::integer_i64(-1)].concat()),
            der::sequence(&der::integer_i64(1)),
            [der::sequence(&der::boolean(true)), vec![0]].concat(),
        ] {
            assert!(constraints(&value).is_err());
        }
        let valid = der::sequence(&[der::boolean(true), der::integer_i64(0)].concat());
        for end in 0..valid.len() {
            assert!(constraints(&valid[..end]).is_err());
        }
        assert!(signing_usage(&[3, 2, 8, 0]).is_err());
        assert!(key_id(&[der::octet_string(&[1]), vec![0]].concat(), false).is_err());
    }
}
