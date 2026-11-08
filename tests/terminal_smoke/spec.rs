//! Checks that every smoke test links the SPEC sections it checks.

use std::fs;
use std::path::Path;

use crate::fixtures::ROOT;

/// Modules whose tests check the harness rather than the app.
const HARNESS: &[&str] = &["fixtures.rs", "main.rs", "pty.rs", "screen.rs", "spec.rs"];

/// How a test's `SPEC:` doc line links a SPEC section, before its anchor.
const LINK: &str = "](../../docs/SPEC.md#";

/// The anchor GitHub gives a Markdown heading.
fn anchor(heading: &str) -> String {
    heading
        .chars()
        .filter_map(|c| match c {
            ' ' => Some('-'),
            c if c.is_alphanumeric() || c == '-' || c == '_' => Some(c.to_ascii_lowercase()),
            _ => None,
        })
        .collect()
}

fn spec_anchors() -> Vec<String> {
    fs::read_to_string(Path::new(ROOT).join("docs/SPEC.md"))
        .unwrap()
        .lines()
        .filter(|line| line.starts_with('#'))
        .map(|line| anchor(line.trim_start_matches('#').trim()))
        .collect()
}

/// The anchors linked from `docs`.
fn linked_anchors(docs: &str) -> Vec<&str> {
    docs.split(LINK)
        .skip(1)
        .map(|rest| rest.split(')').next().unwrap())
        .collect()
}

#[test]
fn every_test_links_to_spec_sections() {
    let anchors = spec_anchors();
    let mut problems = Vec::new();
    let mut tests = 0;
    for file in fs::read_dir(Path::new(ROOT).join("tests/terminal_smoke")).unwrap() {
        let path = file.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.ends_with(".rs") || HARNESS.contains(&name.as_str()) {
            continue;
        }
        let source = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = source.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            if line.trim() != "#[test]" {
                continue;
            }
            tests += 1;
            let test = format!("{name}: {}", lines.get(index + 1).map_or("", |l| l.trim()));
            let docs: Vec<&str> = lines[..index]
                .iter()
                .rev()
                .take_while(|line| line.trim_start().starts_with("///"))
                .copied()
                .collect();
            let docs = docs.join("\n");
            let linked = linked_anchors(&docs);
            if !docs.contains("SPEC:") || linked.is_empty() {
                problems.push(format!("{test} has no `SPEC:` doc line linking a section"));
            }
            for link in linked {
                if !anchors.iter().any(|anchor| anchor == link) {
                    problems.push(format!("{test} links #{link}, which no SPEC heading has"));
                }
            }
        }
    }
    assert!(tests > 0, "no smoke tests found");
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn anchors_match_github() {
    assert_eq!(
        anchor("JKS compatibility (matching Java)"),
        "jks-compatibility-matching-java"
    );
    assert_eq!(anchor("ASN.1 and PEM views"), "asn1-and-pem-views");
    assert_eq!(anchor("Command-line startup"), "command-line-startup");
}
