use std::{
    fs,
    io::{self, Read},
    path::Path,
};

use crown::asn1::Asn1Time;
use ratatui::{Terminal, backend::TestBackend, buffer::Buffer};

use super::*;
use certificate::Summary;
use keystore::{Content, Kind};
use test_support::{
    KEYTOOL_JKS, TestDirectory, UNICODE_ALIAS_JKS, UNICODE_PASSWORD_JKS, empty_keystore,
    fixture_summary, mixed_keystore,
};

mod browser;
mod certificate_files;
mod chains;
mod creating;
mod editing_entries;
mod entry_list_view;
mod generating;
mod generation_lock;
mod input;
mod key_pairs;
mod key_passwords;
mod opening;
mod passwords;
mod secret_keys;
mod signing_requests;

fn browsing(directory: &Path) -> App {
    App {
        file_picker: Some(FilePicker::new(directory).unwrap()),
        ..App::default()
    }
}

fn press(app: &mut App, code: KeyCode) -> bool {
    app.handle_key(KeyEvent::new(code, KeyModifiers::NONE))
}

fn buffer(app: &mut App, width: u16, height: u16) -> Buffer {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| app.draw(frame)).unwrap();
    terminal.backend().buffer().clone()
}

fn screen(app: &mut App, width: u16, height: u16) -> String {
    buffer(app, width, height)
        .content
        .chunks(usize::from(width))
        .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}

fn red_text(app: &mut App) -> String {
    buffer(app, 200, 24)
        .content
        .iter()
        .filter(|cell| cell.fg == Color::Red)
        .map(|cell| cell.symbol())
        .collect()
}

fn type_password(app: &mut App, password: &str) {
    for ch in password.chars() {
        assert!(!press(app, KeyCode::Char(ch)));
    }
}

fn selected_alias(app: &App) -> &str {
    &app.entries[app.selected_entry().unwrap()].alias
}

fn shown_aliases(app: &App) -> Vec<&str> {
    app.visible
        .iter()
        .map(|&index| app.entries[index].alias.as_str())
        .collect()
}

/// Chooses the file starting with `name` as the CA reply of the selected key.
fn reply(app: &mut App, name: &str) {
    press(app, KeyCode::Char('R'));
    type_password(app, name);
    press(app, KeyCode::Enter);
}

/// Selects the entry named `alias`.
fn select(app: &mut App, alias: &str) {
    let row = app
        .visible
        .iter()
        .position(|&index| app.entries[index].alias == alias)
        .unwrap();
    app.entries_state.select(Some(row));
}

/// A keystore saved as `name` with a trusted certificate and two private
/// keys holding synthetic bytes: `own`, protected by `keypass`, and `shared`,
/// protected by the keystore's password, `changeit`.
fn keystore_with_keys(directory: &TestDirectory, name: &str) -> (App, PathBuf, Vec<u8>) {
    use crate::keystore::{PRIVATE_KEY_TAG, TRUSTED_CERT_TAG, VERSION_02};
    use crate::test_support::{Builder, TestRng, synthetic_pkcs8};
    let jceks = name.ends_with(".jceks");
    let key = synthetic_pkcs8(b"synthetic, not a private key");
    let mut builder = if jceks {
        Builder::jceks(VERSION_02, 3)
    } else {
        Builder::new(VERSION_02, 3)
    };
    builder.entry(TRUSTED_CERT_TAG, b"cert", VERSION_02, 1);
    for (alias, password) in [(&b"own"[..], "keypass"), (b"shared", "changeit")] {
        builder.entry_header(PRIVATE_KEY_TAG, alias);
        builder.payload(&key_protection::protect(&key, password, jceks, &mut TestRng(0)).unwrap());
        builder.u32_field(1);
        builder.certificate(VERSION_02);
    }
    let path = directory.path().join(name);
    fs::write(&path, builder.finish("changeit")).unwrap();
    let mut app = App::default();
    app.open_file(path.clone());
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.entries.len(), 3);
    (app, path, key)
}

/// The key that `password` recovers from the entry listed at `index` of the
/// keystore saved at `path`.
fn saved_key(path: &Path, index: usize, password: &str) -> Result<Vec<u8>, key_protection::Error> {
    let (_, writable) = keystore::parse(fs::read(path).unwrap())
        .unwrap()
        .open("changeit")
        .ok()
        .unwrap();
    key_protection::recover(writable.protected_key(index).unwrap(), password)
        .map(|key| key.to_vec())
}

/// The entries of the PKCS12 keystore at `path`, read completely.
fn pkcs12_entries(path: &Path, password: &str) -> Vec<KeystoreEntry> {
    let verified = pkcs12::parse(&fs::read(path).unwrap())
        .unwrap()
        .verify(password)
        .unwrap();
    assert!(!verified.incomplete);
    verified.entries
}

/// Opens `mixed_keystore()`, saved as `store.jks`, with its password.
fn editing(directory: &TestDirectory) -> (App, PathBuf) {
    let path = directory.path().join("store.jks");
    fs::write(&path, mixed_keystore()).unwrap();
    let mut app = App::default();
    app.open_file(path.clone());
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.entries.len(), 2);
    (app, path)
}

fn aliases(path: &Path) -> Vec<String> {
    keystore::load_entries(&fs::read(path).unwrap(), "changeit")
        .unwrap()
        .into_iter()
        .map(|entry| entry.alias)
        .collect()
}

fn type_alias(app: &mut App, alias: &str) {
    app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    type_password(app, alias);
    press(app, KeyCode::Enter);
}

/// Chooses the file starting with `name` in the import file browser.
fn import(app: &mut App, name: &str) {
    press(app, KeyCode::Char('i'));
    type_password(app, name);
    press(app, KeyCode::Enter);
}

/// PEM text of the synthetic Ed25519 key `key` and of `certificates`.
fn key_pem(label: &str, key: &[u8], certificates: &[&[u8]]) -> String {
    use crown::asn1::pem;
    let mut text = pem::encode(label, key);
    for certificate in certificates {
        text.push_str(&pem::encode("CERTIFICATE", certificate));
    }
    text
}

fn type_new_password(app: &mut App, first: &str, second: &str) {
    type_password(app, first);
    press(app, KeyCode::Enter);
    type_password(app, second);
    press(app, KeyCode::Enter);
}
