//! Exercise the built TUI in a real Unix PTY using generated public test data.
//!
//! `cargo test` builds the binary and runs these tests on Unix (including
//! Linux/WSL and macOS). Set `KEYSTORE_TUI_BINARY=/absolute/path/to/keystore-tui`
//! to test another build: `cargo test --locked --test terminal_smoke`.
//!
//! Coverage (keep this list in step with the tests):
//!
//! - Opening a public-certificate fixture with an empty password: detail
//!   navigation, scrolling, signature checks, fingerprints, extensions, the file
//!   path, resizing, and returning to the list.
//! - The hidden startup password prompt for JKS, JCEKS, and PKCS12 fixtures,
//!   including the no-MAC `encrypted-no-mac.p12`; a wrong password, `Ctrl+C`, or
//!   `Esc` there exits without starting the app.
//! - `empty-password.p12` and the no-MAC `passwordless.p12` open without a prompt.
//! - A missing, invalid, or malformed path shows a warning, a path with spaces
//!   opens, and extra arguments print usage.
//! - PEM, DER, and request files given at startup open straight into their
//!   details; the chain diagnostics view opens and closes.
//! - A three-entry store, built at runtime from copies of the certificate:
//!   entry selection wrapping with the arrow keys, filtering (including `q` typed
//!   into the filter and `Esc` cancelling it), and sorting.
//! - Exporting a PEM certificate file: `q` is typed into the export name and
//!   `Esc` cancels the prompt.
//! - The `keytool` certificate request fixture: its signature is verified and it
//!   exports as PEM.
//! - `--version` and `--help` print and exit without starting the app.
//! - `q`, `Esc`, and `Ctrl+C` (including while typing a filter) restore terminal
//!   modes, leave the alternate screen, and show the cursor again.

#![cfg(unix)]

use std::ffi::OsStr;
use std::fs;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::{Mode, OFlags, open};
use rustix::io::{Errno, FdFlags, fcntl_setfd, read, write};
use rustix::process::{ioctl_tiocsctty, setsid};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{Winsize, tcgetattr, tcgetwinsize, tcsetwinsize};
use sha1::{Digest, Sha1};

const ROOT: &str = env!("CARGO_MANIFEST_DIR");
const TIMEOUT: Duration = Duration::from_secs(5);

fn binary() -> PathBuf {
    let binary = std::env::var_os("KEYSTORE_TUI_BINARY").map_or_else(
        || PathBuf::from(env!("CARGO_BIN_EXE_keystore-tui")),
        PathBuf::from,
    );
    assert!(binary.is_file(), "no TUI binary at {}", binary.display());
    binary
}

fn fixture(name: &str) -> PathBuf {
    Path::new(ROOT).join("tests/fixtures").join(name)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    rfind(haystack, needle).is_some()
}

fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .rposition(|window| window == needle)
}

/// A directory under Cargo's target directory, removed when dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
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

    fn path(&self) -> &Path {
        &self.0
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Own the child and PTY, retaining the slave to inspect restored modes.
struct PtyApp {
    args: Vec<String>,
    master: OwnedFd,
    slave: OwnedFd,
    child: Child,
    output: Vec<u8>,
    original_modes: String,
}

impl PtyApp {
    fn spawn(directory: &Path, args: &[&OsStr]) -> Self {
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
        fcntl_setfd(&master, FdFlags::CLOEXEC).unwrap();
        grantpt(&master).unwrap();
        unlockpt(&master).unwrap();
        let name = ptsname(&master, Vec::new()).unwrap();
        let slave = open(
            name.as_c_str(),
            OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        set_size(&slave, 100, 30);
        let original_modes = modes(&slave);

        let mut command = Command::new(binary());
        command
            .args(args)
            .current_dir(directory)
            .env_remove("NO_COLOR")
            .env("TERM", "xterm-256color")
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave.try_clone().unwrap()));
        // SAFETY: the hook only makes async-signal-safe system calls, and file
        // descriptor 0 is the PTY slave by the time it runs.
        unsafe {
            command.pre_exec(|| {
                setsid()?;
                ioctl_tiocsctty(BorrowedFd::borrow_raw(0))?;
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        Self {
            args: args
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect(),
            master,
            slave,
            child,
            output: Vec::new(),
            original_modes,
        }
    }

    /// Resize the terminal, then wait for the app's full redraw at the new size.
    ///
    /// The kernel sends `SIGWINCH` to the app. Keys are only sent after the
    /// redraw because crossterm can hold back a key that arrives together with
    /// a resize until the next input.
    fn resize(&mut self, width: u16, height: u16) {
        let start = self.output.len();
        set_size(&self.slave, width, height);
        let deadline = Instant::now() + TIMEOUT;
        while !contains(&self.output[start..], b"\x1b[2J") {
            assert!(
                Instant::now() < deadline,
                "TUI {:?} did not redraw after resizing to {width}x{height}\n{}",
                self.args,
                self.screen()
            );
            self.read(Duration::from_millis(50));
        }
    }

    /// Read whatever is available within `timeout`; return whether data arrived.
    fn read(&mut self, timeout: Duration) -> bool {
        let timeout = Timespec {
            tv_sec: timeout.as_secs() as _,
            tv_nsec: timeout.subsec_nanos() as _,
        };
        let mut fds = [PollFd::new(&self.master, PollFlags::IN)];
        match poll(&mut fds, Some(&timeout)) {
            Ok(0) | Err(Errno::INTR) => return false,
            Ok(_) => {}
            Err(error) => panic!("poll failed: {error}"),
        }
        let mut buffer = [0; 65536];
        match read(&self.master, &mut buffer) {
            Ok(count) => {
                self.output.extend_from_slice(&buffer[..count]);
                count > 0
            }
            Err(Errno::IO | Errno::INTR) => false, // The child may have closed its terminal.
            Err(error) => panic!("read failed: {error}"),
        }
    }

    fn send(&mut self, keys: &[u8]) {
        let mut keys = keys;
        while !keys.is_empty() {
            match write(&self.master, keys) {
                Ok(count) => keys = &keys[count..],
                Err(Errno::INTR) => {}
                Err(error) => panic!("write failed: {error}"),
            }
        }
    }

    fn exited(&mut self) -> Option<i32> {
        self.child
            .try_wait()
            .unwrap()
            .map(|status| status.code().unwrap_or(-1))
    }

    /// Wait for the child to exit and return its exit code.
    fn wait(&mut self) -> i32 {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(code) = self.exited() {
                return code;
            }
            if Instant::now() >= deadline {
                panic!("TUI {:?} did not exit\n{}", self.args, self.screen());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Replay the cursor/erase sequences emitted by Ratatui's backend.
    ///
    /// The fixture uses single-column text. This is a small screen reader for
    /// these checks, not a general ANSI or Unicode terminal emulator.
    fn screen(&self) -> String {
        let size = tcgetwinsize(&self.slave).unwrap();
        let (height, width) = (i64::from(size.ws_row), i64::from(size.ws_col));
        let blank = || vec![vec![' '; width as usize]; height as usize];
        let mut grid = blank();
        let (mut y, mut x) = (0_i64, 0_i64);
        let text: Vec<char> = String::from_utf8_lossy(&self.output).chars().collect();
        let mut i = 0;
        while i < text.len() {
            let token = text[i];
            i += 1;
            if token == '\x1b' {
                if let Some((final_byte, parameters, end)) = csi(&text, i) {
                    i = end;
                    if parameters.starts_with('?') {
                        continue; // Private terminal modes, including cursor visibility.
                    }
                    let numbers: Vec<i64> = parameters
                        .split(';')
                        .map(|n| n.parse().unwrap_or(0))
                        .collect();
                    let count = if numbers[0] == 0 { 1 } else { numbers[0] };
                    let or_one = |n: i64| if n == 0 { 1 } else { n };
                    match final_byte {
                        'H' | 'f' => {
                            y = or_one(numbers[0]) - 1;
                            x = numbers.get(1).map_or(1, |&n| or_one(n)) - 1;
                        }
                        'G' => x = count - 1,
                        'A' => y -= count,
                        'B' => y += count,
                        'C' => x += count,
                        'D' => x -= count,
                        'J' if matches!(numbers[0], 2 | 3) => grid = blank(),
                        'K' if (0..height).contains(&y) => {
                            let start = if matches!(numbers[0], 1 | 2) {
                                0
                            } else {
                                x.max(0)
                            };
                            let end = if matches!(numbers[0], 0 | 2) {
                                width
                            } else {
                                width.min(x + 1)
                            };
                            for cell in start.max(0)..end.min(width) {
                                grid[y as usize][cell as usize] = ' ';
                            }
                        }
                        _ => {}
                    }
                } else if text.get(i).is_some_and(|&next| next != '\n') {
                    i += 1; // Another two-character escape sequence.
                }
                continue;
            }
            match token {
                '\r' => x = 0,
                '\n' => y += 1,
                token if token >= ' ' => {
                    if (0..height).contains(&y) && (0..width).contains(&x) {
                        grid[y as usize][x as usize] = token;
                    }
                    x += 1;
                }
                _ => {}
            }
        }
        grid.iter()
            .map(|row| row.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn expect(&mut self, fragments: &[&str]) {
        let deadline = Instant::now() + TIMEOUT;
        while Instant::now() < deadline {
            self.read(Duration::from_millis(50));
            let screen = self.screen();
            if fragments.iter().all(|fragment| screen.contains(fragment)) {
                return;
            }
            if self.exited().is_some() {
                break;
            }
        }
        let exit = self.exited();
        panic!(
            "TUI {:?}: expected screen text: {fragments:?}; child exit: {exit:?}\nLast screen:\n{}",
            self.args,
            self.screen()
        );
    }

    fn assert_modes_restored(&self) {
        assert_eq!(
            modes(&self.slave),
            self.original_modes,
            "TUI {:?}",
            self.args
        );
    }

    fn assert_restored(&mut self) {
        assert_eq!(self.wait(), 0, "TUI {:?}", self.args);
        while self.read(Duration::ZERO) {}
        self.assert_modes_restored();
        for (enabled, restored) in [
            (&b"\x1b[?1049h"[..], &b"\x1b[?1049l"[..]), // Alternate screen.
            (b"\x1b[?25l", b"\x1b[?25h"),               // Cursor visibility.
        ] {
            assert!(contains(&self.output, enabled), "TUI {:?}", self.args);
            assert!(
                rfind(&self.output, restored) > rfind(&self.output, enabled),
                "TUI {:?} did not restore {:?}",
                self.args,
                String::from_utf8_lossy(restored)
            );
        }
    }
}

impl Drop for PtyApp {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

/// Parse a CSI sequence whose `[` starts at `start`, returning its final
/// character, its parameters, and the index after it.
fn csi(text: &[char], start: usize) -> Option<(char, String, usize)> {
    if text.get(start) != Some(&'[') {
        return None;
    }
    let mut end = start + 1;
    while text.get(end).is_some_and(|c| ('0'..='?').contains(c)) {
        end += 1;
    }
    let parameters_end = end;
    while text.get(end).is_some_and(|c| (' '..='/').contains(c)) {
        end += 1;
    }
    let final_byte = *text.get(end).filter(|c| ('@'..='~').contains(*c))?;
    let parameters = text[start + 1..parameters_end].iter().collect();
    Some((final_byte, parameters, end + 1))
}

fn set_size(slave: &OwnedFd, width: u16, height: u16) {
    let size = Winsize {
        ws_row: height,
        ws_col: width,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    tcsetwinsize(slave, size).unwrap();
}

fn modes(slave: &OwnedFd) -> String {
    format!("{:?}", tcgetattr(slave).unwrap())
}

/// Append the JKS integrity digest for an empty password.
fn with_empty_password_digest(mut body: Vec<u8>) -> Vec<u8> {
    let digest = Sha1::new()
        .chain_update(b"Mighty Aphrodite")
        .chain_update(&body)
        .finalize();
    body.extend_from_slice(&digest);
    body
}

/// `trusted-cert.jks` with its digest recomputed for an empty password.
fn empty_password_fixture() -> Vec<u8> {
    let mut data = fs::read(fixture("trusted-cert.jks")).unwrap();
    data.truncate(data.len() - 20);
    with_empty_password_digest(data)
}

/// The DER certificate stored in the public fixture under `root-cert`.
fn fixture_certificate() -> Vec<u8> {
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

fn certificate_pem(der: &[u8]) -> String {
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
fn pem_der(text: &str) -> Vec<u8> {
    let body: String = text
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with("-----"))
        .collect();
    base64_decode(&body)
}

/// Build an empty-password JKS with three copies of the public fixture
/// certificate. One copy's notAfter is moved earlier to exercise sorting;
/// certificate signatures are never checked by the app.
fn triage_keystore() -> Vec<u8> {
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

#[test]
fn startup_password() {
    for name in [
        "trusted-cert.jks",
        "trusted-cert.jceks",
        "trusted-cert.p12",
        "encrypted-no-mac.p12",
    ] {
        let path = fixture(name);
        let mut app = PtyApp::spawn(Path::new(ROOT), &[path.as_os_str()]);
        app.expect(&["Keystore password:"]);
        assert!(!contains(&app.output, b"\x1b[?1049h"), "{name}");
        app.send(b"changeit\r");
        app.expect(&["root-cert"]);
        assert!(!contains(&app.output, b"changeit"), "{name}");
        app.send(b"q");
        assert_eq!(app.wait(), 0, "{name}");
        app.assert_modes_restored();
    }
}

#[test]
fn startup_password_failure() {
    let path = fixture("trusted-cert.jks");
    for keys in [&b"wrong-secret\r"[..], b"\x03", b"\x1b"] {
        let mut app = PtyApp::spawn(Path::new(ROOT), &[path.as_os_str()]);
        app.expect(&["Keystore password:"]);
        app.send(keys);
        assert_eq!(app.wait(), 1, "{keys:?}");
        app.read(Duration::from_millis(100));
        assert!(!contains(&app.output, b"wrong-secret"), "{keys:?}");
        assert!(!contains(&app.output, b"\x1b[?1049h"), "{keys:?}");
        app.assert_modes_restored();
    }
}

#[test]
fn startup_invalid_path() {
    for path in ["missing.jks", "README.md", "tests"] {
        let mut app = PtyApp::spawn(Path::new(ROOT), &[OsStr::new(path)]);
        app.expect(&["No keystore selected", path, "Quit"]);
        assert!(!contains(&app.output, b"Keystore password:"), "{path}");
        assert!(contains(&app.output, b"38;5;3;"), "{path}");
        app.send(b"q");
        assert_eq!(app.wait(), 0, "{path}");
    }
}

#[test]
fn startup_spaces_and_malformed() {
    let directory = TempDir::new();
    let name = OsStr::new("store with spaces.jks");
    let path = directory.join("store with spaces.jks");
    let fixture = empty_password_fixture();
    fs::write(&path, &fixture).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[name]);
    app.expect(&["root-cert", "Quit"]);
    app.send(b"q");
    app.assert_restored();

    fs::write(&path, &fixture[..12]).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[name]);
    app.expect(&["No keystore selected", "not a valid", "Quit"]);
    assert!(contains(&app.output, b"38;5;3;"));
    app.send(b"q");
    app.assert_restored();
}

#[test]
fn startup_certificate_details() {
    let directory = TempDir::new();
    let der = fixture_certificate();
    for (name, data, heading) in [
        (
            "certificate with spaces.pem",
            certificate_pem(&der).into_bytes(),
            "Certificate hierarchy",
        ),
        ("certificate.der", der.clone(), "Certificate hierarchy"),
        (
            "request.csr",
            fs::read(fixture("keytool-request.csr")).unwrap(),
            "Request details",
        ),
    ] {
        fs::write(directory.join(name), data).unwrap();
        let mut app = PtyApp::spawn(directory.path(), &[OsStr::new(name)]);
        app.expect(&[heading, "[verified]", &format!("{name}'")]);
        assert!(!contains(&app.output, b"Keystore password:"), "{name}");
        app.send(b"\x1b");
        app.expect(&["1 entries | Sort: alias"]);
        app.send(b"q");
        app.assert_restored();
    }
}

#[test]
fn chain_diagnostics_navigation() {
    let directory = TempDir::new();
    fs::write(directory.join("certificate.der"), fixture_certificate()).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[OsStr::new("certificate.der")]);
    app.expect(&["Certificate details", "[verified]"]);
    app.send(b"d");
    app.expect(&[
        "Chain diagnostics",
        "Trust: not checked",
        "Revocation: not checked",
        "certificate.der'",
    ]);
    app.resize(60, 24);
    app.send(b"\x1b[F");
    app.expect(&["self-issued; trust not checked"]);
    app.send(b"d");
    app.expect(&["Certificate details", "Subject:"]);
    app.send(b"\x1b");
    app.expect(&["1 entries | Sort: alias"]);
    app.send(b"q");
    app.assert_restored();
}

#[test]
fn startup_extra_arguments() {
    let result = Command::new(binary()).args(["a", "b"]).output().unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(contains(&result.stderr, b"Usage:"));
}

#[test]
fn version_and_help() {
    for (flag, expected) in [
        ("--version", &b"keystore-tui "[..]),
        ("-V", b"keystore-tui "),
        ("--help", b"Usage: keystore-tui [path]"),
        ("-h", b"Usage: keystore-tui [path]"),
    ] {
        let result = Command::new(binary()).arg(flag).output().unwrap();
        assert_eq!(result.status.code(), Some(0), "{flag}");
        assert!(contains(&result.stdout, expected), "{flag}");
        assert!(!contains(&result.stdout, b"\x1b[?1049h"), "{flag}");
    }
}

#[test]
fn startup_empty_password() {
    for name in ["empty-password.p12", "passwordless.p12"] {
        let path = fixture(name);
        let mut app = PtyApp::spawn(Path::new(ROOT), &[path.as_os_str()]);
        app.expect(&["root-cert"]);
        assert!(!contains(&app.output, b"Keystore password:"), "{name}");
        app.send(b"q");
        assert_eq!(app.wait(), 0, "{name}");
    }
}

/// Open a file through the picker: it selects the first file or folder.
fn open_from_picker(app: &mut PtyApp, name: &str) {
    app.expect(&["No keystore selected"]);
    app.send(b"o");
    app.expect(&[name]);
    app.send(b"\r");
}

fn exercise(exit_key: &[u8]) {
    // This fixture contains only a generated public certificate. Its integrity
    // digest is recomputed for an empty password, avoiding password input.
    let directory = TempDir::new();
    fs::write(directory.join("entry.jks"), empty_password_fixture()).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[]);
    open_from_picker(&mut app, "entry.jks");
    app.expect(&["root-cert", "Expires"]);
    app.send(b"\r");
    app.expect(&["Certificate hierarchy", "Version: 3", "[verified]"]);
    app.send(b"\t");
    app.expect(&["Certificate details [focused]"]);
    app.send(b"\x1b[F"); // End scrolls to the fingerprint and extensions.
    app.expect(&[
        "Signature: verified with its own public key (self-signed).",
        "Fingerprint (SHA-256)",
        "Extensions:",
        "Subject Key Identifier (2.5.29.14)",
    ]);
    app.send(b"f");
    app.expect(&["Fingerprint (SHA-1)"]);
    app.send(b"\x1b[H"); // Home restores the top fields.
    app.expect(&["Version: 3"]);
    app.resize(40, 8);
    app.expect(&["Resize terminal"]);
    app.resize(100, 30);
    app.expect(&["Certificate hierarchy", "Version: 3"]);
    app.send(b"\x1b");
    app.expect(&["root-cert", "Expires"]);
    app.send(b"\r");
    app.expect(&["Certificate hierarchy"]);
    app.send(exit_key);
    app.assert_restored();
}

#[test]
fn quit_restores_terminal() {
    exercise(b"q");
}

#[test]
fn ctrl_c_restores_terminal() {
    exercise(b"\x03");
}

#[test]
fn entry_selection_wraps_with_arrow_keys() {
    let directory = TempDir::new();
    let path = directory.join("triage.jks");
    fs::write(&path, triage_keystore()).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[path.as_os_str()]);
    app.expect(&["3 entries | Sort: alias"]);
    app.send(b"\x1b[A\r"); // Up from alpha wraps to zeta-soon.
    app.expect(&["Certificate hierarchy", "zeta-soon"]);
    app.send(b"\x1b");
    app.expect(&["3 entries | Sort: alias"]);
    app.send(b"\x1b[B\r"); // Down wraps back to alpha.
    app.expect(&["Certificate hierarchy", "alpha"]);
    app.send(b"\x1b");
    app.expect(&["3 entries | Sort: alias"]);
    app.send(b"q");
    app.assert_restored();
}

fn assert_before(screen: &str, first: &str, second: &str) {
    let position = |text| {
        screen
            .find(text)
            .unwrap_or_else(|| panic!("{text} missing"))
    };
    assert!(
        position(first) < position(second),
        "{first} before {second}\n{screen}"
    );
}

fn triage(quit_while_typing: bool, exit_key: &[u8]) {
    let directory = TempDir::new();
    fs::write(directory.join("triage.jks"), triage_keystore()).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[]);
    open_from_picker(&mut app, "triage.jks");
    app.expect(&["alpha", "beta-quit", "zeta-soon", "3 entries | Sort: alias"]);
    app.send(b"/");
    app.expect(&["Type to filter", "Filter: _ | 3 of 3 entries"]);
    app.send(b"q"); // Typed into the filter, not a quit.
    app.expect(&["Filter: q_ | 1 of 3 entries", "beta-quit"]);
    assert_eq!(app.exited(), None);
    assert!(!app.screen().contains("alpha"));
    app.send(b"x");
    app.expect(&["Filter: qx_ | 0 of 3 entries", "No matching entries"]);
    app.send(b"\x1b"); // Cancels and clears the filter.
    app.expect(&["3 entries | Sort: alias", "alpha", "Up/Down j/k Scroll"]);
    assert!(!app.screen().contains("Filter:"));
    app.send(b"/zeta\r");
    app.expect(&["Filter: 'zeta' | 1 of 3 entries"]);
    assert!(!app.screen().contains("alpha"));
    app.send(b"\r"); // Details open for the filtered selection.
    app.expect(&["Certificate hierarchy", "zeta-soon"]);
    app.send(b"\x1b");
    app.expect(&["Filter: 'zeta' | 1 of 3 entries"]);
    app.send(b"/");
    app.expect(&["Filter: zeta_"]);
    app.send(b"\x1b");
    app.expect(&["3 entries | Sort: alias", "alpha"]);
    assert_before(&app.screen(), "alpha", "zeta-soon");
    app.send(b"s");
    app.expect(&["3 entries | Sort: expiry"]);
    assert_before(&app.screen(), "zeta-soon", "alpha");
    app.send(b"s");
    app.expect(&["3 entries | Sort: alias"]);
    app.send(b"/a\r");
    app.expect(&["Filter: 'a' | 3 of 3 entries"]);
    if quit_while_typing {
        app.send(b"/");
        app.expect(&["Filter: a_"]);
    }
    app.send(exit_key);
    app.assert_restored();
}

#[test]
fn filter_and_sort_then_quit_restores_terminal() {
    triage(false, b"q");
}

#[test]
fn filter_and_sort_then_escape_restores_terminal() {
    triage(false, b"\x1b");
}

#[test]
fn ctrl_c_while_filtering_restores_terminal() {
    triage(true, b"\x03");
}

fn certificate_file(exit_key: &[u8]) {
    let pem = certificate_pem(&fixture_certificate());
    let directory = TempDir::new();
    fs::write(directory.join("bundle.pem"), &pem).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[]);
    open_from_picker(&mut app, "bundle.pem");
    app.expect(&[
        "JKS TUI test fixture",
        "Certificate",
        "1 entries | Sort: alias",
    ]);
    app.send(b"\r");
    app.expect(&["Certificate hierarchy", "x Export certificate"]);
    app.send(b"x");
    app.expect(&["Save certificate to:"]);
    app.send(b"\x15"); // Ctrl+U clears the suggested absolute path.
    app.expect(&["Save certificate to: _"]);
    app.send(b"q"); // Typed into the name, not a quit.
    app.expect(&["Save certificate to: q_"]);
    assert_eq!(app.exited(), None);
    app.send(b"x\x7f.pem\r"); // Backspace, then save next to the file.
    app.expect(&["Saved certificate to"]);
    assert_eq!(fs::read_to_string(directory.join("q.pem")).unwrap(), pem);
    app.send(b"X");
    app.expect(&["Save chain to:"]);
    app.send(b"\x1b"); // Cancels the export, staying in the details.
    app.expect(&["x Export certificate", "Certificate hierarchy"]);
    app.send(exit_key);
    app.assert_restored();
}

#[test]
fn certificate_file_export_then_quit_restores_terminal() {
    certificate_file(b"q");
}

#[test]
fn certificate_file_export_then_ctrl_c_restores_terminal() {
    certificate_file(b"\x03");
}

#[test]
fn certificate_request_export_then_quit_restores_terminal() {
    let request = fs::read_to_string(fixture("keytool-request.csr")).unwrap();
    let directory = TempDir::new();
    fs::write(directory.join("server.csr"), &request).unwrap();
    let mut app = PtyApp::spawn(directory.path(), &[]);
    open_from_picker(&mut app, "server.csr");
    app.expect(&[
        "CSR TUI test fixture",
        "Certificate request",
        "1 entries | Sort: alias",
    ]);
    app.send(b"\r");
    app.expect(&["Request details", "[verified]", "x Export request"]);
    app.send(b"x");
    app.expect(&["Save certificate request to:"]);
    app.send(b"\x15"); // Ctrl+U clears the suggested absolute path.
    app.send(b"q.csr\r");
    app.expect(&["Saved certificate request to"]);
    let saved = fs::read_to_string(directory.join("q.csr")).unwrap();
    assert!(saved.starts_with("-----BEGIN CERTIFICATE REQUEST-----\n"));
    assert_eq!(pem_der(&saved), pem_der(&request));
    app.send(b"q");
    app.assert_restored();
}

#[test]
fn base64_round_trips() {
    for data in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
        assert_eq!(base64_decode(&base64_encode(data)), data);
    }
    assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    assert_eq!(base64_encode(b"fo"), "Zm8=");
}
