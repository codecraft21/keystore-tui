//! The app under test, running in a Unix PTY.

use std::ffi::{CString, OsStr};
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::{Mode, OFlags, fcntl_getfl, fcntl_setfl, open};
use rustix::io::{Errno, FdFlags, fcntl_setfd, read, write};
use rustix::process::{ioctl_tiocsctty, setsid};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{Winsize, tcgetattr, tcsetwinsize};

use crate::screen::{self, contains, rfind};

const TIMEOUT: Duration = Duration::from_secs(5);

/// The binary under test: `KEYSTORE_TUI_BINARY`, or the one Cargo built.
pub fn binary() -> PathBuf {
    let binary = std::env::var_os("KEYSTORE_TUI_BINARY").map_or_else(
        || PathBuf::from(env!("CARGO_BIN_EXE_keystore-tui")),
        PathBuf::from,
    );
    assert!(binary.is_file(), "no TUI binary at {}", binary.display());
    binary
}

/// Own the child and PTY, retaining the slave's name to inspect restored modes.
pub struct PtyApp {
    args: Vec<String>,
    master: OwnedFd,
    slave: OwnedFd,
    slave_name: CString,
    /// The terminal's width and height.
    size: (u16, u16),
    child: Child,
    output: Vec<u8>,
    original_modes: String,
}

impl PtyApp {
    pub fn spawn(directory: &Path, args: &[&OsStr]) -> Self {
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
        fcntl_setfd(&master, FdFlags::CLOEXEC).unwrap();
        // Reads and writes must never block: see `read`.
        fcntl_setfl(&master, fcntl_getfl(&master).unwrap() | OFlags::NONBLOCK).unwrap();
        grantpt(&master).unwrap();
        unlockpt(&master).unwrap();
        let name = ptsname(&master, Vec::new()).unwrap();
        let slave = open_slave(&name);
        set_size(&slave, 100, 30);
        let original_modes = modes(&name);

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
            slave_name: name,
            size: (100, 30),
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
    pub fn resize(&mut self, width: u16, height: u16) {
        let start = self.output.len();
        set_size(&self.slave, width, height);
        self.size = (width, height);
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
    ///
    /// The master is non-blocking, so a read never waits longer than
    /// `timeout`: on macOS, a blocking read after `poll` reported the master
    /// ready could wait forever for output the app wasn't going to write.
    /// macOS's poll(2) documents that it doesn't support devices; when it
    /// reports `POLLNVAL`, sleep briefly between reads instead.
    pub fn read(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut buffer = [0; 65536];
        loop {
            match read(&self.master, &mut buffer) {
                Ok(count) => {
                    self.output.extend_from_slice(&buffer[..count]);
                    return count > 0;
                }
                Err(Errno::AGAIN | Errno::INTR) => {}
                Err(Errno::IO) => return false, // The child may have closed its terminal.
                Err(error) => panic!("read failed: {error}"),
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            self.wait_readable(remaining);
        }
    }

    /// Wait up to `timeout` for output, or less if `poll` can't wait.
    fn wait_readable(&self, timeout: Duration) {
        let timespec = Timespec {
            tv_sec: timeout.as_secs() as _,
            tv_nsec: timeout.subsec_nanos() as _,
        };
        let mut fds = [PollFd::new(&self.master, PollFlags::IN)];
        match poll(&mut fds, Some(&timespec)) {
            Ok(0) | Err(Errno::INTR) => {}
            Ok(_) if fds[0].revents().contains(PollFlags::NVAL) => {
                thread::sleep(timeout.min(Duration::from_millis(10)));
            }
            Ok(_) => {}
            Err(error) => panic!("poll failed: {error}"),
        }
    }

    /// Write keys to the app, reading its output while the PTY is full.
    pub fn send(&mut self, keys: &[u8]) {
        let deadline = Instant::now() + TIMEOUT;
        let mut keys = keys;
        while !keys.is_empty() {
            match write(&self.master, keys) {
                Ok(count) => keys = &keys[count..],
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => {
                    assert!(
                        Instant::now() < deadline,
                        "TUI {:?} did not accept input\n{}",
                        self.args,
                        self.screen()
                    );
                    self.read(Duration::from_millis(10));
                }
                Err(error) => panic!("write failed: {error}"),
            }
        }
    }

    pub fn exited(&mut self) -> Option<i32> {
        self.child
            .try_wait()
            .unwrap()
            .map(|status| status.code().unwrap_or(-1))
    }

    /// Wait for the child to exit and return its exit code, reading its output
    /// so that it never blocks writing to a full PTY.
    pub fn wait(&mut self) -> i32 {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(code) = self.exited() {
                return code;
            }
            if Instant::now() >= deadline {
                panic!("TUI {:?} did not exit\n{}", self.args, self.screen());
            }
            self.read(Duration::from_millis(10));
        }
    }

    /// Everything the app has written so far.
    pub fn output(&self) -> &[u8] {
        &self.output
    }

    /// The screen as last drawn; see [`screen::render`].
    pub fn screen(&self) -> String {
        screen::render(&self.output, self.size)
    }

    pub fn expect(&mut self, fragments: &[&str]) {
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

    pub fn assert_modes_restored(&self) {
        assert_eq!(
            modes(&self.slave_name),
            self.original_modes,
            "TUI {:?}",
            self.args
        );
    }

    pub fn assert_restored(&mut self) {
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

    /// Open a file through the picker: it selects the first file or folder.
    pub fn open_from_picker(&mut self, name: &str) {
        self.expect(&["No keystore selected"]);
        self.send(b"o");
        self.expect(&[name]);
        self.send(b"\r");
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

fn set_size(slave: &OwnedFd, width: u16, height: u16) {
    let size = Winsize {
        ws_row: height,
        ws_col: width,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    tcsetwinsize(slave, size).unwrap();
}

fn open_slave(name: &CString) -> OwnedFd {
    open(
        name.as_c_str(),
        OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap()
}

/// The terminal modes, read through a newly opened slave: when the app, the
/// session leader, exits, macOS revokes its controlling terminal, so the
/// harness's earlier slave descriptor no longer accepts terminal calls.
fn modes(name: &CString) -> String {
    format!("{:?}", tcgetattr(open_slave(name)).unwrap())
}
