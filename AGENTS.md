# Agent and contributor guide

keystore-tui is a Rust and Ratatui TUI for inspecting and editing keystores
and inspecting certificates and certificate signing requests.

## Conventions and constraints

- **Scope:** keep changes focused on the small TUI. Add modules as
  responsibilities grow rather than enlarging existing ones.
- **Self-contained:** opening keystores must work without Java or `keytool`.
- **Dependencies:** keep dependencies and their enabled features to a minimum.
  Check that a new dependency is really needed before adding it.
- **Terminal safety:** keep terminal restoration working on initialization
  failure, on errors, and on normal exit. Keep every documented quit shortcut.
- **Secrets:** use generated fixtures only. Keep passwords, private keys, and
  real keystores out of logs, test output, and commits. Wipe password buffers
  after use; the password of an open, editable keystore is kept for saving
  and wiped when the keystore is closed.
- **Writes:** the app changes a keystore file only on an explicit save, and
  replaces it atomically. Exports and "save as" only ever create new files.
  Private and secret keys are decrypted or generated only in memory, only where the
  [SPEC](docs/SPEC.md) says so, and are wiped after use; they are never
  displayed or logged, and are written unencrypted only by an export the user
  confirms. Change this only by implementing a
  [ROADMAP](docs/ROADMAP.md) feature, following the write rules listed there.

## Development

After any code or dependency change, run:

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo llvm-cov --locked --summary-only
```

The coverage check needs [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov)
and the `llvm-tools-preview` rustup component; the keystore-tui cloud
environment installs both. Compare against `main` to tell new uncovered code
from code that only moved.

On Linux, macOS, or WSL, `cargo test` also runs the PTY smoke tests in
`tests/terminal_smoke/` against the built binary. To test another build, run:

```sh
KEYSTORE_TUI_BINARY=/absolute/path/to/keystore-tui cargo test --locked --test terminal_smoke
```

Give each smoke test a `SPEC:` doc line linking the [SPEC](docs/SPEC.md)
sections it checks; `spec.rs` fails on a missing link or a renamed heading. For TUI
changes, also check rendering, input, and terminal restoration by hand in an
interactive terminal.

See the [CI workflow](.github/workflows/rust.yml), [Dependabot configuration](.github/dependabot.yml), and [auto-merge workflow](.github/workflows/dependabot-auto-merge.yml).
When changing `rust-version` in `Cargo.toml`, update the toolchain in the CI workflow's `msrv` job.

Use the environment's default temporary directory. If a sandbox cannot write
there, create `target/tmp` and set `TMPDIR="$PWD/target/tmp"` for the affected
command only (set `TMP` and `TEMP` on Windows). Keep this override local to the
environment rather than committing Cargo configuration.

Fixture regeneration tools are not build, test, or runtime dependencies. Before changing
fixtures, read [their generation instructions](tests/fixtures/README.md).
Tests needing private-key entries use synthetic bytes at runtime; never commit private keys.

## Documentation

- Read [ARCHITECTURE](docs/ARCHITECTURE.md) when locating responsibilities or
  changing module boundaries; update it when modules or dependencies change.
- Update [README](README.md) when the overview, installation, quick start, or limitations change.
- Update [REFERENCE](docs/REFERENCE.md) when user-visible behaviour changes,
  including usage and key bindings.
- Read the relevant [SPEC](docs/SPEC.md) contracts before changing behaviour;
  update them with every behaviour change.
- Read [ROADMAP](docs/ROADMAP.md) before adding a write feature; update it when
  plans change or a planned feature ships.
- Add user-visible changes under the next version's heading in
  [CHANGELOG](CHANGELOG.md); its version section becomes the release notes.
- Read [RELEASING](docs/RELEASING.md) before version bumps or release-workflow
  changes; update it when release procedures change.
- Update this file when development checks, conventions, or workflows change.

## Workflow

Keep Git credentials out of the workspace. If a remote operation requires
unavailable credentials, report the limitation.

**Ship** means complete the development workflow below without further confirmation.
Shipping includes no version bump or release tag. Keep any existing version bump
out of the shipping PR without discarding the user's work.

1. Run the applicable [development checks](#development) and fix failures.
2. Create a feature branch and commit the completed changes there, never directly to `main`.
3. Publish the branch and open a PR against `main`.
4. Wait for all required checks to pass, then merge. Fix failures and rerun
   checks, or report what remains blocked.
5. Synchronize local `main` with the merged result and switch to it; delete the
   remote and local feature branches. Preserve unrelated local work.
6. Report the PR link, what changed, check results, and any unresolved failures.

**Release** means only a version bump and required lockfile/changelog bookkeeping,
with no feature changes, fixes, or unrelated edits. Follow [RELEASING](docs/RELEASING.md).
Ship changes first, then release separately: merging a version bump automatically
triggers tagging and release publication.
