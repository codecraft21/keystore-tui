# Agent and contributor guide

keystore-tui is a read-only Rust and Ratatui TUI for inspecting keystores,
certificates, and certificate signing requests.

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
  after use.
- **Read-only:** the app never writes keystores and never decrypts private keys.
  Certificate exports only ever create new files.

## Development

After any code or dependency change, run:

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

On Linux, macOS, or WSL, also run the PTY smoke tests (Python 3, standard library only):

```sh
cargo build --locked
python3 tests/terminal_smoke.py
```

Use `--binary /absolute/path/to/keystore-tui` to test another build. The
script's docstring lists what the smoke tests cover; keep it current when
adding or changing them. For TUI
changes, also check rendering, input, and terminal restoration by hand in an
interactive terminal. CI (`.github/workflows/rust.yml`) runs these automated
checks on Linux for pushes to `main` and PRs; release CI also runs `dist plan` on PRs.

Cargo sets `TMPDIR` to the repository root (`.cargo/config.toml`). Fixture
regeneration tools are not build, test, or runtime dependencies. Before changing
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
- Add user-visible changes under the next version's heading in
  [CHANGELOG](CHANGELOG.md); its version section becomes the release notes.
- Read [RELEASING](docs/RELEASING.md) before version bumps or release-workflow
  changes; update it when release procedures change.
- Update this file when development checks, conventions, or workflows change.

## Workflow

Use the coding agent's configured GitHub integration for authenticated remote
operations; keep Git credentials out of the workspace. Local Git may be used
for inspection, branching, commits, checkouts, and cleanup. Synchronize through
the integration or credential-free access. If an operation is unsupported,
report the limitation instead of adding workspace credentials.

**Ship** means complete the development workflow below without further confirmation.
Shipping includes no version bump or release tag. Keep any existing version bump
out of the shipping PR without discarding the user's work.

1. Run the applicable [development checks](#development) and fix failures.
2. Create a feature branch and commit the completed changes there, never directly to `main`.
3. Use the GitHub integration to publish the branch and open a PR against `main`.
4. Wait for all required checks to pass, then merge. Fix failures and rerun
   checks, or report what remains blocked.
5. Synchronize local `main` with the merged result and switch to it; delete the
   remote and local feature branches. Preserve unrelated local work.
6. Report the PR link, what changed, check results, and any unresolved failures.

**Release** means only a version bump and required lockfile/changelog bookkeeping,
with no feature changes, fixes, or unrelated edits. Follow [RELEASING](docs/RELEASING.md).
Ship changes first, then release separately: merging a version bump automatically
triggers tagging and release publication.
