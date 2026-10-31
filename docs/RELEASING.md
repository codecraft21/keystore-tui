# Releasing

When the user says **release**, change only the version and required release
bookkeeping: `Cargo.toml`, the corresponding `Cargo.lock` update, and the
version heading for existing `CHANGELOG.md` entries. Ship feature changes,
fixes, refactoring, and other edits separately first; exclude unrelated local
changes without discarding them. Use the configured GitHub integration and
local Git permissions described in [AGENTS.md](../AGENTS.md#workflow).

Read this guide before bumping a version or changing release workflows.
Release-workflow changes themselves belong in a shipping PR, not a release PR.

Releases are built by `.github/workflows/release.yml`, which
[`dist`](https://github.com/axodotdev/cargo-dist) generates from
`dist-workspace.toml`. Pushing a version tag such as `v1.2.0` builds static
Linux (x86_64 and ARM64, musl), macOS (x86_64 and ARM64), and Windows (x86_64)
binaries. It then pushes the Homebrew formula to `codecraft21/homebrew-tap`,
publishes the crate to crates.io, and creates a GitHub release with the
archives, SHA-256 checksums, build provenance attestations, and shell and
PowerShell installers.

1. From current `main`, create a release branch. In a release-only pull request,
   bump `version` in `Cargo.toml` (run `cargo build`, not `--locked`, to update
   `Cargo.lock`), and move existing changelog entries into a `## <version>`
   section of `CHANGELOG.md`.
2. Run the [development checks](../AGENTS.md#development), wait for all required
   PR checks to pass, and merge. Synchronize local `main`, switch to it, and
   delete the remote and local release branches, preserving unrelated local work.
   On merge, `tag-release.yml` tags the merge commit with
   `v<version>`, which starts the release. It does nothing when that tag
   already exists. To tag by hand instead, push `v<version>`; the tag must
   match the `Cargo.toml` version, or `dist` finds nothing to release.
3. Check that the release workflow passed and that the release lists every
   archive.

To rehearse, release a pre-release version such as `1.2.0-rc.1` the same way:
bump `Cargo.toml` to it, and `v1.2.0-rc.1` is tagged on merge. Pre-releases
skip the Homebrew and crates.io jobs.

`publish-crates.yml` publishes with crates.io
[Trusted Publishing](https://crates.io/docs/trusted-publishing), so no
crates.io token is stored. crates.io trusts `release.yml` in this repository
(the calling workflow, not `publish-crates.yml`). The job skips a version that
is already on crates.io. The first version, 1.0.0, is published by hand,
because crates.io requires a crate's first version to be published with an API
token.

Don't edit `release.yml` by hand. Change `dist-workspace.toml` and run
`dist generate`, using the `cargo-dist-version` it pins. `dist` is only needed
for this; it is not a build or test dependency.

The workflows need two repository secrets:

- `HOMEBREW_TAP_TOKEN`: a token that can push to `codecraft21/homebrew-tap`.
- `RELEASE_TAG_TOKEN`: a fine-grained token for this repository with Contents
  read and write access, used by `tag-release.yml`. Tags created with the
  built-in `GITHUB_TOKEN` don't start other workflows, so `release.yml` would
  not run.
