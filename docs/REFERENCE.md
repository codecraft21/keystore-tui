# Usage reference

[Back to the README](../README.md) for an overview and installation instructions.

## Contents

- [Opening a file from the command line](#opening-a-file-from-the-command-line)
- [Opening a file with the browser](#opening-a-file-with-the-browser)
- [Entry list](#entry-list)
- [Entry details](#entry-details)
- [Offline chain diagnostics](#offline-chain-diagnostics)
- [Certificate requests](#certificate-requests)
- [Exporting certificates](#exporting-certificates)
- [Quitting](#quitting)

## Opening a file from the command line

Pass a keystore or certificate file path when starting the app:

```sh
keystore-tui "path/to/store.jks"
keystore-tui "path/to/certificate.pem"
# From the repository:
cargo run --locked -- "path/to/store.jks"
```

The path can be relative or absolute; quote it if it contains spaces. JKS,
JCEKS, and PKCS12 keystores are supported. Empty-password stores and unencrypted
PKCS12 stores without an integrity MAC open immediately. PKCS12 stores with
no MAC can still require a password to decrypt their contents; no integrity
verification is available for these stores. Otherwise, enter the password at
the hidden terminal prompt.
There is one attempt: an incorrect password exits with code 1. `Esc`, `Ctrl+C`,
or `Ctrl+D` cancels and exits non-zero.

Standalone certificates (PEM, DER, or PKCS#7) and certificate requests open
directly in the detail screen without a password. For files with multiple
entries, the first entry is shown. Press `Esc` to return to the entry list.

If the path is missing, unreadable, or not a supported file, the app opens
normally with a yellow message at the bottom. Use the file browser to open
another file, including a standalone certificate or certificate request.
Without a path, the app starts with no file selected. Extra arguments print
usage and exit with code 2. `keystore-tui --version` (`-V`) prints the version
and `keystore-tui --help` (`-h`) prints usage; both exit without starting the
app.

## Opening a file with the browser

Press `o` (or `Ctrl+O`) to open the file browser. It starts in the working
directory, or in the current file's directory when you open another file. It
shows directories first, then keystores (`.jks`, `.jceks`, `.p12`, `.pfx`),
certificate files (`.pem`, `.crt`, `.cer`, `.der`, `.p7b`, `.p7c`), and
certificate requests (`.csr`, `.p10`). Java truststores named `cacerts` or
`jssecacerts` also appear without a file extension.

| Key | Action in the file browser |
| --- | --- |
| `Up` / `Down` or `k` / `j` | Move the selection, wrapping at either end (including `../`) |
| `Home` / `End` | Jump to the first / last entry |
| `Enter` | Enter a directory or select a file |
| `Right` | Enter the selected directory |
| `Left` / `Backspace` or `Enter` on `../` | Go to the parent directory |
| `Esc` | Cancel and keep the previous selection |

After you select a file, type the keystore password and press `Enter`. Input is
masked, `Backspace` deletes a character, and `Esc` cancels. A keystore with an
empty password opens without asking. If the file is invalid, unreadable, or the
password is wrong, an error appears in red. Cancelling the browser or the
password prompt keeps the keystore that was already open. The path of the file
being opened is shown below the prompt, and the path of the open file stays
visible below the entry list and the detail view.

A certificate file opens without a password. Each certificate in it, in PEM,
DER, or PKCS#7 form, is listed as a `Certificate` entry in file order, named by
its subject common name. Its hierarchy is built from the other certificates in
the same file. Certificate signing requests (PKCS#10), in PEM or DER, open the
same way and are listed as `Certificate request` entries. Private keys and
other PEM blocks are not read; a yellow warning says when some were present.

## Entry list

The main view lists the keystore's entries, sorted by alias. The status bar
shows the path of the open keystore, and the table's bottom border shows the
entry count, any filter, and the sort order.

| Column | Shows |
| --- | --- |
| Alias | The entry alias |
| Type | Private key, Trusted certificate, Secret key, Certificate, or Certificate request |
| Algorithm | The certificate's public key algorithm (RSA, EC, DSA, Ed25519, ...) |
| Key size | The key size in bits (RSA/DSA modulus, EC curve size) |
| Expires | The certificate's expiry date (UTC): yellow within 30 days of expiry, red once it has passed; `-` for a request |
| Crypto | `Weak`, in yellow, when the certificate's key is too short or its signature uses a broken hash |

| Key | Action in the entry list |
| --- | --- |
| `Up` / `Down` or `k` / `j` | Move the selection, wrapping at either end |
| `Enter` | Inspect the selected entry |
| `/` | Type a filter, or edit the applied one |
| `s` | Switch the sort order between alias and expiry date |
| `o` | Open another keystore or certificate file |

Press `/` to filter by part of the alias or the certificate subject (such as
`CN=example`), ignoring case. The list updates as you type, and every letter,
including `q` and `s`, goes into the filter. `Backspace` deletes a character,
`Enter` keeps the filter, and `Esc` clears it. To clear an applied filter, press
`/` and then `Esc`.

Press `s` to sort by expiry date, soonest first, and again to return to alias
order.

## Entry details

Pressing `Enter` on an entry opens a full-screen, read-only view. The top pane
shows the certificate hierarchy, with the entry's own certificate selected. The
bottom pane shows the selected certificate's fields: version, subject, issuer,
serial number, validity, public key, signature algorithm, SHA-256 or SHA-1
fingerprint, and extensions. Common extensions such as Subject Alternative Name,
Key Usage, Extended Key Usage, and Basic Constraints are decoded; others are
shown as their OID and value in hex.

Weak keys and signatures are explained in yellow below the signature algorithm,
and weak certificates are marked `[weak]` in the hierarchy. A self-signed
certificate's own signature is not flagged, because a root is trusted for where
it is stored rather than for its signature.

Each certificate's signature is checked offline with the public key of the
certificate above it in the hierarchy, or with its own key for a self-signed
root. The hierarchy marks each certificate `[verified]` in green, `[bad
signature]` in red, or `[unchecked]` when the issuer is not stored or the
algorithm is not supported, such as brainpool or secp256k1 keys. The details
explain the result below the signature algorithm.

| Key | Action in the detail view |
| --- | --- |
| `Tab` / `Shift+Tab` | Switch focus between hierarchy and details |
| `Up` / `Down` or `k` / `j` | Select a certificate or scroll the focused details |
| `PageUp` / `PageDown`, `Home` / `End` | Scroll details by a page or to the start / end |
| `d` | Toggle certificate details / whole-chain diagnostics |
| `f` | Toggle SHA-256 / SHA-1 fingerprints; kept while switching certificates |
| `x` | Export the selected certificate, or the certificate request |
| `X` | Export the entry's whole chain, leaf first |
| `Esc` | Return to the entry list, preserving its selection and scroll position |
| `q` / `Ctrl+C` | Quit |

The hierarchy only shows certificates stored in the keystore. It does not fetch
missing issuers or check whether a certificate is trusted: a verified signature
only means the stored issuer's key made it, not that the chain is valid.

## Offline chain diagnostics

Press `d` in a certificate detail view to show the whole stored chain, leaf
first, in the bottom pane. Press `d` again to return to the selected certificate.
The pane takes keyboard focus; use arrows, `PageUp` / `PageDown`, or `Home` /
`End` to scroll. `Esc` returns to the entry list, as usual.

Each certificate has separate green `PASS`, red `PROBLEM`, and yellow `UNKNOWN`
results for its validity period and signature. Adjacent certificates are checked
for issuer-name and AKI/SKI agreement. Certificates acting as issuers are checked
for CA Basic Constraints, certificate-signing Key Usage when present, and path
length limits (excluding the target and self-issued intermediates). Missing,
malformed, duplicate, or unsupported data is reported explicitly. Existing chain
construction warnings are included.

These are diagnostics of the stored path, not full certificate validation.
Trust and revocation remain unchecked. No issuers are downloaded and no system
trust store is used. Name constraints, certificate policies, intended purpose,
hostnames, and authority issuer/serial matching are not evaluated by this view.
A passing check does not establish that a certificate is trusted or usable.

## Certificate requests

A certificate request opens in the same view. The top pane shows the request
instead of a hierarchy, and the details show its version, subject, public key,
signature algorithm, fingerprint, requested extensions (decoded like a
certificate's), and any other attributes. A challenge password is reported as
present but never shown. The signature is checked with the request's own public
key: `[verified]` means the request is intact and was signed with the matching
private key. Short keys are flagged as weak; the request's signature hash is not,
because it does not carry into the issued certificate. The details pane has
focus, so `Up` / `Down` scroll it, and `x` exports the request.

## Exporting certificates

Press `x` or `X` in the detail view, then edit the suggested file name and press
`Enter`. The suggestion is `<alias>.pem` (or `<alias>-chain.pem`) next to the
open file, or `<alias>.csr` for a certificate request. A name ending in `.der`
saves a single certificate or the request as DER; any other name saves PEM. Relative names are saved next to the open file. Every key,
including `q`, is typed into the name; `Backspace` deletes a character,
`Ctrl+U` clears the name, and `Esc` cancels. Existing files are never replaced:
the save fails with a red message and you can choose another name.

## Quitting

| Key | Quits from |
| --- | --- |
| `q` | The file browser, entry list (when not typing a filter), or detail view (when not typing an export name) |
| `Esc` | The entry list, when not typing a filter |
| `Ctrl+C` | Any view, including the password prompt and while typing a filter or export name |

The terminal is restored when the app exits.
