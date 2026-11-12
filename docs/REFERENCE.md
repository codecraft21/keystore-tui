# Usage reference

[Back to the README](../README.md) for an overview and installation instructions.

## Contents

- [Opening a file from the command line](#opening-a-file-from-the-command-line)
- [Opening a file with the browser](#opening-a-file-with-the-browser)
- [Entry list](#entry-list)
- [Editing and saving](#editing-and-saving)
- [Entry details](#entry-details)
- [Offline chain diagnostics](#offline-chain-diagnostics)
- [ASN.1 and PEM views](#asn1-and-pem-views)
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
without a password. A file holding a single certificate or request opens
directly in the detail screen, both from the command line and from the file
browser; press `Esc` to return to the entry list. Files with several entries
open on the entry list. Keystores always open on the entry list, even with a
single entry.

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
`jssecacerts` also appear without a file extension. The first directory or
file is selected when a directory opens.

Type the start of a name to list only the entries that begin with it, ignoring
case. `../` is hidden while you filter, and each directory you enter starts
without a filter. Every letter, including `j`, `k`, and `q`, is typed into the
filter.

| Key | Action in the file browser |
| --- | --- |
| Characters | Add to the name filter |
| `Backspace` | Delete the last filter character |
| `Up` / `Down` | Move the selection, wrapping at either end (including `../`) |
| `Home` / `End` | Jump to the first / last entry |
| `Enter` | Enter a directory or select a file |
| `Right` | Enter the selected directory |
| `Left` or `Enter` on `../` | Go to the parent directory |
| `Esc` | Clear the filter; with no filter, cancel and keep the previous selection |

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

Entries sharing an alias remain separate rows, including PKCS12 trusted
certificates whose names match another certificate or key.

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
| `n` | Create a new, empty JKS, JCEKS, or PKCS12 keystore |
| `i` | Import a trusted certificate, a key pair, or another keystore's entries from a file |
| `e` | Export the selected private key, alone or with its certificates |
| `r` | Rename the selected entry |
| `d` / `Delete` | Delete the selected entry |
| `w` | Save the changes to the opened file |
| `W` | Save the keystore to a new file, converting it when the name asks for another format |
| `p` | Change the keystore password |
| `P` | Change the selected private key's own password (JKS and JCEKS) |

Press `/` to filter by part of the alias or the certificate subject (such as
`CN=example`), ignoring case. The list updates as you type, and every letter,
including `q` and `s`, goes into the filter. `Backspace` deletes a character,
`Enter` keeps the filter, and `Esc` clears it. To clear an applied filter, press
`/` and then `Esc`.

Press `s` to sort by expiry date, soonest first, and again to return to alias
order.

## Editing and saving

JKS, JCEKS, and PKCS12 keystores can be changed; certificate files cannot,
and neither can a PKCS12 keystore whose entry list is incomplete. Every change appears in the list at once and puts `[modified]`
next to the app name, but nothing changes on disk until you save.

- **Delete:** press `d` or `Delete` on an entry, then `y` to confirm; any other
  key cancels. In PKCS12, a private key goes with its certificate and the
  chain certificates no other entry uses.
- **Rename:** press `r` on an entry, edit its alias, and press `Enter`.
- **Import a trusted certificate:** press `i`, choose a file holding one
  certificate (PEM, DER, or PKCS#7) in the browser, then confirm or edit the
  suggested alias and press `Enter`.
- **Import a key pair:** press `i` and choose the file holding the private
  key: a PEM file (PKCS #8, plain or encrypted, or OpenSSL's `RSA PRIVATE KEY`
  and `EC PRIVATE KEY`) or a DER PKCS #8 file. Type the file's password if it
  is encrypted. If the file has no
  certificate, choose the certificate file next. Then confirm or edit the
  alias. The key must match one of the certificates; it is stored under the
  keystore's password. Keys encrypted in OpenSSL's old PEM format are not
  read; convert them first with `openssl pkcs8 -topk8`.
- **Copy entries from another keystore:** press `i`, choose a JKS, JCEKS, or
  PKCS12 keystore, and type its password. In the list, press `Space` to choose
  entries or `a` for all, then `Enter`. Several entries keep their aliases,
  and those whose alias already exists are skipped; a single entry lets you
  edit its alias. Private keys are stored under the open keystore's password.
  Secret keys and keys with a password of their own are not copied.
- **Export a private key:** press `e` on a private key, edit the file name,
  and type a password twice. A `.p12` or `.pfx` name writes a PKCS12 keystore
  with the key and its certificates, a `.pem` name the key followed by its
  certificates, a `.key` name the key alone as PEM, and a `.p8` or `.der`
  name the key alone as DER. The key is encrypted with the password. With an
  empty password (not for PKCS12) the key is written unencrypted, after you
  confirm with `y`. Existing files are never replaced.
- **Change the password:** press `p`, then type the new password twice. In JKS
  and JCEKS only the keystore's own password changes; private-key and
  secret-key entries keep the passwords they were protected with, as with
  `keytool -storepasswd`. In PKCS12, the private and secret keys are re-encrypted
  with the new password too, as Java expects; if a key is protected by another
  password, nothing is changed.
- **Change a key password:** in JKS and JCEKS, press `P` on a private key. If
  the key has a password other than the keystore's, type it first; then type
  the new password twice. JCEKS key passwords must be printable ASCII. PKCS12
  keys always share the keystore's password.

To create a keystore, press `n`, edit the suggested file name, and type its
password twice. A `.jceks` name creates a JCEKS keystore, a `.p12` or `.pfx`
name a PKCS12 keystore, which needs a password, and any other name a JKS
keystore. The empty keystore is written at once and opened, ready for
importing certificates.

In an alias prompt every key, including `q`, is typed into the alias;
`Backspace` deletes a character, `Ctrl+U` clears it, and `Esc` cancels. Aliases
are stored in lower case, as Java does, and an alias another entry already has
is refused.

Press `w` to save the changes to the opened file. The file is replaced in one
step, so it holds either the old or the new content, never a partial one. The
other entries are written exactly as they were read: private and secret keys
stay encrypted, and the keystore keeps its format and password. A PKCS12
keystore is saved with AES-256 and HMAC-SHA256, whatever it used before, which
Java 8u301, 11.0.12, and later, and OpenSSL 1.1 and later, read; one without a
password stays without one.

Press `W` to save the keystore under a new name, then edit the suggested name
and press `Enter`. The prompt works like the [export
prompt](#exporting-certificates): existing files are never replaced, and `Esc`
cancels. The new file becomes the opened one.

To convert a keystore to another format, give the new name that format's
extension: `.jks`, `.jceks`, or `.p12` (or `.pfx`). The converted keystore has
the same password, for the keystore and for every private key in it, and the
original file is left as it was. A key with a password of its own must first be
given the keystore's password with `P`. Secret keys cannot be converted yet.

With unsaved changes, `q`, `Esc`, `o`, and `n` ask before discarding them; press `y`
to go on. `Ctrl+C` quits at once and discards them.

The keystore password stays in memory while the keystore is open, because
saving needs it, and is wiped when the keystore is closed.

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
| `d` | Toggle whole-chain diagnostics / certificate details |
| `a` | Toggle the selected certificate's ASN.1 structure / details |
| `p` | Toggle the selected certificate's PEM encoding / details |
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

## ASN.1 and PEM views

Press `a` in the detail view to show the DER structure of the selected
certificate, or of a certificate request, in the bottom pane. Press `p` to show
it in PEM instead. Press the same key again to return to the details. The pane
takes keyboard focus; press `Tab` to focus the hierarchy and select another
certificate.

Each line of the ASN.1 view starts with the element's byte offset and is
indented by depth. OIDs are named when known, strings and times are decoded,
and wrapped DER inside OCTET and BIT STRINGs, such as extension values and
public keys, is listed as nested elements. Other values are shown in hex, and
bytes that cannot be decoded are reported with the reason.

A certificate request's challenge password is never shown, not even in these
views. When a request holds one, or has bytes that cannot be decoded, the ASN.1
view leaves them out with a note, and the PEM view is not shown; press `x` to
export the request instead.

## Certificate requests

A certificate request opens in the same view. The top pane shows the request
instead of a hierarchy, and the details show its version, subject, public key,
signature algorithm, fingerprint, requested extensions (decoded like a
certificate's), and any other attributes. A challenge password is reported as
present but never shown. The signature is checked with the request's own public
key: `[verified]` means the request is intact and was signed with the matching
private key. Short keys are flagged as weak; the request's signature hash is not,
because it does not carry into the issued certificate. The details pane has
focus, so `Up` / `Down` scroll it, and `x` exports the request. `a` and `p`
show the request's [ASN.1 structure and PEM encoding](#asn1-and-pem-views).

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
| `q` | The entry list (when not typing a filter, alias, or file name) or detail view (when not typing an export name); asks first with unsaved changes |
| `Esc` | The entry list, when not typing a filter, alias, or file name; asks first with unsaved changes |
| `Ctrl+C` | Any view, including the file browser, the password prompt, and while typing a filter or file name; discards unsaved changes without asking |

The terminal is restored when the app exits.
