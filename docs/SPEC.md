# keystore-tui behaviour specification

This document is the reference for how keystore-tui behaves. The key bindings
are listed in [`REFERENCE.md`](REFERENCE.md). When behaviour changes, update this
document and the usage reference, and also the README if its overview changes.

## Contents

- [Scope](#scope)
- [Command-line startup](#command-line-startup)
- [File selection](#file-selection)
- [Loading and validation](#loading-and-validation)
  - [JKS compatibility (matching Java)](#jks-compatibility-matching-java)
  - [JCEKS compatibility](#jceks-compatibility)
  - [PKCS12 compatibility](#pkcs12-compatibility)
  - [Certificate files](#certificate-files)
- [Password prompt](#password-prompt)
- [Entry list](#entry-list)
  - [Filtering](#filtering)
  - [Sorting](#sorting)
  - [Deleting entries](#deleting-entries)
  - [Renaming entries](#renaming-entries)
  - [Importing certificates](#importing-certificates)
  - [Changing the password](#changing-the-password)
- [Creating a keystore](#creating-a-keystore)
- [Saving](#saving)
  - [Writing PKCS12 keystores](#writing-pkcs12-keystores)
- [Entry details](#entry-details)
  - [Certificate requests](#certificate-requests)
  - [Weak cryptography](#weak-cryptography)
  - [Extensions](#extensions)
  - [Certificate hierarchy](#certificate-hierarchy)
  - [Exporting](#exporting)
  - [Small terminals](#small-terminals)
- [Visual style](#visual-style)
- [Quitting and terminal restoration](#quitting-and-terminal-restoration)
- [Offline chain diagnostics](#offline-chain-diagnostics)
- [ASN.1 and PEM views](#asn1-and-pem-views)

## Scope

- The app reads Java KeyStore (JKS), JCEKS, and PKCS12 files, standalone
  certificate files, and PKCS#10 certificate requests. It changes a keystore
  file only when the user saves it; see [Saving](#saving). Certificate files
  and requests are never written or modified.
- The other files it writes are new certificate and request exports; see
  [Exporting](#exporting).
- It runs without Java or `keytool` installed.
- Private keys are never decrypted, displayed, or exported.
- The following are out of scope for now: importing anything but a trusted
  certificate, keystore editing other than [deleting](#deleting-entries) and
  [renaming](#renaming-entries) entries, and clipboard actions. The [ROADMAP](ROADMAP.md) lists the planned write
  features; each one updates this section when it ships.

## Command-line startup

Run `keystore-tui [path]` (or `cargo run --locked -- "path/to/store.jks"`).
One optional relative or absolute path is accepted; quote paths containing spaces.
Extra arguments print usage and exit with code 2. Without a path, startup is unchanged.

A single `--version` or `-V` argument prints `keystore-tui <version>` to
standard output and exits with code 0. A single `--help` or `-h` argument prints
the version, a one-line description, the usage line, and these options to
standard output and exits with code 0. Neither touches the terminal modes or
the alternate screen. A flag given together with another argument prints usage
and exits with code 2. Any other single argument is a path, so a file named
`--help` opens as `./--help`.

JKS, JCEKS, and PKCS12 files use the same format detection and size limit as the
file browser. Empty-password stores open automatically. Otherwise, a hidden
terminal password prompt appears before the TUI starts. There is one attempt:
an incorrect password or failed integrity check exits with code 1. Escape,
Ctrl+C, Ctrl+D, or an input error also exits non-zero. Password buffers are wiped
and terminal settings restored after input.

Standalone certificate files (PEM, DER, and PKCS#7) and PKCS#10 requests use
the same loader as the file browser and open without prompting for a password.
A file with exactly one certificate or request opens its detail screen
directly, as described in [Certificate files](#certificate-files). Skipped-PEM
block warnings are retained for display on the entry list.

Missing paths, directories, unreadable files, malformed files, and unsupported
files open the empty TUI with
a yellow message in the bottom status area. Structural errors discovered after
password verification behave the same way. Opening another file clears this
message; interactive errors retain their existing red styling. A normal quit
after a startup warning exits successfully. Successfully opened stores retain
any existing incomplete-entry warnings.

## File selection

- The browser starts in the working directory. If a keystore is open, it starts
  in that keystore's directory, which for a bare file name is the working
  directory.
- It lists directories, then files whose extension is `.jks`, `.jceks`, `.p12`,
  `.pfx`, `.pem`, `.crt`, `.cer`, `.der`, `.p7b`, `.p7c`, `.csr`, or `.p10`
  (case-insensitive). It also lists the Java truststore names `cacerts` and
  `jssecacerts`, case-insensitively. Directories come first.
- Paths are shown as users type them: on Windows, without the verbatim `\\?\`
  prefix (`C:\certs`, not `\\?\C:\certs`), unless a path needs it, such as
  one longer than 259 characters. This applies to the browser's directory, the
  opened file's path in the status bar, and the export prompt's suggestion.
- A `../` entry leads to the parent directory. Selection wraps at both ends, and
  `../` takes part in the wrap.
- Each directory opens with its first directory or file selected. When it has
  none, `../` is selected.
- Typing printable characters (without Ctrl or Alt) builds a name filter, shown
  below the directory path. Only entries whose name starts with the filter,
  ignoring case, are listed; `../` is hidden while the filter is non-empty.
  Selection moves and wraps within the listed entries. The selected entry stays
  selected while it is still listed; otherwise the first listed entry other than
  `../` is selected, or nothing when no entry matches. Nothing opens until
  `Enter`.
- While the browser is open, letters such as `j`, `k`, and `q` are typed into
  the filter. `Backspace` deletes the last filter character and never changes
  directory; `Left` opens the parent. `Esc` clears a non-empty filter and
  otherwise closes the browser. Each directory opened starts with no filter.
- Cancelling the browser keeps the keystore that was already loaded.

## Loading and validation

- Files larger than 64 MiB are refused.
- The format comes from the file content where it is unambiguous:
  1. The JKS magic number means JKS, and the JCEKS magic number means JCEKS.
  2. A PEM `-----BEGIN ` line means a certificate file.
  3. Otherwise a `.p12` or `.pfx` name means PKCS12, and a certificate-file
     extension means a DER certificate or PKCS#7 bundle.
  4. Other DER content is tried as a certificate file, then as PKCS12.
  5. Anything else is read as JKS, so its error describes a JKS file.
- **JKS and JCEKS:** the header, lengths, counts, and structure are checked
  before the password prompt appears.
- **PKCS12:** the outer structure is checked before the password prompt appears.
  The integrity MAC is optional, independently of content encryption.
- When an integrity MAC is present, entries are shown only after the
  password-based integrity check succeeds. An absent MAC provides no integrity
  verification.
- A keystore with an empty password opens without a prompt. For PKCS12, an
  empty password is also tried in Java's encoding as a single NUL character,
  both for the integrity MAC and, in a store without a MAC, for decrypting its
  contents. One encoding must work for the whole store.
- An invalid file, an unreadable file, or a failed integrity check produces a red
  error message in the TUI.

### JKS compatibility (matching Java)

- Data after the integrity digest is ignored.
- Private-key entries are listed whatever the length of their encrypted key.
- Only X.509 certificates are accepted.
- Unicode passwords and aliases are supported, including supplementary characters
  such as emoji.
- Java allows an alias to contain an unpaired UTF-16 surrogate. Such a surrogate
  is shown as an escape, for example `\uD83D`.

### JCEKS compatibility

- JCEKS has the JKS layout and integrity digest, and everything under
  [JKS compatibility](#jks-compatibility-matching-java) applies to it.
- It adds secret-key entries, shown as `Secret key`. Java stores each one as a
  serialized `SealedObject` without a length, so the app walks the Java
  serialization grammar to find where it ends. The sealed key is never
  decrypted or deserialized, and no class is loaded.
- A secret key that is not a `com.sun.crypto.provider.SealedObjectForKeyProtector`,
  uses serialization features Java does not write for sealed keys (enums, proxy
  classes, externalizable objects, resets, or exceptions), or nests more than 32
  levels deep (including superclass descriptors) is reported as an error.
- Secret-key entries in a JKS file are an error, as they are in Java.

### PKCS12 compatibility

- PKCS12 stores from Java, OpenSSL, and other tools are supported with either
  current AES encryption or older legacy encryption. Stores without an integrity
  MAC open without a prompt when their contents are unencrypted. Encrypted
  contents still require the decryption password. Without a MAC, a password is
  accepted only if every encrypted safe decrypts to a well-formed SafeContents
  sequence. Any other decryption failure, or decrypted contents that do not
  parse (a wrong key can pass the CBC padding check, and RC4 has no padding),
  prompts for a password or allows a retry. An encrypted safe that is
  malformed, uses an unsupported algorithm, or exceeds the iteration or salt
  limits is not a password error; it is skipped and the list is marked
  incomplete. The RC4 schemes are identified by their RFC 7292 OIDs
  (`1.2.840.113549.1.12.1.1` is 128-bit, `.2` is 40-bit), as OpenSSL
  writes them. A present MAC must verify; PBMAC1 (RFC 9579) is not supported.
- Unicode aliases are supported.
- A key without a friendly name, as OpenSSL writes when not given `-name`, is
  listed under the subject name (common name, else the full subject) of the
  certificate sharing its local key ID, else as `Private key N`.
- Certificates marked with Java's trusted-key-usage attribute are `Trusted
  certificate` entries, named by their friendly name. Every such certificate
  is listed, even if another certificate or key has the same name or a name
  differing only in case. Identical copies, with the same name and the same
  certificate, are listed once. A certificate without it
  is listed as a `Certificate` entry unless it is part of a private key's
  chain. Such an entry is named by its friendly name, else its subject name,
  else `Certificate N`.
- A verified store may still contain entries that cannot be read. In that case
  the readable entries are listed, along with a persistent warning that the list
  is incomplete.

### Certificate files

- A certificate file opens without a password prompt.
- Accepted forms:
  - PEM blocks labelled `CERTIFICATE`, `X509 CERTIFICATE`, or `TRUSTED
    CERTIFICATE` (OpenSSL's trust settings after the certificate are ignored)
  - PEM `PKCS7` or `CMS` blocks, and DER PKCS#7 SignedData; their X.509
    certificates are listed and anything else in them is ignored
  - a single DER certificate, which must be one complete DER element
  - PEM blocks labelled `CERTIFICATE REQUEST` or `NEW CERTIFICATE REQUEST`
    (as `keytool -certreq` writes), and a single DER PKCS#10 request, which
    must be one complete DER element
- Text outside PEM blocks is ignored. Other PEM blocks, such as private keys,
  are not decoded; a persistent yellow warning says some were skipped.
- A malformed PEM block, invalid Base64, or a file without any certificate or
  request is an error. A certificate inside a PEM block that cannot be decoded is still
  listed, as for keystores.
- Each certificate is one entry of type `Certificate`, and each request one
  entry of type `Certificate request`, listed in file order (the alias sort
  keeps that order). The alias is the subject common name, else the whole
  subject, else `Certificate N` or `Certificate request N` for its position in
  the file. Requests are never part of a certificate's chain.
- A file with exactly one certificate or request opens straight into its
  detail screen, whether it is opened from the command line or the file
  browser. `Esc` returns to the entry list, which then shows that one entry.
  A file with several entries opens on the entry list. Keystores always open on
  the entry list, even with a single entry.

## Password prompt

- Input is masked. `Backspace` deletes a character, `Enter` submits, and `Esc`
  cancels.
- Keys pressed with `Ctrl` or `Alt` are not typed into the password. The
  exception is Windows: it reports `AltGr` as `Ctrl+Alt`, so that combination
  types its character there.
- The password buffer is wiped after each attempt and whenever a character is
  deleted.
- Cancelling the prompt keeps the keystore that was already loaded.
- The status bar shows the path of the file being opened, not the one already
  loaded.

## Entry list

- Every entry is listed, even when several entries share an alias. Entries are
  sorted by alias by default; entries sharing an alias keep their stored order.
- Columns: Alias, Type, Algorithm, Key size, Expires, Crypto. The meaning of
  each column is in the README.
- For a private-key entry, the certificate used for the columns is the first one
  in its chain. In PKCS12, that is the certificate that shares the key's local
  key ID.
- Secret keys and unreadable certificates show `-` in the certificate columns.
- A certificate request shows its public key's algorithm and size, and `-`
  under Expires. Its Crypto column checks only the key size; see
  [Certificate requests](#certificate-requests).
- An unrecognized algorithm is shown as its OID.
- Key size means the modulus size for RSA and DSA, and the curve size for EC.
- Expiry dates are in UTC. They are yellow when the certificate expires within
  30 days and red once it has expired.
- The Crypto column shows `Weak` in yellow when the entry's certificate has a
  weakness (see [Weak cryptography](#weak-cryptography)), and is empty
  otherwise. It checks the entry's own certificate, not the rest of its chain.
- A status bar above the keyboard shortcuts shows the keystore's absolute path as
  `Path: '<path>'`, with the path in blue and the label and quotes in the
  default colour. Paths too long for the terminal width are clipped.
- The table's bottom border shows, right-aligned, the entry count and sort order,
  for example `3 entries | Sort: alias`. With a filter it shows the filter and
  how many entries match, for example `Filter: 'web' | 2 of 9 entries | Sort:
  expiry`; while the filter is being typed it is shown with a trailing `_`
  instead of quotes.
- `/` and `s` do nothing when no keystore is loaded or it has no entries.
- `Up` / `Down` or `k` / `j` move the selection through the visible entries
  in the current sort order, wrapping at either end. A single visible entry
  stays selected; an empty list keeps no selection.

### Filtering

- `/` starts typing a filter, or resumes editing the applied one.
- The filter is a case-insensitive substring match against the alias and the
  certificate subject distinguished name (for example `CN=example`). An entry
  whose subject cannot be decoded matches on its alias only.
- The list updates as the filter is typed. While typing, every character
  without `Ctrl` or `Alt` goes into the filter, including `q`, `s`, `o`, `j`,
  and `k`. `Up` / `Down` still move the selection and wrap at either end.
  `Backspace` deletes a character, `Enter` keeps the filter, and `Esc` clears it.
  `Ctrl+C` still quits.
- With the filter applied and not being typed, all list keys, including the
  quit keys, work as usual.
- When nothing matches, the list shows "No matching entries." with a hint on how
  to edit or clear the filter, and `Enter` does nothing.
- Opening another keystore clears the filter.

### Sorting

- `s` switches between alias order and expiry order.
- Expiry order puts the soonest expiry first and entries without an expiry date,
  including certificate requests, last. The sort is stable, so entries with equal dates keep their alias order.
- The sort order is kept when another keystore is opened.
- Filtering and sorting keep the same entry selected while it is still listed;
  otherwise the first listed entry is selected. The detail view always opens
  the selected entry, and returning from it restores the filtered list.

### Deleting entries

- JKS, JCEKS, and PKCS12 keystores can be changed. In the entry list of one,
  a line above the shortcuts shows `n New | i Import certificate | r Rename | d
  Delete entry | w Save | W Save as | p Password`.
- `d` or `Delete` asks, in yellow, `Delete entry '<alias>'?` for the selected
  entry. `y` deletes it; any other key cancels and does nothing else. The
  keys do nothing when no entry is selected.
- Deleting changes only the list in memory, not the file. A green message
  names the deleted entry, and the selection stays on the same row, or on the
  last row when the last one was deleted.
- While the list differs from the file, `[modified]` is shown in yellow after
  the app name. Entries sharing an alias are deleted one at a time.
- In PKCS12, deleting a private key also removes its certificate and the
  chain certificates that no other entry uses, which would otherwise be
  listed as entries of their own. Certificates another key's chain needs, and
  trusted certificates, stay.
- For a certificate file, `d`, `Delete`, `r`, `i`, `p`, `w`, and `W` show a
  red message that only keystores can be changed. A PKCS12 keystore whose
  entry list is incomplete (see [PKCS12
  compatibility](#pkcs12-compatibility)) cannot be changed either, because
  saving it would lose what was not read; the message says so. With no file
  loaded the keys do nothing.
- With unsaved changes, `o` first asks before opening the file browser, and
  `n` before asking for a new keystore's name; `y` continues and any other key
  cancels. The changes are kept until another file is loaded, so cancelling the browser or a password prompt keeps them.
- Messages about editing and saving clear on the next key.

### Renaming entries

- In a keystore, `r` opens a prompt in place of the shortcuts,
  `New alias for '<alias>':`, holding the selected entry's alias. It does
  nothing when no entry is selected.
- While the prompt is open, every character without `Ctrl` or `Alt` is typed
  into the alias, including `q`. `Backspace` deletes a character, `Ctrl+U`
  clears the alias, `Enter` confirms, and `Esc` cancels. `Ctrl+C` still quits.
- The alias is stored in lower case, as Java looks aliases up. Confirming the
  entry's own alias changes nothing.
- An empty alias, an alias another entry already has (ignoring case), or an
  alias longer than 65,535 bytes in Java's string encoding is refused with a
  red message, and the prompt stays open.
- Renaming changes only the list in memory, like deleting. The entry moves to
  its place in alias order and stays selected when the filter still shows it;
  a green message names the old and new alias. On saving, only the alias
  changes: the entry keeps its content, creation date, and place in the file.
- In PKCS12 the alias is the `friendlyName` attribute, written as a
  BMPString. A private key's name is set on its key bag and on its
  certificate's bag; an entry without a name gets one. The bags' values and
  other attributes keep their bytes.

### Importing certificates

- In a keystore, `i` opens the file browser, titled `Import
  certificate from file`, in the opened file's directory. `Esc` cancels.
- The chosen file must hold exactly one certificate, as PEM, DER, or PKCS#7.
  A file with several certificates, with none, or of another kind is refused
  with a red message, and nothing is imported.
- A prompt then asks `Alias for the imported certificate:`, suggesting the
  certificate's subject name in lower case. It follows the same rules as the
  [rename prompt](#renaming-entries).
- The certificate is added as a trusted certificate, with the current time as
  its creation date, listed in alias order and selected. A green message names
  it. On saving it is stored after the existing entries, byte for byte as it
  was in the file (PEM is decoded to its DER).
- Whether the certificate is trusted, valid, or already in the keystore under
  another alias is not checked.
- In PKCS12 the certificate is stored with Java's trusted-key-usage
  attribute, so Java lists it as a trusted certificate. It joins the
  encrypted certificates when the keystore has any; in a keystore that stores
  its certificates unencrypted, it is unencrypted too.

### Changing the password

- In a keystore, `p` opens a prompt in place of the shortcuts,
  `New keystore password:`, then `Type the password again:` after `Enter`.
  Typed characters are shown as `*`, including `q`; `Backspace` deletes one,
  `Esc` cancels at either step, and `Ctrl+C` still quits.
- If the two entries differ, a red message says so and the prompt starts over.
  An empty password is accepted for JKS and JCEKS.
- The new password replaces the one kept in memory, the old one is wiped, and
  the keystore counts as modified; a green message says the password is
  written on saving. On saving, only the integrity digest changes.
- In JKS and JCEKS, private-key and secret-key entries keep the passwords
  they were protected with, as with `keytool -storepasswd`.
- In PKCS12, keys are encrypted with the keystore's password and are never
  decrypted, so a keystore holding private or secret keys cannot change its
  password yet. Neither can a keystore that no password protects, and the new
  password cannot be empty. Each is refused with a red message after the
  password is typed, and nothing changes.

## Creating a keystore

- `n` in the entry list, with or without a file loaded, opens a prompt in
  place of the shortcuts, `New keystore file (.jks, .jceks, or .p12):`. It suggests
  `keystore.jks` in the opened file's directory, or in the working directory
  when no file is loaded, as an absolute path, numbered like `keystore-2.jks`
  when that name exists. It takes keys like the "save as" prompt; see
  [Saving](#saving).
- A `.jceks` name (case-insensitive) creates a JCEKS keystore, a `.p12` or
  `.pfx` name a PKCS12 keystore, and any other name a JKS keystore. The name
  of an existing file is refused with a red message and the prompt stays
  open.
- The password is then asked for twice, as when [changing the
  password](#changing-the-password). `Esc` cancels, and nothing is created.
- A PKCS12 keystore needs a password that is not empty; with an empty one a
  red message says so and nothing is created.
- Confirming the password writes an empty keystore, in the version Java
  writes, to the new file and opens it. A green message names it. If the file
  cannot be created, a red message explains why and the loaded file stays.

## Saving

- `w` saves the changes to the opened file; without changes it only reports
  `No changes to save.` `W` saves the keystore, changed or not, to a new file.
- The saved keystore keeps its format and password. For PKCS12, see [Writing
  PKCS12 keystores](#writing-pkcs12-keystores). A JKS or JCEKS keystore also
  keeps its version, and every remaining
  entry is written byte for byte as it was read, in its stored order, with its
  creation date; private and secret keys stay encrypted and are never
  decrypted. Only the entry count and the integrity digest are recomputed. Data
  after the digest, which Java ignores, is not kept.
- The password is kept in memory while the keystore is open, to protect the
  saved file with, and is wiped when the keystore is closed or replaced by another
  file.
- Before anything is written, the new content is read back and compared with
  the entry list; on a mismatch nothing is written.
- `w` replaces the file in one step: the content is written to a temporary
  file in the same directory, which is then renamed over the opened file. A
  symbolic link is followed and stays a link, and the file keeps its
  permissions. If anything fails, the file keeps its old content, the
  temporary file is removed, and the changes stay unsaved.
- `W` opens a prompt in place of the shortcuts, suggesting
  `<name>-copy.<extension>` next to the opened file as an absolute path,
  numbered like `store-copy-2.jks` when that name exists. It takes keys like
  the [export prompt](#exporting): characters are typed into the name,
  `Backspace` deletes one, `Ctrl+U` clears the name, `Enter` saves, `Esc`
  cancels, and a relative name is resolved against the opened file's
  directory.
- The "save as" file must not exist yet; it is never replaced. On failure a
  red message explains why and the prompt stays open. On success the new file
  becomes the opened file, so later saves go to it.
- A green message names the saved file, and `[modified]` disappears.

### Writing PKCS12 keystores

- Every bag is written byte for byte as it was read, except the bags of a
  renamed entry. Private and secret keys stay encrypted as they were and are
  never decrypted.
- Bags stay in their safes, in order. A safe that was encrypted is encrypted
  again, and one that was not stays unencrypted; a safe left without bags is
  dropped.
- Encrypted safes are written with PBES2: AES-256-CBC with a key from PBKDF2
  with HMAC-SHA256, 10,000 iterations, and a new random 20-byte salt and IV on
  every save. This replaces older encryption, such as RC2 or Triple DES.
- A keystore that had an integrity MAC gets a new one: HMAC-SHA256 with 10,000
  iterations and a new random 20-byte salt. A keystore without a MAC stays
  without one, so a passwordless Java truststore stays passwordless.
- An empty password keeps the encoding it was read with, empty or a NUL
  character.
- A new keystore has a MAC and encrypts its certificates.
- Saved keystores are read by Java 8u301, 11.0.12, and later, and by OpenSSL
  1.1 and later. Older Java 8 builds cannot read HMAC-SHA256 or PBES2
  keystores.
- If the system provides no random numbers, saving fails and nothing is
  written.

## Entry details

- The view is full-screen and read-only, and it does not change the entry list's
  state. Returning to the list keeps the list's selection and scroll position.
- As in the entry list, a status bar above the keyboard shortcuts shows the
  opened file's path as `Path: '<path>'`, whatever the bottom pane shows.
- The top pane is a selectable certificate hierarchy, starting with the leaf
  certificate selected. The bottom pane shows the fields of the selected
  certificate:
  - version
  - subject and issuer
  - serial number, in both hexadecimal and decimal
  - validity timestamps in UTC; "Valid Until" turns red once the certificate
    has expired
  - public key algorithm and size
  - signature algorithm, followed by one yellow `Weak: ...` line for each
    weakness of the certificate, then the signature check; see
    [Signature checks](#signature-checks)
  - fingerprint: SHA-256 by default, SHA-1 as an alternative. Both are computed
    over the original certificate bytes. The chosen fingerprint stays selected
    when switching certificates.
  - extensions; see [Extensions](#extensions).
- Long values wrap and can be scrolled. Switching certificates resets the detail
  scroll position.
- An entry without certificates still opens, with an explanation.
- If one certificate in a chain cannot be read, the other chain members are
  still shown.

### Certificate requests

- A certificate request entry opens in the same full-screen view. The top pane,
  titled "Certificate request", has one row: the request's subject (or
  `Certificate request (unreadable or unnamed)`), followed by `[weak]` when its
  key is short and the signature tag. The bottom pane, titled "Request
  details", has focus when the view opens, so `Up` / `Down` scroll it.
- The details show, in order:
  - alias and type
  - version (the stored value plus one, as for certificates)
  - subject
  - public key algorithm and size
  - signature algorithm, followed by a yellow `Weak: ...` line for a short key,
    then the signature check
  - fingerprint, SHA-256 or SHA-1 as for certificates, over the request's bytes
  - "Requested extensions:", from the PKCS#9 extension request attribute (or
    Microsoft's `1.3.6.1.4.1.311.2.1.14`), decoded as in
    [Extensions](#extensions); `Requested extensions: None` when there are none
  - "Attributes:", only when the request has other attributes. A challenge
    password is shown as `Present; not shown.` and its value is never
    displayed, not even in hex when the attribute is malformed. An unstructured name is shown as text, with control characters
    escaped. Other attributes show their OID and each value in hex. An
    extension request whose value cannot be decoded is listed here with
    `Could not decode; value:` and its hex, and a malformed attribute as
    "Malformed attribute" with its encoding in hex.
  - a closing note that a request has no issuer or validity and is not trusted.
- A request whose fields cannot be decoded, including one with data after it,
  shows "Certificate request could not be decoded." and its fingerprint, and
  its signature is `[unchecked]`.
- The signature is checked with the request's own public key, as for a
  self-signed certificate. The details line reads `verified with its own public
  key.`, `does not verify with its own public key: <reason>.`, or `not checked
  (<reason>).`, with the colours and supported algorithms of
  [Signature checks](#signature-checks).
- Only the key size is checked for weakness. The signature hash is not flagged,
  because the issued certificate is signed by the CA, not with the request's
  hash.
- `x` exports the request; `X` does nothing. See [Exporting](#exporting).
- `a` and `p` show the request's ASN.1 structure and PEM encoding; `d` does
  nothing. See [ASN.1 and PEM views](#asn1-and-pem-views).

### Weak cryptography

- A certificate is weak when either:
  - its RSA, RSASSA-PSS, or DSA key is shorter than 2048 bits, or its EC curve
    is smaller than 256 bits (NIST SP 800-131A); or
  - it is signed with MD2, MD5, or SHA-1 (RSA, ECDSA, or DSA signatures).
- The signature of a self-signed certificate (issuer and subject encoded
  identically) is not checked: a root is trusted for where it is stored, not
  for its signature. Its key size is still checked.
- Keys of unknown size, unrecognized algorithms, and other signature algorithms
  are not flagged. This check reads only the stored fields; signatures are
  checked separately, see [Signature checks](#signature-checks).
- In the hierarchy, a weak certificate's label ends with `[weak]` in yellow.

### Extensions

- An "Extensions:" section follows the fingerprint and scrolls with the other
  fields. A certificate without extensions shows `Extensions: None`.
- Each extension is listed in certificate order by name and dotted OID, with
  ` [critical]` appended when flagged, and its decoded values indented below.
- Decoded extensions:

  | Extension | Shows |
  | --- | --- |
  | Subject / Issuer Alternative Name | DNS names, IPv4/IPv6 addresses, emails, URIs, directory names, registered IDs; other name forms in hex |
  | Key Usage | Named usages on one line (Digital Signature, Certificate Sign, ...); unknown bits as `Bit N` |
  | Extended Key Usage | `serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`, `timeStamping`, `OCSPSigning`, `anyExtendedKeyUsage`; others as dotted OIDs |
  | Basic Constraints | CA flag and path length (`unlimited` for a CA without one) |
  | Subject / Authority Key Identifier | Key identifiers in hex; the authority's issuer names and serial when present |
  | CRL Distribution Points | Distribution point names (usually URIs) and CRL issuers; reasons and relative names in hex |
  | Authority Information Access | OCSP and CA Issuers locations |
  | Certificate Policies | Policy OIDs, naming `anyPolicy` and the CA/Browser Forum validation levels; qualifiers are not shown |

- Other extensions show their OID and `Value:` in hex. Hex is colon-separated
  uppercase, as for fingerprints.
- A known extension whose value cannot be decoded, including truncated or
  trailing data, shows `Could not decode; value:` with the value in hex. An
  extension whose own structure is malformed is shown as "Malformed extension"
  with its encoding in hex. Neither hides the other fields or extensions, and
  neither prevents chain linking.
- Control characters in decoded names are shown escaped, for example `\u{1b}`,
  so they cannot affect the terminal.

### Certificate hierarchy

- **JKS:** the hierarchy is the chain stored in the keystore.
- **PKCS12:** the app links certificates stored in the file by issuer identity
  and by any authority and subject key identifiers. It stops with an explanation
  when an issuer is missing or ambiguous, or when it finds a cycle.
- **Certificate files:** each entry's chain follows issuer names to the first
  certificate in the same file with that subject. Names are compared by their
  decoded text, ignoring case. The chain stops at a self-issued certificate, a
  missing issuer, or a certificate already in the chain.
- The app never fetches certificates and never verifies trust.

### Signature checks

- Each certificate's signature is checked with the public key of the next
  certificate in the hierarchy (its stored issuer). The last certificate is
  checked with its own key when it is self-issued (issuer and subject decode to
  the same name); otherwise its issuer is not stored and it is not checked.
- Checks run offline when the detail view opens. Only the signature is checked:
  names, validity, basic constraints, key usage, and revocation are not, and no
  trust decision is made. A verified self-signature only shows that the root
  certificate is intact.
- Results, as a tag at the end of each hierarchy label (after any `[weak]`) and
  as a `Signature:` line in the details:

  | Result | Tag | Details line |
  | --- | --- | --- |
  | Verified | `[verified]`, green | `verified with the public key of <issuer subject>.` or `verified with its own public key (self-signed).`, green |
  | Failed | `[bad signature]`, red | `does not verify with ...: <reason>.`, red |
  | Unchecked | `[unchecked]` | `not checked (<reason>).` |

- A signature fails when the signature algorithm inside the signed part differs
  from the one outside it, when the issuer's key type cannot make that kind of
  signature, or when the signature does not match the signed bytes.
- A signature is unchecked when the issuer is not stored, when either
  certificate cannot be decoded, or when the signature algorithm or the issuer's
  key type is not supported.
- Supported signatures include RSA PKCS#1 v1.5, RSASSA-PSS made by RSA keys,
  ECDSA on P-256, P-384, and P-521, DSA, Ed25519, and Ed448. Keys of type
  RSASSA-PSS, brainpool curves, and secp256k1 are not supported.

### Exporting

- `x` exports the certificate selected in the hierarchy; `X` exports every
  certificate stored with the entry, leaf first. Neither does anything for an
  entry without certificates. For a certificate request entry, `x` exports the
  request and `X` does nothing.
- A prompt replaces the detail shortcuts. It suggests `<alias>.pem`,
  `<alias>-chain.pem`, or `<alias>.csr` for a request, in the open file's
  directory, shown as an absolute path with any `..` resolved. Characters
  other than letters, digits, `-`, `_`, and `.` in the alias become `_`, and a
  name that already exists gets a number, such as `server-2.pem`.
- While the prompt is open, every character without `Ctrl` or `Alt` is typed
  into the name, including `q`, `x`, and `j`. `Backspace` deletes a character,
  `Ctrl+U` clears the name, `Enter` saves, and `Esc` cancels without leaving the
  detail view. `Ctrl+C` still quits.
- A relative name is resolved against the open file's directory.
- A `.der` name (case-insensitive) saves one certificate or the request as raw
  DER; a chain cannot be saved as DER. Any other name saves PEM `CERTIFICATE`
  blocks, or a `CERTIFICATE REQUEST` block for a request, with 64-character
  lines. The DER is written byte for byte as stored.
- The file must not exist yet; it is never replaced. On success a green message
  names the saved file and the prompt closes. On failure a red message explains
  why and the prompt stays open to correct the name. The message clears on the
  next key.

### Small terminals

- When the panes cannot fit, a resize hint is shown instead. The back and quit
  shortcuts still work while the hint is shown.

## Visual style

- The app name at the top is shown in blue.
- The selected row has a `>` marker and bold black text on a light cyan
  background. The colours are explicit RGB values, so contrast stays the same
  across terminal palettes.
- Expired dates are red. On the selected row they are bold white on a dark red
  background instead.
- Dates expiring within 30 days, and not yet expired, are yellow. On the
  selected row they are bold black on an amber (`Rgb(255, 175, 0)`) background
  instead. A `Weak` crypto marker uses the same colours.

## Quitting and terminal restoration

- `q` quits from the entry list and the detail view, except while an export
  or "save as" name is being typed; see [Exporting](#exporting) and
  [Saving](#saving). In the file browser, `q` is
  typed into the name filter; see [File selection](#file-selection).
- `Esc` quits from the entry list.
- While a filter is being typed, `q` and `Esc` edit the filter instead; see
  [Filtering](#filtering).
- With unsaved changes, `q` and `Esc` first ask `Quit without saving the
  changes?` on the main view, in yellow. `y` quits and discards the changes;
  any other key cancels and returns to the view the question came from.
- `Ctrl+C` quits from any view, including the password prompt and while typing
  a filter or a file name. It quits at once, even with unsaved changes, which
  are discarded; the file on disk is left as it was last saved.
- The terminal is restored on normal exit, on errors, and when initialization
  fails. Restoring means raw mode is turned off, the alternate screen is left,
  and the cursor is visible again.

The event loop checks for terminal size changes at least every 250 ms while
idle, so a missed resize notification does not require a key press to redraw.

## Offline chain diagnostics

- `d` shows a report of the entire stored chain, leaf first, in the bottom
  pane, or returns to the certificate details when the report is shown. From
  the ASN.1 or PEM view it switches to the report. It does nothing for CSRs.
- Toggling preserves the hierarchy selection and fingerprint preference, resets
  scroll to zero, and focuses the details pane. Existing scrolling, resizing,
  export, Back, and Quit keys retain their behaviour.
- The report identifies each certificate by its 1-based stored index and subject.
  PASS is green, PROBLEM red, UNKNOWN yellow; headings are uncoloured.
- Validity is checked for every decoded certificate at the current UTC time,
  inclusively at both endpoints. Reversed intervals, not-yet-valid certificates,
  and expired certificates are problems. Signature results are shown separately
  using the existing signature checks, without implying trust.
- Each adjacent pair is checked for issuer/subject Name equality using the same
  parsed Name equality as chain construction. AKI keyIdentifier and SKI are
  compared when both exist; missing identifiers are unknown, conflicts problems.
  Authority issuer/serial fields are not evaluated by this view.
- Each certificate at index greater than zero acts as an issuer: missing or
  false CA Basic Constraints is a problem. Key Usage, if present, must allow
  keyCertSign; absence is unknown with no declared usage restriction.
- A CA pathLenConstraint bounds the number of non-self-issued intermediates
  below it, excluding index zero. An unreadable intermediate makes that count
  unknown. Negative lengths and lengths with CA false are malformed.
- Relevant duplicate or malformed extensions produce unknown results, never a
  passing result. Unsupported critical extension semantics are reported unknown.
  Chain-construction warnings, missing issuers, and unreadable certificates
  remain visible. Empty chains report that no certificates are stored.
- The report always states that trust and revocation are unchecked. It performs
  no network access, path building, or system trust-store lookup, and is not full
  RFC 5280 validation. Name constraints, policy processing, purpose/EKU, hostname,
  and authority issuer/serial matching are outside these checks. Root certificates
  are inspected as stored issuers, not treated as trusted anchors.

## ASN.1 and PEM views

- `a` shows the DER structure of the certificate selected in the hierarchy, or
  of the request, in the bottom pane; `p` shows its PEM encoding. Pressing the
  same key again returns to the details, and `d` switches to the chain
  diagnostics. Each key resets scroll to zero and focuses the bottom pane.
  Its title is "Certificate ASN.1", "Certificate PEM", "Request ASN.1", or
  "Request PEM".
- The hierarchy selection and fingerprint preference are kept. With the
  hierarchy focused, selecting another certificate shows its structure or PEM
  from the top. Scrolling, resizing, export, Back, and Quit keys keep their
  behaviour. An entry without certificates shows "No certificate is stored with
  this entry."
- The ASN.1 view starts with the DER length, then lists one element per line,
  indented by depth, each line starting with the element's byte offset:
  - Constructed elements show their element count, then their elements.
  - INTEGER and ENUMERATED values of up to 8 bytes are shown in signed decimal,
    longer ones in hex. BOOLEAN is `true` or `false`, and NULL is shown as is.
  - OIDs are dotted, followed by a name when known, such as
    `2.5.29.19 (Basic Constraints)`.
  - Strings are quoted, with control characters escaped. Times show the UTC
    time and the stored text. Implicitly tagged values that are visible ASCII,
    such as DNS names and URIs, are quoted.
  - An OCTET STRING, or a BIT STRING without unused bits, whose content is
    exactly one well-formed element, such as an extension value or a public
    key, is marked `(encapsulates)` and its content is listed as nested
    elements. Other values are shown in colon-separated hex: inline up to 16
    bytes, otherwise in rows of 16 bytes below the element. A BIT STRING with
    unused bits says how many.
  - Bytes that cannot be decoded, including data after the last element, are
    reported with their length and the reason, followed by their hex.
  - Elements nested more than 48 levels deep are summarized, and the dump stops
    after 20,000 lines with a note.
- A request's challenge password value is never shown: elements after the
  challenge password OID in its attribute are listed as `(challenge password;
  not shown)`. A request's undecodable bytes are reported without their hex,
  because they could hold a password. When anything is left out, a yellow
  note says so, and the PEM view shows a yellow explanation instead of the
  encoding; `x` can still export the request.
- The PEM view shows a `CERTIFICATE` or `CERTIFICATE REQUEST` block of the
  stored bytes with 64-character lines, as exports write it.
