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
  - [Importing key pairs](#importing-key-pairs)
  - [Generating key pairs](#generating-key-pairs)
  - [Making certificate requests](#making-certificate-requests)
  - [Importing a CA reply](#importing-a-ca-reply)
  - [Copying entries from another keystore](#copying-entries-from-another-keystore)
  - [Exporting private keys](#exporting-private-keys)
  - [Changing the password](#changing-the-password)
  - [Changing a key password](#changing-a-key-password)
- [Creating a keystore](#creating-a-keystore)
- [Saving](#saving)
  - [Writing PKCS12 keystores](#writing-pkcs12-keystores)
  - [Converting a keystore](#converting-a-keystore)
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
- The other files it writes are new exports: certificates and requests (see
  [Exporting](#exporting)), private keys (see [Exporting private
  keys](#exporting-private-keys)), and new certificate requests (see [Making
  certificate requests](#making-certificate-requests)).
- It runs without Java or `keytool` installed.
- Private and secret keys are never displayed. A private key is written
  unencrypted only by an export that the user confirms; see [Exporting
  private keys](#exporting-private-keys). Otherwise keys are decrypted only in
  memory, and only to encrypt them again: when a PKCS12 keystore's password changes (see [Changing the
  password](#changing-the-password)), when a JKS or JCEKS key's password
  changes (see [Changing a key password](#changing-a-key-password)), when
  a keystore is converted to another format (see [Converting a
  keystore](#converting-a-keystore)), when a key pair is imported (see
  [Importing key pairs](#importing-key-pairs)) or copied from another
  keystore (see [Copying entries from another
  keystore](#copying-entries-from-another-keystore)), and when a private key
  is exported under a password. A private key is also decrypted in memory to
  sign a certificate request (see [Making certificate
  requests](#making-certificate-requests)) and to work out its public key
  for a certificate authority's reply (see [Importing a CA
  reply](#importing-a-ca-reply)). A new private key is made only in memory, and
  is encrypted with the keystore's password at once; see [Generating key
  pairs](#generating-key-pairs).
- The following are out of scope for now: importing anything but a trusted
  certificate, a key pair, or another keystore's entries, keystore editing other than [deleting](#deleting-entries) and
  [renaming](#renaming-entries) entries, [generating key pairs](#generating-key-pairs), and [importing a CA reply](#importing-a-ca-reply), and clipboard actions. The [ROADMAP](ROADMAP.md) lists the planned write
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
  `.pfx`, `.pem`, `.crt`, `.cer`, `.der`, `.p7b`, `.p7c`, `.csr`, `.p10`,
  `.key`, or `.p8` (case-insensitive). The last two are private key files,
  listed for [importing key pairs](#importing-key-pairs). It also lists the Java truststore names `cacerts` and
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
  two lines above the shortcuts show `Keystore: n New | g Generate | i Import
  | w Save | W Save as | p Password` and `Entry: e Export | c Request | R
  CA reply | r Rename | d Delete | P Key password`.
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
- For a certificate file, `d`, `Delete`, `r`, `i`, `g`, `c`, `R`, `p`, `w`, and `W` show a
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
  certificate or key pair from file`, in the opened file's directory. `Esc`
  cancels.
- A chosen file that holds a private key starts a [key pair
  import](#importing-key-pairs), and a JKS, JCEKS, or PKCS12 keystore a [copy
  of its entries](#copying-entries-from-another-keystore). Any other file is
  read as a certificate file.
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

### Importing key pairs

- The file chosen with `i` starts a key pair import when it is one of:
  - A PEM file with one private key block: `PRIVATE KEY` (PKCS #8),
    `ENCRYPTED PRIVATE KEY`, `RSA PRIVATE KEY`, or `EC PRIVATE KEY` (OpenSSL's
    own formats; the EC key must name its curve). It may also hold the
    certificates.
  - A DER file holding a PKCS #8 key, plain or encrypted.
- A PEM file with several private keys, with a key encrypted in OpenSSL's old
  format (a `Proc-Type: 4,ENCRYPTED` header), with a malformed key, or with
  any other `... PRIVATE KEY` block is refused with a red message.
- For an encrypted key, a prompt asks `Password of
  '<file name>':`, masked like the keystore password. A wrong password shows
  `Incorrect password.` and leaves the prompt open; `Esc` cancels. The
  password is wiped once the key is read.
- When the key's file holds no certificate, the file browser opens again,
  titled `Certificate file of the imported key`, to choose a PEM, DER, or
  PKCS#7 certificate file. `Esc` cancels the import.
- The key's certificate is the one holding the key's public key, which is
  worked out from the private key. Its chain is built from the other
  certificates in the same file by issuer and subject names; certificates
  outside the chain are left out. Without a matching certificate, or for a
  type of key whose public key the app cannot work out, nothing is imported.
  RSA, EC (the NIST curves), Ed25519, and Ed448 keys are supported.
- A prompt then asks `Alias for the imported key pair:`, suggesting the
  certificate's subject name in lower case. It follows the same rules as the [rename prompt](#renaming-entries).
- The key pair is added as a private-key entry with the current time as its
  creation date, listed in alias order and selected. A green message names it.
  The key is protected with the keystore's password in the keystore's own
  scheme, as in [Converting a keystore](#converting-a-keystore), and the plain
  key is wiped from memory. A JCEKS keystore needs a printable-ASCII password
  for this, and a PKCS12 keystore a password that is not empty.
- A PKCS12 keystore refuses a key pair whose certificate already belongs to
  one of its private keys, because the key and certificate are paired by the
  certificate's digest.
- Whether the certificates are trusted or valid is not checked.

### Generating key pairs

- In a keystore, `g` opens a form titled `Generate key pair` over the list,
  72 columns by 16 rows, with one field per row:
  - `Algorithm`: `RSA 2048`, `RSA 3072`, `RSA 4096`, `EC P-256`, `EC P-384`,
    `EC P-521`, or `Ed25519`. It starts at `EC P-256`.
  - The subject name: `Common name (CN)`, `Organization (O)`, `Org. unit
    (OU)`, `Locality (L)`, `State (ST)`, and `Country (C)`. Only the common
    name is required. The country is a two-letter code, stored in upper case.
  - `Valid for (days)`: from 1 to 36500, starting at `365`.
  - `Alternative names`: optional, separated by commas. A name that reads as
    an IPv4 or IPv6 address is stored as an IP address, one holding `@` as an
    email address, and any other as a DNS name. Names must be ASCII without
    spaces.
  - `Purpose`: `None`, `TLS server`, `TLS client`, `TLS server and client`,
    `Certificate authority`, or `Code signing`. It starts at `None`.
- `Up` / `Down` or `Shift+Tab` / `Tab` move between the fields, wrapping at
  either end. The selected row is highlighted like the selected entry, and a
  line below the fields says what the field is for. `Left` / `Right` change
  the algorithm and the purpose, wrapping at either end. In the other fields
  every character without `Ctrl` or `Alt` is typed, including `q`;
  `Backspace` deletes a character and `Ctrl+U` clears the field. A text too
  long for its row shows its end. `Esc` closes the form and changes nothing;
  `Ctrl+C` still quits.
- `Enter` checks the form. The first field that is wrong is selected and a
  red message below the fields says why; the message clears on the next key.
- A prompt then asks `Alias for the generated key pair:`, suggesting the
  common name in lower case. It follows the same rules as the [rename
  prompt](#renaming-entries), except that `Esc` returns to the form as it was
  filled in.
- Once the alias is accepted, `Generating <algorithm> key pair...` is shown
  in yellow while the key is made; keys are not read until it is done. RSA
  4096 takes a few seconds.
- The certificate is version 3 and signed with the new key: RSA with SHA-256,
  EC with SHA-256, SHA-384, or SHA-512 for P-256, P-384, or P-521, and
  Ed25519 with its own signature. RSA keys use the public exponent 65537.
  The issuer is the subject, the validity starts at the current time, and
  the serial number is 16 random bytes, positive. The subject lists the
  country first and the common name last, leaving out empty fields.
- The certificate always holds a subject key identifier, and the alternative
  names when any were given. The purpose adds:
  - `None`: nothing.
  - `TLS server`: a critical key usage of digital signature, with key
    encipherment for an RSA key, and the extended key usage server
    authentication.
  - `TLS client`: a critical key usage of digital signature, and the
    extended key usage client authentication.
  - `TLS server and client`: the key usage of `TLS server`, and both
    extended key usages.
  - `Certificate authority`: critical basic constraints marking a CA, without
    a path length, and a critical key usage of certificate signing and CRL
    signing.
  - `Code signing`: a critical key usage of digital signature, and the
    extended key usage code signing.
- The key pair is added as a private-key entry with a chain of that one
  certificate, listed in alias order and selected, under the rules of an
  [imported key pair](#importing-key-pairs): the key is protected with the
  keystore's password and the plain key is wiped from memory. A green message
  such as `Generated EC P-256 key pair '<alias>'.` names it. Nothing is
  written until the keystore is saved.
- When the key pair cannot be added, for example to a PKCS12 keystore with an
  empty password, a red message says why and the generated key is discarded.
- In a terminal smaller than the form, a resize hint is shown instead; `Esc`
  and `Ctrl+C` still work.

### Making certificate requests

- In a keystore, `c` makes a PKCS #10 certificate request for the selected
  private key, signed with that key. On another kind of entry a red message
  says that only a private key can sign a request. The key must be one that
  the keystore's password unlocks, in PKCS #8 form, as for an
  [export](#exporting-private-keys), and its certificate must be readable.
- A form titled `Certificate request for '<alias>'` opens. It is the form of
  [Generating key pairs](#generating-key-pairs) without the algorithm and the
  validity, and works the same way. It starts from the key's certificate: the
  subject name's fields, and the DNS names, IP addresses, and email addresses
  among its alternative names. The purpose starts at `None`.
- While the subject's fields are left as they were, the request holds the
  certificate's subject exactly, including attributes the form has no field
  for. Once a field is changed, the subject is made of the form's fields
  alone, and a common name is required.
- `Enter` then asks `Save certificate request as:`, suggesting `<alias>.csr`
  next to the opened file, as the [request export](#exporting) does. A
  `.der` name writes DER and any other name PEM. `Esc` returns to the form
  as it was filled in. An existing file is never replaced: a red message
  asks for another name.
- The request is version 1 and holds the key's public key. It is signed with
  the algorithm a [generated key pair](#generating-key-pairs)'s certificate
  uses for that type of key; an Ed448 key signs with Ed448. When a purpose
  other than `None` or alternative names are given, the request holds one
  extension request with the purpose's extensions and then the alternative
  names; otherwise it has no attributes.
- A green message names the entry and the file. The keystore is not changed.

### Importing a CA reply

- In a keystore, `R` replaces the selected private key's certificate chain
  with the one a certificate authority issued. On another kind of entry a
  red message says that only a private key takes a reply. The key must be
  one that the keystore's password unlocks, in PKCS #8 form, as for an
  [export](#exporting-private-keys).
- The file browser opens, titled `CA reply for '<alias>'`, to choose a PEM,
  DER, or PKCS#7 certificate file. `Esc` gives up.
- The reply's certificate is the one in the file holding the key's public
  key, which is worked out from the private key as for an [imported key
  pair](#importing-key-pairs). Without one, a red message says that no
  certificate in the file holds the public key of the entry, and nothing
  changes. A file without certificates is refused too.
- The new chain is that certificate followed by its issuers among the file's
  other certificates, found by issuer and subject names, in whatever order
  the file holds them. Where the file's certificates end before a
  self-issued one, the chain goes on in the same way with certificates the
  keystore holds, in any entry. An issuer is never guessed between several
  candidates: the chain ends there. Certificates outside the chain are left
  out.
- The entry's chain is replaced in memory; the private key is not changed,
  and in JKS and JCEKS the entry keeps its creation date. A green message
  such as `Replaced the certificate chain of '<alias>' with the 3
  certificates from '<file name>'.` reports it. Nothing is written until the
  keystore is saved.
- When the new chain is the one the entry already has, a green message says
  that nothing changed, and the keystore is not marked as modified.
- In PKCS12 the key and its new certificate are named with the entry's alias
  and share a new local key ID, and the old chain's certificates that no
  other entry uses are dropped. A reply whose certificate already belongs to
  another private key is refused, as is a chain the keystore would not list
  again as given.
- Whether the certificates are trusted or valid is not checked; the
  [chain diagnostics](#offline-chain-diagnostics) of the entry show what the
  new chain looks like.

### Copying entries from another keystore

- A JKS, JCEKS, or PKCS12 keystore chosen with `i` is a source to copy entries
  from. A prompt asks `Password of '<file name>':`, as for an encrypted key;
  press `Enter` alone for an empty password. A wrong password shows `Incorrect
  password.` and leaves the prompt open. A PKCS12 keystore that cannot be read
  completely, or a keystore without entries, is refused. The source file is
  never changed.
- A list titled `Import entries from '<file name>'` then shows the source's
  entries as `[ ] <alias> | <type>`. `Up`, `Down`, `j`, and `k` move the
  highlight, wrapping at both ends. `Space` chooses the highlighted entry or
  drops it, shown as `[x]`; `a` chooses every entry that can be copied, or
  none when they all are chosen. `Esc` cancels, and `q` does nothing.
- Entries that cannot be copied are greyed, marked `[-]`, and followed by the
  reason: secret keys, and private keys that the source's password does not
  unlock or that are not in PKCS #8 form. An entry whose alias the open
  keystore already has, ignoring case, is followed by `(alias exists)`.
- `Enter` imports the chosen entries, or the highlighted one when none is
  chosen:
  - A single entry goes through the alias prompt of a [certificate
    import](#importing-certificates) or a [key pair
    import](#importing-key-pairs), which suggests its alias in lower case.
  - Several entries keep their aliases, in lower case. Those whose alias
    exists are skipped. A message such as `Imported 2 entries from
    '<file name>'. Skipped, alias exists: <aliases>.` reports the result, in
    red when nothing was imported or an entry failed.
- A source with a single entry skips the list and goes straight to the alias
  prompt.
- A certificate is added as a trusted certificate, and a private key with its
  certificate chain, protected with the open keystore's password, under the
  same rules as the two imports above. Creation dates are not copied.

### Exporting private keys

- In a keystore, `e` exports the selected private key to a new file. On
  another kind of entry a red message points to the certificate export in the
  details. The key must be one that the keystore's password unlocks, in PKCS
  #8 form; a JKS or JCEKS key with a password of its own is refused with a
  message that says to give it the keystore's password first (`P`).
- A prompt asks `Export key to:`, suggesting `<alias>.p12` in the open file's
  directory, named and edited like the [certificate export](#exporting)
  prompt. The name chooses what is written, ignoring case:
  - `.p12` or `.pfx`: a PKCS12 keystore holding the key and its certificate
    chain under the entry's alias, written like [any PKCS12
    keystore](#writing-pkcs12-keystores).
  - `.key`: the key alone, as a PKCS #8 PEM block.
  - `.p8` or `.der`: the key alone, as PKCS #8 DER.
  - Any other name, such as `.pem`: the key as a PKCS #8 PEM block, followed
    by its certificates as `CERTIFICATE` blocks, leaf first.
- A name that already exists is refused with a red message and the prompt
  stays open. Then a prompt asks `Password for the exported key:`, typed
  twice like a [new keystore password](#changing-the-password).
- With a password, the key is encrypted with PBES2 (AES-256-CBC, PBKDF2 with
  HMAC-SHA256, 10,000 iterations) as an `ENCRYPTED PRIVATE KEY`, and is
  decrypted again as a check before the file is written. A PKCS12 file is
  also read back, and is not written if its certificate chain would differ,
  as when the chain is not linked by issuer names.
- An empty password is refused for a PKCS12 file. For the other files the
  prompt's shortcuts start with `Empty: unencrypted`, and an empty password
  asks, in yellow, `Write the private key '<alias>' unencrypted?`; only `y`
  writes the key, as a plain `PRIVATE KEY`.
- The file is new and is never replaced. On Unix only its owner can read or
  write it. A green message names it. The keystore is not changed.

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
- In PKCS12, Java expects keys to be encrypted with the keystore's password.
  When the password is confirmed, every private key and secret key is
  decrypted in memory with the current password and encrypted again with the
  new one, using PBES2 as in [Writing PKCS12
  keystores](#writing-pkcs12-keystores), with a new random salt and IV. The
  decrypted key is wiped at once; its bytes, and the bag's type and
  attributes, are unchanged. Like the password, the re-encrypted keys reach
  the file only on saving.
- The PKCS12 password is not changed, and no key is touched, when a key does
  not decrypt with the current password, when a key or secret uses encryption
  or a form the app does not support, when no password protects the keystore
  and it holds no keys, when the new password is empty, or when the system
  provides no random numbers. A red message gives the reason.

### Changing a key password

- In JKS and JCEKS, each private key has a password of its own, which may
  differ from the keystore's. `P` changes it for the selected private key.
- When the keystore's password unlocks the key, the new password is asked for
  at once. Otherwise a prompt first asks `Current password of key '<alias>':`,
  typed once and shown as `*`. A wrong password shows a red message and the
  prompt stays open; `Esc` cancels.
- The new password is then asked for twice, `New password for key '<alias>':`
  and `Type the password again:`, as when [changing the
  password](#changing-the-password). An empty password is accepted.
- The key is recovered in memory, protected again under the new password as
  Java protects keys in the keystore's format, with a new random salt, and
  wiped. JKS uses Java's SHA-1 based key protector. JCEKS uses
  `PBEWithMD5AndTripleDES` with 200,000 iterations, and accepts only printable
  ASCII passwords, as Java does; another password is refused with a red
  message.
- A JKS or JCEKS keystore may hold keys protected either way; each is
  recovered by its own scheme and protected again by the keystore's.
- The change counts as a modification and reaches the file on saving, where
  only the protected key changes: the entry keeps its alias, creation date,
  certificate chain, and place in the file. A green message names the key.
- `P` shows a red message, and changes nothing, for an entry that is not a
  private key, for a key whose protection the app cannot read, for a PKCS12
  keystore, whose keys share the keystore's password, and where the keystore
  cannot be changed. JCEKS secret keys are not supported yet.
- The keystore's own password is not affected, and changing it does not
  change key passwords.

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
  renamed entry and, after a password change, the key bags. Otherwise private
  and secret keys stay encrypted as they were.
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

### Converting a keystore

- In the "save as" prompt, a name ending in `.jks`, `.jceks`, or `.p12` or
  `.pfx` (ignoring case) that asks for another format than the keystore's
  converts it: the new file is written in that format, with the same password,
  and becomes the opened file. Any other name keeps the format. The prompt's
  hint line says so, and the green message ends with `as JKS`, `as JCEKS`, or
  `as PKCS12`.
- The opened file is not changed. Unsaved changes go into the converted file.
- Each private key is recovered in memory with the keystore's password,
  protected again as the new format does, and wiped: Java's key protector for
  JKS, `PBEWithMD5AndTripleDES` for JCEKS, and PBES2 for PKCS12, each with a
  new random salt. In the converted keystore every key has the keystore's
  password.
- Certificates and chains are copied byte for byte. To JKS or JCEKS, a
  certificate entry of either PKCS12 kind becomes a trusted certificate,
  aliases become lower case, and entries get the current time as creation
  date. To PKCS12, entries are written as in [Writing PKCS12
  keystores](#writing-pkcs12-keystores) for a new keystore: a key shares a
  local key ID, the SHA-1 digest of its certificate, with that certificate;
  chain certificates are stored once; trusted certificates carry Java's
  attribute; and creation dates are not kept. Between JKS and JCEKS, creation
  dates are kept.
- Before anything is written, the converted keystore is opened as a file
  would be, and its entries, certificates, chains, and recovered keys are
  compared with the originals. On any difference nothing is written. A chain
  that is not linked by issuer names fails this check for PKCS12, which
  rebuilds chains from them.
- The conversion is refused, with a red message and the prompt left open,
  when a key has a password other than the keystore's (change it first with
  `P`), when a key's protection is not supported or the key is not PKCS #8,
  when the keystore holds a secret key, when two aliases would be the same in
  lower case, when the target is PKCS12 and the password is empty, when the
  target is JCEKS and the password is not printable ASCII, or when the file
  already exists.

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
