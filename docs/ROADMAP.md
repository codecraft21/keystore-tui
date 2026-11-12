# Roadmap

Planned work, in order of importance. Nothing here is implemented until it
appears in the [CHANGELOG](../CHANGELOG.md); the [SPEC](SPEC.md) describes what
the app does today.

## Release 1.1

keystore-tui 1.0 only inspects keystores. Release 1.1 adds the write features
expected of a keystore manager, using
[KeyStore Explorer](https://github.com/kaikramer/keystore-explorer) as the
reference. The tiers are ordered by importance, and each tier builds on the
ones before it.

Rules for every write feature:

- A file changes only when the user saves explicitly.
- Saves are atomic: write a temporary file, then rename it over the target.
- Decrypted private keys and passwords are wiped from memory after use.
- Everything keeps working without Java or `keytool`.

### Tier 1: the write foundation

These need no private-key cryptography for JKS and PKCS12 truststores.

Done for JKS, JCEKS, and PKCS12: all six items. Still open: the optional
backup.

1. **Save and Save As:** write JKS, JCEKS, and PKCS12 files, with an optional
   backup, an unsaved-changes marker, and a confirmation before quitting with
   unsaved changes. Every other feature depends on this.
2. **Delete entry.**
3. **Rename entry:** change an entry's alias.
4. **Import trusted certificate:** add a certificate from a PEM, DER, or P7B
   file under a chosen alias.
5. **Create new keystore:** an empty store of a chosen type.
6. **Set or change the keystore password.**

### Tier 2: private-key handling

From this tier on, the app decrypts private keys.

Done: item 7. PKCS12 keys are re-encrypted when the keystore password
changes, and a JKS or JCEKS private key's own password can be changed. Still
open for item 7: JCEKS secret keys, which Java seals in a serialized object.

7. **Unlock entry, and set or change an entry password:** decrypt key entries
   (JKS and JCEKS key protection, PKCS12 shrouded key bags). Items 8 to 16
   depend on this.
8. **Import key pair:** from a PKCS12 file, a PKCS#8 key (plain or encrypted)
   with its certificate chain, or OpenSSL PEM key files.
9. **Export key pair** to PKCS12 or PEM, and **export private key** as PKCS#8
   or OpenSSL PEM, optionally encrypted.
10. **Change keystore type:** convert between JKS, JCEKS, and PKCS12.
11. **Copy entries between keystores:** import chosen entries from another
    keystore.

### Tier 3: certificate lifecycle

12. **Generate key pair with a self-signed certificate:** RSA, EC, and Ed25519,
    with a subject name, validity period, and basic extensions (subject
    alternative names, key usage, extended key usage, basic constraints).
13. **Generate certificate signing request** from a key-pair entry.
14. **Import CA reply:** replace a key pair's certificate with the issued
    chain, after checking that the public key matches.
15. **Edit certificate chain:** append or remove chain certificates on a
    key-pair entry, to fix what the chain diagnostics report.

### Tier 4: certificate authority and niche features

16. **Sign a certificate signing request** with a key-pair entry, and **sign a
    new key pair** with an existing one.
17. **Secret keys:** generate, import, and export AES and HMAC keys (JCEKS and
    PKCS12).
18. **Export public key** as SubjectPublicKeyInfo in PEM or DER.
19. **Sign a certificate revocation list.**

### Out of scope

- BKS, UBER, and BCFKS keystores.
- PKCS#11 tokens and the Windows and macOS system stores.
- A special mode for the JRE `cacerts` file; open it by path like any keystore.
- JAR, JWT, and MIDlet signing.
