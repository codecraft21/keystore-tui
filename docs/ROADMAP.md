# Roadmap

Planned work, in order of importance. Nothing here is implemented until it
appears in the [CHANGELOG](../CHANGELOG.md); the [SPEC](SPEC.md) describes what
the app does today.

## Release 1.1

keystore-tui 1.0 only inspects keystores. Release 1.1 adds the write features
expected of a keystore manager, using
[KeyStore Explorer](https://github.com/kaikramer/keystore-explorer) as the
reference. The tiers are ordered by importance, and each tier builds on the
ones before it. All items in the 1.1 scope below are implemented; further
format support and enhancements are planned for 1.2.

Rules for every write feature:

- A file changes only when the user saves explicitly.
- Saves are atomic: write a temporary file, then rename it over the target.
- Decrypted private keys and passwords are wiped from memory after use.
- Everything keeps working without Java or `keytool`.

### Tier 1: the write foundation

These need no private-key cryptography for JKS and PKCS12 truststores.

Done for JKS, JCEKS, and PKCS12: all six items.

1. **Save and Save As:** write JKS, JCEKS, and PKCS12 files, with an
   unsaved-changes marker and a confirmation before quitting with unsaved
   changes (`Ctrl+C` still quits immediately). Every other feature depends on this.
2. **Delete entry.**
3. **Rename entry:** change an entry's alias.
4. **Import trusted certificate:** add a certificate from a PEM, DER, or P7B
   file under a chosen alias.
5. **Create new keystore:** an empty store of a chosen type.
6. **Set or change the keystore password.**

### Tier 2: private-key handling

From this tier on, the app decrypts private keys.

Done: all five items. PKCS12 keys are re-encrypted when the keystore
password changes. Conversion and copying support certificates, private keys, and secret
keys unlocked with the source keystore's password.

7. **Unlock key entry, and set or change an entry password:** decrypt
   JKS and JCEKS private keys, JCEKS sealed secret keys, and PKCS12 key bags;
   change a JKS or JCEKS key's own password. PKCS12 keys use the keystore password.
8. **Import key pair:** from a PKCS12 file, a PKCS #8 key (plain or encrypted)
   with its certificate chain, or unencrypted OpenSSL RSA and EC PEM files.
9. **Export key pair** to PKCS12 or PEM, and **export private key** as PKCS #8
   in PEM or DER, optionally encrypted.
10. **Change keystore type:** convert certificates and private keys between
    JKS, JCEKS, and PKCS12, and secret keys between JCEKS and PKCS12.
11. **Copy entries between keystores:** import chosen certificates and private
    keys, as well as secret keys where supported, from another keystore.

### Tier 3: certificate lifecycle

Done: all four items.

12. **Generate key pair with a self-signed certificate:** RSA, EC, and Ed25519,
    with a subject name, validity period, and basic extensions (subject
    alternative names, key usage, extended key usage, basic constraints).
13. **Generate certificate signing request** from a key-pair entry.
14. **Import CA reply:** replace a key pair's certificate with the issued
    chain, after checking that the public key matches.
15. **Edit certificate chain:** append or remove chain certificates on a
    key-pair entry, to fix what the chain diagnostics report.

### Tier 4: certificate authority and niche features

Done: all four items.

16. **Sign a certificate signing request** with a key-pair entry into a PEM or
    DER certificate, and **sign a new key pair** with an existing one.
17. **Secret keys:** generate, import, and export AES and HMAC keys (JCEKS
    and PKCS12), using hex digits or raw bytes for import and export.
18. **Export public key** as SubjectPublicKeyInfo in PEM or DER.
19. **Sign a certificate revocation list.** Revocation lists can also be opened
    for inspection.

## Release 1.2

Planned extensions to the completed 1.1 scope. The write rules above apply
here too.

1. **Optional backup** when saving a keystore.
2. **Legacy OpenSSL PEM:** import keys encrypted in OpenSSL's older PEM
   format, and export `RSA PRIVATE KEY` and `EC PRIVATE KEY` PEM files,
   optionally encrypted.
3. **Separate key passwords when copying or converting:** prompt for
   a key's own password when the source keystore password cannot unlock it.
4. **PKCS #7 CA replies:** write signed replies as `.p7b` files.
5. **Verify revocation-list signatures** when reading a CRL with an available
   issuer certificate.

## Out of scope

- BKS, UBER, and BCFKS keystores.
- PKCS#11 tokens and the Windows and macOS system stores.
- A special mode for the JRE `cacerts` file; open it by path like any keystore.
- JAR, JWT, and MIDlet signing.
