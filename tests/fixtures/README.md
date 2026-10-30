`example.jks` contains 20 distinct, self-signed P-256 public certificate entries
and uses an **empty password**, so it opens directly in the entry list:

```sh
cargo run -- tests/fixtures/example.jks
```

Aliases `example-01-expired` and `example-02-expired` expired on 2024-01-01 UTC.
Aliases `example-03` through `example-20` expire on 2040-01-01 UTC. All are valid
from 2020-01-01 UTC. No private keys are stored. This fixture is useful for
testing scrolling, selection wrapping, expiry highlighting, filtering, and
sorting.

Regenerate it from the repository root with Python 3 and the `cryptography`
package installed (neither is needed to open the committed fixture):

```sh
python3 tests/fixtures/generate_example.py
```

Regeneration creates new keys and signatures in memory and writes only public
certificates, so the resulting bytes differ while the aliases and dates stay
the same.

`trusted-cert.jks` is a Java-generated test fixture containing only a trusted
certificate (`root-cert`), with the test store password `changeit`. No private key
is included. Tests construct private-key entries at runtime using synthetic bytes,
so listing both entry types is covered without committing private keys.

Generate a replacement from this directory (remove the old fixture first):

```sh
fixture_dir=$(mktemp -d)
keytool -genkeypair -alias server-key -dname 'CN=JKS TUI test fixture' \
  -keyalg EC -groupname secp256r1 -validity 3650 -storetype JKS \
  -keystore "$fixture_dir/key.jks" -storepass changeit -keypass keypass
keytool -exportcert -alias server-key -keystore "$fixture_dir/key.jks" \
  -storepass changeit -file "$fixture_dir/cert.der"
keytool -importcert -noprompt -alias root-cert -file "$fixture_dir/cert.der" \
  -keystore trusted-cert.jks -storepass changeit -storetype JKS
rm "$fixture_dir/key.jks" "$fixture_dir/cert.der"
rmdir "$fixture_dir"
```

Tests read the committed fixture; Java is not required to run them.

`trusted-cert.p12` and `trusted-cert-legacy.p12` are generated Java PKCS12
truststores containing the same public certificate. `unicode-alias.p12` contains
that certificate under the alias `certificate-😀`. Recreate them with:

```sh
keytool -importkeystore -noprompt -srckeystore trusted-cert.jks \
  -srcstoretype JKS -srcstorepass changeit -destkeystore trusted-cert.p12 \
  -deststoretype PKCS12 -deststorepass changeit
keytool -J-Dkeystore.pkcs12.legacy=true -importkeystore -noprompt \
  -srckeystore trusted-cert.jks -srcstoretype JKS -srcstorepass changeit \
  -destkeystore trusted-cert-legacy.p12 -deststoretype PKCS12 \
  -deststorepass changeit
keytool -importkeystore -noprompt -srckeystore trusted-cert.jks \
  -srcstoretype JKS -srcstorepass changeit -srcalias root-cert \
  -destkeystore unicode-alias.p12 -deststoretype PKCS12 \
  -deststorepass changeit -destalias 'certificate-😀'
```

`passwordless.p12` contains the same public certificate in an unencrypted Java
truststore without MacData. Generate it with:

```sh
keytool -J-Dkeystore.pkcs12.certProtectionAlgorithm=NONE \
  -J-Dkeystore.pkcs12.macAlgorithm=NONE -importkeystore -noprompt \
  -srckeystore trusted-cert.jks -srcstoretype JKS -srcstorepass changeit \
  -destkeystore passwordless.p12 -deststoretype PKCS12 -deststorepass changeit
```

The destination password is required by `keytool` but does not protect this
fixture. Tests read the committed fixture without Java.

`encrypted-no-mac.p12` contains the same public certificate with password-encrypted
safe contents and no MacData. It requires `changeit` to decrypt the certificate.
Generate it with:

```sh
keytool -J-Dkeystore.pkcs12.macAlgorithm=NONE -importkeystore -noprompt \
  -srckeystore trusted-cert.jks -srcstoretype JKS -srcstorepass changeit \
  -destkeystore encrypted-no-mac.p12 -deststoretype PKCS12 -deststorepass changeit
```

Both of these no-MAC fixtures are generated with Java `keytool`; neither
contains private keys.

`openssl-no-mac-aes.p12`, `openssl-no-mac-3des.p12`, `openssl-no-mac-rc2.p12`,
`openssl-no-mac-rc4.p12`, and `openssl-no-mac-rc4-40.p12` are OpenSSL stores
without MacData. Each holds the same certificate in a safe encrypted with
`changeit`, using AES-256-CBC (PBES2), 3-key 3DES, 40-bit RC2, 128-bit RC4, and
40-bit RC4. Without a MAC, only decryption can reject a wrong password. These
fixtures are useful for checking by hand that any wrong password, including the
empty one tried at startup, brings back the password prompt:

- With AES-256-CBC, `wrong130` is a wrong password that still passes the CBC
  padding check. It must be rejected.
- RC4 has no padding, so any wrong password decrypts to garbage, which must
  also be rejected.

Recreate them from this directory with:

```sh
keytool -exportcert -rfc -alias root-cert -keystore trusted-cert.jks \
  -storepass changeit -file fixture.pem
openssl pkcs12 -export -nomac -nokeys -certpbe AES-256-CBC -in fixture.pem \
  -out openssl-no-mac-aes.p12 -passout pass:changeit
openssl pkcs12 -export -nomac -nokeys -certpbe PBE-SHA1-3DES -in fixture.pem \
  -out openssl-no-mac-3des.p12 -passout pass:changeit
openssl pkcs12 -export -legacy -nomac -nokeys -certpbe PBE-SHA1-RC2-40 \
  -in fixture.pem -out openssl-no-mac-rc2.p12 -passout pass:changeit
openssl pkcs12 -export -legacy -nomac -nokeys -certpbe PBE-SHA1-RC4-128 \
  -in fixture.pem -out openssl-no-mac-rc4.p12 -passout pass:changeit
openssl pkcs12 -export -legacy -nomac -nokeys -certpbe PBE-SHA1-RC4-40 \
  -in fixture.pem -out openssl-no-mac-rc4-40.p12 -passout pass:changeit
rm fixture.pem
```

`-certpbe` must be given: with `-nomac` and the default algorithm, OpenSSL
leaves the certificates unencrypted. Each run uses a new salt, so after
regenerating `openssl-no-mac-aes.p12`, find a new wrong password that passes the
padding check and update `VALID_PADDING_PASSWORD` in `src/pkcs12.rs`, the
password in `src/tests.rs`, and this file. OpenSSL reports such a password with
an ASN.1 error instead of `bad decrypt`:

```sh
for n in $(seq 1 10000); do
  openssl pkcs12 -in openssl-no-mac-aes.p12 -nomacver -nokeys -noout \
    -passin "pass:wrong$n" 2>&1 | grep -q 'bad decrypt' || { echo "wrong$n"; break; }
done
```

`invalid-ciphertext-no-mac.p12` is `openssl-no-mac-3des.p12` with the last byte
of its encrypted content removed, so the 3DES ciphertext is no longer a whole
number of blocks. It opens without a prompt, as an empty store with the
incomplete-list warning, and must not crash. The script needs only the Python
standard library. Recreate it with:

```sh
python3 truncate_ciphertext.py openssl-no-mac-3des.p12 invalid-ciphertext-no-mac.p12
```

`empty-password.p12` and `nul-password.p12` contain the same certificate under
the alias `root-cert`, stored by Java with an empty password and with a single
NUL character as the password. Java opens both with an empty password. `keytool`
rejects such short passwords, so recreate them with `jshell` from this directory:

```sh
jshell -q <<'EOF'
var source = java.security.KeyStore.getInstance("PKCS12");
source.load(new java.io.FileInputStream("trusted-cert.p12"), "changeit".toCharArray());
for (var fixture : new String[][] {{"empty-password.p12", ""}, {"nul-password.p12", "\0"}}) {
  var store = java.security.KeyStore.getInstance("PKCS12");
  store.load(null, null);
  store.setCertificateEntry("root-cert", source.getCertificate("root-cert"));
  try (var out = new java.io.FileOutputStream(fixture[0])) { store.store(out, fixture[1].toCharArray()); }
}
/exit
EOF
```

`empty-password-no-mac.p12` holds the same certificate, stored by Java with an
empty password and no MacData. Its certificate is encrypted with legacy 40-bit
RC2, whose key derivation encodes Java's empty password as a NUL character, so
it opens only through the NUL fallback. Recreate it with `jshell` from this
directory:

```sh
jshell -q -R-Dkeystore.pkcs12.macAlgorithm=NONE \
  -R-Dkeystore.pkcs12.certProtectionAlgorithm=PBEWithSHA1AndRC2_40 <<'EOF'
var source = java.security.KeyStore.getInstance("PKCS12");
source.load(new java.io.FileInputStream("trusted-cert.p12"), "changeit".toCharArray());
var store = java.security.KeyStore.getInstance("PKCS12");
store.load(null, null);
store.setCertificateEntry("root-cert", source.getCertificate("root-cert"));
try (var out = new java.io.FileOutputStream("empty-password-no-mac.p12")) { store.store(out, "".toCharArray()); }
/exit
EOF
```

With Java's default AES encryption, an empty password is encoded as no bytes
at all and needs no fallback.

Private-key and secret-key PKCS12 cases are generated only in memory by tests;
no private key fixture is committed. Neither Java nor `keytool` is needed to run
the app or its tests.

`unicode-password.jks` and `unicode-alias.jks` are copies of the same trusted
certificate fixture. The first uses the synthetic test password `pässwörd-😀` to
exercise Java's UTF-16 password digest encoding. The second keeps `changeit` and
uses the alias `certificate-😀` to exercise Java's modified UTF-8 string encoding.
Neither contains private keys. Recreate them from this directory with:

```sh
cp trusted-cert.jks unicode-password.jks
keytool -storepasswd -keystore unicode-password.jks -storetype JKS \
  -storepass changeit -new 'pässwörd-😀'
cp trusted-cert.jks unicode-alias.jks
keytool -changealias -keystore unicode-alias.jks -storetype JKS \
  -storepass changeit -alias root-cert -destalias 'certificate-😀'
```

`trusted-cert.jceks` holds the same certificate under `root-cert` in a JCEKS
store with the password `changeit`. JCEKS secret-key entries are built only in
memory by tests, from synthetic bytes in the layout Java writes. Recreate the
fixture with:

```sh
keytool -importkeystore -noprompt -srckeystore trusted-cert.jks \
  -srcstoretype JKS -srcstorepass changeit -destkeystore trusted-cert.jceks \
  -deststoretype JCEKS -deststorepass changeit
```

`openssl-cert.p12` and `openssl-cert-legacy.p12` are OpenSSL PKCS12 stores
containing only that certificate, with the password `changeit`. They have no
friendly names or Java trust attributes, as OpenSSL writes them. The first uses
OpenSSL 3's default AES encryption and the second its legacy RC2 encryption.
Recreate them with:

```sh
keytool -exportcert -rfc -alias root-cert -keystore trusted-cert.jks \
  -storepass changeit -file fixture.pem
openssl pkcs12 -export -nokeys -in fixture.pem -out openssl-cert.p12 \
  -passout pass:changeit
openssl pkcs12 -export -legacy -nokeys -in fixture.pem \
  -out openssl-cert-legacy.p12 -passout pass:changeit
rm fixture.pem
```

`keytool-request.csr` and `openssl-request.der` are certificate signing
requests. The first is a PEM request from `keytool -certreq` for a P-256 key,
with Subject Alternative Name and Extended Key Usage extensions. The second is
a DER request from OpenSSL for an RSA 2048 key with a Subject Alternative Name.
Their private keys exist only in a temporary directory while the requests are
made. Recreate them from this directory with:

```sh
key_dir=$(mktemp -d)
keytool -genkeypair -alias request-key \
  -dname 'CN=CSR TUI test fixture, O=keystore-tui' -keyalg EC \
  -groupname secp256r1 -storetype PKCS12 -keystore "$key_dir/key.p12" \
  -storepass changeit
keytool -certreq -alias request-key -keystore "$key_dir/key.p12" \
  -storepass changeit -ext 'SAN=dns:csr.example.test,ip:192.0.2.1' \
  -ext 'EKU=serverAuth' -file keytool-request.csr
openssl req -new -newkey rsa:2048 -nodes -keyout "$key_dir/key.pem" \
  -subj '/CN=OpenSSL CSR fixture' \
  -addext 'subjectAltName=DNS:openssl.example.test' -outform DER \
  -out openssl-request.der
rm -r "$key_dir"
```

Tests that need other attributes, such as a challenge password, build requests
in memory with a synthetic Ed25519 key.
