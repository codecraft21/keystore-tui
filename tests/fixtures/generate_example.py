#!/usr/bin/env python3
"""Regenerate example.jks; requires Python's cryptography package.

Only public certificates are written. Private keys are generated in memory and
discarded. The JKS uses an empty password for convenient interactive testing.
"""

from datetime import datetime, timezone
import hashlib
from pathlib import Path
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def utf(text):
    encoded = text.encode("ascii")
    return struct.pack(">H", len(encoded)) + encoded


def generate():
    body = bytearray(struct.pack(">III", 0xFEEDFEED, 2, 20))
    for index in range(1, 21):
        expired = index <= 2
        alias = f"example-{index:02}" + ("-expired" if expired else "")
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"{alias}.example.test"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "keystore-tui test fixture"),
        ])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(index)
            .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2024 if expired else 2040, 1, 1, tzinfo=timezone.utc))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
            .public_bytes(serialization.Encoding.DER)
        )
        # Trusted-certificate tag, alias, and a fixed creation timestamp.
        body += struct.pack(">I", 2) + utf(alias) + struct.pack(">Q", 1577836800000)
        body += utf("X.509") + struct.pack(">I", len(certificate)) + certificate

    digest = hashlib.sha1(b"Mighty Aphrodite" + body).digest()
    Path(__file__).with_name("example.jks").write_bytes(body + digest)


if __name__ == "__main__":
    generate()
