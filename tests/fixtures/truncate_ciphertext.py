"""Copy a PKCS12 store, dropping the last byte of each encrypted safe's ciphertext.

Usage: python3 truncate_ciphertext.py SOURCE.p12 DESTINATION.p12

Only the Python standard library is needed. Enclosing DER lengths are
re-encoded, so the result is well-formed DER whose CBC ciphertext length is not
a multiple of the cipher's block size. Any MacData is left as it is, so use a
store without a MAC.
"""

import sys


def read_tlv(data, offset):
    tag = data[offset]
    length = data[offset + 1]
    offset += 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    return tag, data[offset : offset + length], offset + length


def encode_tlv(tag, content):
    length = len(content)
    if length < 0x80:
        header = bytes([length])
    else:
        size = length.to_bytes((length.bit_length() + 7) // 8, "big")
        header = bytes([0x80 | len(size)]) + size
    return bytes([tag]) + header + content


def parse_all(data):
    """Return the TLVs in data, or None if it is not a run of DER TLVs."""
    tlvs, offset = [], 0
    try:
        while offset < len(data):
            tag, content, offset = read_tlv(data, offset)
            tlvs.append((tag, content))
    except IndexError:
        return None
    return tlvs if offset == len(data) else None


def rewrite(data):
    out = b""
    for tag, content in parse_all(data):
        if tag == 0x80:
            # EncryptedContentInfo's [0] IMPLICIT encryptedContent.
            content = content[:-1]
        elif tag & 0x20:
            content = rewrite(content)
        elif tag == 0x04 and content and parse_all(content):
            # The authenticated safe is DER inside an OCTET STRING.
            content = rewrite(content)
        out += encode_tlv(tag, content)
    return out


source, destination = sys.argv[1:]
with open(source, "rb") as file:
    data = file.read()
with open(destination, "wb") as file:
    file.write(rewrite(data))
