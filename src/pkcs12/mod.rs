use crown::{
    asn1::{
        der::{self, Reader},
        oid::{self, ObjectIdentifier},
    },
    core::CoreWrite,
    envelope::EvpHash,
    error::CryptoError,
    kdf::pkcs12kdf,
    pkcs7::ContentInfo,
    pkcs12::{Bag, MacData, Pfx, SafeBag},
    rng::Rng,
    x509::{
        algorithm::{AlgorithmIdentifier, Hash},
        attribute::parse_attributes,
        keys::EncryptedPrivateKeyInfo,
        pbe::{LegacyPbe, LegacyPbeKind, Pbes2, Pbes2Cipher, encrypt_private_key, pkcs12_password},
    },
};
use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

use crate::{
    certificate, certificate_file,
    keystore::{Content, KeystoreEntry, Kind},
};

const MAX_ITERATIONS: u32 = 1_000_000;
const MAX_TOTAL_ITERATIONS: u64 = 2_000_000;
const MAX_SALT_SIZE: usize = 64;
const TRUSTED_KEY_USAGE: &[u64] = &[2, 16, 840, 1, 113894, 746875, 1, 1];
// RFC 7292, appendix C. Crown 0.31 swaps these two OIDs.
const PBE_SHA1_128BIT_RC4: &[u64] = &[1, 2, 840, 113549, 1, 12, 1, 1];
const PBE_SHA1_40BIT_RC4: &[u64] = &[1, 2, 840, 113549, 1, 12, 1, 2];

mod bags;
mod crypto;
mod read;
mod write;

#[cfg(test)]
mod tests;

use bags::*;
pub(crate) use crypto::*;
pub use read::*;
pub use write::*;
