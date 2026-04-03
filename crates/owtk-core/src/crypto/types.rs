use serde::{Deserialize, Serialize};

use crate::crypto::sha1_hash;

#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CryptoMethod {
    AesECB128,
    AesCTR128,
    AesCTR128DynIv,
}

impl std::fmt::Display for CryptoMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AesECB128 => "AES-128-ECB",
            Self::AesCTR128 => "AES-128-CTR",
            Self::AesCTR128DynIv => "AES-128-CTR-DynIV",
        })
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CryptoIdentifier {
    pub method: CryptoMethod,
    pub key_hash: [u8; 20],
    pub iv_hash: Option<[u8; 20]>,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CryptoKey {
    pub identifier: CryptoIdentifier,
    pub key: [u8; 16],
    pub iv: Option<[u8; 16]>,
}

impl CryptoKey {
    /// Finds the first key in `keys` whose identifier matches `ident`.
    pub fn find_by_identifier(keys: &[Self], ident: &CryptoIdentifier) -> Option<Self> {
        keys.iter().find(|k| k.identifier == *ident).copied()
    }

    /// Produces a hex-encoded SHA-1 fingerprint of the key material
    /// (key bytes followed by the IV bytes, if present).
    ///
    /// Used in the UI to display a stable, compact identifier for a
    /// loaded key without exposing the raw bytes in the header.
    pub fn display_hash(&self) -> String {
        let mut buf = [0u8; 32];
        buf[..16].copy_from_slice(&self.key);
        let len = if let Some(iv) = &self.iv {
            buf[16..32].copy_from_slice(iv);
            32
        } else {
            16
        };
        hex::encode(sha1_hash(buf.get(..len).expect("len is 16 or 32, within buffer")))
    }
}
