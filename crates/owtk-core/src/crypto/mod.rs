use sha1::{Digest as _, Sha1};

pub mod cipher;
mod extract;
mod types;

pub use extract::{CRYPTO_ID_GT_CTR, CRYPTO_ID_GT_CTR_DYN, extract_keys_from_dump};
pub use types::{CryptoIdentifier, CryptoKey, CryptoMethod};

/// Computes the SHA-1 hash of the given data.
pub fn sha1_hash(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Decodes a hex string into a `[u8; 20]` SHA-1 hash.
///
/// Panics with a descriptive message on invalid input — this is only
/// called during registry initialisation where bad data is a build-time
/// bug.
pub fn decode_sha1_hex(hex_str: &str) -> [u8; 20] {
    let bytes = hex::decode(hex_str).unwrap_or_else(|e| panic!("invalid hex in registry: {e} ({hex_str:?})"));
    bytes.try_into().unwrap_or_else(|v: Vec<u8>| panic!("hash must be exactly 20 bytes, got {} ({hex_str:?})", v.len()))
}

/// Parses a hex string (with optional `0x`/`0X` prefix) into a `u32`.
///
/// Panics on invalid input — intended for build-time-embedded registry data.
pub fn parse_hex_u32(s: &str) -> u32 {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u32::from_str_radix(s, 16).unwrap_or_else(|e| panic!("invalid hex u32 '{s}': {e}"))
}
