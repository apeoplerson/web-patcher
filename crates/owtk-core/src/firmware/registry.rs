use std::sync::LazyLock;

use serde::Deserialize;

use super::types::FirmwareDescriptor;
use crate::board::BoardGeneration;
use crate::crypto::{CryptoIdentifier, CryptoMethod, decode_sha1_hex, parse_hex_u32};

// The build script (build.rs) scans src/firmware/defs/ for JSON files,
// merges them into a single JSON array, and writes the result to
// $OUT_DIR/firmware_registry.json.
//
// Each firmware def file is a JSON object with a top-level `board` field
// and a `firmwares` array, so the board only needs to be specified once
// per file rather than repeated on every entry.
//
// To add a new firmware, just drop a JSON file into src/firmware/defs/
// and rebuild — the build script picks it up automatically.
static FIRMWARE_JSON: &str = include_str!(concat!(env!("OUT_DIR"), "/firmware_registry.json"));

/// The fully parsed, merged firmware registry.
///
/// Lazily initialised on first access.  The JSON is embedded in the
/// binary at compile time, so a parse failure here is always a
/// build-time bug — we panic with a descriptive message rather than
/// propagating an error.
static FIRMWARE_REGISTRY: LazyLock<Vec<FirmwareDescriptor>> = LazyLock::new(|| {
    let groups: Vec<JsonBoardGroup> = serde_json::from_str(FIRMWARE_JSON)
        .unwrap_or_else(|e| panic!("failed to parse embedded firmware registry: {e}"));

    groups
        .into_iter()
        .flat_map(|group| {
            let board = group.board;
            group.firmwares.into_iter().map(move |entry| entry.into_descriptor(board))
        })
        .collect()
});

/// Returns every known firmware descriptor from the embedded database.
pub fn known_firmwares() -> &'static [FirmwareDescriptor] {
    &FIRMWARE_REGISTRY
}

// These mirror the on-disk JSON format.  Each file is an object with a
// `board` field and a `firmwares` array, so the board generation is
// specified once per file rather than repeated on every entry.
//
// The firmware entries use plain hex strings for hashes, then convert
// into the runtime `FirmwareDescriptor` / `CryptoIdentifier` types.
// This avoids adding custom serde implementations to the shared crypto
// types (which would break existing app-state serialisation).

#[derive(Deserialize)]
struct JsonBoardGroup {
    board: BoardGeneration,
    firmwares: Vec<JsonFirmwareEntry>,
}

#[derive(Deserialize)]
struct JsonFirmwareEntry {
    version: u16,
    #[serde(default)]
    encrypted_hash: Option<String>,
    #[serde(default)]
    decrypted_hash: Option<String>,
    #[serde(default)]
    decrypted_partial_hash: Option<String>,
    #[serde(default)]
    sram_free_start: Option<String>,
    crypto: JsonCryptoIdentifier,
}

#[derive(Deserialize)]
struct JsonCryptoIdentifier {
    method: CryptoMethod,
    key_hash: String,
    #[serde(default)]
    iv_hash: Option<String>,
}

impl JsonFirmwareEntry {
    fn into_descriptor(self, board: BoardGeneration) -> FirmwareDescriptor {
        FirmwareDescriptor {
            board,
            version: self.version,
            encrypted_hash: self.encrypted_hash.as_deref().map(decode_sha1_hex),
            decrypted_hash: self.decrypted_hash.as_deref().map(decode_sha1_hex),
            decrypted_partial_hash: self.decrypted_partial_hash.as_deref().map(decode_sha1_hex),
            crypto_identifier: self.crypto.into_identifier(),
            sram_free_start: self.sram_free_start.as_deref().map(parse_hex_u32),
        }
    }
}

impl JsonCryptoIdentifier {
    fn into_identifier(self) -> CryptoIdentifier {
        CryptoIdentifier {
            method: self.method,
            key_hash: decode_sha1_hex(&self.key_hash),
            iv_hash: self.iv_hash.as_deref().map(decode_sha1_hex),
        }
    }
}
