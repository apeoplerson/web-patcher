use std::sync::LazyLock;

use serde::Deserialize;

use super::types::BootloaderDescriptor;
use crate::board::BoardGeneration;
use crate::crypto::{decode_sha1_hex, parse_hex_u32};

// The build script (build.rs) scans src/bootloader/defs/ for JSON files,
// merges them into a single JSON array, and writes the result to
// $OUT_DIR/bootloader_registry.json.
//
// Each bootloader def file is a JSON object with a top-level `board`
// field and a `bootloaders` array.
static BOOTLOADER_JSON: &str = include_str!(concat!(env!("OUT_DIR"), "/bootloader_registry.json"));

/// The fully parsed, merged bootloader registry.
static BOOTLOADER_REGISTRY: LazyLock<Vec<BootloaderDescriptor>> = LazyLock::new(|| {
    let groups: Vec<JsonBoardGroup> = serde_json::from_str(BOOTLOADER_JSON)
        .unwrap_or_else(|e| panic!("failed to parse embedded bootloader registry: {e}"));

    groups
        .into_iter()
        .flat_map(|group| {
            let board = group.board;
            group.bootloaders.into_iter().map(move |entry| entry.into_descriptor(board))
        })
        .collect()
});

/// Returns every known bootloader descriptor from the embedded database.
pub fn known_bootloaders() -> &'static [BootloaderDescriptor] {
    &BOOTLOADER_REGISTRY
}

#[derive(Deserialize)]
struct JsonBoardGroup {
    board: BoardGeneration,
    bootloaders: Vec<JsonBootloaderEntry>,
}

#[derive(Deserialize)]
struct JsonBootloaderEntry {
    version: u16,
    hash: String,
    #[serde(default)]
    partial_hash: Option<String>,
    #[serde(default)]
    sram_free_start: Option<String>,
}

impl JsonBootloaderEntry {
    fn into_descriptor(self, board: BoardGeneration) -> BootloaderDescriptor {
        BootloaderDescriptor {
            board,
            version: self.version,
            hash: decode_sha1_hex(&self.hash),
            partial_hash: self.partial_hash.as_deref().map(decode_sha1_hex),
            sram_free_start: self.sram_free_start.as_deref().map(parse_hex_u32),
        }
    }
}
