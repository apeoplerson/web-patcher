use super::registry::known_bootloaders;
use super::types::IdentifiedBootloader;
use crate::crypto::sha1_hash;

/// Number of leading bytes used for partial-hash identification.
///
/// Same value as firmware identification — covers the Cortex-M vector
/// table which is unique per build but never modified by patches.
pub const PARTIAL_HASH_SIZE: usize = 0x200;

/// Computes the partial identification hash for a bootloader buffer.
///
/// Returns `None` if the buffer is shorter than [`PARTIAL_HASH_SIZE`].
fn partial_hash(data: &[u8]) -> Option<[u8; 20]> {
    Some(sha1_hash(data.get(..PARTIAL_HASH_SIZE)?))
}

/// Attempts to identify a bootloader image by hashing it and matching
/// against the known bootloader database.
///
/// The matching strategy mirrors the firmware identification approach:
///
/// 1. **Exact match** — full SHA-1 against the descriptor's `hash`.
/// 2. **Partial match** — SHA-1 of the first [`PARTIAL_HASH_SIZE`]
///    bytes against `partial_hash`.  This catches patched bootloaders
///    whose vector table is still intact.
///
/// Returns `None` if the bootloader is not recognised.
pub fn identify_bootloader(data: &[u8]) -> Option<IdentifiedBootloader> {
    if data.is_empty() {
        return None;
    }

    let bootloaders = known_bootloaders();
    let hash = sha1_hash(data);

    // ── Pass 1: exact full-file hash match ──────────────────────────
    for descriptor in bootloaders {
        if descriptor.hash == hash {
            return Some(IdentifiedBootloader { descriptor, exact_match: true });
        }
    }

    // ── Pass 2: partial hash fallback ───────────────────────────────
    if let Some(p_hash) = partial_hash(data) {
        for descriptor in bootloaders {
            if let Some(expected) = &descriptor.partial_hash
                && *expected == p_hash
            {
                return Some(IdentifiedBootloader { descriptor, exact_match: false });
            }
        }
    }

    None
}
