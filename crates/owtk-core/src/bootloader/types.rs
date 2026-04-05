use crate::board::BoardGeneration;

/// A known bootloader entry in the database.
///
/// Each entry pairs a board generation and version number with the
/// SHA-1 hash of the bootloader region.  Because bootloader version
/// numbers overlap between board generations (e.g. version 3 exists
/// for both XR and GT), the `board` field is essential for
/// disambiguation.
#[derive(Debug)]
pub struct BootloaderDescriptor {
    pub board: BoardGeneration,
    /// Bootloader version number.
    pub version: u16,
    /// SHA-1 hash of the full bootloader region.
    pub hash: [u8; 20],
    /// SHA-1 hash of the first [`PARTIAL_HASH_SIZE`](crate::crypto::PARTIAL_HASH_SIZE)
    /// bytes of the bootloader, if known.
    ///
    /// Used as a fallback when the full hash doesn't match (e.g.
    /// because the bootloader has been patched).  The partial hash
    /// covers the Cortex-M vector table which is unique per build
    /// but never modified by patches.
    pub partial_hash: Option<[u8; 20]>,
    /// Verified start address of free SRAM for this bootloader.
    ///
    /// When present, the SRAM allocator uses the region from this address
    /// to the physical SRAM end for patch variables.
    pub sram_free_start: Option<u32>,
}

/// The result of successfully identifying a bootloader image.
#[derive(Debug)]
pub struct IdentifiedBootloader {
    /// The matching descriptor from the known bootloader database.
    pub descriptor: &'static BootloaderDescriptor,
    /// `true` when the bootloader was identified by a full hash match.
    /// `false` when identified via a partial hash (modified bootloader).
    pub exact_match: bool,
}
