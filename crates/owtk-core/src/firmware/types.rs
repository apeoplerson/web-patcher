use crate::board::BoardGeneration;
use crate::crypto::{CryptoIdentifier, CryptoMethod};

/// Whether a firmware image is in its encrypted or decrypted form.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FirmwareState {
    Encrypted,
    Decrypted,
}

impl std::fmt::Display for FirmwareState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Encrypted => "Encrypted",
            Self::Decrypted => "Decrypted",
        })
    }
}

/// A known firmware entry in the database.
///
/// Each entry pairs a board generation and version number with the
/// SHA-1 hashes of its encrypted and/or decrypted forms, along with
/// the [`CryptoIdentifier`] that specifies which encryption key is
/// used. This is stored per-firmware rather than per-board because
/// the same board (e.g. GT) can use different encryption schemes
/// depending on its bootloader version.
///
/// At least one hash should be `Some` for the entry to be useful.
#[derive(Debug)]
pub struct FirmwareDescriptor {
    pub board: BoardGeneration,
    /// Firmware version number (e.g. `4150`, `6109`).
    pub version: u16,
    /// SHA-1 hash of the encrypted firmware image, if known.
    pub encrypted_hash: Option<[u8; 20]>,
    /// SHA-1 hash of the decrypted firmware image, if known.
    pub decrypted_hash: Option<[u8; 20]>,
    /// SHA-1 hash of the first [`PARTIAL_HASH_SIZE`](super::identify::PARTIAL_HASH_SIZE)
    /// bytes of the **decrypted** firmware image, if known.
    ///
    /// This is used as a fallback when the full-file hash doesn't match
    /// (e.g. because the firmware has been patched).  The partial hash
    /// covers the Cortex-M vector table which is never modified by
    /// patches, so it stays stable across patched and stock variants of
    /// the same firmware version.
    ///
    /// # Populating this field
    ///
    /// Load a stock decrypted firmware that is identified by its full
    /// hash.  The partial hash is logged to the console on successful
    /// exact identification — copy the value into this field.
    pub decrypted_partial_hash: Option<[u8; 20]>,
    /// The crypto identifier that determines which key encrypts this firmware.
    pub crypto_identifier: CryptoIdentifier,
    /// Verified start address of free SRAM (after BSS/stack) for this firmware.
    ///
    /// When present, the SRAM allocator uses the region from this address to
    /// the physical SRAM end for patch variables, instead of guessing from the
    /// initial stack pointer.  Values come from offline static analysis of each
    /// firmware image and are stored in the firmware definition JSON files.
    pub sram_free_start: Option<u32>,
}

impl FirmwareDescriptor {
    /// Returns `true` when this descriptor targets the given board
    /// generation and uses the given crypto identifier.
    pub fn matches(&self, board: BoardGeneration, crypto: &CryptoIdentifier) -> bool {
        self.board == board && self.crypto_identifier == *crypto
    }
}

/// The result of successfully identifying a loaded firmware image.
#[derive(Debug)]
pub struct IdentifiedFirmware {
    /// The matching descriptor from the known firmware database.
    pub descriptor: &'static FirmwareDescriptor,
    /// Whether the loaded image was in encrypted or decrypted form.
    pub state: FirmwareState,
    /// `true` when the firmware was identified by a full-file hash match
    /// (i.e. an exact, byte-for-byte known image).  `false` when it was
    /// identified via a partial hash, meaning the firmware is recognised
    /// but has been modified (e.g. patched).
    pub exact_match: bool,
    /// The crypto identifier that applies to this specific file.
    ///
    /// Usually matches `descriptor.crypto_identifier`, but differs when
    /// the firmware was encrypted with a non-native method (e.g. a `DynIV`
    /// firmware exported for the older v2 static-CTR bootloader).
    pub effective_crypto: CryptoIdentifier,
}

impl IdentifiedFirmware {
    /// Returns `true` when the firmware was loaded in encrypted form.
    pub fn is_encrypted(&self) -> bool {
        self.state == FirmwareState::Encrypted
    }

    /// Shorthand for the effective crypto method.
    pub fn crypto_method(&self) -> CryptoMethod {
        self.effective_crypto.method
    }
}
