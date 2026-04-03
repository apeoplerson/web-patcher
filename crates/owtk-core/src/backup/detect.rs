use super::config::{BackupConfig, parse_f1_config, parse_f4_config, read_f4_otp_serial};
use super::layout::{
    F1_BOOTLOADER_END, F1_BOOTLOADER_START, F1_CONFIG_PRIMARY_END, F1_CONFIG_PRIMARY_START, F1_FIRMWARE_END,
    F1_FIRMWARE_START, F4_BOOTLOADER_END, F4_BOOTLOADER_START, F4_CONFIG_A_END, F4_CONFIG_A_START, F4_CONFIG_B_END,
    F4_CONFIG_B_START, F4_FIRMWARE_END, F4_FIRMWARE_START,
};
use crate::board::McuFamily;
use crate::bootloader::{IdentifiedBootloader, identify_bootloader};
use crate::crypto::CryptoKey;
use crate::firmware::{IdentifiedFirmware, identify_firmware};

/// A fully parsed flash backup.
pub struct ParsedBackup {
    /// The raw backup data.
    pub data: Vec<u8>,
    /// The MCU family determined from the file size.
    pub mcu_family: McuFamily,
    /// Whether the bootloader region contains data (not all `0xFF`).
    pub bootloader_present: bool,
    /// The identified bootloader, if it matched the registry.
    pub bootloader: Option<IdentifiedBootloader>,
    /// Whether the firmware region contains data (not all `0xFF`).
    pub firmware_present: bool,
    /// The identified firmware extracted from the backup.
    pub firmware: Option<IdentifiedFirmware>,
    /// The bootloader version stored in flash (u16 LE at the version offset).
    /// Editable by the user; written back on save.
    pub bootloader_version: Option<u16>,
    /// The original bootloader version read from the raw data (for reset).
    pub original_bootloader_version: Option<u16>,
    /// The config as originally parsed from the backup (immutable reference copy).
    pub original_config: BackupConfig,
    /// The working copy that the UI edits.
    pub config: BackupConfig,
}

impl ParsedBackup {
    /// Reads the bootloader version (u16 LE) from the raw backup data.
    ///
    /// Returns `None` when the field is erased (`0xFFFF`).
    pub fn read_bootloader_version(&self) -> Option<u16> {
        let offset = self.mcu_family.bootloader_version_offset();
        let bytes: [u8; 2] = self.data.get(offset..offset + 2)?.try_into().ok()?;
        let val = u16::from_le_bytes(bytes);
        if val == 0xFFFF { None } else { Some(val) }
    }

    /// Writes the current [`bootloader_version`](Self::bootloader_version)
    /// into the given data buffer at the correct offset for this MCU family.
    ///
    /// Writes the erased sentinel (`0xFFFF`) when the version is `None`.
    pub fn write_bootloader_version(&self, data: &mut [u8]) {
        let offset = self.mcu_family.bootloader_version_offset();
        let val = self.bootloader_version.unwrap_or(0xFFFF);
        data.get_mut(offset..offset + 2)
            .expect("backup data too small for bootloader version field")
            .copy_from_slice(&val.to_le_bytes());
    }

    /// Resets [`bootloader_version`](Self::bootloader_version) and
    /// [`original_bootloader_version`](Self::original_bootloader_version)
    /// by re-reading the value from the raw data.
    pub fn reload_bootloader_version(&mut self) {
        let v = self.read_bootloader_version();
        self.bootloader_version = v;
        self.original_bootloader_version = v;
    }

    /// Returns a descriptive default filename for saving this backup.
    ///
    /// Format: `{board}_{bl_version}_{fw_version}.bin` (all lowercase).
    ///
    /// The board name comes from the identified bootloader (falls back
    /// to the MCU family).  Version segments are omitted when unknown;
    /// the `bl`/`fw` prefix is only added when the respective image
    /// was identified.
    pub fn default_filename(&self) -> String {
        let board =
            self.bootloader.as_ref().map_or_else(|| self.mcu_family.to_string(), |b| b.descriptor.board.to_string());

        let bl = match self.bootloader.as_ref() {
            Some(b) => format!("_bl{}", b.descriptor.version),
            None => "_no_bl".to_owned(),
        };
        let fw = match self.firmware.as_ref() {
            Some(f) => format!("_fw{}", f.descriptor.version),
            None => "_no_fw".to_owned(),
        };

        format!("{board}{bl}{fw}.bin").to_lowercase()
    }
}

/// Attempts to detect whether `data` is a full flash backup and, if
/// so, parse its contents.
pub fn detect_and_parse_backup(data: Vec<u8>, keys: Option<&[CryptoKey]>) -> Option<ParsedBackup> {
    let mcu_family = McuFamily::from_size(data.len())?;

    match mcu_family {
        McuFamily::F1 => parse_f1_backup(data, keys),
        McuFamily::F4 => parse_f4_backup(data, keys),
    }
}

/// Returns `true` when the region contains at least one non-`0xFF` byte.
fn region_has_data(data: &[u8]) -> bool {
    data.iter().any(|&b| b != 0xFF)
}

fn parse_f1_backup(data: Vec<u8>, keys: Option<&[CryptoKey]>) -> Option<ParsedBackup> {
    let bootloader_bytes = data.get(F1_BOOTLOADER_START..F1_BOOTLOADER_END)?;
    let firmware_bytes = data.get(F1_FIRMWARE_START..F1_FIRMWARE_END)?;
    let config_page = data.get(F1_CONFIG_PRIMARY_START..F1_CONFIG_PRIMARY_END)?;

    let bootloader_present = region_has_data(bootloader_bytes);
    let firmware_present = region_has_data(firmware_bytes);
    let bootloader = if bootloader_present { identify_bootloader(bootloader_bytes) } else { None };
    let firmware = if firmware_present { identify_firmware(firmware_bytes, keys) } else { None };
    let config = parse_f1_config(config_page);

    let mut parsed = ParsedBackup {
        data,
        mcu_family: McuFamily::F1,
        bootloader_present,
        bootloader,
        firmware_present,
        firmware,
        bootloader_version: None,
        original_bootloader_version: None,
        original_config: config.clone(),
        config,
    };
    parsed.reload_bootloader_version();
    Some(parsed)
}

fn parse_f4_backup(data: Vec<u8>, keys: Option<&[CryptoKey]>) -> Option<ParsedBackup> {
    let bootloader_bytes = data.get(F4_BOOTLOADER_START..F4_BOOTLOADER_END)?;
    let firmware_bytes = data.get(F4_FIRMWARE_START..F4_FIRMWARE_END)?;
    let sector_a = data.get(F4_CONFIG_A_START..F4_CONFIG_A_END)?;
    let sector_b = data.get(F4_CONFIG_B_START..F4_CONFIG_B_END)?;

    let bootloader_present = region_has_data(bootloader_bytes);
    let firmware_present = region_has_data(firmware_bytes);
    let bootloader = if bootloader_present { identify_bootloader(bootloader_bytes) } else { None };
    let firmware = if firmware_present { identify_firmware(firmware_bytes, keys) } else { None };
    let mut config = parse_f4_config(sector_a, sector_b);

    // Read OTP serial from Sector 4.
    let (otp_lo, otp_hi) = read_f4_otp_serial(&data);
    config.otp_serial_lo = otp_lo;
    config.otp_serial_hi = otp_hi;

    let mut parsed = ParsedBackup {
        data,
        mcu_family: McuFamily::F4,
        bootloader_present,
        bootloader,
        firmware_present,
        firmware,
        bootloader_version: None,
        original_bootloader_version: None,
        original_config: config.clone(),
        config,
    };
    parsed.reload_bootloader_version();
    Some(parsed)
}
