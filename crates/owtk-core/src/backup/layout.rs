use crate::board::McuFamily;

/// Total size of an F1 flash dump.
pub const F1_FLASH_SIZE: usize = 0x1_0000;

/// Bootloader region in an F1 dump (12 KB).
pub const F1_BOOTLOADER_START: usize = 0x0_0000;
pub const F1_BOOTLOADER_END: usize = 0x0_3000;

/// Firmware region in an F1 dump (~50 KB).
pub const F1_FIRMWARE_START: usize = 0x0_3000;
pub const F1_FIRMWARE_END: usize = 0x0_F800;

/// Bootloader version field in an F1 dump (u16 LE, last 2 bytes of bootloader region).
pub const F1_BOOTLOADER_VERSION: usize = 0x0_2FFE;

/// Config backup page in an F1 dump (1 KB).
pub const F1_CONFIG_BACKUP_START: usize = 0x0_F800;

/// Config primary page in an F1 dump (1 KB).
pub const F1_CONFIG_PRIMARY_START: usize = 0x0_FC00;
pub const F1_CONFIG_PRIMARY_END: usize = 0x1_0000;

/// Total size of an F4 flash dump.
pub const F4_FLASH_SIZE: usize = 0x10_0000;

/// Bootloader region in an F4 dump (Sectors 0-1, 32 KB).
pub const F4_BOOTLOADER_START: usize = 0x0_0000;
pub const F4_BOOTLOADER_END: usize = 0x0_8000;

/// Bootloader version field in an F4 dump (u16 LE, last 2 bytes of bootloader region).
pub const F4_BOOTLOADER_VERSION: usize = 0x0_7FFE;

/// Config Sector A in an F4 dump (Sector 2, 16 KB).
pub const F4_CONFIG_A_START: usize = 0x0_8000;
pub const F4_CONFIG_A_END: usize = 0x0_C000;

/// Config Sector B in an F4 dump (Sector 3, 16 KB).
pub const F4_CONFIG_B_START: usize = 0x0_C000;
pub const F4_CONFIG_B_END: usize = 0x1_0000;

/// Firmware region in an F4 dump (Sectors 5-7, 384 KB).
pub const F4_FIRMWARE_START: usize = 0x2_0000;
pub const F4_FIRMWARE_END: usize = 0x8_0000;

/// OTP `serial_lo` offset within the F4 dump (u16 LE).
pub const F4_OTP_SERIAL_LO: usize = 0x1_0002;

/// OTP `serial_hi` offset within the F4 dump (u16 LE).
pub const F4_OTP_SERIAL_HI: usize = 0x1_0004;

impl McuFamily {
    /// Determines the MCU family from a file's size, if it matches a
    /// known flash dump size.
    pub fn from_size(size: usize) -> Option<Self> {
        match size {
            F1_FLASH_SIZE => Some(Self::F1),
            F4_FLASH_SIZE => Some(Self::F4),
            _ => None,
        }
    }

    /// Returns the byte range of the bootloader region for this MCU family.
    pub fn bootloader_range(self) -> std::ops::Range<usize> {
        match self {
            Self::F1 => F1_BOOTLOADER_START..F1_BOOTLOADER_END,
            Self::F4 => F4_BOOTLOADER_START..F4_BOOTLOADER_END,
        }
    }

    /// Returns the byte range of the firmware region for this MCU family.
    pub fn firmware_range(self) -> std::ops::Range<usize> {
        match self {
            Self::F1 => F1_FIRMWARE_START..F1_FIRMWARE_END,
            Self::F4 => F4_FIRMWARE_START..F4_FIRMWARE_END,
        }
    }

    /// Maximum bootloader image size for this MCU family.
    pub fn max_bootloader_size(self) -> usize {
        self.bootloader_range().len()
    }

    /// Returns the offset of the bootloader version field (u16 LE) for this MCU family.
    pub fn bootloader_version_offset(self) -> usize {
        match self {
            Self::F1 => F1_BOOTLOADER_VERSION,
            Self::F4 => F4_BOOTLOADER_VERSION,
        }
    }
}
