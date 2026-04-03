use serde::{Deserialize, Serialize};

/// Represents a `OneWheel` board model.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BoardGeneration {
    V1,
    V1_2,
    Plus,
    XR,
    Pint,
    GT,
    PintX,
    PintS,
    GTS,
    XRC,
}

impl std::str::FromStr for BoardGeneration {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "V1" => Ok(Self::V1),
            "V1_2" | "V1.2" => Ok(Self::V1_2),
            "Plus" => Ok(Self::Plus),
            "XR" => Ok(Self::XR),
            "Pint" => Ok(Self::Pint),
            "GT" => Ok(Self::GT),
            "PintX" | "Pint X" => Ok(Self::PintX),
            "PintS" | "Pint S" => Ok(Self::PintS),
            "GTS" => Ok(Self::GTS),
            "XRC" => Ok(Self::XRC),
            _ => Err(format!("unknown board generation '{s}'")),
        }
    }
}

impl std::fmt::Display for BoardGeneration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::V1 => "V1",
            Self::V1_2 => "V1.2",
            Self::Plus => "Plus",
            Self::XR => "XR",
            Self::Pint => "Pint",
            Self::PintX => "PintX",
            Self::PintS => "PintS",
            Self::GT => "GT",
            Self::GTS => "GTS",
            Self::XRC => "XRC",
        })
    }
}

impl BoardGeneration {
    /// The MCU family this board generation uses.
    pub fn mcu_family_from_board_gen(self) -> McuFamily {
        match self {
            Self::V1 | Self::V1_2 | Self::Plus | Self::XR | Self::Pint | Self::PintX | Self::PintS => McuFamily::F1,
            Self::GT | Self::GTS | Self::XRC => McuFamily::F4,
        }
    }
}

/// The MCU family that a board generation uses.
///
/// Determines the flash layout and config storage format.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum McuFamily {
    /// STM32F1 — 64 KB flash.
    /// Newer pint and pintx use a 128kb flash chip but we dont support those yet.
    F1,
    /// STM32F4 — 1 MB flash.
    F4,
}

impl std::fmt::Display for McuFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::F1 => "F1",
            Self::F4 => "F4",
        })
    }
}

impl McuFamily {
    /// Maximum firmware image size accepted for OTA updates.
    ///
    /// F1: 0xC800 (51,200 bytes) — firmware lives at 0x08003000..0x0800F800;
    ///     the last two 1 KB pages (0x0800F800..0x08010000) are reserved for
    ///     config primary/backup storage.
    /// F4: 0x5FF00 (393,984 bytes).
    pub fn max_firmware_size(self) -> usize {
        match self {
            Self::F1 => 0xC800,
            Self::F4 => 0x5_FF00,
        }
    }

    /// Flash base address of the firmware region on this MCU.
    ///
    /// F1: `0x0800_3000` (firmware starts after the 12 KB bootloader),
    /// F4: `0x0802_0000` (Sector 5).
    pub fn firmware_base_address(self) -> u32 {
        match self {
            Self::F1 => 0x0800_3000,
            Self::F4 => 0x0802_0000,
        }
    }

    /// Physical end address of the SRAM region (one past the last usable byte).
    ///
    /// F1 (STM32F103): 20 KB → `0x2000_5000`, F4 (STM32F407): 128 KB → `0x2002_0000`.
    pub fn sram_end(self) -> u32 {
        match self {
            Self::F1 => 0x2000_5000,
            Self::F4 => 0x2002_0000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f1_boards_map_to_f1() {
        for board in [
            BoardGeneration::V1,
            BoardGeneration::V1_2,
            BoardGeneration::Plus,
            BoardGeneration::XR,
            BoardGeneration::Pint,
            BoardGeneration::PintX,
            BoardGeneration::PintS,
        ] {
            assert_eq!(board.mcu_family_from_board_gen(), McuFamily::F1, "{board}");
        }
    }

    #[test]
    fn f4_boards_map_to_f4() {
        for board in [BoardGeneration::GT, BoardGeneration::GTS, BoardGeneration::XRC] {
            assert_eq!(board.mcu_family_from_board_gen(), McuFamily::F4, "{board}");
        }
    }

    #[test]
    fn display_parse_round_trip() {
        for name in ["V1", "V1.2", "Plus", "XR", "Pint", "GT", "PintX", "PintS", "GTS", "XRC"] {
            let board: BoardGeneration = name.parse().expect(name);
            let displayed = board.to_string();
            let board2: BoardGeneration = displayed.parse().expect(&displayed);
            assert_eq!(board, board2, "round-trip failed for {name}");
        }
    }

    #[test]
    fn parse_aliases() {
        assert_eq!("V1_2".parse::<BoardGeneration>().expect("V1_2"), BoardGeneration::V1_2);
        assert_eq!("Pint X".parse::<BoardGeneration>().expect("Pint X"), BoardGeneration::PintX);
        assert_eq!("Pint S".parse::<BoardGeneration>().expect("Pint S"), BoardGeneration::PintS);
    }

    #[test]
    fn parse_unknown_fails() {
        assert!("Potato".parse::<BoardGeneration>().is_err());
    }

    #[test]
    fn mcu_family_constants() {
        // F1: 64 KB flash, 20 KB SRAM
        assert_eq!(McuFamily::F1.max_firmware_size(), 0xC800);
        assert_eq!(McuFamily::F1.sram_end(), 0x2000_5000);

        // F4: 1 MB flash, 128 KB SRAM
        assert_eq!(McuFamily::F4.max_firmware_size(), 0x5_FF00);
        assert_eq!(McuFamily::F4.sram_end(), 0x2002_0000);
    }

    #[test]
    fn mcu_family_display() {
        assert_eq!(McuFamily::F1.to_string(), "F1");
        assert_eq!(McuFamily::F4.to_string(), "F4");
    }

    #[test]
    fn flash_size_detection() {
        assert_eq!(McuFamily::from_size(0x1_0000), Some(McuFamily::F1));
        assert_eq!(McuFamily::from_size(0x10_0000), Some(McuFamily::F4));
        assert_eq!(McuFamily::from_size(12345), None);
    }

    #[test]
    fn bootloader_and_firmware_ranges() {
        let f1 = McuFamily::F1;
        assert!(f1.bootloader_range().start < f1.bootloader_range().end);
        assert!(f1.firmware_range().start < f1.firmware_range().end);
        assert!(f1.max_bootloader_size() > 0);

        let f4 = McuFamily::F4;
        assert!(f4.bootloader_range().start < f4.bootloader_range().end);
        assert!(f4.firmware_range().start < f4.firmware_range().end);
        assert!(f4.max_bootloader_size() > 0);
        assert!(f4.max_firmware_size() > f1.max_firmware_size());
    }

    #[test]
    fn board_generation_ordering() {
        // BoardGeneration derives Ord — verify it's consistent.
        assert!(BoardGeneration::V1 < BoardGeneration::XRC);
    }
}
