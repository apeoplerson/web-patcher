mod identify;
mod registry;

pub mod types;

pub use identify::identify_firmware;
pub use registry::known_firmwares;
pub use types::{FirmwareState, IdentifiedFirmware};
