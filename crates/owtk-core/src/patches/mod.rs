mod apply;
mod registry;
pub mod scripting;
pub mod types;

pub use apply::{
    PatchApplyContext, apply_patches_to_copy, apply_patches_to_copy_with_report, build_patch_entries,
    has_pending_patch_changes,
};
pub use registry::{all_patches_grouped, patches_for_bootloader, patches_for_firmware};
pub use types::{PatchDiffEntry, PatchDiffReport, PatchEntry, PatchSelection, PatchStatus, PatchWriteRecord};
