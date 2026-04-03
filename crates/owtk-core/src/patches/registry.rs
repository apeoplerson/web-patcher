use std::collections::BTreeMap;
use std::sync::LazyLock;

use super::scripting::{self, CompiledScript};
use super::types::{PatchDefinition, PatchTarget};
use crate::board::BoardGeneration;

// The build script (build.rs) scans src/patches/scripts/firmware/ and
// src/patches/scripts/bootloader/ for .rhai files and writes a JSON
// array of script source strings per directory.
//
// To add a new patch, drop a .rhai file into the appropriate
// subdirectory and rebuild — the build script picks it up automatically.
static FIRMWARE_PATCH_SCRIPTS: &str = include_str!(concat!(env!("OUT_DIR"), "/firmware_patch_scripts.json"));
static BOOTLOADER_PATCH_SCRIPTS: &str = include_str!(concat!(env!("OUT_DIR"), "/bootloader_patch_scripts.json"));

/// The fully parsed, merged patch registry (firmware + bootloader).
///
/// Lazily initialised on first access.  Each script source is compiled,
/// its `patch()` function called to extract metadata, and the result
/// flattened into one [`PatchDefinition`] per `(board, version)` pair.
static PATCH_REGISTRY: LazyLock<Vec<PatchDefinition>> = LazyLock::new(|| {
    let mut defs = Vec::new();
    let mut compiled_scripts = Vec::new();

    load_scripts(FIRMWARE_PATCH_SCRIPTS, PatchTarget::Firmware, &mut defs, &mut compiled_scripts);
    load_scripts(BOOTLOADER_PATCH_SCRIPTS, PatchTarget::Bootloader, &mut defs, &mut compiled_scripts);

    if !compiled_scripts.is_empty() {
        scripting::compile_scripts(compiled_scripts);
    }

    defs
});

/// Parses and compiles a JSON array of script sources, appending the
/// resulting definitions and compiled scripts to the provided vectors.
fn load_scripts(
    json: &str,
    target: PatchTarget,
    defs: &mut Vec<PatchDefinition>,
    compiled_scripts: &mut Vec<(String, CompiledScript)>,
) {
    let sources: Vec<String> =
        serde_json::from_str(json).unwrap_or_else(|e| panic!("failed to parse embedded {target} patch scripts: {e}"));

    for source in &sources {
        let (ast, info) =
            scripting::compile_and_extract(source).unwrap_or_else(|e| panic!("{target} patch script error: {e:#}"));

        // Flatten boards × versions into individual PatchDefinitions.
        for (board, version_entries) in &info.boards {
            for ve in version_entries {
                let params = scripting::extract_params(&ast, &ve.targets);

                for &version in &ve.versions {
                    let key = scripting::cache_key(&info.id, *board, version);

                    compiled_scripts.push((key, CompiledScript { ast: ast.clone(), params: params.clone() }));

                    defs.push(PatchDefinition {
                        id: info.id.clone(),
                        name: info.name.clone(),
                        description: info.description.clone(),
                        target,
                        board: *board,
                        version,
                        targets: ve.targets.clone(),
                        experimental: info.experimental,
                        sram: info.sram.clone(),
                    });
                }
            }
        }
    }
}

/// Returns all patch definitions that target the given board generation and
/// firmware version.
pub fn patches_for_firmware(board: BoardGeneration, version: u16) -> Vec<&'static PatchDefinition> {
    PATCH_REGISTRY
        .iter()
        .filter(|p| p.target == PatchTarget::Firmware && p.board == board && p.version == version)
        .collect()
}

/// Returns all patch definitions that target the given board generation and
/// bootloader version.
pub fn patches_for_bootloader(board: BoardGeneration, version: u16) -> Vec<&'static PatchDefinition> {
    PATCH_REGISTRY
        .iter()
        .filter(|p| p.target == PatchTarget::Bootloader && p.board == board && p.version == version)
        .collect()
}

/// Returns every patch definition grouped by board generation and then by
/// version number.  Within each version the patches are in registry order.
///
/// The outer map is sorted by `BoardGeneration` variant order, and the inner
/// map is sorted by version number.
pub fn all_patches_grouped() -> BTreeMap<BoardGeneration, BTreeMap<u16, Vec<&'static PatchDefinition>>> {
    let mut grouped: BTreeMap<BoardGeneration, BTreeMap<u16, Vec<&'static PatchDefinition>>> = BTreeMap::new();

    for def in PATCH_REGISTRY.iter() {
        grouped.entry(def.board).or_default().entry(def.version).or_default().push(def);
    }

    grouped
}
