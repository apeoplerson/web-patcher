use std::path::Path;
use std::{env, fs};

fn main() {
    collect_patch_scripts(Path::new("src/patches/scripts/firmware"), "firmware_patch_scripts.json");
    collect_patch_scripts(Path::new("src/patches/scripts/bootloader"), "bootloader_patch_scripts.json");

    merge_json_dir(Path::new("src/firmware/defs"), "firmware_registry.json");
    merge_json_dir(Path::new("src/bootloader/defs"), "bootloader_registry.json");
}

/// Scans `scripts_dir` for `.rhai` files, reads each one, and writes a
/// JSON array of script source strings to `$OUT_DIR/{out_name}`.
///
/// Each element is a JSON string containing the raw Rhai script content.
/// At runtime, the registry module compiles each script and calls its
/// `patch()` function to extract metadata.
fn collect_patch_scripts(scripts_dir: &Path, out_name: &str) {
    println!("cargo:rerun-if-changed={}", scripts_dir.display());

    let mut scripts: Vec<String> = Vec::new();

    if scripts_dir.is_dir() {
        let mut rhai_files: Vec<_> = fs::read_dir(scripts_dir)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", scripts_dir.display()))
            .filter_map(|entry| {
                let entry = entry.expect("failed to read directory entry");
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("rhai") { Some(path) } else { None }
            })
            .collect();

        // Sort for deterministic output regardless of filesystem ordering.
        rhai_files.sort();

        for path in rhai_files {
            println!("cargo:rerun-if-changed={}", path.display());

            let content =
                fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));

            scripts.push(content);
        }
    }

    let merged =
        serde_json::to_string_pretty(&scripts).unwrap_or_else(|e| panic!("failed to serialize patch scripts: {e}"));

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_path = Path::new(&out_dir).join(out_name);
    fs::write(&out_path, merged).unwrap_or_else(|e| panic!("failed to write {}: {e}", out_path.display()));
}

/// Scans `defs_dir` for JSON files, merges their top-level arrays into a
/// single JSON array, and writes the result to `$OUT_DIR/{out_name}`.
///
/// Each JSON file must be a top-level array (`[ ... ]`) or a single
/// object.  Array contents are concatenated; objects become array elements.
fn merge_json_dir(defs_dir: &Path, out_name: &str) {
    println!("cargo:rerun-if-changed={}", defs_dir.display());

    let mut merged: Vec<serde_json::Value> = Vec::new();

    if defs_dir.is_dir() {
        let mut json_files: Vec<_> = fs::read_dir(defs_dir)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", defs_dir.display()))
            .filter_map(|entry| {
                let entry = entry.expect("failed to read directory entry");
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("json") { Some(path) } else { None }
            })
            .collect();

        json_files.sort();

        for path in json_files {
            println!("cargo:rerun-if-changed={}", path.display());

            let content =
                fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
            let value: serde_json::Value =
                serde_json::from_str(&content).unwrap_or_else(|e| panic!("{}: invalid JSON: {e}", path.display()));

            match value {
                serde_json::Value::Array(items) => merged.extend(items),
                serde_json::Value::Object(_) => merged.push(value),
                _ => panic!("{}: definition file must be a JSON array or object", path.display()),
            }
        }
    }

    let output =
        serde_json::to_string_pretty(&merged).unwrap_or_else(|e| panic!("failed to serialize merged JSON: {e}"));

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_path = Path::new(&out_dir).join(out_name);
    fs::write(&out_path, output).unwrap_or_else(|e| panic!("failed to write {}: {e}", out_path.display()));
}
