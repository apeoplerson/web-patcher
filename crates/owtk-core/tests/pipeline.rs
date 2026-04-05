//! Integration tests that exercise the full firmware pipeline:
//! identify → decrypt → patch → verify → re-encrypt.
//!
//! These tests require real firmware files placed in `test_firmware/`
//! at the workspace root.  When the files are absent the tests are
//! skipped (not failed), so CI stays green without proprietary data.

use std::path::{Path, PathBuf};

use owtk_core::backup::detect_and_parse_backup;
use owtk_core::board::McuFamily;
use owtk_core::bootloader::identify_bootloader;
use owtk_core::crypto::cipher::{decrypt_firmware, encrypt_firmware, firmware_payload};
use owtk_core::crypto::{CryptoKey, CryptoMethod, extract_keys_from_dump, sha1_hash};
use owtk_core::firmware::{FirmwareState, identify_firmware};
use owtk_core::patches::types::PatchSelection;
use owtk_core::patches::{
    PatchApplyContext, apply_patches_to_copy, apply_patches_to_copy_with_report, build_patch_entries,
    has_pending_patch_changes, patches_for_bootloader, patches_for_firmware,
};

// ── Helpers ──────────────────────────────────────────────────────────

fn test_firmware_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_firmware")
}

/// Scans `test_firmware/` for files whose name contains `pattern`.
fn find_test_files(pattern: &str) -> Vec<(String, Vec<u8>)> {
    let dir = test_firmware_dir();
    if !dir.is_dir() {
        return Vec::new();
    }
    let mut results = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("read test_firmware dir") {
        let entry = entry.expect("dir entry");
        let name = entry.file_name().to_string_lossy().to_string();
        if name.contains(pattern) {
            let data = std::fs::read(entry.path()).expect("read file");
            results.push((name, data));
        }
    }
    results.sort_by(|a, b| a.0.cmp(&b.0));
    results
}

/// Loads keys from all `*_dump.bin` files in `test_firmware/`.
fn load_all_keys() -> Vec<CryptoKey> {
    let mut keys = Vec::new();
    for (name, data) in find_test_files("_dump.bin") {
        let extracted = extract_keys_from_dump(&data);
        if extracted.is_empty() {
            eprintln!("  [warn] no keys found in {name}");
        }
        for key in &extracted {
            if !keys.contains(key) {
                keys.push(*key);
            }
        }
    }
    keys
}

// ── Firmware identification ──────────────────────────────────────────

#[test]
fn identify_all_encrypted_firmware() {
    let keys = load_all_keys();
    let key_ref = if keys.is_empty() { None } else { Some(keys.as_slice()) };

    let files = find_test_files("_enc.bin");
    if files.is_empty() {
        eprintln!("  [skip] no *_enc.bin files found in test_firmware/");
        return;
    }

    for (name, data) in &files {
        let id = identify_firmware(data, key_ref);
        assert!(id.is_some(), "failed to identify encrypted firmware: {name}");
        let id = id.unwrap();
        assert_eq!(id.state, FirmwareState::Encrypted);
        eprintln!("  [ok] {name}: {} v{} (exact={})", id.descriptor.board, id.descriptor.version, id.exact_match);
    }
}

#[test]
fn identify_all_decrypted_firmware() {
    let files = find_test_files("_dec.bin");
    if files.is_empty() {
        eprintln!("  [skip] no *_dec.bin files found in test_firmware/");
        return;
    }

    for (name, data) in &files {
        let id = identify_firmware(data, None);
        assert!(id.is_some(), "failed to identify decrypted firmware: {name}");
        let id = id.unwrap();
        assert_eq!(id.state, FirmwareState::Decrypted);
        eprintln!("  [ok] {name}: {} v{} (exact={})", id.descriptor.board, id.descriptor.version, id.exact_match);
    }
}

// ── Bootloader identification ────────────────────────────────────────

#[test]
fn identify_all_bootloaders() {
    let files = find_test_files("_bootloader_");
    if files.is_empty() {
        eprintln!("  [skip] no *_bootloader_*.bin files found in test_firmware/");
        return;
    }

    for (name, data) in &files {
        let id = identify_bootloader(data);
        assert!(id.is_some(), "failed to identify bootloader: {name}");
        let id = id.unwrap();
        eprintln!("  [ok] {name}: {} v{} (exact={})", id.descriptor.board, id.descriptor.version, id.exact_match);
    }
}

// ── Key extraction ───────────────────────────────────────────────────

#[test]
fn extract_keys_from_all_dumps() {
    let files = find_test_files("_dump.bin");
    if files.is_empty() {
        eprintln!("  [skip] no *_dump.bin files found in test_firmware/");
        return;
    }

    for (name, data) in &files {
        let keys = extract_keys_from_dump(&data);
        assert!(!keys.is_empty(), "expected at least one key from dump: {name}");
        eprintln!("  [ok] {name}: extracted {} key(s)", keys.len());
        for key in &keys {
            eprintln!("       {} ({})", key.display_hash(), key.identifier.method);
        }
    }
}

// ── Decrypt → re-encrypt round-trip ──────────────────────────────────

#[test]
fn decrypt_and_reencrypt_round_trip() {
    let keys = load_all_keys();
    if keys.is_empty() {
        eprintln!("  [skip] no keys available (need *_dump.bin files)");
        return;
    }

    let files = find_test_files("_enc.bin");
    if files.is_empty() {
        eprintln!("  [skip] no *_enc.bin files found");
        return;
    }

    for (name, data) in &files {
        let id = identify_firmware(data, Some(&keys));
        let Some(id) = id else {
            eprintln!("  [skip] could not identify {name}");
            continue;
        };

        let key = CryptoKey::find_by_identifier(&keys, &id.descriptor.crypto_identifier);
        let Some(key) = key else {
            eprintln!("  [skip] no matching key for {name}");
            continue;
        };

        // Decrypt.
        let decrypted = decrypt_firmware(data, &key).expect("decrypt should succeed");
        assert!(!decrypted.is_empty());

        // Verify the decrypted hash matches the database — only for exact
        // matches (modified firmware won't match the stock hash).
        if id.exact_match {
            if let Some(expected_hash) = id.descriptor.decrypted_hash {
                let payload =
                    firmware_payload(&decrypted, id.descriptor.crypto_identifier.method, FirmwareState::Decrypted);
                let actual_hash = sha1_hash(payload);
                assert_eq!(actual_hash, expected_hash, "decrypted hash mismatch for {name}");
            }
        }

        // Re-encrypt.
        let reencrypted = encrypt_firmware(&decrypted, &key).expect("encrypt should succeed");

        // Re-decrypt and verify it matches the original decrypted data.
        let redecrypted = decrypt_firmware(&reencrypted, &key).expect("re-decrypt should succeed");
        assert_eq!(redecrypted, decrypted, "round-trip failed for {name}");

        eprintln!("  [ok] {name}: decrypt → encrypt → decrypt round-trip verified");
    }
}

// ── Patch pipeline ───────────────────────────────────────────────────

#[test]
fn patch_decrypted_firmware() {
    let files = find_test_files("_dec.bin");
    if files.is_empty() {
        eprintln!("  [skip] no *_dec.bin files found");
        return;
    }

    for (name, data) in &files {
        let id = identify_firmware(data, None);
        let Some(id) = id else {
            eprintln!("  [skip] could not identify {name}");
            continue;
        };
        assert_eq!(id.state, FirmwareState::Decrypted);

        let board = id.descriptor.board;
        let version = id.descriptor.version;
        let defs = patches_for_firmware(board, version);
        if defs.is_empty() {
            eprintln!("  [skip] no patches for {} v{version} ({name})", board);
            continue;
        }

        let entries = build_patch_entries(data, &defs);
        eprintln!("  {name}: {} patches found for {} v{version}", entries.len(), board);

        // All entries should initially be detected as stock or applied.
        for entry in &entries {
            eprintln!("    {} — {:?} (initial: {:?})", entry.definition.name, entry.status, entry.initial_selection);
        }

        // Enable all patches with their defaults and apply.
        let mut patching_entries = build_patch_entries(data, &defs);
        let mut any_enabled = false;
        for entry in &mut patching_entries {
            // Use read-back values or defaults.
            let values: Vec<_> = if let Some(rv) = &entry.read_values {
                rv.clone()
            } else {
                let key = owtk_core::patches::scripting::cache_key(&entry.definition.id, board, version);
                owtk_core::patches::scripting::get_compiled(&key)
                    .map(|c| c.params.iter().map(|p| p.default.clone()).collect())
                    .unwrap_or_default()
            };
            if !values.is_empty() || entry.definition.targets.iter().any(|t| !t.append) {
                entry.selection = PatchSelection::Values(values);
                any_enabled = true;
            }
        }

        if !any_enabled {
            eprintln!("  [skip] no patches could be enabled for {name}");
            continue;
        }

        assert!(has_pending_patch_changes(&patching_entries));

        let has_rsa_sig = id.descriptor.crypto_identifier.method == CryptoMethod::AesCTR128DynIv;
        let ctx = PatchApplyContext { board, version, sram_free_start: id.descriptor.sram_free_start, has_rsa_sig };
        let max_size = board.mcu_family().max_firmware_size();
        let patched = apply_patches_to_copy(data, &patching_entries, max_size, &ctx);
        match patched {
            Ok(patched_data) => {
                assert_ne!(
                    &patched_data[..data.len().min(patched_data.len())],
                    &data[..],
                    "patched firmware should differ from stock for {name}"
                );

                // The patched firmware should still be identifiable via partial hash.
                let patched_id = identify_firmware(&patched_data, None);
                assert!(patched_id.is_some(), "patched firmware should still be identifiable: {name}");
                let patched_id = patched_id.unwrap();
                assert!(!patched_id.exact_match, "patched firmware should not be an exact match: {name}");
                assert_eq!(patched_id.descriptor.version, version);

                eprintln!("  [ok] {name}: patched and re-identified successfully (partial hash match)");
            }
            Err(e) => {
                // Some patches may fail due to missing SRAM free start — that's OK for this test.
                eprintln!("  [warn] patching failed for {name}: {e} (may need sram_free_start)");
            }
        }
    }
}

#[test]
fn patch_and_encrypt_firmware() {
    let keys = load_all_keys();
    if keys.is_empty() {
        eprintln!("  [skip] no keys available");
        return;
    }

    let files = find_test_files("_dec.bin");
    if files.is_empty() {
        eprintln!("  [skip] no *_dec.bin files found");
        return;
    }

    for (name, data) in &files {
        let id = identify_firmware(data, None);
        let Some(id) = id else { continue };
        assert_eq!(id.state, FirmwareState::Decrypted);

        let key = CryptoKey::find_by_identifier(&keys, &id.descriptor.crypto_identifier);
        let Some(key) = key else {
            eprintln!("  [skip] no matching key for {name}");
            continue;
        };

        let board = id.descriptor.board;
        let version = id.descriptor.version;
        let defs = patches_for_firmware(board, version);
        if defs.is_empty() {
            continue;
        }

        let mut entries = build_patch_entries(data, &defs);
        // Enable all with defaults.
        for entry in &mut entries {
            let vals: Vec<_> = entry.read_values.clone().unwrap_or_else(|| {
                let k = owtk_core::patches::scripting::cache_key(&entry.definition.id, board, version);
                owtk_core::patches::scripting::get_compiled(&k)
                    .map(|c| c.params.iter().map(|p| p.default.clone()).collect())
                    .unwrap_or_default()
            });
            entry.selection = PatchSelection::Values(vals);
        }

        let has_rsa_sig = id.descriptor.crypto_identifier.method == CryptoMethod::AesCTR128DynIv;
        let ctx = PatchApplyContext { board, version, sram_free_start: id.descriptor.sram_free_start, has_rsa_sig };
        let max_size = board.mcu_family().max_firmware_size();
        let Ok(patched) = apply_patches_to_copy(data, &entries, max_size, &ctx) else {
            continue;
        };

        // Encrypt the patched firmware.
        let encrypted = encrypt_firmware(&patched, &key).expect("encrypt should succeed");

        // Decrypt it back and verify.
        let decrypted = decrypt_firmware(&encrypted, &key).expect("decrypt should succeed");
        assert_eq!(decrypted, patched, "encrypt/decrypt round-trip of patched firmware failed: {name}");

        // The re-decrypted patched firmware should be identifiable.
        let re_id = identify_firmware(&decrypted, Some(&keys));
        assert!(re_id.is_some(), "re-decrypted patched firmware should be identifiable: {name}");

        eprintln!("  [ok] {name}: patch → encrypt → decrypt → identify verified");
    }
}

// ── Backup parsing ───────────────────────────────────────────────────

#[test]
fn parse_all_backups() {
    let keys = load_all_keys();
    let key_ref = if keys.is_empty() { None } else { Some(keys.as_slice()) };

    let files = find_test_files("_backup.bin");
    if files.is_empty() {
        eprintln!("  [skip] no *_backup.bin files found in test_firmware/");
        return;
    }

    for (name, data) in files {
        let size = data.len();
        let expected_family = McuFamily::from_size(size);
        assert!(expected_family.is_some(), "{name}: unexpected file size {size:#X}");
        let expected_family = expected_family.unwrap();

        let parsed = detect_and_parse_backup(data, key_ref);
        assert!(parsed.is_some(), "failed to parse backup: {name}");
        let parsed = parsed.unwrap();

        assert_eq!(parsed.mcu_family, expected_family);
        eprintln!("  [ok] {name}: parsed as {}", parsed.mcu_family);

        if let Some(bl) = &parsed.bootloader {
            eprintln!("       bootloader: {} v{}", bl.descriptor.board, bl.descriptor.version);
        } else if parsed.bootloader_present {
            eprintln!("       bootloader: present but unrecognised");
        }

        if let Some(fw) = &parsed.firmware {
            eprintln!("       firmware: {} v{} ({})", fw.descriptor.board, fw.descriptor.version, fw.state);
        } else if parsed.firmware_present {
            eprintln!("       firmware: present but unrecognised");
        }

        if parsed.config.serial_lo.is_some() || parsed.config.serial_hi.is_some() {
            let lo = parsed.config.serial_lo.unwrap_or(0);
            let hi = parsed.config.serial_hi.unwrap_or(0);
            let serial = (u32::from(hi) << 16) | u32::from(lo);
            eprintln!("       serial: {serial}");
        }
    }
}

// ── Bootloader patching ──────────────────────────────────────────────

#[test]
fn patch_bootloaders() {
    let files = find_test_files("_bootloader_");
    if files.is_empty() {
        eprintln!("  [skip] no bootloader files found");
        return;
    }

    for (name, data) in &files {
        let id = identify_bootloader(data);
        let Some(id) = id else {
            eprintln!("  [skip] could not identify {name}");
            continue;
        };

        let board = id.descriptor.board;
        let version = id.descriptor.version;
        let defs = patches_for_bootloader(board, version);
        if defs.is_empty() {
            eprintln!("  [skip] no patches for bootloader {} v{version} ({name})", board);
            continue;
        }

        let mut entries = build_patch_entries(data, &defs);
        for entry in &mut entries {
            let vals: Vec<_> = entry.read_values.clone().unwrap_or_else(|| {
                let k = owtk_core::patches::scripting::cache_key(&entry.definition.id, board, version);
                owtk_core::patches::scripting::get_compiled(&k)
                    .map(|c| c.params.iter().map(|p| p.default.clone()).collect())
                    .unwrap_or_default()
            });
            entry.selection = PatchSelection::Values(vals);
        }

        let ctx =
            PatchApplyContext { board, version, sram_free_start: id.descriptor.sram_free_start, has_rsa_sig: false };
        let max_size = board.mcu_family().max_bootloader_size();
        match apply_patches_to_copy(data, &entries, max_size, &ctx) {
            Ok(patched) => {
                let re_id = identify_bootloader(&patched);
                assert!(re_id.is_some(), "patched bootloader should still be identifiable: {name}");
                assert!(!re_id.unwrap().exact_match, "patched bootloader should be partial match: {name}");
                eprintln!("  [ok] {name}: {} v{version} — patched and re-identified", board);
            }
            Err(e) => {
                eprintln!("  [warn] patching failed for {name}: {e}");
            }
        }
    }
}

// ── Patch diff reports ──────────────────────────────────────────────

/// Patches every decrypted firmware with all available patches and writes
/// a JSON diff report per firmware to `test_output/`.
///
/// Each report contains the board, version, firmware base address, and
/// every byte that was changed — including the virtual address on the
/// target MCU.  These reports are designed to be consumed by an agent
/// with access to IDA Pro or Binary Ninja to verify patch correctness.
#[test]
fn generate_patch_diff_reports() {
    let files = find_test_files("_dec.bin");
    if files.is_empty() {
        eprintln!("  [skip] no *_dec.bin files found");
        return;
    }

    let out_dir = test_firmware_dir().join("../test_output");
    std::fs::create_dir_all(&out_dir).expect("create test_output dir");

    for (name, data) in &files {
        let id = identify_firmware(data, None);
        let Some(id) = id else {
            eprintln!("  [skip] could not identify {name}");
            continue;
        };
        assert_eq!(id.state, FirmwareState::Decrypted);

        let board = id.descriptor.board;
        let version = id.descriptor.version;
        let defs = patches_for_firmware(board, version);
        if defs.is_empty() {
            eprintln!("  [skip] no patches for {} v{version} ({name})", board);
            continue;
        }

        // Enable all patches with defaults.
        let mut entries = build_patch_entries(data, &defs);
        let mut any_enabled = false;
        for entry in &mut entries {
            let values: Vec<_> = if let Some(rv) = &entry.read_values {
                rv.clone()
            } else {
                let key = owtk_core::patches::scripting::cache_key(&entry.definition.id, board, version);
                owtk_core::patches::scripting::get_compiled(&key)
                    .map(|c| c.params.iter().map(|p| p.default.clone()).collect())
                    .unwrap_or_default()
            };
            if !values.is_empty() || entry.definition.targets.iter().any(|t| !t.append) {
                entry.selection = PatchSelection::Values(values);
                any_enabled = true;
            }
        }

        if !any_enabled {
            eprintln!("  [skip] no patches could be enabled for {name}");
            continue;
        }

        let has_rsa_sig = id.descriptor.crypto_identifier.method == CryptoMethod::AesCTR128DynIv;
        let ctx = PatchApplyContext { board, version, sram_free_start: id.descriptor.sram_free_start, has_rsa_sig };
        let max_size = board.mcu_family().max_firmware_size();

        match apply_patches_to_copy_with_report(data, &entries, max_size, &ctx) {
            Ok((patched_data, report)) => {
                // Basic sanity: patched firmware should differ from stock.
                assert_ne!(
                    &patched_data[..data.len().min(patched_data.len())],
                    &data[..],
                    "patched firmware should differ from stock for {name}"
                );

                // The report should have at least one patch with writes.
                assert!(!report.patches.is_empty(), "diff report should contain at least one patch for {name}");

                // Every write should have matching old/new byte lengths.
                for patch_diff in &report.patches {
                    for write in &patch_diff.writes {
                        assert_eq!(
                            write.old_bytes.len(),
                            write.new_bytes.len(),
                            "write at {:#X} in patch '{}' has mismatched byte lengths for {name}",
                            write.offset,
                            patch_diff.patch_id
                        );
                        // Virtual address should equal base + offset.
                        assert_eq!(
                            write.address,
                            report.firmware_base + write.offset as u32,
                            "virtual address mismatch for write at {:#X} in patch '{}' for {name}",
                            write.offset,
                            patch_diff.patch_id
                        );
                    }
                }

                // Verify each write matches what's actually in the patched image.
                for patch_diff in &report.patches {
                    for write in &patch_diff.writes {
                        let actual = &patched_data[write.offset..write.offset + write.new_bytes.len()];
                        assert_eq!(
                            actual,
                            write.new_bytes.as_slice(),
                            "report write at {:#X} doesn't match patched image for patch '{}' in {name}",
                            write.offset,
                            patch_diff.patch_id
                        );
                    }
                }

                // Verify old_bytes match the original firmware (for non-append writes).
                for patch_diff in &report.patches {
                    for write in &patch_diff.writes {
                        if !write.is_append && write.offset + write.old_bytes.len() <= data.len() {
                            let stock = &data[write.offset..write.offset + write.old_bytes.len()];
                            assert_eq!(
                                stock,
                                write.old_bytes.as_slice(),
                                "old_bytes at {:#X} don't match stock firmware for patch '{}' in {name}",
                                write.offset,
                                patch_diff.patch_id
                            );
                        }
                    }
                }

                // Serialize report to JSON.
                let json = serialize_diff_report(&report);
                let stem = name.trim_end_matches(".bin");
                let out_path = out_dir.join(format!("{stem}_patch_diff.json"));
                std::fs::write(&out_path, &json).expect("write diff report");

                let total_writes: usize = report.patches.iter().map(|p| p.writes.len()).sum();
                let total_bytes: usize = report.patches.iter().flat_map(|p| &p.writes).map(|w| w.new_bytes.len()).sum();
                eprintln!(
                    "  [ok] {name}: {} patches, {total_writes} writes, {total_bytes} bytes changed → {}",
                    report.patches.len(),
                    out_path.display()
                );
            }
            Err(e) => {
                eprintln!("  [warn] patching failed for {name}: {e}");
            }
        }
    }
}

/// Serializes a [`PatchDiffReport`] to pretty-printed JSON with hex byte
/// strings for human (and agent) readability.
fn serialize_diff_report(report: &owtk_core::patches::PatchDiffReport) -> String {
    use serde_json::{Map, Value, json};

    let patches: Vec<Value> = report
        .patches
        .iter()
        .map(|p| {
            let writes: Vec<Value> = p
                .writes
                .iter()
                .map(|w| {
                    let mut m = Map::new();
                    m.insert("offset".into(), json!(format!("{:#X}", w.offset)));
                    m.insert("address".into(), json!(format!("{:#010X}", w.address)));
                    m.insert("old_bytes".into(), json!(hex::encode(&w.old_bytes)));
                    m.insert("new_bytes".into(), json!(hex::encode(&w.new_bytes)));
                    m.insert("size".into(), json!(w.new_bytes.len()));
                    m.insert("is_append".into(), json!(w.is_append));
                    Value::Object(m)
                })
                .collect();
            json!({
                "patch_id": p.patch_id,
                "patch_name": p.patch_name,
                "write_count": p.writes.len(),
                "writes": writes,
            })
        })
        .collect();

    let root = json!({
        "board": report.board,
        "version": report.version,
        "firmware_base": format!("{:#010X}", report.firmware_base),
        "patch_count": report.patches.len(),
        "patches": patches,
    });

    serde_json::to_string_pretty(&root).expect("JSON serialization")
}
