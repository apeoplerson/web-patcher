use owtk_core::board::BoardGeneration;
use owtk_core::firmware::known_firmwares;
use owtk_core::patches::{all_patches_grouped, patches_for_bootloader, patches_for_firmware};

#[test]
fn firmware_registry_loads() {
    let fws = known_firmwares();
    assert!(!fws.is_empty(), "firmware registry should not be empty");
}

#[test]
fn firmware_registry_has_multiple_boards() {
    let fws = known_firmwares();
    let boards: std::collections::HashSet<_> = fws.iter().map(|f| f.board).collect();
    assert!(boards.len() >= 3, "expected at least 3 board generations, got {}", boards.len());
}

#[test]
fn firmware_descriptors_have_at_least_one_hash() {
    for fw in known_firmwares() {
        assert!(
            fw.encrypted_hash.is_some() || fw.decrypted_hash.is_some(),
            "firmware {} v{} has no hashes",
            fw.board,
            fw.version,
        );
    }
}

#[test]
fn firmware_versions_are_nonzero() {
    for fw in known_firmwares() {
        assert!(fw.version > 0, "firmware {} has version 0", fw.board);
    }
}

#[test]
fn patch_registry_loads() {
    let grouped = all_patches_grouped();
    assert!(!grouped.is_empty(), "patch registry should not be empty");
}

#[test]
fn patches_have_valid_metadata() {
    let grouped = all_patches_grouped();
    for (board, versions) in &grouped {
        for (version, defs) in versions {
            for def in defs {
                assert!(!def.id.is_empty(), "patch for {board} v{version} has empty id");
                assert!(!def.name.is_empty(), "patch '{}' for {board} v{version} has empty name", def.id);
                assert!(!def.description.is_empty(), "patch '{}' for {board} v{version} has empty description", def.id);
                assert!(!def.targets.is_empty(), "patch '{}' for {board} v{version} has no targets", def.id);
            }
        }
    }
}

#[test]
fn patches_for_firmware_returns_expected_results() {
    // We know from the registry that at least some boards have patches.
    let grouped = all_patches_grouped();

    // Pick any board+version that has patches and verify the lookup function works.
    for (board, versions) in &grouped {
        for (&version, defs) in versions {
            let fw_defs = patches_for_firmware(*board, version);
            let bl_defs = patches_for_bootloader(*board, version);
            // The sum of firmware + bootloader patches should match the total.
            assert_eq!(fw_defs.len() + bl_defs.len(), defs.len(), "patch count mismatch for {board} v{version}",);
            return; // one check is enough to verify the lookup works
        }
    }
}

#[test]
fn patches_for_unknown_version_returns_empty() {
    let result = patches_for_firmware(BoardGeneration::XR, 9999);
    assert!(result.is_empty());
}
