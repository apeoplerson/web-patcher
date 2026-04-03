# Test Firmware

Place sample firmware and board dump files here for integration tests.
These files are gitignored and must be sourced from your own hardware.

## Expected layout

```
test_firmware/
├── <board>_<version>_enc.bin     Encrypted firmware image
├── <board>_<version>_dec.bin     Decrypted firmware image
├── <board>_bootloader_v<N>.bin   Bootloader image
├── <board>_dump.bin              Full flash dump (for key extraction)
└── <board>_backup.bin            Full flash backup (F1: 64KB, F4: 1MB)
```

### Examples

```
test_firmware/
├── xr_4142_enc.bin
├── xr_4142_dec.bin
├── xr_dump.bin
├── gt_6109_enc.bin
├── gt_dump.bin
└── gt_backup.bin
```

## How tests use these files

The integration tests in `crates/owtk-core/tests/pipeline.rs` scan this
directory at runtime. Tests that require a specific file are skipped
(not failed) when the file is absent.

- **Encrypted firmware** — tested for identification and decrypt round-trip
- **Decrypted firmware** — tested for identification, patching, and re-encryption
- **Dump files** — tested for key extraction, then used to decrypt firmware
- **Backup files** — tested for backup parsing, config extraction, firmware/bootloader identification within the backup
