use std::time::Duration;

use owtk_core::backup::detect_and_parse_backup;
use owtk_core::board::BoardGeneration;
use owtk_core::bootloader::{IdentifiedBootloader, identify_bootloader};
use owtk_core::crypto::cipher::{decrypt_firmware, firmware_payload};
use owtk_core::crypto::{CryptoKey, extract_keys_from_dump, sha1_hash};
use owtk_core::firmware::{FirmwareState, IdentifiedFirmware, identify_firmware};

use super::{MobileView, PatcherApp};

#[derive(Clone, Copy, Debug)]
pub(crate) enum PendingFileKind {
    Firmware,
    Bootloader,
    Dump,
    Backup,
    BackupImportBootloader,
    BackupImportFirmware,
}

impl PatcherApp {
    pub(crate) fn start_file_request(&mut self, kind: PendingFileKind, ctx: &egui::Context) {
        let dialog_title = match kind {
            PendingFileKind::Firmware | PendingFileKind::BackupImportFirmware => "Select Firmware",
            PendingFileKind::Bootloader | PendingFileKind::BackupImportBootloader => "Select Bootloader",
            PendingFileKind::Dump => "Select Board Dump",
            PendingFileKind::Backup => "Select Flash Backup",
        };

        let repaint = ctx.clone();
        self.pending_file_req = Some((
            kind,
            poll_promise::Promise::spawn_local(async move {
                let file = rfd::AsyncFileDialog::new().set_title(dialog_title).pick_file().await?;
                let data = file.read().await;
                repaint.request_repaint();
                Some(data)
            }),
        ));
    }

    pub(crate) fn poll_file_request(&mut self) {
        // Check readiness without consuming.
        let is_ready = self.pending_file_req.as_ref().is_some_and(|(_, promise)| promise.ready().is_some());

        if !is_ready {
            return;
        }

        // Take ownership to avoid cloning potentially large file data.
        let (kind, promise) = self.pending_file_req.take().expect("checked above");
        let Ok(result) = promise.try_take() else {
            return;
        };
        let Some(bytes) = result else {
            return;
        };

        match kind {
            PendingFileKind::Firmware => self.handle_firmware_loaded(bytes),
            PendingFileKind::Bootloader => self.handle_bootloader_loaded(bytes),
            PendingFileKind::Dump => self.handle_dump_loaded(&bytes),
            PendingFileKind::Backup => self.handle_backup_loaded(bytes),
            PendingFileKind::BackupImportBootloader => {
                self.handle_backup_import_bootloader(&bytes);
            }
            PendingFileKind::BackupImportFirmware => {
                self.handle_backup_import_firmware(&bytes);
            }
        }
    }

    fn handle_firmware_loaded(&mut self, bytes: Vec<u8>) {
        let identity = identify_firmware(&bytes, self.crypto_keys.as_deref());

        let Some(id) = identity else {
            self.toasts.warning("Firmware not recognised").duration(Some(Duration::from_secs(5)));
            return;
        };

        // Reject files larger than the firmware region for the detected
        // board's MCU family. Catches malformed or oversized firmware files
        // that happen to match a known hash.
        let max_size = id.descriptor.board.mcu_family().max_firmware_size();

        if bytes.len() > max_size {
            self.toasts
                .warning(format!(
                    "File too large for {} firmware ({} bytes, max {max_size})",
                    id.descriptor.board,
                    bytes.len(),
                ))
                .duration(Some(Duration::from_secs(5)));
            return;
        }

        let modifier = if id.exact_match { "" } else { ", Modified" };
        self.toasts
            .success(format!(
                "Identified: {} - {} ({}{})",
                id.descriptor.board, id.descriptor.version, id.state, modifier
            ))
            .duration(Some(Duration::from_secs(5)));

        self.firmware = Some(bytes);
        self.firmware_identity = Some(id);
        self.patch_entries = None;
        self.mobile_view = MobileView::Firmware;
        self.save_format_prompt = None;

        // Auto-decrypt when possible and patches exist for this firmware.
        self.try_auto_decrypt();
    }

    /// Automatically decrypts the loaded firmware if it is encrypted,
    /// a matching key is available, and patches exist for it.
    fn try_auto_decrypt(&mut self) {
        let Some(id) = &self.firmware_identity else {
            return;
        };
        if !id.is_encrypted() {
            return;
        }

        let Some(key) = self.crypto_keys.as_deref().and_then(|keys| CryptoKey::find_by_identifier(keys, &id.effective_crypto)) else {
            return;
        };

        let fw_data = self.firmware.as_ref().expect("firmware is loaded");
        let was_exact_match = id.exact_match;
        let expected_decrypted_hash = id.descriptor.decrypted_hash;
        let crypto_method = id.crypto_method();
        let effective_crypto = id.effective_crypto;
        let descriptor = id.descriptor;

        match decrypt_firmware(fw_data, &key) {
            Ok(decrypted) => {
                let hash_ok = if was_exact_match {
                    if let Some(expected) = expected_decrypted_hash {
                        let payload = firmware_payload(&decrypted, crypto_method, FirmwareState::Decrypted);
                        sha1_hash(payload) == expected
                    } else {
                        true
                    }
                } else {
                    true
                };

                self.firmware = Some(decrypted);
                self.firmware_identity = Some(IdentifiedFirmware {
                    descriptor,
                    state: FirmwareState::Decrypted,
                    exact_match: was_exact_match,
                    effective_crypto,
                });
                self.patch_entries = None;

                if hash_ok {
                    let msg = if was_exact_match {
                        "Firmware decrypted automatically (hash verified)"
                    } else {
                        "Firmware decrypted automatically (modified firmware)"
                    };
                    self.toasts.success(msg).duration(Some(Duration::from_secs(4)));
                } else {
                    self.toasts
                        .warning("Firmware decrypted automatically but hash mismatch — result may be incorrect")
                        .duration(Some(Duration::from_secs(6)));
                }
            }
            Err(e) => {
                self.toasts.error(format!("Auto-decryption failed: {e}")).duration(Some(Duration::from_secs(5)));
            }
        }
    }

    fn handle_bootloader_loaded(&mut self, bytes: Vec<u8>) {
        let identity = identify_bootloader(&bytes);

        let Some(id) = identity else {
            self.toasts.warning("Bootloader not recognised").duration(Some(Duration::from_secs(5)));
            return;
        };

        // Reject files larger than the bootloader region for the detected
        // board's MCU family.  Without this, full flash backups would match
        // via the partial hash since the backup starts with the bootloader's
        // vector table.
        let max_size = id.descriptor.board.mcu_family().max_bootloader_size();

        if bytes.len() > max_size {
            self.toasts
                .warning(format!(
                    "File too large for a {} bootloader ({} bytes, max {max_size})",
                    id.descriptor.board,
                    bytes.len(),
                ))
                .duration(Some(Duration::from_secs(5)));
            return;
        }

        let modifier = if id.exact_match { "" } else { ", Modified" };
        self.toasts
            .success(format!(
                "Identified: {} - v{} (Bootloader{})",
                id.descriptor.board, id.descriptor.version, modifier
            ))
            .duration(Some(Duration::from_secs(5)));

        self.bootloader = Some(bytes);
        self.bootloader_identity = Some(id);
        self.bootloader_patch_entries = None;
        self.mobile_view = MobileView::Bootloader;
    }

    fn handle_dump_loaded(&mut self, bytes: &[u8]) {
        let keys = extract_keys_from_dump(bytes);
        if keys.is_empty() {
            self.toasts.warning("No encryption keys found in file").duration(Some(Duration::from_secs(5)));
        } else {
            let mut added = 0usize;
            let mut skipped = 0usize;

            if let Some(existing_keys) = &mut self.crypto_keys {
                for key in &keys {
                    if existing_keys.contains(key) {
                        skipped += 1;
                        continue;
                    }
                    existing_keys.push(*key);
                    added += 1;
                }
            } else {
                added = keys.len();
                self.crypto_keys = Some(keys);
            }

            if added > 0 {
                self.toasts.success(format!("Loaded {added} encryption key(s)")).duration(Some(Duration::from_secs(4)));
                self.show_keys_window = true;
                self.mobile_view = MobileView::Keys;
            }

            if skipped > 0 {
                self.toasts
                    .warning(format!("{skipped} key(s) already loaded, skipped"))
                    .duration(Some(Duration::from_secs(4)));
            }
        }
    }

    fn handle_backup_loaded(&mut self, bytes: Vec<u8>) {
        let backup = detect_and_parse_backup(bytes, self.crypto_keys.as_deref());

        if let Some(parsed) = backup {
            self.toasts
                .success(format!("Backup loaded ({})", parsed.mcu_family))
                .duration(Some(Duration::from_secs(5)));

            self.parsed_backup = Some(parsed);
            self.mobile_view = MobileView::Backup;
        } else {
            self.toasts.warning("File not recognised as a flash backup").duration(Some(Duration::from_secs(5)));
        }
    }

    fn handle_backup_import_bootloader(&mut self, bytes: &[u8]) {
        let Some(backup) = &mut self.parsed_backup else {
            return;
        };
        let range = backup.mcu_family.bootloader_range();
        if bytes.len() > range.len() {
            self.toasts
                .warning(format!("Bootloader too large: expected at most {} bytes, got {}", range.len(), bytes.len()))
                .duration(Some(Duration::from_secs(5)));
            return;
        }
        let identified = identify_bootloader(bytes);
        if let Some(bl) = identified {
            let msg = format!("Bootloader replaced: {} - v{}", bl.descriptor.board, bl.descriptor.version);
            let region = backup.data.get_mut(range.clone()).expect("bootloader region out of bounds");
            region.fill(0xFF);
            backup
                .data
                .get_mut(range.start..range.start + bytes.len())
                .expect("bootloader write region out of bounds")
                .copy_from_slice(bytes);
            backup.bootloader_present = true;
            backup.bootloader = Some(bl);

            backup.reload_bootloader_version();

            self.toasts.success(msg).duration(Some(Duration::from_secs(4)));
        } else {
            self.toasts.warning("Bootloader not recognised").duration(Some(Duration::from_secs(5)));
        }
    }

    fn handle_backup_import_firmware(&mut self, bytes: &[u8]) {
        let Some(backup) = &mut self.parsed_backup else {
            return;
        };
        let range = backup.mcu_family.firmware_range();
        if bytes.len() > range.len() {
            self.toasts
                .warning(format!("Firmware too large: expected at most {} bytes, got {}", range.len(), bytes.len()))
                .duration(Some(Duration::from_secs(5)));
            return;
        }
        let identified = identify_firmware(bytes, self.crypto_keys.as_deref());
        if let Some(fw) = identified {
            if fw.state != FirmwareState::Decrypted {
                self.toasts
                    .warning("Firmware must be decrypted before replacing")
                    .duration(Some(Duration::from_secs(5)));
                return;
            }

            // Boards with RSA-signed firmware require an unmodified
            // firmware so the signature in the backup stays valid.
            let requires_rsa = requires_rsa_signature(backup.bootloader.as_ref());
            if requires_rsa && !fw.exact_match {
                self.toasts
                    .warning("RSA-signed board requires unmodified firmware")
                    .duration(Some(Duration::from_secs(5)));
                return;
            }

            let msg = format!("Firmware replaced: {} - {}", fw.descriptor.board, fw.descriptor.version);

            // Wipe region to 0xFF (erased flash) before writing in
            // case the new firmware is shorter than the old one.
            let region = backup.data.get_mut(range.clone()).expect("firmware region out of bounds");
            region.fill(0xFF);
            backup
                .data
                .get_mut(range.start..range.start + bytes.len())
                .expect("firmware write region out of bounds")
                .copy_from_slice(bytes);
            backup.firmware_present = true;
            backup.firmware = Some(fw);
            self.toasts.success(msg).duration(Some(Duration::from_secs(4)));
        } else {
            self.toasts.warning("Firmware not recognised").duration(Some(Duration::from_secs(5)));
        }
    }
}

/// Returns `true` when the backup's bootloader indicates that the board
/// performs RSA signature verification on firmware (GT v3+, all GTS, all XRC).
fn requires_rsa_signature(bootloader: Option<&IdentifiedBootloader>) -> bool {
    let Some(bl) = bootloader else {
        return false;
    };
    matches!(bl.descriptor.board, BoardGeneration::GTS | BoardGeneration::XRC)
        || (bl.descriptor.board == BoardGeneration::GT && bl.descriptor.version >= 3)
}
