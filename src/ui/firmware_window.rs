use std::time::Duration;

use crate::app::PatcherApp;
use owtk_core::board::BoardGeneration;
use owtk_core::crypto::cipher::{RSA_SIG_SIZE, decrypt_firmware, encrypt_firmware, firmware_payload};
use owtk_core::crypto::{CRYPTO_ID_GT_CTR, CRYPTO_ID_GT_CTR_DYN, CryptoKey, CryptoMethod, sha1_hash};
use owtk_core::firmware::{FirmwareState, IdentifiedFirmware};
use owtk_core::patches::{
    PatchApplyContext, apply_patches_to_copy, build_patch_entries, has_pending_patch_changes, patches_for_firmware,
};

/// Finds the matching crypto key for the currently identified firmware.
/// Returns a *copy* so we don't hold an immutable borrow on `app`.
fn find_matching_key(app: &PatcherApp) -> Option<CryptoKey> {
    let ident = &app.firmware_identity.as_ref()?.effective_crypto;
    CryptoKey::find_by_identifier(app.crypto_keys.as_deref()?, ident)
}

/// Desktop: renders the firmware window as a floating `egui::Window`.
pub(crate) fn show(app: &mut PatcherApp, ui: &egui::Ui) {
    if app.firmware.is_none() {
        return;
    }

    let mut open = true;

    let max_width = (ui.ctx().viewport_rect().width() - 32.0).max(300.0);
    egui::Window::new("Firmware").default_width(520.0_f32.min(max_width)).default_height(480.0).open(&mut open).show(
        ui.ctx(),
        |ui| {
            show_content(app, ui);
        },
    );

    // ── Save-format prompt (shown outside the firmware window) ──────
    if app.save_format_prompt.is_some() {
        show_save_format_prompt(app, ui);
    }

    // Unload firmware when the window is closed via the x button.
    if !open {
        app.firmware = None;
        app.firmware_identity = None;
        app.patch_entries = None;
        app.save_format_prompt = None;
    }
}

/// Mobile: renders the firmware content directly into the provided `ui`.
pub(crate) fn show_inline(app: &mut PatcherApp, ui: &mut egui::Ui) {
    if app.firmware.is_none() {
        ui.label("No firmware loaded.");
        return;
    }

    show_content(app, ui);

    // ── Save-format prompt ──────
    if app.save_format_prompt.is_some() {
        show_save_format_prompt(app, ui);
    }
}

/// Shared content renderer used by both `show` (desktop) and `show_inline` (mobile).
#[expect(clippy::too_many_lines, reason = "UI rendering function — length is driven by layout code")]
fn show_content(app: &mut PatcherApp, ui: &mut egui::Ui) {
    // ── Firmware identity info ──────────────────────────────
    if let Some(id) = &app.firmware_identity {
        egui::Grid::new("firmware_info_grid").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
            ui.strong("Board:");
            ui.label(id.descriptor.board.to_string());
            ui.end_row();

            ui.strong("Version:");
            ui.label(id.descriptor.version.to_string());
            ui.end_row();

            ui.strong("State:");
            if id.exact_match {
                ui.label(id.state.to_string());
            } else {
                ui.horizontal(|ui| {
                    ui.label(id.state.to_string());
                    ui.label(
                        egui::RichText::new("(modified)").color(egui::Color32::from_rgb(255, 210, 100)).size(12.0),
                    )
                    .on_hover_text("Firmware only matches partial hash.");
                });
            }
            ui.end_row();

            ui.strong("Encryption:");
            ui.label(id.effective_crypto.method.to_string());
            ui.end_row();
        });
    }

    // ── Pre-extract identity fields ─────────────────────────
    let matching_key: Option<CryptoKey> = find_matching_key(app);
    let id = app.firmware_identity.as_ref();
    let is_encrypted = id.is_some_and(|id| id.is_encrypted());
    let expected_decrypted_hash = id.and_then(|id| id.descriptor.decrypted_hash);
    let crypto_method = id.map(|id| id.crypto_method());
    let effective_crypto = id.map(|id| id.effective_crypto);
    let descriptor = id.map(|id| id.descriptor);
    let was_exact_match = id.is_none_or(|id| id.exact_match);

    let has_patch_changes = app.patch_entries.as_deref().is_some_and(has_pending_patch_changes);
    let is_patched = has_patch_changes || !was_exact_match;

    // ── Patches section (only when decrypted) ───────────────
    let show_patches = app.firmware.is_some() && id.is_some_and(|id| !id.is_encrypted());

    if show_patches {
        // Lazily build patch entries
        if app.patch_entries.is_none()
            && let (Some(fw), Some(id)) = (&app.firmware, &app.firmware_identity)
        {
            let defs = patches_for_firmware(id.descriptor.board, id.descriptor.version);
            if !defs.is_empty() {
                app.patch_entries = Some(build_patch_entries(fw, &defs));
            }
        }

        ui.add_space(2.0);
        ui.separator();
        ui.add_space(2.0);

        // ── Warning for already-modified firmware ─────────────
        if !was_exact_match {
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                ui.label(
                    egui::RichText::new(egui_phosphor::regular::INFO).color(egui::Color32::from_rgb(100, 160, 220)),
                );
                ui.label(
                    egui::RichText::new(
                        "This firmware has been modified. Even with all patches \
                         disabled, it will not be identical to the original — \
                         padding, IV, and RSA signature cannot be restored. It \
                         will not pass stock bootloader integrity checks unless \
                         the bootloader is also patched.",
                    )
                    .weak()
                    .size(11.5),
                );
            });
            ui.add_space(2.0);
            ui.separator();
            ui.add_space(2.0);
        }

        // ── Patches header with save button ─────────────
        ui.horizontal(|ui| {
            ui.heading("Patches");

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let save_label = if is_patched { "Save Patched Firmware" } else { "Save Firmware" };

                if ui.button(save_label).clicked() {
                    let fw = app.firmware.as_ref().expect("firmware is loaded");
                    let save_data = if has_patch_changes {
                        let entries = app.patch_entries.as_ref().expect("has changes");
                        let ident = app.firmware_identity.as_ref().expect("identified");
                        let descriptor = ident.descriptor;
                        let board = descriptor.board;
                        let ctx = PatchApplyContext {
                            board,
                            version: descriptor.version,
                            sram_free_start: descriptor.sram_free_start,
                            has_rsa_sig: ident.effective_crypto.method == CryptoMethod::AesCTR128DynIv,
                        };
                        match apply_patches_to_copy(
                            fw,
                            entries,
                            board.mcu_family_from_board_gen().max_firmware_size(),
                            &ctx,
                        ) {
                            Ok(patched) => Some(patched),
                            Err(e) => {
                                app.toasts.error(format!("Patch failed: {e}")).duration(Some(Duration::from_secs(6)));
                                None
                            }
                        }
                    } else {
                        Some(fw.clone())
                    };

                    if let Some(data) = save_data {
                        if matching_key.is_some() {
                            app.save_format_prompt = Some((data, is_patched));
                        } else {
                            let name = app.default_save_name(FirmwareState::Decrypted, is_patched);
                            app.start_save_request(data, &name, "Save Firmware", ui.ctx());
                        }
                    }
                }
            });
        });

        ui.add_space(2.0);

        let max_scroll = ui.available_height().max(100.0);

        let patches_frame = egui::Frame::new()
            .fill(ui.visuals().extreme_bg_color)
            .corner_radius(4.0)
            .inner_margin(6.0)
            .stroke(ui.visuals().widgets.noninteractive.bg_stroke);

        patches_frame.show(ui, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("patch_scroll")
                .max_height(max_scroll)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    if let Some(entries) = &mut app.patch_entries {
                        if entries.is_empty() {
                            ui.label("No patches available for this firmware.");
                        } else {
                            for (i, entry) in entries.iter_mut().enumerate() {
                                if i > 0 {
                                    ui.add_space(2.0);
                                }
                                super::patch_controls::show_patch_entry(ui, entry);
                            }
                        }
                    } else {
                        ui.label("No patches available for this firmware.");
                    }
                });
        });
    } else if app.firmware.is_some() {
        // Clear stale patch state when firmware is not decrypted.
        app.patch_entries = None;
    }

    // ── Action buttons (only when encrypted) ────────────────
    if is_encrypted {
        ui.add_space(2.0);
        ui.separator();
        ui.add_space(2.0);

        ui.horizontal_wrapped(|ui| {
            let can_decrypt = matching_key.is_some();
            let decrypt_tooltip = if !can_decrypt { "No matching encryption key loaded" } else { "Decrypt firmware" };

            let decrypt_btn = ui.add_enabled(can_decrypt, egui::Button::new("Decrypt"));
            if decrypt_btn.clicked()
                && let Some(key) = &matching_key
            {
                let fw_data = app.firmware.as_ref().expect("firmware is loaded");
                match decrypt_firmware(fw_data, key) {
                    Ok(decrypted) => {
                        let hash_ok = if was_exact_match {
                            match (expected_decrypted_hash, crypto_method) {
                                (Some(expected), Some(method)) => {
                                    let payload = firmware_payload(&decrypted, method, FirmwareState::Decrypted);
                                    sha1_hash(payload) == expected
                                }
                                _ => true,
                            }
                        } else {
                            true
                        };

                        app.firmware = Some(decrypted);
                        app.firmware_identity = descriptor.map(|d| IdentifiedFirmware {
                            descriptor: d,
                            state: FirmwareState::Decrypted,
                            exact_match: was_exact_match,
                            effective_crypto: effective_crypto.unwrap_or(d.crypto_identifier),
                        });
                        app.patch_entries = None;

                        if hash_ok {
                            let msg = if was_exact_match {
                                "Firmware decrypted successfully (hash verified)"
                            } else {
                                "Firmware decrypted successfully (modified firmware)"
                            };
                            app.toasts.success(msg).duration(Some(Duration::from_secs(4)));
                        } else {
                            app.toasts
                                .warning(
                                    "Firmware decrypted but hash mismatch — \
                                         result may be incorrect",
                                )
                                .duration(Some(Duration::from_secs(6)));
                        }
                    }
                    Err(e) => {
                        app.toasts.error(format!("Decryption failed: {e}")).duration(Some(Duration::from_secs(5)));
                    }
                }
            }
            if !can_decrypt {
                decrypt_btn.on_hover_text(decrypt_tooltip);
            }

            // Save button (encrypted state)
            if ui.button("Save Firmware").clicked() {
                let fw = app.firmware.as_ref().expect("firmware is loaded");
                let name = app.default_save_name(FirmwareState::Encrypted, false);
                app.start_save_request(fw.clone(), &name, "Save Firmware", ui.ctx());
            }
        });
    }
}

/// Describes a save action chosen by the user in the save-format prompt.
#[derive(Clone, Copy)]
enum SaveAction {
    Decrypted,
    /// Encrypt with the key that matches the firmware's effective crypto.
    Encrypted,
    /// Encrypt with a specific GT key (v2 static-CTR or v3 DynIV),
    /// regardless of how the firmware was originally encrypted.
    EncryptedGt(GtEncVersion),
    Cancel,
}

/// GT encryption version for the explicit v2/v3 save options.
#[derive(Clone, Copy)]
enum GtEncVersion {
    V2,
    V3,
}

/// Returns the firmware-only payload (without RSA signature) from the
/// given data, using the effective crypto method to decide whether
/// the trailing 256 bytes are a signature that should be stripped.
fn firmware_without_rsa(data: &[u8], app: &PatcherApp) -> Vec<u8> {
    let has_sig =
        app.firmware_identity.as_ref().is_some_and(|id| id.effective_crypto.method == CryptoMethod::AesCTR128DynIv);
    if has_sig {
        data.len().checked_sub(RSA_SIG_SIZE).map_or_else(|| data.to_vec(), |end| data[..end].to_vec())
    } else {
        data.to_vec()
    }
}

/// Returns the firmware payload with an RSA signature placeholder
/// (256 bytes of `0xFF`) appended, unless one is already present.
fn firmware_with_rsa(data: &[u8], app: &PatcherApp) -> Vec<u8> {
    let has_sig =
        app.firmware_identity.as_ref().is_some_and(|id| id.effective_crypto.method == CryptoMethod::AesCTR128DynIv);
    if has_sig {
        data.to_vec()
    } else {
        let mut buf = data.to_vec();
        buf.resize(buf.len() + RSA_SIG_SIZE, 0xFF);
        buf
    }
}

/// Executes the chosen [`SaveAction`] — encrypts if needed, then starts
/// the save-file dialog. Called from both the mobile and desktop branches
/// of the save-format prompt.
fn execute_save_action(action: SaveAction, app: &mut PatcherApp, ctx: &egui::Context) {
    match action {
        SaveAction::Decrypted => {
            if let Some((data, has_patches)) = app.save_format_prompt.take() {
                let name = app.default_save_name(FirmwareState::Decrypted, has_patches);
                app.start_save_request(data, &name, "Save Firmware", ctx);
            }
        }
        SaveAction::Encrypted => {
            if let Some((data, has_patches)) = app.save_format_prompt.take() {
                let key: Option<CryptoKey> = find_matching_key(app);
                if let Some(key) = &key {
                    match encrypt_firmware(&data, key) {
                        Ok(encrypted) => {
                            let name = app.default_save_name(FirmwareState::Encrypted, has_patches);
                            app.start_save_request(encrypted, &name, "Save Firmware", ctx);
                        }
                        Err(e) => {
                            app.toasts.error(format!("Encryption failed: {e}")).duration(Some(Duration::from_secs(5)));
                        }
                    }
                }
            }
        }
        SaveAction::EncryptedGt(version) => {
            if let Some((data, has_patches)) = app.save_format_prompt.take() {
                let (ident, payload) = match version {
                    GtEncVersion::V3 => (CRYPTO_ID_GT_CTR_DYN, firmware_with_rsa(&data, app)),
                    GtEncVersion::V2 => (CRYPTO_ID_GT_CTR, firmware_without_rsa(&data, app)),
                };
                let key = app.crypto_keys.as_deref().and_then(|keys| CryptoKey::find_by_identifier(keys, &ident));
                if let Some(key) = &key {
                    match encrypt_firmware(&payload, key) {
                        Ok(encrypted) => {
                            let name = app.default_save_name(FirmwareState::Encrypted, has_patches);
                            app.start_save_request(encrypted, &name, "Save Firmware", ctx);
                        }
                        Err(e) => {
                            let label = match version {
                                GtEncVersion::V3 => "v3",
                                GtEncVersion::V2 => "v2",
                            };
                            app.toasts
                                .error(format!("Encryption ({label}) failed: {e}"))
                                .duration(Some(Duration::from_secs(5)));
                        }
                    }
                }
            }
        }
        SaveAction::Cancel => {
            app.save_format_prompt = None;
        }
    }
}

/// Shows a modal dialog asking the user whether to save the firmware
/// as decrypted or encrypted.
///
/// Uses [`egui::Modal`] so the background is dimmed and all other
/// windows are blocked from receiving input while the prompt is open.
fn show_save_format_prompt(app: &mut PatcherApp, ui: &egui::Ui) {
    let mobile = super::helpers::is_mobile(ui.ctx());

    // For GT boards, offer explicit v2/v3 encryption options based on
    // which keys the user has loaded.
    let is_gt = app.firmware_identity.as_ref().is_some_and(|id| id.descriptor.board == BoardGeneration::GT);

    let has_v3_key = is_gt
        && app
            .crypto_keys
            .as_deref()
            .and_then(|keys| CryptoKey::find_by_identifier(keys, &CRYPTO_ID_GT_CTR_DYN))
            .is_some();
    let has_v2_key = is_gt
        && app.crypto_keys.as_deref().and_then(|keys| CryptoKey::find_by_identifier(keys, &CRYPTO_ID_GT_CTR)).is_some();

    // Non-GT boards: show a single "Encrypted" option with the matching key.
    let has_matching_key = !is_gt && find_matching_key(app).is_some();

    let modal_width = if mobile { (ui.ctx().viewport_rect().width() - 32.0).clamp(200.0, 320.0) } else { 280.0 };

    let modal = egui::Modal::new("save_format_modal".into()).show(ui.ctx(), |ui| {
        ui.set_width(modal_width);

        ui.heading("Save Format");

        ui.add_space(4.0);

        ui.label("Save the firmware as encrypted or decrypted?");

        ui.add_space(8.0);

        let opts = SaveFormatOptions { is_gt, has_v3_key, has_v2_key, has_matching_key };

        // Collect the user's chosen action (if any) from the button layout,
        // then execute it after the UI code to avoid borrow conflicts.
        let action =
            if mobile { save_format_buttons_mobile(ui, &opts) } else { save_format_buttons_desktop(ui, &opts) };

        if let Some(action) = action {
            execute_save_action(action, app, ui.ctx());
        }
    });

    // Dismiss when the user clicks the backdrop or presses Escape.
    if modal.should_close() {
        app.save_format_prompt = None;
    }
}

/// Options that control which buttons appear in the save-format prompt.
struct SaveFormatOptions {
    is_gt: bool,
    has_v3_key: bool,
    has_v2_key: bool,
    has_matching_key: bool,
}

/// Mobile layout: full-width vertical buttons. Returns the chosen action, if any.
fn save_format_buttons_mobile(ui: &mut egui::Ui, opts: &SaveFormatOptions) -> Option<SaveAction> {
    let btn_width = ui.available_width();

    if ui.add_sized([btn_width, 36.0], egui::Button::new("Decrypted")).clicked() {
        return Some(SaveAction::Decrypted);
    }

    if opts.is_gt {
        if opts.has_v3_key {
            ui.add_space(4.0);
            if ui
                .add_sized([btn_width, 36.0], egui::Button::new("Encrypted (v3)"))
                .on_hover_text("Encrypt with the v3 DynIV key.")
                .clicked()
            {
                return Some(SaveAction::EncryptedGt(GtEncVersion::V3));
            }
        }
        if opts.has_v2_key {
            ui.add_space(4.0);
            if ui
                .add_sized([btn_width, 36.0], egui::Button::new("Encrypted (v2)"))
                .on_hover_text("Encrypt with the older static-CTR key for the v2 bootloader.")
                .clicked()
            {
                return Some(SaveAction::EncryptedGt(GtEncVersion::V2));
            }
        }
    } else if opts.has_matching_key {
        ui.add_space(4.0);
        if ui.add_sized([btn_width, 36.0], egui::Button::new("Encrypted")).clicked() {
            return Some(SaveAction::Encrypted);
        }
    }

    ui.add_space(4.0);

    if ui.add_sized([btn_width, 36.0], egui::Button::new("Cancel")).clicked() {
        return Some(SaveAction::Cancel);
    }

    None
}

/// Desktop layout: horizontal buttons. Returns the chosen action, if any.
fn save_format_buttons_desktop(ui: &mut egui::Ui, opts: &SaveFormatOptions) -> Option<SaveAction> {
    let mut action = None;

    ui.horizontal(|ui| {
        if ui.button("Decrypted").clicked() {
            action = Some(SaveAction::Decrypted);
        }

        if opts.is_gt {
            if opts.has_v3_key && ui.button("Encrypted (v3)").on_hover_text("Encrypt with the v3 DynIV key.").clicked()
            {
                action = Some(SaveAction::EncryptedGt(GtEncVersion::V3));
            }
            if opts.has_v2_key
                && ui
                    .button("Encrypted (v2)")
                    .on_hover_text("Encrypt with the older static-CTR key for the v2 bootloader.")
                    .clicked()
            {
                action = Some(SaveAction::EncryptedGt(GtEncVersion::V2));
            }
        } else if opts.has_matching_key && ui.button("Encrypted").clicked() {
            action = Some(SaveAction::Encrypted);
        }

        if ui.button("Cancel").clicked() {
            action = Some(SaveAction::Cancel);
        }
    });

    action
}
