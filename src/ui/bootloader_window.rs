use std::time::Duration;

use crate::app::PatcherApp;
use owtk_core::patches::{
    PatchApplyContext, apply_patches_to_copy, build_patch_entries, has_pending_patch_changes, patches_for_bootloader,
};

/// Desktop: renders the bootloader window as a floating `egui::Window`.
pub(crate) fn show(app: &mut PatcherApp, ui: &egui::Ui) {
    if app.bootloader.is_none() {
        return;
    }

    let mut open = true;

    let max_width = (ui.ctx().viewport_rect().width() - 32.0).max(300.0);
    egui::Window::new("Bootloader").default_width(520.0_f32.min(max_width)).default_height(480.0).open(&mut open).show(
        ui.ctx(),
        |ui| {
            show_content(app, ui);
        },
    );

    // Unload bootloader when the window is closed via the x button.
    if !open {
        app.bootloader = None;
        app.bootloader_identity = None;
        app.bootloader_patch_entries = None;
    }
}

/// Mobile: renders the bootloader content directly into the provided `ui`.
pub(crate) fn show_inline(app: &mut PatcherApp, ui: &mut egui::Ui) {
    if app.bootloader.is_none() {
        ui.label("No bootloader loaded.");
        return;
    }

    show_content(app, ui);
}

/// Shared content renderer used by both `show` (desktop) and `show_inline` (mobile).
#[expect(clippy::too_many_lines, reason = "UI rendering function — length is driven by layout code")]
fn show_content(app: &mut PatcherApp, ui: &mut egui::Ui) {
    // ── Bootloader identity info ─────────────────────────
    if let Some(id) = &app.bootloader_identity {
        egui::Grid::new("bootloader_info_grid").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
            ui.strong("Board:");
            ui.label(id.descriptor.board.to_string());
            ui.end_row();

            ui.strong("Version:");
            ui.label(id.descriptor.version.to_string());
            ui.end_row();

            ui.strong("State:");
            if id.exact_match {
                ui.label("Stock");
            } else {
                ui.horizontal(|ui| {
                    ui.label("Modified");
                    ui.label(
                        egui::RichText::new("(partial hash match)")
                            .color(egui::Color32::from_rgb(255, 210, 100))
                            .size(12.0),
                    );
                });
            }
            ui.end_row();
        });
    }

    // ── Pre-extract identity fields ──────────────────────
    let id = app.bootloader_identity.as_ref();
    let descriptor = id.map(|id| id.descriptor);

    let has_patch_changes = app.bootloader_patch_entries.as_deref().is_some_and(has_pending_patch_changes);

    // ── Patches section ──────────────────────────────────
    if app.bootloader.is_some() && id.is_some() {
        // Lazily build patch entries.
        if app.bootloader_patch_entries.is_none()
            && let (Some(bl), Some(id)) = (&app.bootloader, &app.bootloader_identity)
        {
            let defs = patches_for_bootloader(id.descriptor.board, id.descriptor.version);
            if !defs.is_empty() {
                app.bootloader_patch_entries = Some(build_patch_entries(bl, &defs));
            }
        }

        ui.add_space(2.0);
        ui.separator();
        ui.add_space(2.0);

        // ── Patches header with save button ──────────
        ui.horizontal(|ui| {
            ui.heading("Patches");

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let save_label = if has_patch_changes { "Save Patched Bootloader" } else { "Save Bootloader" };

                if ui.button(save_label).clicked() {
                    let bl = app.bootloader.as_ref().expect("bootloader is loaded");
                    let save_data = if has_patch_changes {
                        let entries = app.bootloader_patch_entries.as_ref().expect("has changes");
                        let desc = app.bootloader_identity.as_ref().expect("identified").descriptor;
                        let ctx = PatchApplyContext {
                            board: desc.board,
                            version: desc.version,
                            sram_free_start: desc.sram_free_start,
                            has_rsa_sig: false,
                        };
                        let max_size = desc.board.mcu_family_from_board_gen().max_bootloader_size();
                        match apply_patches_to_copy(bl, entries, max_size, &ctx) {
                            Ok(patched) => Some(patched),
                            Err(e) => {
                                app.toasts.error(format!("Patch failed: {e}")).duration(Some(Duration::from_secs(6)));
                                None
                            }
                        }
                    } else {
                        Some(bl.clone())
                    };

                    if let Some(data) = save_data {
                        let name = default_bootloader_save_name(descriptor, has_patch_changes);
                        app.start_save_request(data, &name, "Save Bootloader", ui.ctx());
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
                .id_salt("bootloader_patch_scroll")
                .max_height(max_scroll)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    if let Some(entries) = &mut app.bootloader_patch_entries {
                        if entries.is_empty() {
                            ui.label("No patches available for this bootloader.");
                        } else {
                            for (i, entry) in entries.iter_mut().enumerate() {
                                if i > 0 {
                                    ui.add_space(2.0);
                                }
                                super::patch_controls::show_patch_entry(ui, entry);
                            }
                        }
                    } else {
                        ui.label("No patches available for this bootloader.");
                    }
                });
        });
    }
}

fn default_bootloader_save_name(
    descriptor: Option<&owtk_core::bootloader::types::BootloaderDescriptor>,
    is_patched: bool,
) -> String {
    if let Some(d) = descriptor {
        let suffix = if is_patched { "patched" } else { "stock" };
        format!("bootloader_{}_v{}_{suffix}.bin", d.board.to_string().to_lowercase(), d.version)
    } else {
        "bootloader.bin".to_owned()
    }
}
