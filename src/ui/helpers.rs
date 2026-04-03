use egui::Ui;

/// Returns true when the viewport is narrow enough to use mobile layout.
///
/// Uses `screen_rect` (the full canvas size in egui points) rather than
/// `content_rect` (which excludes already-placed panels and can be stale
/// on the first frame).  On high-DPI devices egui points map 1:1 to CSS
/// pixels, so 600 pt ≈ 600 CSS px regardless of `devicePixelRatio`.
pub(crate) fn is_mobile(ctx: &egui::Context) -> bool {
    ctx.viewport_rect().width() < 600.0
}

/// Returns the standard card-styled [`egui::Frame`] used throughout the UI.
pub(crate) fn card_frame(ui: &Ui) -> egui::Frame {
    let fill = if ui.visuals().dark_mode {
        ui.visuals().extreme_bg_color.gamma_multiply(1.3)
    } else {
        ui.visuals().extreme_bg_color
    };
    egui::Frame::new()
        .fill(fill)
        .corner_radius(6.0)
        .inner_margin(10.0)
        .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
}

/// Resolves the monospace font for the current UI style.
fn mono_font(ui: &Ui) -> egui::FontId {
    egui::TextStyle::Monospace.resolve(ui.style())
}

/// Measures the horizontal pixel width of `text` rendered in the
/// default monospace font, without wrapping.
pub(crate) fn text_width(ui: &Ui, text: &str) -> f32 {
    ui.painter().layout_no_wrap(text.to_owned(), mono_font(ui), egui::Color32::PLACEHOLDER).size().x
}

/// Returns the estimated pixel width of a small button containing `label`,
/// accounting for button padding and item spacing.
pub(crate) fn small_button_width(ui: &Ui, label: &str) -> f32 {
    ui.spacing().item_spacing.x + ui.spacing().button_padding.x * 2.0 + text_width(ui, label)
}

/// Truncates `text` so that, when prefixed with `prefix` and suffixed with
/// `"…"` (if truncated), the result fits within `max_width` pixels using the
/// default monospace font.
///
/// Returns the full `"{prefix}{text}"` when it fits, otherwise
/// `"{prefix}{text[..n]}…"` where `n` is the largest number of **characters**
/// (not bytes) that fits (at least `min_chars` characters from `text` are
/// always kept so the result stays recognisable).
///
/// The full, untruncated `text` is always suitable as a hover-tooltip.
pub(crate) fn truncate_to_fit(ui: &Ui, prefix: &str, text: &str, max_width: f32, min_chars: usize) -> String {
    let full = format!("{prefix}{text}");
    if text_width(ui, &full) <= max_width {
        return full;
    }

    let prefix_w = text_width(ui, prefix);
    let ellipsis_w = text_width(ui, "…");
    let char_w = text_width(ui, "a"); // monospace → uniform width

    let available = (max_width - prefix_w - ellipsis_w).max(0.0);

    let max_chars = if char_w > 0.0 { (available / char_w).floor() as usize } else { text.chars().count() };

    let show_chars = max_chars.max(min_chars).min(text.chars().count());

    // Find the byte boundary corresponding to `show_chars` Unicode scalar
    // values. Using char_indices avoids the panic that byte-indexing a &str
    // can cause when the string contains multibyte characters.
    let byte_end = text.char_indices().nth(show_chars).map_or(text.len(), |(idx, _)| idx);

    format!("{prefix}{}…", &text[..byte_end])
}
