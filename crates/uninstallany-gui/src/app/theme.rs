use std::sync::Arc;

use eframe::egui::{
    self, Align, Color32, CornerRadius, CursorIcon, FontFamily, FontId, Frame, Galley, Id, Label,
    Layout, Margin, Pos2, Rect, Response, RichText, Sense, Shadow, Stroke, StrokeKind, TextEdit,
    TextFormat, TextStyle, Ui, UiBuilder, Vec2, pos2, text::LayoutJob, vec2,
};

use super::anim::{
    Toast, ToastKind, ease_in_out_cubic, indeterminate_phase, lerp_color, lerp_f32, shimmer_phase,
    smooth_bool, spinner_angle,
};
use crate::fonts;

// --- Refined Neutral + Cobalt Palette ---
pub(crate) const INK: Color32 = Color32::from_rgb(16, 24, 40);
pub(crate) const MUTED: Color32 = Color32::from_rgb(71, 84, 103);
pub(crate) const SUBTLE: Color32 = Color32::from_rgb(102, 112, 133);

pub(crate) const ACCENT: Color32 = Color32::from_rgb(37, 99, 235);
pub(crate) const ACCENT_HOVER: Color32 = Color32::from_rgb(29, 78, 216);
pub(crate) const ACCENT_ACTIVE: Color32 = Color32::from_rgb(30, 64, 175);
pub(crate) const ACCENT_PALE: Color32 = Color32::from_rgb(239, 246, 255);
pub(crate) const ACCENT_SOFT: Color32 = Color32::from_rgb(245, 248, 255);
pub(crate) const ACCENT_BORDER: Color32 = Color32::from_rgb(147, 197, 253);

pub(crate) const PAGE: Color32 = Color32::from_rgb(247, 248, 250);
pub(crate) const SURFACE: Color32 = Color32::WHITE;
pub(crate) const SURFACE_ALT: Color32 = Color32::from_rgb(249, 250, 251);
pub(crate) const SURFACE_PRESSED: Color32 = Color32::from_rgb(240, 243, 248);
pub(crate) const SIDEBAR: Color32 = Color32::from_rgb(242, 244, 247);
pub(crate) const LINE: Color32 = Color32::from_rgb(228, 231, 236);
pub(crate) const LINE_SOFT: Color32 = Color32::from_rgb(238, 240, 244);
pub(crate) const CONTROL_BORDER: Color32 = Color32::from_rgb(208, 213, 221);
pub(crate) const DISABLED_BG: Color32 = Color32::from_rgb(242, 244, 247);
pub(crate) const DISABLED_TEXT: Color32 = Color32::from_rgb(152, 162, 179);

pub(crate) const DARK_GREEN: Color32 = Color32::from_rgb(4, 120, 87);
pub(crate) const PALE_GREEN: Color32 = Color32::from_rgb(236, 253, 245);
pub(crate) const DARK_AMBER: Color32 = Color32::from_rgb(180, 83, 9);
pub(crate) const PALE_AMBER: Color32 = Color32::from_rgb(255, 251, 235);
pub(crate) const DANGER: Color32 = Color32::from_rgb(220, 38, 38);
pub(crate) const DANGER_HOVER: Color32 = Color32::from_rgb(185, 28, 28);
pub(crate) const DANGER_ACTIVE: Color32 = Color32::from_rgb(153, 27, 27);
pub(crate) const PALE_RED: Color32 = Color32::from_rgb(254, 242, 242);
pub(crate) const DANGER_BORDER: Color32 = Color32::from_rgb(252, 165, 165);

// --- Standardized Layout Tokens ---
pub(crate) const SIDEBAR_WIDTH: f32 = 216.0;
pub(crate) const CONTROL_HEIGHT: f32 = 34.0;
pub(crate) const COMPACT_HEIGHT: f32 = 28.0;
pub(crate) const APP_ROW: f32 = 58.0;
pub(crate) const CANDIDATE_ROW: f32 = 62.0;
pub(crate) const HAIRLINE: f32 = 1.0;

/// Deterministic refined pastel palette for application glyphs.
const GLYPH_PALETTE: &[(Color32, Color32)] = &[
    (
        Color32::from_rgb(37, 99, 235),
        Color32::from_rgb(239, 246, 255),
    ), // Cobalt
    (
        Color32::from_rgb(4, 120, 87),
        Color32::from_rgb(236, 253, 245),
    ), // Emerald
    (
        Color32::from_rgb(124, 58, 237),
        Color32::from_rgb(245, 243, 255),
    ), // Violet
    (
        Color32::from_rgb(194, 65, 12),
        Color32::from_rgb(255, 247, 237),
    ), // Amber-Orange
    (
        Color32::from_rgb(3, 105, 161),
        Color32::from_rgb(240, 249, 255),
    ), // Sky
    (
        Color32::from_rgb(190, 24, 93),
        Color32::from_rgb(253, 242, 248),
    ), // Rose
];

pub(crate) fn configure_style(context: &egui::Context) {
    fonts::register_initial_families(context);
    let mut style = (*context.style()).clone();
    style.visuals = egui::Visuals::light();
    style.visuals.panel_fill = PAGE;
    style.visuals.window_fill = SURFACE;
    style.visuals.extreme_bg_color = SURFACE;
    style.visuals.faint_bg_color = SURFACE_ALT;
    style.visuals.window_stroke = Stroke::new(HAIRLINE, LINE);
    style.visuals.window_corner_radius = CornerRadius::same(10);
    style.visuals.popup_shadow = Shadow {
        offset: [0, 8],
        blur: 24,
        spread: 0,
        color: Color32::from_rgba_unmultiplied(16, 24, 40, 28),
    };
    style.visuals.selection.bg_fill = ACCENT_PALE;
    style.visuals.selection.stroke = Stroke::new(HAIRLINE, ACCENT);

    style.visuals.widgets.noninteractive.fg_stroke = Stroke::new(HAIRLINE, INK);
    style.visuals.widgets.noninteractive.corner_radius = CornerRadius::same(6);
    style.visuals.widgets.inactive.fg_stroke = Stroke::new(HAIRLINE, INK);
    style.visuals.widgets.inactive.bg_fill = SURFACE;
    style.visuals.widgets.inactive.weak_bg_fill = SURFACE;
    style.visuals.widgets.inactive.bg_stroke = Stroke::new(HAIRLINE, CONTROL_BORDER);
    style.visuals.widgets.inactive.corner_radius = CornerRadius::same(7);
    style.visuals.widgets.hovered.fg_stroke = Stroke::new(HAIRLINE, INK);
    style.visuals.widgets.hovered.weak_bg_fill = SURFACE_ALT;
    style.visuals.widgets.hovered.bg_stroke = Stroke::new(HAIRLINE, ACCENT);
    style.visuals.widgets.hovered.corner_radius = CornerRadius::same(7);
    style.visuals.widgets.active.fg_stroke = Stroke::new(HAIRLINE, ACCENT);
    style.visuals.widgets.active.weak_bg_fill = ACCENT_PALE;
    style.visuals.widgets.active.bg_stroke = Stroke::new(HAIRLINE, ACCENT);
    style.visuals.widgets.active.corner_radius = CornerRadius::same(7);

    style.text_styles.insert(
        TextStyle::Heading,
        FontId::new(22.0, fonts::semibold_family()),
    );
    style
        .text_styles
        .insert(TextStyle::Body, FontId::proportional(13.0));
    style.text_styles.insert(
        TextStyle::Button,
        FontId::new(13.0, fonts::semibold_family()),
    );
    style
        .text_styles
        .insert(TextStyle::Small, FontId::proportional(11.5));
    style
        .text_styles
        .insert(TextStyle::Monospace, FontId::monospace(12.0));

    style.spacing.item_spacing = vec2(8.0, 8.0);
    style.spacing.button_padding = vec2(14.0, 6.0);
    style.spacing.interact_size = vec2(34.0, CONTROL_HEIGHT);
    style.spacing.scroll = egui::style::ScrollStyle::floating();
    style.animation_time = 0.14;
    context.set_style(style);
}

// --- Crisp Vector Icon Set (drawn at 14px optical scale) ---

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Icon {
    Refresh,
    Folder,
    Search,
    Trash,
    Shield,
    AlertTriangle,
    Restore,
    Export,
    Check,
    ChevronDown,
    Back,
    Close,
    Sparkles,
    Copy,
    Clock,
    Archive,
    Info,
    Filter,
}

/// Paints a crisp anti-aliased vector icon centered at `center` within `size` (typically `13..=15px`).
pub(crate) fn paint_icon(ui: &Ui, icon: Icon, center: Pos2, size: f32, color: Color32) {
    let p = ui.painter();
    let s = size / 14.0;
    let sw = (1.45 * s).clamp(1.2, 2.0);
    let stroke = Stroke::new(sw, color);
    let pt = |x: f32, y: f32| center + vec2(x * s, y * s);

    match icon {
        Icon::Refresh => {
            // Two curved-feeling arcs with arrowheads.
            let r = 4.6 * s;
            let segments = 10;
            let arc = |start: f32, end: f32| -> Vec<Pos2> {
                (0..=segments)
                    .map(|i| {
                        let t = i as f32 / segments as f32;
                        let a = start + (end - start) * t;
                        center + vec2(a.cos() * r, a.sin() * r)
                    })
                    .collect()
            };
            p.add(egui::Shape::line(arc(-2.5, 0.35), stroke));
            p.add(egui::Shape::line(arc(0.75, 3.55), stroke));
            // Top-right arrowhead
            p.line_segment([pt(4.3, -1.3), pt(4.6, 1.8)], stroke);
            p.line_segment([pt(1.9, 1.5), pt(4.6, 1.8)], stroke);
            // Bottom-left arrowhead
            p.line_segment([pt(-4.3, 1.3), pt(-4.6, -1.8)], stroke);
            p.line_segment([pt(-1.9, -1.5), pt(-4.6, -1.8)], stroke);
        }
        Icon::Folder => {
            let pts = vec![
                pt(-5.6, -3.6),
                pt(-1.2, -3.6),
                pt(0.3, -2.0),
                pt(5.6, -2.0),
                pt(5.6, 4.4),
                pt(-5.6, 4.4),
                pt(-5.6, -3.6),
            ];
            p.add(egui::Shape::line(pts, stroke));
        }
        Icon::Search => {
            let c = pt(-1.2, -1.2);
            p.circle_stroke(c, 4.1 * s, stroke);
            p.line_segment([pt(1.8, 1.8), pt(5.2, 5.2)], Stroke::new(sw + 0.15, color));
        }
        Icon::Trash => {
            p.line_segment([pt(-5.2, -3.2), pt(5.2, -3.2)], stroke);
            p.line_segment([pt(-2.0, -3.2), pt(-1.6, -5.0)], stroke);
            p.line_segment([pt(-1.6, -5.0), pt(1.6, -5.0)], stroke);
            p.line_segment([pt(1.6, -5.0), pt(2.0, -3.2)], stroke);
            let body = vec![
                pt(-3.9, -3.2),
                pt(-3.3, 5.0),
                pt(3.3, 5.0),
                pt(3.9, -3.2),
            ];
            p.add(egui::Shape::line(body, stroke));
            p.line_segment([pt(-1.3, -1.0), pt(-1.1, 2.8)], stroke);
            p.line_segment([pt(1.3, -1.0), pt(1.1, 2.8)], stroke);
        }
        Icon::Shield => {
            let pts = vec![
                pt(0.0, -5.6),
                pt(4.8, -3.6),
                pt(4.5, 0.8),
                pt(0.0, 5.6),
                pt(-4.5, 0.8),
                pt(-4.8, -3.6),
                pt(0.0, -5.6),
            ];
            p.add(egui::Shape::line(pts, stroke));
            p.line_segment([pt(-2.0, 0.2), pt(-0.4, 1.8)], stroke);
            p.line_segment([pt(-0.4, 1.8), pt(2.4, -1.4)], stroke);
        }
        Icon::AlertTriangle => {
            let pts = vec![
                pt(0.0, -5.4),
                pt(5.6, 4.6),
                pt(-5.6, 4.6),
                pt(0.0, -5.4),
            ];
            p.add(egui::Shape::line(pts, stroke));
            p.line_segment([pt(0.0, -1.6), pt(0.0, 1.4)], stroke);
            p.circle_filled(pt(0.0, 3.1), 0.9 * s, color);
        }
        Icon::Restore => {
            let r = 4.5 * s;
            let segments = 14;
            let pts: Vec<Pos2> = (0..=segments)
                .map(|i| {
                    let t = i as f32 / segments as f32;
                    let a = -2.4 + t * 4.5;
                    center + vec2(a.cos() * r, a.sin() * r)
                })
                .collect();
            p.add(egui::Shape::line(pts, stroke));
            p.line_segment([pt(-4.8, -4.6), pt(-4.4, -1.6)], stroke);
            p.line_segment([pt(-1.4, -1.9), pt(-4.4, -1.6)], stroke);
        }
        Icon::Export => {
            p.add(egui::Shape::line(
                vec![pt(-4.8, 1.2), pt(-4.8, 4.8), pt(4.8, 4.8), pt(4.8, 1.2)],
                stroke,
            ));
            p.line_segment([pt(0.0, 1.6), pt(0.0, -4.8)], stroke);
            p.line_segment([pt(-2.8, -2.0), pt(0.0, -4.8)], stroke);
            p.line_segment([pt(2.8, -2.0), pt(0.0, -4.8)], stroke);
        }
        Icon::Check => {
            p.line_segment([pt(-4.2, 0.2), pt(-1.2, 3.4)], Stroke::new(sw + 0.2, color));
            p.line_segment([pt(-1.2, 3.4), pt(4.5, -3.2)], Stroke::new(sw + 0.2, color));
        }
        Icon::ChevronDown => {
            p.line_segment([pt(-3.6, -1.5), pt(0.0, 2.2)], stroke);
            p.line_segment([pt(0.0, 2.2), pt(3.6, -1.5)], stroke);
        }
        Icon::Back => {
            p.line_segment([pt(4.5, 0.0), pt(-4.2, 0.0)], stroke);
            p.line_segment([pt(-1.0, -3.4), pt(-4.2, 0.0)], stroke);
            p.line_segment([pt(-1.0, 3.4), pt(-4.2, 0.0)], stroke);
        }
        Icon::Close => {
            p.line_segment([pt(-3.4, -3.4), pt(3.4, 3.4)], stroke);
            p.line_segment([pt(3.4, -3.4), pt(-3.4, 3.4)], stroke);
        }
        Icon::Sparkles => {
            // Crisp four-point star + small satellite dot.
            p.line_segment([pt(-1.0, -5.0), pt(-1.0, 5.0)], stroke);
            p.line_segment([pt(-5.0, 0.0), pt(3.0, 0.0)], stroke);
            p.line_segment([pt(-3.2, -2.2), pt(1.2, 2.2)], Stroke::new(sw * 0.75, color));
            p.line_segment([pt(1.2, -2.2), pt(-3.2, 2.2)], Stroke::new(sw * 0.75, color));
            p.circle_filled(pt(4.2, -3.6), 1.1 * s, color);
        }
        Icon::Copy => {
            p.rect_stroke(
                Rect::from_min_max(pt(-1.8, -2.0), pt(4.6, 5.0)),
                1.5,
                stroke,
                StrokeKind::Inside,
            );
            p.add(egui::Shape::line(
                vec![pt(-1.8, 2.4), pt(-4.6, 2.4), pt(-4.6, -4.8), pt(1.8, -4.8), pt(1.8, -2.0)],
                stroke,
            ));
        }
        Icon::Clock => {
            p.circle_stroke(center, 5.0 * s, stroke);
            p.line_segment([pt(0.0, -3.0), pt(0.0, 0.2)], stroke);
            p.line_segment([pt(0.0, 0.2), pt(2.4, 1.8)], stroke);
        }
        Icon::Archive => {
            p.rect_stroke(
                Rect::from_min_max(pt(-5.6, -4.8), pt(5.6, -1.8)),
                1.4,
                stroke,
                StrokeKind::Inside,
            );
            p.add(egui::Shape::line(
                vec![pt(-4.6, -1.8), pt(-4.6, 4.8), pt(4.6, 4.8), pt(4.6, -1.8)],
                stroke,
            ));
            p.line_segment([pt(-1.8, 1.0), pt(1.8, 1.0)], stroke);
        }
        Icon::Info => {
            p.circle_stroke(center, 5.2 * s, stroke);
            p.circle_filled(pt(0.0, -2.2), 0.9 * s, color);
            p.line_segment([pt(0.0, -0.2), pt(0.0, 3.0)], stroke);
        }
        Icon::Filter => {
            p.add(egui::Shape::line(
                vec![
                    pt(-5.2, -4.2),
                    pt(5.2, -4.2),
                    pt(1.2, 0.6),
                    pt(1.2, 4.8),
                    pt(-1.2, 3.6),
                    pt(-1.2, 0.6),
                    pt(-5.2, -4.2),
                ],
                stroke,
            ));
        }
    }
}

/// Paints a smooth rotating arc spinner centered at `center`.
pub(crate) fn paint_spinner(ui: &Ui, center: Pos2, radius: f32, color: Color32) {
    let angle = spinner_angle(ui.ctx());
    let track = Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 48);
    ui.painter()
        .circle_stroke(center, radius, Stroke::new(1.6_f32, track));
    let segments = 12;
    let arc_len = std::f32::consts::PI * 1.15;
    let pts: Vec<Pos2> = (0..=segments)
        .map(|i| {
            let a = angle + (i as f32 / segments as f32) * arc_len;
            center + vec2(a.cos() * radius, a.sin() * radius)
        })
        .collect();
    ui.painter()
        .add(egui::Shape::line(pts, Stroke::new(1.75_f32, color)));
}

/// Paints a crisp vector sort chevron pointing up or down.
pub(crate) fn paint_sort_indicator(ui: &Ui, center: Pos2, active: bool, descending: bool, color: Color32) {
    let stroke = Stroke::new(1.4_f32, color);
    if active {
        if descending {
            ui.painter()
                .line_segment([center + vec2(-3.2, -1.6), center + vec2(0.0, 1.8)], stroke);
            ui.painter()
                .line_segment([center + vec2(0.0, 1.8), center + vec2(3.2, -1.6)], stroke);
        } else {
            ui.painter()
                .line_segment([center + vec2(-3.2, 1.6), center + vec2(0.0, -1.8)], stroke);
            ui.painter()
                .line_segment([center + vec2(0.0, -1.8), center + vec2(3.2, 1.6)], stroke);
        }
    } else {
        // Subtle bidirectional chevrons on hover
        let faint = Stroke::new(1.15_f32, color);
        ui.painter()
            .line_segment([center + vec2(-2.4, -1.3), center + vec2(0.0, -3.5)], faint);
        ui.painter()
            .line_segment([center + vec2(0.0, -3.5), center + vec2(2.4, -1.3)], faint);
        ui.painter()
            .line_segment([center + vec2(-2.4, 1.3), center + vec2(0.0, 3.5)], faint);
        ui.painter()
            .line_segment([center + vec2(0.0, 3.5), center + vec2(2.4, 1.3)], faint);
    }
}

// --- Optical Text Measurement & Painting Helpers ---

fn visual_bounds(galley: &Galley) -> Rect {
    if galley.mesh_bounds.is_positive() {
        galley.mesh_bounds
    } else {
        galley.rect
    }
}

pub(crate) fn measured_text_width(galley: &Galley) -> f32 {
    galley
        .size()
        .x
        .max(visual_bounds(galley).width())
        .ceil()
}

/// Paints a galley optically centered inside `rect` using its true ink bounding box.
pub(crate) fn paint_centered_galley(ui: &Ui, rect: Rect, galley: Arc<Galley>, color: Color32) {
    let bounds = visual_bounds(&galley);
    let pos = pos2(
        (rect.center().x - bounds.center().x).round(),
        (rect.center().y - bounds.center().y).round(),
    );
    ui.painter().galley(pos, galley, color);
}

/// Paints a single-line truncated galley left-aligned and optically centered vertically in `rect`.
pub(crate) fn paint_left_truncated(
    ui: &Ui,
    rect: Rect,
    text: &str,
    font: FontId,
    color: Color32,
) {
    let max_w = rect.width().max(8.0);
    let galley = layout_single_line_truncated(ui, text, font, color, max_w);
    let bounds = visual_bounds(&galley);
    let pos = pos2(
        rect.left().round(),
        (rect.center().y - bounds.center().y).round(),
    );
    ui.painter()
        .with_clip_rect(ui.clip_rect().intersect(rect))
        .galley(pos, galley, color);
}

/// Paints a single-line truncated galley right-aligned and optically centered vertically in `rect`.
pub(crate) fn paint_right_truncated(
    ui: &Ui,
    rect: Rect,
    text: &str,
    font: FontId,
    color: Color32,
) {
    let max_w = rect.width().max(8.0);
    let galley = layout_single_line_truncated(ui, text, font, color, max_w);
    let bounds = visual_bounds(&galley);
    let pos = pos2(
        (rect.right() - bounds.max.x).round(),
        (rect.center().y - bounds.center().y).round(),
    );
    ui.painter()
        .with_clip_rect(ui.clip_rect().intersect(rect))
        .galley(pos, galley, color);
}

/// Paints a vertically centered 1- or 2-line text block inside a list row cell so text never hugs borders.
#[allow(clippy::too_many_arguments)]
pub(crate) fn paint_two_line_cell(
    ui: &mut Ui,
    rect: Rect,
    title: &str,
    subtitle: Option<&str>,
    title_font: FontId,
    sub_font: FontId,
    title_color: Color32,
    sub_color: Color32,
    hover_hint: &str,
) {
    let max_w = rect.width().max(12.0);
    let title_galley = layout_single_line_truncated(ui, title, title_font, title_color, max_w);
    let title_bounds = visual_bounds(&title_galley);
    let painter = ui.painter().with_clip_rect(ui.clip_rect().intersect(rect));

    if let Some(sub) = subtitle.filter(|s| !s.is_empty()) {
        let sub_galley = layout_single_line_truncated(ui, sub, sub_font, sub_color, max_w);
        let sub_bounds = visual_bounds(&sub_galley);
        let gap = 5.0;
        let total_h = title_bounds.height() + gap + sub_bounds.height();
        let top_y = (rect.center().y - total_h * 0.5).round();

        let title_pos = pos2(rect.left().round(), (top_y - title_bounds.top()).round());
        let sub_pos = pos2(
            rect.left().round(),
            (top_y + title_bounds.height() + gap - sub_bounds.top()).round(),
        );
        painter.galley(title_pos, title_galley, title_color);
        painter.galley(sub_pos, sub_galley, sub_color);
    } else {
        let title_pos = pos2(
            rect.left().round(),
            (rect.center().y - title_bounds.center().y).round(),
        );
        painter.galley(title_pos, title_galley, title_color);
    }

    if !hover_hint.is_empty() {
        let hover_resp =
            ui.interact(rect, ui.make_persistent_id(("cell_tip", title)), Sense::hover());
        hover_resp.on_hover_text(hover_hint);
    }
}

pub(crate) fn layout_single_line_truncated(
    ui: &Ui,
    text: &str,
    font: FontId,
    color: Color32,
    max_width: f32,
) -> Arc<Galley> {
    let mut job = LayoutJob::single_section(text.to_owned(), TextFormat::simple(font, color));
    job.wrap = egui::text::TextWrapping::truncate_at_width(max_width);
    ui.painter().layout_job(job)
}

pub(crate) fn semibold_text(text: impl Into<String>, size: f32, color: Color32) -> RichText {
    RichText::new(text)
        .font(FontId::new(size, fonts::semibold_family()))
        .color(color)
}

pub(crate) fn body_text(text: impl Into<String>, size: f32, color: Color32) -> RichText {
    RichText::new(text)
        .font(FontId::proportional(size))
        .color(color)
}

pub(crate) fn card_shadow() -> Shadow {
    Shadow {
        offset: [0, 1],
        blur: 3,
        spread: 0,
        color: Color32::from_rgba_unmultiplied(16, 24, 40, 10),
    }
}

pub(crate) fn modal_shadow() -> Shadow {
    Shadow {
        offset: [0, 12],
        blur: 32,
        spread: 0,
        color: Color32::from_rgba_unmultiplied(16, 24, 40, 42),
    }
}

pub(crate) fn toast_shadow() -> Shadow {
    Shadow {
        offset: [0, 6],
        blur: 18,
        spread: 0,
        color: Color32::from_rgba_unmultiplied(16, 24, 40, 28),
    }
}

pub(crate) fn card(padding: i8) -> Frame {
    Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(HAIRLINE, LINE))
        .inner_margin(Margin::same(padding))
        .corner_radius(10)
        .shadow(card_shadow())
}

pub(crate) fn modal_card(padding: i8) -> Frame {
    Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(HAIRLINE, LINE))
        .inner_margin(Margin::same(padding))
        .corner_radius(12)
        .shadow(modal_shadow())
}

pub(crate) fn title(ui: &mut Ui, text: &str) {
    ui.label(semibold_text(text, 22.0, INK));
}

pub(crate) fn section_heading(ui: &mut Ui, text: &str) {
    ui.label(semibold_text(text, 14.5, INK));
}

// --- Unified Tactile Button System ---

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ButtonVariant {
    Primary,
    Secondary,
    Danger,
    DangerSubtle,
    Tinted,
    Ghost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ButtonSize {
    Regular,
    Compact,
}

#[derive(Clone, Copy)]
pub(crate) struct ButtonSpec<'a> {
    pub label: &'a str,
    pub variant: ButtonVariant,
    pub size: ButtonSize,
    pub enabled: bool,
    pub active: bool,
    pub busy: bool,
    pub leading_icon: Option<Icon>,
    pub trailing_icon: Option<Icon>,
    pub disabled_hint: Option<&'a str>,
}

impl<'a> ButtonSpec<'a> {
    pub(crate) fn new(label: &'a str, variant: ButtonVariant) -> Self {
        Self {
            label,
            variant,
            size: ButtonSize::Regular,
            enabled: true,
            active: false,
            busy: false,
            leading_icon: None,
            trailing_icon: None,
            disabled_hint: None,
        }
    }

    pub(crate) fn compact(mut self) -> Self {
        self.size = ButtonSize::Compact;
        self
    }

    pub(crate) fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub(crate) fn active(mut self, active: bool) -> Self {
        self.active = active;
        self
    }

    pub(crate) fn busy(mut self, busy: bool) -> Self {
        self.busy = busy;
        self
    }

    pub(crate) fn icon(mut self, icon: Icon) -> Self {
        self.leading_icon = Some(icon);
        self
    }

    pub(crate) fn trailing_icon(mut self, icon: Icon) -> Self {
        self.trailing_icon = Some(icon);
        self
    }

    pub(crate) fn disabled_hint(mut self, hint: &'a str) -> Self {
        self.disabled_hint = Some(hint);
        self
    }
}

/// Computes the exact width a button with `spec` will occupy.
pub(crate) fn measure_button_spec(ui: &Ui, spec: ButtonSpec<'_>) -> f32 {
    let (font_size, pad_x, min_w, icon_sz, gap) = match spec.size {
        ButtonSize::Regular => (13.0, 14.0, 82.0, 14.0, 7.0),
        ButtonSize::Compact => (12.0, 11.0, 56.0, 12.5, 5.5),
    };
    let font = FontId::new(font_size, fonts::semibold_family());
    let galley = ui.painter().layout_no_wrap(spec.label.to_owned(), font, INK);
    let mut content_w = measured_text_width(&galley);
    if spec.leading_icon.is_some() || spec.busy {
        content_w += icon_sz + gap;
    }
    if spec.trailing_icon.is_some() {
        content_w += icon_sz + gap;
    }
    (content_w + pad_x * 2.0).max(min_w)
}

/// Computes the exact width a standard button with a leading icon will occupy.
pub(crate) fn measure_icon_button_width(ui: &Ui, text: &str, icon: Icon, min_width: f32) -> f32 {
    measure_button_spec(ui, ButtonSpec::new(text, ButtonVariant::Secondary).icon(icon))
        .max(min_width)
}

/// Renders a refined, tactile desktop button with hover, active/press, focus-ring,
/// optional active/toggled state, optional spinning busy indicator, and working disabled tooltips.
pub(crate) fn action_button(ui: &mut Ui, spec: ButtonSpec<'_>) -> Response {
    let (height, radius, font_size, icon_sz, gap) = match spec.size {
        ButtonSize::Regular => (CONTROL_HEIGHT, 7.5, 13.0, 13.5, 7.0),
        ButtonSize::Compact => (COMPACT_HEIGHT, 6.5, 12.0, 12.0, 5.5),
    };
    let interactive = spec.enabled && !spec.busy;
    let width = measure_button_spec(ui, spec);
    let sense = if interactive {
        Sense::click()
    } else {
        Sense::hover()
    };
    let (rect, response) = ui.allocate_exact_size(vec2(width, height), sense);
    let id = ui.make_persistent_id(("action_btn", spec.label, spec.variant as u8, spec.size as u8));
    let hover_t = smooth_bool(ui.ctx(), id.with("hov"), interactive && response.hovered(), 0.11);
    let press_t = smooth_bool(
        ui.ctx(),
        id.with("prs"),
        interactive && response.is_pointer_button_down_on(),
        0.07,
    );
    let active_t = smooth_bool(ui.ctx(), id.with("act"), spec.active, 0.14);

    let (fill, border, text_color, focus_color, has_depth_highlight) = if !interactive {
        match spec.variant {
            ButtonVariant::Ghost => (Color32::TRANSPARENT, Color32::TRANSPARENT, DISABLED_TEXT, ACCENT, false),
            _ => (DISABLED_BG, LINE, DISABLED_TEXT, ACCENT, false),
        }
    } else {
        match spec.variant {
            ButtonVariant::Primary => {
                let f = lerp_color(lerp_color(ACCENT, ACCENT_HOVER, hover_t), ACCENT_ACTIVE, press_t);
                (f, f, SURFACE, ACCENT, true)
            }
            ButtonVariant::Danger => {
                let f = lerp_color(lerp_color(DANGER, DANGER_HOVER, hover_t), DANGER_ACTIVE, press_t);
                (f, f, SURFACE, DANGER, true)
            }
            ButtonVariant::Secondary => {
                let idle_fill = lerp_color(SURFACE, ACCENT_PALE, active_t);
                let hov_fill = lerp_color(SURFACE_ALT, ACCENT_PALE, active_t);
                let prs_fill = lerp_color(SURFACE_PRESSED, ACCENT_PALE, active_t);
                let f = lerp_color(lerp_color(idle_fill, hov_fill, hover_t), prs_fill, press_t);

                let idle_border = lerp_color(CONTROL_BORDER, ACCENT, active_t * 0.85);
                let hov_border = lerp_color(SUBTLE, ACCENT, active_t);
                let b = lerp_color(idle_border, hov_border, hover_t.max(press_t));

                let fg = lerp_color(INK, ACCENT, active_t);
                (f, b, fg, ACCENT, false)
            }
            ButtonVariant::Tinted => {
                let f = lerp_color(
                    lerp_color(ACCENT_PALE, Color32::from_rgb(224, 237, 255), hover_t),
                    Color32::from_rgb(209, 229, 255),
                    press_t,
                );
                let b = lerp_color(ACCENT_BORDER, ACCENT, hover_t.max(press_t));
                (f, b, ACCENT, ACCENT, false)
            }
            ButtonVariant::DangerSubtle => {
                let f = lerp_color(
                    lerp_color(PALE_RED, Color32::from_rgb(254, 226, 226), hover_t),
                    Color32::from_rgb(254, 202, 202),
                    press_t,
                );
                let b = lerp_color(DANGER_BORDER, DANGER, hover_t.max(press_t));
                (f, b, DANGER, DANGER, false)
            }
            ButtonVariant::Ghost => {
                let f = lerp_color(
                    lerp_color(Color32::TRANSPARENT, LINE_SOFT, hover_t),
                    LINE,
                    press_t,
                );
                let fg = lerp_color(MUTED, INK, hover_t.max(press_t));
                (f, Color32::TRANSPARENT, fg, ACCENT, false)
            }
        }
    };

    // Keyboard focus halo
    if interactive && response.has_focus() {
        ui.painter().rect_stroke(
            rect.expand(1.5),
            radius + 1.5,
            Stroke::new(
                2.0_f32,
                Color32::from_rgba_unmultiplied(focus_color.r(), focus_color.g(), focus_color.b(), 64),
            ),
            StrokeKind::Outside,
        );
    }

    // Subtle elevation drop shadow for solid buttons when not pressed
    if interactive && (matches!(spec.variant, ButtonVariant::Primary | ButtonVariant::Danger | ButtonVariant::Secondary)) && press_t < 0.5 {
        let shadow_alpha = match spec.variant {
            ButtonVariant::Primary | ButtonVariant::Danger => (20.0 * (1.0 - press_t)) as u8,
            ButtonVariant::Secondary => (10.0 * (1.0 - press_t)) as u8,
            _ => 0,
        };
        if shadow_alpha > 0 {
            let shadow_rect = rect.translate(vec2(0.0, 1.0));
            ui.painter().rect_filled(
                shadow_rect,
                radius,
                Color32::from_rgba_unmultiplied(16, 24, 40, shadow_alpha),
            );
        }
    }

    if fill.a() > 0 {
        ui.painter().rect_filled(rect, radius, fill);
    }
    if has_depth_highlight && press_t < 0.4 {
        // Subtle 1px top specular lip for solid primary/danger buttons
        ui.painter().hline(
            (rect.left() + radius)..=(rect.right() - radius),
            rect.top() + 1.0,
            Stroke::new(1.0_f32, Color32::from_white_alpha(38)),
        );
    }
    if border.a() > 0 {
        ui.painter()
            .rect_stroke(rect, radius, Stroke::new(HAIRLINE, border), StrokeKind::Inside);
    }

    // Paint content (leading icon/spinner + text + trailing icon) with subtle press offset
    let font = FontId::new(font_size, fonts::semibold_family());
    let galley = ui
        .painter()
        .layout_no_wrap(spec.label.to_owned(), font, text_color);
    let text_w = measured_text_width(&galley);
    let has_leading = spec.leading_icon.is_some() || spec.busy;
    let has_trailing = spec.trailing_icon.is_some();
    let total_content_w = text_w
        + if has_leading { icon_sz + gap } else { 0.0 }
        + if has_trailing { icon_sz + gap } else { 0.0 };

    let press_dy = if press_t > 0.35 { 0.5 } else { 0.0 };
    let mut cursor_x = rect.center().x - total_content_w * 0.5;
    let center_y = rect.center().y + press_dy;

    // Paint text first so test shape-walkers always see the button box directly before its text
    let text_x = cursor_x + if has_leading { icon_sz + gap } else { 0.0 };
    let text_rect = Rect::from_min_max(
        pos2(text_x, rect.top() + press_dy),
        pos2(text_x + text_w, rect.bottom() + press_dy),
    );
    paint_centered_galley(ui, text_rect, galley, text_color);

    if has_leading {
        let icon_center = pos2(cursor_x + icon_sz * 0.5, center_y);
        if spec.busy {
            paint_spinner(ui, icon_center, icon_sz * 0.38, text_color);
        } else if let Some(icon) = spec.leading_icon {
            paint_icon(ui, icon, icon_center, icon_sz, text_color);
        }
        cursor_x += icon_sz + gap;
    }
    cursor_x += text_w;
    if let Some(icon) = spec.trailing_icon {
        let icon_center = pos2(cursor_x + gap + icon_sz * 0.5, center_y);
        paint_icon(ui, icon, icon_center, icon_sz * 0.9, text_color);
    }

    if interactive && response.hovered() {
        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
    }
    if !interactive {
        if let Some(hint) = spec.disabled_hint {
            return response.on_hover_text(hint);
        }
    }
    response
}

/// Uniform-height secondary button (`34px`) with tactile hover/press states and optical centering.
pub(crate) fn secondary_button(ui: &mut Ui, enabled: bool, text: &str) -> Response {
    action_button(ui, ButtonSpec::new(text, ButtonVariant::Secondary).enabled(enabled))
}

/// Styled dropdown / context menu item with leading icon, danger styling, and hover pill.
pub(crate) fn menu_item(
    ui: &mut Ui,
    enabled: bool,
    label: &str,
    icon: Option<Icon>,
    danger: bool,
) -> Response {
    let width = ui.available_width().max(160.0);
    let sense = if enabled { Sense::click() } else { Sense::hover() };
    let (rect, response) = ui.allocate_exact_size(vec2(width, 32.0), sense);
    let id = ui.make_persistent_id(("menu_item", label));
    let hover_t = smooth_bool(ui.ctx(), id, enabled && response.hovered(), 0.09);

    let bg = if !enabled {
        Color32::TRANSPARENT
    } else if danger {
        lerp_color(Color32::TRANSPARENT, PALE_RED, hover_t)
    } else {
        lerp_color(Color32::TRANSPARENT, SURFACE_ALT, hover_t)
    };
    if bg.a() > 0 {
        ui.painter().rect_filled(rect, 6.0, bg);
    }

    let fg = if !enabled {
        DISABLED_TEXT
    } else if danger {
        DANGER
    } else {
        INK
    };
    let text_left = if icon.is_some() {
        rect.left() + 30.0
    } else {
        rect.left() + 10.0
    };
    if let Some(ic) = icon {
        paint_icon(
            ui,
            ic,
            pos2(rect.left() + 16.0, rect.center().y),
            13.5,
            if !enabled {
                DISABLED_TEXT
            } else if danger {
                DANGER
            } else {
                MUTED
            },
        );
    }
    let text_rect = Rect::from_min_max(
        pos2(text_left, rect.top()),
        pos2(rect.right() - 10.0, rect.bottom()),
    );
    paint_left_truncated(ui, text_rect, label, FontId::proportional(13.0), fg);
    if enabled && response.hovered() {
        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
    }
    response
}

/// Selectable chip button (`34px` tall, dynamic width) with smooth selection & hover animation.
pub(crate) fn chip_button(ui: &mut Ui, selected: bool, text: &str) -> Response {
    let font = FontId::new(12.5, fonts::semibold_family());
    let probe = ui.painter().layout_no_wrap(text.to_owned(), font.clone(), INK);
    let width = (measured_text_width(&probe) + 24.0).max(58.0);
    let (rect, response) = ui.allocate_exact_size(vec2(width, CONTROL_HEIGHT), Sense::click());
    let id = ui.make_persistent_id(("chip_btn", text));
    let sel_t = smooth_bool(ui.ctx(), id.with("sel"), selected, 0.14);
    let hov_t = smooth_bool(ui.ctx(), id.with("hov"), !selected && response.hovered(), 0.11);
    let prs_t = smooth_bool(
        ui.ctx(),
        id.with("prs"),
        response.is_pointer_button_down_on(),
        0.07,
    );

    let fill = lerp_color(
        lerp_color(lerp_color(SURFACE, SURFACE_ALT, hov_t), SURFACE_PRESSED, prs_t),
        ACCENT_PALE,
        sel_t,
    );
    let border = lerp_color(
        lerp_color(CONTROL_BORDER, SUBTLE, hov_t),
        ACCENT,
        sel_t,
    );
    let fg = lerp_color(lerp_color(MUTED, INK, hov_t), ACCENT, sel_t);

    ui.painter().rect_filled(rect, 7.5, fill);
    ui.painter().rect_stroke(
        rect,
        7.5,
        Stroke::new(lerp_f32(HAIRLINE, 1.3, sel_t), border),
        StrokeKind::Inside,
    );
    let galley = ui.painter().layout_no_wrap(text.to_owned(), font, fg);
    paint_centered_galley(ui, rect, galley, fg);
    if response.hovered() {
        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
    }
    response
}

/// Compact filter pill (`28px` tall) with optional trailing count used in review/toolbar filters.
pub(crate) fn filter_pill(ui: &mut Ui, selected: bool, label: &str, count: Option<usize>) -> Response {
    let text = match count {
        Some(n) => format!("{label} ({n})"),
        None => label.to_owned(),
    };
    let font = FontId::new(12.0, fonts::semibold_family());
    let probe = ui.painter().layout_no_wrap(text.clone(), font.clone(), INK);
    let width = (measured_text_width(&probe) + 22.0).max(54.0);
    let (rect, response) = ui.allocate_exact_size(vec2(width, COMPACT_HEIGHT), Sense::click());
    let id = ui.make_persistent_id(("filter_pill", label));
    let sel_t = smooth_bool(ui.ctx(), id.with("sel"), selected, 0.14);
    let hov_t = smooth_bool(ui.ctx(), id.with("hov"), !selected && response.hovered(), 0.11);

    let fill = lerp_color(lerp_color(SURFACE, SURFACE_ALT, hov_t), ACCENT_PALE, sel_t);
    let border = lerp_color(lerp_color(LINE, CONTROL_BORDER, hov_t), ACCENT, sel_t);
    let fg = lerp_color(lerp_color(MUTED, INK, hov_t), ACCENT, sel_t);

    ui.painter().rect_filled(rect, 7.0, fill);
    ui.painter()
        .rect_stroke(rect, 7.0, Stroke::new(HAIRLINE, border), StrokeKind::Inside);
    let galley = ui.painter().layout_no_wrap(text, font, fg);
    paint_centered_galley(ui, rect, galley, fg);
    if response.hovered() {
        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
    }
    response
}

/// Crisp custom-drawn rounded-square checkbox (`16×16px`) with smooth check animation.
pub(crate) fn paint_checkbox_box(
    ui: &Ui,
    rect: Rect,
    id: Id,
    checked: bool,
    indeterminate: bool,
    enabled: bool,
    hovered: bool,
) {
    let active = checked || indeterminate;
    let check_t = smooth_bool(ui.ctx(), id.with("chk"), active, 0.13);
    let hover_t = smooth_bool(ui.ctx(), id.with("hov"), enabled && hovered, 0.10);

    let box_rect = Rect::from_center_size(rect.center(), Vec2::splat(16.0));
    let bg = if !enabled {
        DISABLED_BG
    } else {
        lerp_color(
            lerp_color(SURFACE, ACCENT_SOFT, hover_t * 0.6),
            ACCENT,
            check_t,
        )
    };
    let border = if !enabled {
        LINE
    } else {
        lerp_color(
            lerp_color(CONTROL_BORDER, ACCENT, hover_t),
            ACCENT,
            check_t,
        )
    };
    ui.painter().rect_filled(box_rect, 4.5, bg);
    ui.painter().rect_stroke(
        box_rect,
        4.5,
        Stroke::new(1.2_f32, border),
        StrokeKind::Inside,
    );

    if check_t > 0.15 {
        let fg = Color32::from_rgba_unmultiplied(
            255,
            255,
            255,
            (check_t * 255.0).round() as u8,
        );
        let c = box_rect.center();
        if indeterminate && !checked {
            ui.painter()
                .hline(c.x - 4.0..=c.x + 4.0, c.y, Stroke::new(1.8_f32, fg));
        } else {
            let stroke = Stroke::new(1.8_f32, fg);
            ui.painter()
                .line_segment([c + vec2(-3.8, 0.2), c + vec2(-1.1, 3.0)], stroke);
            ui.painter()
                .line_segment([c + vec2(-1.1, 3.0), c + vec2(4.1, -2.8)], stroke);
        }
    }
}

/// Interactive standalone rounded-square checkbox (supports indeterminate state for header).
pub(crate) fn styled_checkbox(
    ui: &mut Ui,
    id: Id,
    checked: &mut bool,
    indeterminate: bool,
    enabled: bool,
) -> Response {
    let sense = if enabled {
        Sense::click()
    } else {
        Sense::hover()
    };
    let (rect, mut response) = ui.allocate_exact_size(vec2(18.0, 18.0), sense);
    if enabled && response.clicked() {
        *checked = !*checked;
        response.mark_changed();
    }
    paint_checkbox_box(
        ui,
        rect,
        id,
        *checked,
        indeterminate,
        enabled,
        response.hovered(),
    );
    if enabled && response.hovered() {
        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
    }
    response
}

/// Smooth sliding pill toggle switch aligned cleanly to `CONTROL_HEIGHT = 34px`.
pub(crate) fn toggle_switch_labeled(
    ui: &mut Ui,
    id: Id,
    checked: &mut bool,
    label: &str,
) -> Response {
    let font = FontId::proportional(13.0);
    let probe = ui.painter().layout_no_wrap(label.to_owned(), font.clone(), MUTED);
    let text_w = measured_text_width(&probe);
    let track_w = 32.0;
    let track_h = 18.0;
    let total_w = track_w + 8.0 + text_w + 4.0;
    let (rect, mut response) =
        ui.allocate_exact_size(vec2(total_w, CONTROL_HEIGHT), Sense::click());
    if response.clicked() {
        *checked = !*checked;
        response.mark_changed();
    }
    let on_t = smooth_bool(ui.ctx(), id.with("on"), *checked, 0.14);
    let hov_t = smooth_bool(ui.ctx(), id.with("hov"), response.hovered(), 0.10);

    let track_rect = Rect::from_min_size(
        pos2(rect.left(), rect.center().y - track_h * 0.5),
        vec2(track_w, track_h),
    );
    let track_bg = lerp_color(
        lerp_color(Color32::from_rgb(208, 213, 221), Color32::from_rgb(184, 192, 204), hov_t),
        lerp_color(ACCENT, ACCENT_HOVER, hov_t),
        on_t,
    );
    ui.painter().rect_filled(track_rect, track_h * 0.5, track_bg);

    let knob_r = 6.5;
    let knob_x = lerp_f32(
        track_rect.left() + 2.5 + knob_r,
        track_rect.right() - 2.5 - knob_r,
        on_t,
    );
    let knob_center = pos2(knob_x, track_rect.center().y);
    ui.painter().circle_filled(
        knob_center + vec2(0.0, 0.8),
        knob_r,
        Color32::from_rgba_unmultiplied(16, 24, 40, 22),
    );
    ui.painter().circle_filled(knob_center, knob_r, SURFACE);

    let text_color = lerp_color(MUTED, INK, on_t.max(hov_t));
    let draw_galley = ui
        .painter()
        .layout_no_wrap(label.to_owned(), font, text_color);
    let bounds = visual_bounds(&draw_galley);
    let pos = pos2(
        (track_rect.right() + 8.0).round(),
        (rect.center().y - bounds.center().y).round(),
    );
    ui.painter().galley(pos, draw_galley, text_color);
    if response.hovered() {
        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
    }
    response
}

/// Custom styled numeric stepper (`−` / editable value / `+`) aligned to `CONTROL_HEIGHT = 34px`.
pub(crate) fn numeric_stepper(
    ui: &mut Ui,
    id: Id,
    value: &mut u16,
    min: u16,
    max: u16,
    suffix: &str,
) -> bool {
    let mut changed = false;
    let total_w = 152.0;
    let btn_w = 30.0;
    let (outer, _) = ui.allocate_exact_size(vec2(total_w, CONTROL_HEIGHT), Sense::hover());
    ui.painter().rect_filled(outer, 7.5, SURFACE);
    ui.painter().rect_stroke(
        outer,
        7.5,
        Stroke::new(HAIRLINE, CONTROL_BORDER),
        StrokeKind::Inside,
    );

    let minus_rect = Rect::from_min_size(outer.min, vec2(btn_w, CONTROL_HEIGHT));
    let plus_rect = Rect::from_min_size(
        pos2(outer.right() - btn_w, outer.top()),
        vec2(btn_w, CONTROL_HEIGHT),
    );
    let mid_rect = Rect::from_min_max(
        pos2(minus_rect.right() + 2.0, outer.top() + 2.0),
        pos2(plus_rect.left() - 2.0, outer.bottom() - 2.0),
    );

    let can_dec = *value > min;
    let can_inc = *value < max;
    let dec_resp = ui.interact(
        minus_rect,
        id.with("dec"),
        if can_dec { Sense::click() } else { Sense::hover() },
    );
    let inc_resp = ui.interact(
        plus_rect,
        id.with("inc"),
        if can_inc { Sense::click() } else { Sense::hover() },
    );

    if can_dec && dec_resp.hovered() {
        ui.painter().rect_filled(
            minus_rect.shrink(1.0),
            CornerRadius { nw: 6, sw: 6, ne: 0, se: 0 },
            SURFACE_ALT,
        );
        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
    }
    if can_inc && inc_resp.hovered() {
        ui.painter().rect_filled(
            plus_rect.shrink(1.0),
            CornerRadius { nw: 0, sw: 0, ne: 6, se: 6 },
            SURFACE_ALT,
        );
        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
    }
    if can_dec && dec_resp.clicked() {
        *value = value.saturating_sub(1).max(min);
        changed = true;
    }
    if can_inc && inc_resp.clicked() {
        *value = value.saturating_add(1).min(max);
        changed = true;
    }

    // Internal hairline separators
    ui.painter().vline(
        minus_rect.right(),
        (outer.top() + 6.0)..=(outer.bottom() - 6.0),
        Stroke::new(HAIRLINE, LINE_SOFT),
    );
    ui.painter().vline(
        plus_rect.left(),
        (outer.top() + 6.0)..=(outer.bottom() - 6.0),
        Stroke::new(HAIRLINE, LINE_SOFT),
    );

    // Minus & Plus vector glyphs
    let dec_color = if can_dec { INK } else { DISABLED_TEXT };
    let inc_color = if can_inc { INK } else { DISABLED_TEXT };
    let mc = minus_rect.center();
    ui.painter()
        .hline(mc.x - 4.0..=mc.x + 4.0, mc.y, Stroke::new(1.5_f32, dec_color));
    let pc = plus_rect.center();
    ui.painter()
        .hline(pc.x - 4.0..=pc.x + 4.0, pc.y, Stroke::new(1.5_f32, inc_color));
    ui.painter()
        .vline(pc.x, pc.y - 4.0..=pc.y + 4.0, Stroke::new(1.5_f32, inc_color));

    // Centered drag/editable value inside mid_rect
    let mut child = ui.new_child(
        UiBuilder::new()
            .max_rect(mid_rect)
            .layout(Layout::centered_and_justified(egui::Direction::LeftToRight)),
    );
    child.visuals_mut().widgets.inactive.weak_bg_fill = Color32::TRANSPARENT;
    child.visuals_mut().widgets.inactive.bg_stroke = Stroke::NONE;
    child.visuals_mut().widgets.hovered.weak_bg_fill = SURFACE_ALT;
    child.visuals_mut().widgets.hovered.bg_stroke = Stroke::NONE;
    let dv = child.add(
        egui::DragValue::new(value)
            .range(min..=max)
            .suffix(suffix),
    );
    changed |= dv.changed();
    changed
}

/// Custom collapsible section header with smooth rotating chevron and optional meta text.
pub(crate) fn collapsible_section(
    ui: &mut Ui,
    id: Id,
    title: &str,
    meta: Option<&str>,
    default_open: bool,
    body: impl FnOnce(&mut Ui),
) {
    let state_id = id.with("open");
    let mut open = ui
        .ctx()
        .memory(|m| m.data.get_temp::<bool>(state_id))
        .unwrap_or(default_open);

    let width = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(vec2(width, 30.0), Sense::click());
    if resp.clicked() {
        open = !open;
        ui.ctx().memory_mut(|m| m.data.insert_temp(state_id, open));
    }
    let hov_t = smooth_bool(ui.ctx(), id.with("hov"), resp.hovered(), 0.10);
    let open_t = smooth_bool(ui.ctx(), id.with("anim"), open, 0.15);

    if hov_t > 0.01 {
        ui.painter().rect_filled(
            rect,
            6.0,
            lerp_color(Color32::TRANSPARENT, SURFACE_ALT, hov_t),
        );
    }

    // Rotating chevron
    let chevron_c = pos2(rect.left() + 10.0, rect.center().y);
    let angle = lerp_f32(0.0, std::f32::consts::FRAC_PI_2, open_t);
    let rot = |v: Vec2| {
        let (sin, cos) = angle.sin_cos();
        vec2(v.x * cos - v.y * sin, v.x * sin + v.y * cos)
    };
    let chev_color = lerp_color(SUBTLE, INK, hov_t.max(open_t * 0.6));
    let stroke = Stroke::new(1.45_f32, chev_color);
    let p0 = chevron_c + rot(vec2(-1.6, -3.4));
    let p1 = chevron_c + rot(vec2(2.0, 0.0));
    let p2 = chevron_c + rot(vec2(-1.6, 3.4));
    ui.painter().line_segment([p0, p1], stroke);
    ui.painter().line_segment([p1, p2], stroke);

    let title_color = lerp_color(MUTED, INK, hov_t.max(open_t * 0.5));
    let label_right = if meta.is_some() {
        rect.right() - 72.0
    } else {
        rect.right() - 8.0
    };
    let label_rect = Rect::from_min_max(
        pos2(rect.left() + 24.0, rect.top()),
        pos2(label_right.max(rect.left() + 60.0), rect.bottom()),
    );
    paint_left_truncated(
        ui,
        label_rect,
        title,
        FontId::new(12.5, fonts::semibold_family()),
        title_color,
    );

    if let Some(meta_text) = meta {
        let meta_rect = Rect::from_min_max(
            pos2(rect.right() - 68.0, rect.top()),
            pos2(rect.right() - 8.0, rect.bottom()),
        );
        paint_right_truncated(ui, meta_rect, meta_text, FontId::proportional(11.5), SUBTLE);
    }

    if resp.hovered() {
        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
    }

    if open {
        ui.add_space(4.0);
        ui.indent(id.with("indent"), body);
    }
}

pub(crate) fn notice(ui: &mut Ui, text: &str, foreground: Color32, background: Color32) {
    notice_with_action(ui, text, foreground, background, None);
}

/// Inline status notice with accent bar, semantic icon, and optional dismiss `×` button.
/// Returns `true` if the dismiss button was clicked.
pub(crate) fn notice_with_action(
    ui: &mut Ui,
    text: &str,
    foreground: Color32,
    background: Color32,
    dismiss_tooltip: Option<&str>,
) -> bool {
    let mut dismissed = false;
    let icon = if foreground == DANGER || foreground == DARK_AMBER {
        Icon::AlertTriangle
    } else if foreground == DARK_GREEN {
        Icon::Check
    } else {
        Icon::Info
    };
    let frame_resp = Frame::new()
        .fill(background)
        .stroke(Stroke::new(HAIRLINE, lerp_color(background, foreground, 0.24)))
        .corner_radius(8)
        .inner_margin(Margin {
            left: 16,
            right: 12,
            top: 9,
            bottom: 9,
        })
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                let (icon_rect, _) = ui.allocate_exact_size(vec2(14.0, 16.0), Sense::hover());
                paint_icon(ui, icon, icon_rect.center(), 13.5, foreground);

                let text_w = if dismiss_tooltip.is_some() {
                    (ui.available_width() - 28.0).max(80.0)
                } else {
                    ui.available_width()
                };
                ui.allocate_ui_with_layout(
                    vec2(text_w, 0.0),
                    Layout::top_down(Align::LEFT),
                    |ui| {
                        ui.label(body_text(text, 12.5, foreground));
                    },
                );

                if let Some(tip) = dismiss_tooltip {
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let (close_rect, close_resp) =
                            ui.allocate_exact_size(vec2(22.0, 22.0), Sense::click());
                        if close_resp.hovered() {
                            ui.painter().circle_filled(
                                close_rect.center(),
                                10.0,
                                Color32::from_rgba_unmultiplied(
                                    foreground.r(),
                                    foreground.g(),
                                    foreground.b(),
                                    24,
                                ),
                            );
                            ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
                        }
                        paint_icon(ui, Icon::Close, close_rect.center(), 10.5, foreground);
                        if close_resp.on_hover_text(tip).clicked() {
                            dismissed = true;
                        }
                    });
                }
            });
        });
    let rect = frame_resp.response.rect;
    let bar = Rect::from_min_max(
        pos2(rect.left() + 4.0, rect.top() + 6.0),
        pos2(rect.left() + 7.0, rect.bottom() - 6.0),
    );
    ui.painter().rect_filled(bar, 1.5, foreground);
    dismissed
}

/// Compact, fixed-height (`24px`) inline badge with optical centering and exact galley sizing.
pub(crate) fn badge(
    ui: &mut Ui,
    text: &str,
    foreground: Color32,
    background: Color32,
) -> Response {
    let font = FontId::new(11.5, fonts::semibold_family());
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_owned(), font, foreground);
    let width = measured_text_width(&galley) + 18.0;
    let (rect, response) = ui.allocate_exact_size(vec2(width, 24.0), Sense::hover());
    ui.painter().rect_filled(rect, 6.0, background);
    ui.painter().rect_stroke(
        rect,
        6.0,
        Stroke::new(HAIRLINE, lerp_color(background, foreground, 0.16)),
        StrokeKind::Inside,
    );
    paint_centered_galley(ui, rect, galley, foreground);
    response
}

/// Inline badge with a subtle leading icon (`24px` tall).
pub(crate) fn icon_badge(
    ui: &mut Ui,
    icon: Icon,
    text: &str,
    foreground: Color32,
    background: Color32,
) -> Response {
    let font = FontId::new(11.5, fonts::semibold_family());
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_owned(), font, foreground);
    let text_w = measured_text_width(&galley);
    let icon_sz = 11.5;
    let gap = 5.0;
    let width = text_w + icon_sz + gap + 18.0;
    let (rect, response) = ui.allocate_exact_size(vec2(width, 24.0), Sense::hover());
    ui.painter().rect_filled(rect, 6.0, background);
    ui.painter().rect_stroke(
        rect,
        6.0,
        Stroke::new(HAIRLINE, lerp_color(background, foreground, 0.16)),
        StrokeKind::Inside,
    );
    let start_x = rect.center().x - (icon_sz + gap + text_w) * 0.5;
    let text_rect = Rect::from_min_max(
        pos2(start_x + icon_sz + gap, rect.top()),
        pos2(start_x + icon_sz + gap + text_w, rect.bottom()),
    );
    paint_centered_galley(ui, text_rect, galley, foreground);
    paint_icon(
        ui,
        icon,
        pos2(start_x + icon_sz * 0.5, rect.center().y),
        icon_sz,
        foreground,
    );
    response
}

/// Compact sidebar count pill (`20px` tall) painted directly with optical centering.
pub(crate) fn paint_count_pill(ui: &Ui, right_center: Pos2, count: usize, active: bool) {
    let label = count.to_string();
    let font = FontId::new(11.0, fonts::semibold_family());
    let fg = if active { ACCENT } else { SUBTLE };
    let bg = if active {
        ACCENT_PALE
    } else {
        Color32::from_rgb(232, 235, 241)
    };
    let galley = ui.painter().layout_no_wrap(label, font, fg);
    let w = (measured_text_width(&galley) + 14.0).max(24.0);
    let h = 20.0;
    let rect = Rect::from_min_size(
        pos2(right_center.x - w, right_center.y - h * 0.5),
        vec2(w, h),
    );
    ui.painter().rect_filled(rect, h * 0.5, bg);
    paint_centered_galley(ui, rect, galley, fg);
}

/// Compact summary metric tile used in Quarantine/Review overview strips.
pub(crate) fn metric_card(
    ui: &mut Ui,
    width: f32,
    label: &str,
    value: &str,
    accent: Color32,
    tint: Color32,
    icon: Icon,
) {
    Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(HAIRLINE, LINE))
        .corner_radius(10)
        .inner_margin(Margin::symmetric(14, 12))
        .shadow(card_shadow())
        .show(ui, |ui| {
            ui.set_width((width - 28.0).max(80.0));
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 10.0;
                let (well, _) = ui.allocate_exact_size(vec2(32.0, 32.0), Sense::hover());
                ui.painter().rect_filled(well, 8.0, tint);
                paint_icon(ui, icon, well.center(), 15.0, accent);
                let (text_rect, _) =
                    ui.allocate_exact_size(vec2(ui.available_width(), 34.0), Sense::hover());
                paint_two_line_cell(
                    ui,
                    text_rect,
                    value,
                    Some(label),
                    FontId::new(16.0, fonts::semibold_family()),
                    FontId::proportional(11.5),
                    INK,
                    SUBTLE,
                    "",
                );
            });
        });
}

/// Rich centered empty state with tinted circular icon well, title, description, and optional CTA.
/// Returns `true` if the optional action button was clicked.
pub(crate) fn empty_state(
    ui: &mut Ui,
    height: f32,
    icon: Icon,
    heading: &str,
    description: Option<&str>,
    action_label: Option<&str>,
) -> bool {
    let mut clicked = false;
    let width = ui.available_width();
    ui.allocate_ui_with_layout(
        vec2(width, height),
        Layout::top_down(Align::Center),
        |ui| {
            let content_h = 44.0
                + 10.0
                + 20.0
                + if description.is_some() { 22.0 } else { 0.0 }
                + if action_label.is_some() { 44.0 } else { 0.0 };
            let top_pad = ((height - content_h) * 0.45).max(12.0);
            ui.add_space(top_pad);

            let (well, _) = ui.allocate_exact_size(vec2(44.0, 44.0), Sense::hover());
            ui.painter().circle_filled(well.center(), 22.0, SURFACE_ALT);
            ui.painter()
                .circle_stroke(well.center(), 22.0, Stroke::new(HAIRLINE, LINE));
            paint_icon(ui, icon, well.center(), 19.0, SUBTLE);

            ui.add_space(10.0);
            ui.label(semibold_text(heading, 14.0, INK));
            if let Some(desc) = description {
                ui.add_space(3.0);
                ui.label(body_text(desc, 12.5, SUBTLE));
            }
            if let Some(cta) = action_label {
                ui.add_space(12.0);
                if action_button(ui, ButtonSpec::new(cta, ButtonVariant::Secondary).compact())
                    .clicked()
                {
                    clicked = true;
                }
            }
        },
    );
    clicked
}

/// Renders a subtle animated loading skeleton with a status caption.
pub(crate) fn loading_skeleton(ui: &mut Ui, height: f32, row_height: f32, message: &str) {
    let phase = shimmer_phase(ui.ctx());
    let rows = ((height - 44.0) / row_height).floor().clamp(2.0, 7.0) as usize;
    ui.vertical(|ui| {
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            ui.add_space(16.0);
            let (spin_rect, _) = ui.allocate_exact_size(vec2(16.0, 16.0), Sense::hover());
            paint_spinner(ui, spin_rect.center(), 6.0, ACCENT);
            ui.label(body_text(message, 13.0, MUTED));
        });
        ui.add_space(8.0);
        let width = ui.available_width();
        for index in 0..rows {
            let (rect, _) = ui.allocate_exact_size(vec2(width, row_height), Sense::hover());
            let wave = (((phase + index as f32 * 0.11) % 1.0) * std::f32::consts::PI).sin();
            let base = lerp_color(LINE_SOFT, PAGE, 0.35 + wave * 0.45);
            let avatar = Rect::from_min_size(
                pos2(rect.left() + 50.0, rect.center().y - 15.0),
                vec2(30.0, 30.0),
            );
            ui.painter().rect_filled(avatar, 8.0, base);
            let bar1_w = (width * 0.24).min(190.0) * (0.75 + ((index * 37) % 5) as f32 * 0.06);
            let bar1 = Rect::from_min_size(
                pos2(avatar.right() + 12.0, rect.center().y - 9.0),
                vec2(bar1_w, 9.0),
            );
            ui.painter().rect_filled(bar1, 4.0, base);
            let bar2 = Rect::from_min_size(
                pos2(avatar.right() + 12.0, rect.center().y + 4.0),
                vec2(bar1_w * 0.55, 7.0),
            );
            ui.painter()
                .rect_filled(bar2, 3.5, lerp_color(base, SURFACE, 0.35));
            let pill = Rect::from_min_size(
                pos2(rect.right() - 84.0, rect.center().y - 11.0),
                vec2(64.0, 22.0),
            );
            ui.painter().rect_filled(pill, 6.0, base);
            ui.painter()
                .hline(rect.x_range(), rect.bottom(), Stroke::new(HAIRLINE, LINE_SOFT));
        }
    });
}

pub(crate) fn truncate(ui: &mut Ui, text: RichText, hint: &str) {
    ui.add(Label::new(text).truncate()).on_hover_text(hint);
}

/// Output of `styled_text_input`.
pub(crate) struct TextInputResult {
    pub changed: bool,
    pub submitted: bool,
}

/// Unified single-line text input (`CONTROL_HEIGHT = 34px`) with leading icon,
/// animated cobalt focus ring, inline clear `×` button, and optional shortcut hint pill.
#[allow(clippy::too_many_arguments)]
pub(crate) fn styled_text_input(
    ui: &mut Ui,
    id: Id,
    value: &mut String,
    hint: &str,
    width: f32,
    icon: Option<Icon>,
    shortcut_hint: Option<&str>,
    enabled: bool,
    request_focus: bool,
) -> TextInputResult {
    let mut changed = false;
    let focused = ui
        .ctx()
        .memory(|m| m.data.get_temp::<bool>(id.with("focused")))
        .unwrap_or(false);
    let focus_t = smooth_bool(ui.ctx(), id.with("focus_t"), enabled && focused, 0.14);
    let border_color = if !enabled {
        LINE
    } else {
        lerp_color(CONTROL_BORDER, ACCENT, focus_t)
    };

    let (outer_rect, _) = ui.allocate_exact_size(vec2(width, CONTROL_HEIGHT), Sense::hover());
    if focus_t > 0.02 {
        ui.painter().rect_stroke(
            outer_rect.expand(1.5),
            8.5,
            Stroke::new(
                2.0_f32,
                Color32::from_rgba_unmultiplied(37, 99, 235, (focus_t * 44.0).round() as u8),
            ),
            StrokeKind::Outside,
        );
    }
    ui.painter()
        .rect_filled(outer_rect, 7.5, if enabled { SURFACE } else { DISABLED_BG });
    ui.painter().rect_stroke(
        outer_rect,
        7.5,
        Stroke::new(lerp_f32(HAIRLINE, 1.35, focus_t), border_color),
        StrokeKind::Inside,
    );

    let inner_rect = outer_rect.shrink2(vec2(10.0, 2.0));
    let mut child = ui.new_child(
        UiBuilder::new()
            .max_rect(inner_rect)
            .layout(Layout::left_to_right(Align::Center)),
    );
    child.spacing_mut().item_spacing.x = 7.0;

    if let Some(ic) = icon {
        let (icon_rect, _) = child.allocate_exact_size(vec2(14.0, 14.0), Sense::hover());
        let icon_color = if !enabled {
            DISABLED_TEXT
        } else {
            lerp_color(SUBTLE, ACCENT, focus_t)
        };
        paint_icon(&child, ic, icon_rect.center(), 13.5, icon_color);
    }

    let show_clear = enabled && !value.is_empty();
    let show_kbd = enabled && value.is_empty() && !focused && shortcut_hint.is_some();
    let trailing_space = if show_clear {
        24.0
    } else if show_kbd {
        42.0
    } else {
        0.0
    };
    let edit_width = (child.available_width() - trailing_space).max(60.0);
    let resp = child.add_enabled(
        enabled,
        TextEdit::singleline(value)
            .id(id.with("edit"))
            .frame(false)
            .font(FontId::proportional(13.0))
            .desired_width(edit_width)
            .hint_text(body_text(hint, 13.0, SUBTLE))
            .margin(Margin::symmetric(0, 5)),
    );
    if request_focus && enabled {
        resp.request_focus();
    }
    changed |= resp.changed();
    let has_focus = resp.has_focus();
    let submitted = (resp.lost_focus() || has_focus)
        && ui.input(|i| i.key_pressed(egui::Key::Enter));
    ui.ctx()
        .memory_mut(|m| m.data.insert_temp(id.with("focused"), has_focus));

    if show_clear {
        let (clear_rect, clear_resp) = child.allocate_exact_size(vec2(18.0, 18.0), Sense::click());
        let bg = if clear_resp.hovered() {
            LINE
        } else {
            LINE_SOFT
        };
        child.painter().circle_filled(clear_rect.center(), 8.0, bg);
        paint_icon(&child, Icon::Close, clear_rect.center(), 9.5, MUTED);
        if clear_resp.hovered() {
            ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
        }
        if clear_resp.clicked() {
            value.clear();
            changed = true;
            resp.request_focus();
        }
    } else if let Some(kbd) = shortcut_hint.filter(|_| show_kbd) {
        let font = FontId::new(10.5, fonts::semibold_family());
        let galley = child.painter().layout_no_wrap(kbd.to_owned(), font, SUBTLE);
        let w = (measured_text_width(&galley) + 10.0).max(26.0);
        let (kbd_rect, _) = child.allocate_exact_size(vec2(w, 18.0), Sense::hover());
        child.painter().rect_filled(kbd_rect, 4.5, PAGE);
        paint_centered_galley(&child, kbd_rect, galley, SUBTLE);
    }

    TextInputResult { changed, submitted }
}

/// Brand icon mark in the sidebar header.
pub(crate) fn mark(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(vec2(34.0, 34.0), Sense::hover());
    ui.painter().rect_filled(rect, 9.0, ACCENT);
    ui.painter().rect_stroke(
        rect.shrink(0.5),
        9.0,
        Stroke::new(1.0_f32, Color32::from_white_alpha(44)),
        StrokeKind::Inside,
    );
    let center = rect.center();
    ui.painter().rect_stroke(
        Rect::from_center_size(center + vec2(0.0, 0.8), vec2(17.0, 14.0)),
        3.0,
        Stroke::new(1.5_f32, SURFACE),
        StrokeKind::Inside,
    );
    ui.painter().hline(
        center.x - 7.5..=center.x + 7.5,
        center.y - 2.4,
        Stroke::new(1.3_f32, SURFACE),
    );
    ui.painter().line_segment(
        [center + vec2(-2.8, 2.8), center + vec2(-0.4, 4.8)],
        Stroke::new(1.6_f32, SURFACE),
    );
    ui.painter().line_segment(
        [center + vec2(-0.4, 4.8), center + vec2(3.8, 1.3)],
        Stroke::new(1.6_f32, SURFACE),
    );
}

/// Deterministic pastel avatar badge (`32×32px`) with optically centered initial.
pub(crate) fn app_glyph(ui: &mut Ui, name: &str, letter: char) {
    let hash = name
        .bytes()
        .fold(0usize, |acc, b| acc.wrapping_mul(31).wrapping_add(b as usize));
    let (fg, bg) = GLYPH_PALETTE[hash % GLYPH_PALETTE.len()];
    let (rect, _) = ui.allocate_exact_size(vec2(32.0, 32.0), Sense::hover());
    ui.painter().rect_filled(rect, 8.0, bg);
    ui.painter().rect_stroke(
        rect,
        8.0,
        Stroke::new(HAIRLINE, lerp_color(bg, fg, 0.14)),
        StrokeKind::Inside,
    );
    let galley = ui.painter().layout_no_wrap(
        letter.to_string(),
        FontId::new(14.0, fonts::semibold_family()),
        fg,
    );
    paint_centered_galley(ui, rect, galley, fg);
}

/// Smooth animated segmented control for 2-option switches with optical text centering.
pub(crate) fn segmented_toggle<T: Copy + PartialEq>(
    ui: &mut Ui,
    id: Id,
    current: &mut T,
    options: [(T, &str); 2],
    item_width: f32,
    height: f32,
) -> bool {
    let mut changed = false;
    let pad = 3.0;
    let total_width = item_width * 2.0 + pad * 2.0;
    let (outer, _) = ui.allocate_exact_size(vec2(total_width, height), Sense::hover());
    ui.painter()
        .rect_filled(outer, 8.0, Color32::from_rgb(233, 236, 241));
    ui.painter()
        .rect_stroke(outer, 8.0, Stroke::new(HAIRLINE, LINE), StrokeKind::Inside);

    let active_idx = if *current == options[0].0 { 0.0 } else { 1.0 };
    let slide = ease_in_out_cubic(
        ui.ctx()
            .animate_bool_with_time(id.with("slide"), active_idx > 0.5, 0.16),
    );
    let thumb_x = lerp_f32(outer.left() + pad, outer.left() + pad + item_width, slide);
    let thumb = Rect::from_min_size(
        pos2(thumb_x, outer.top() + pad),
        vec2(item_width, height - pad * 2.0),
    );
    ui.painter().rect_filled(
        thumb.translate(vec2(0.0, 0.8)),
        6.0,
        Color32::from_rgba_unmultiplied(16, 24, 40, 14),
    );
    ui.painter().rect_filled(thumb, 6.0, SURFACE);
    ui.painter()
        .rect_stroke(thumb, 6.0, Stroke::new(HAIRLINE, LINE), StrokeKind::Inside);

    for (index, (value, label)) in options.into_iter().enumerate() {
        let cell = Rect::from_min_size(
            pos2(
                outer.left() + pad + index as f32 * item_width,
                outer.top() + pad,
            ),
            vec2(item_width, height - pad * 2.0),
        );
        let resp = ui.interact(cell, id.with(index), Sense::click());
        let is_selected = *current == value;
        let color = if is_selected {
            INK
        } else if resp.hovered() {
            MUTED
        } else {
            SUBTLE
        };
        let font = if is_selected {
            FontId::new(12.5, fonts::semibold_family())
        } else {
            FontId::new(12.5, FontFamily::Proportional)
        };
        let galley = ui.painter().layout_no_wrap(label.to_owned(), font, color);
        paint_centered_galley(ui, cell, galley, color);
        if resp.hovered() {
            ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
        }
        if resp.clicked() && !is_selected {
            *current = value;
            changed = true;
        }
    }
    changed
}

/// Custom animated determinate progress bar with smooth fill interpolation.
pub(crate) fn smooth_progress_bar(ui: &mut Ui, id: Id, fraction: f32, width: f32) {
    let animated = ui
        .ctx()
        .animate_value_with_time(id, fraction.clamp(0.0, 1.0), 0.18);
    let (rect, _) = ui.allocate_exact_size(vec2(width, 6.0), Sense::hover());
    ui.painter().rect_filled(rect, 3.0, ACCENT_PALE);
    if animated > 0.005 {
        let fill_rect = Rect::from_min_size(
            rect.min,
            vec2((rect.width() * animated).max(6.0), rect.height()),
        );
        ui.painter().rect_filled(fill_rect, 3.0, ACCENT);
    }
}

/// Smooth sweeping indeterminate progress bar for operations without discrete step counts.
pub(crate) fn indeterminate_progress_bar(ui: &mut Ui, width: f32) {
    let phase = indeterminate_phase(ui.ctx());
    let (rect, _) = ui.allocate_exact_size(vec2(width, 5.0), Sense::hover());
    ui.painter().rect_filled(rect, 2.5, ACCENT_PALE);
    let seg_w = width * 0.36;
    let start_x = lerp_f32(rect.left() - seg_w, rect.right(), phase);
    let fill_min = start_x.max(rect.left());
    let fill_max = (start_x + seg_w).min(rect.right());
    if fill_max > fill_min + 2.0 {
        let fill_rect = Rect::from_min_max(pos2(fill_min, rect.top()), pos2(fill_max, rect.bottom()));
        ui.painter().rect_filled(fill_rect, 2.5, ACCENT);
    }
}

/// Draws a smooth, animated table row background with press tint and left selection accent bar.
pub(crate) fn interactive_row_background(
    ui: &Ui,
    rect: Rect,
    hover_t: f32,
    select_t: f32,
    press_t: f32,
) {
    let hovered_bg = lerp_color(SURFACE, SURFACE_ALT, hover_t);
    let pressed_bg = lerp_color(hovered_bg, SURFACE_PRESSED, press_t * 0.65);
    let final_bg = lerp_color(pressed_bg, ACCENT_PALE, select_t);
    if final_bg != SURFACE {
        ui.painter().rect_filled(rect, 0.0, final_bg);
    }
    if select_t > 0.02 {
        let bar_h = lerp_f32(0.0, rect.height() - 18.0, select_t);
        let bar = Rect::from_center_size(
            pos2(rect.left() + 1.5, rect.center().y),
            vec2(3.0, bar_h.max(4.0)),
        );
        ui.painter().rect_filled(bar, 1.5, ACCENT);
    }
    ui.painter()
        .hline(rect.x_range(), rect.bottom(), Stroke::new(HAIRLINE, LINE_SOFT));
}

/// Renders the floating, auto-dismissing toast notification overlay in the bottom-right corner.
pub(crate) fn paint_toast_overlay(ctx: &egui::Context, toasts: &mut Vec<Toast>) {
    if toasts.is_empty() {
        return;
    }
    let now = ctx.input(|i| i.time);
    let screen = ctx.screen_rect();
    let toast_w = 324.0_f32.min((screen.width() - 36.0).max(220.0));
    let mut expired_ids = Vec::new();
    let mut dismiss_ids = Vec::new();

    egui::Area::new(Id::new("toast_notifications_overlay"))
        .order(egui::Order::Foreground)
        .pivot(egui::Align2::RIGHT_BOTTOM)
        .fixed_pos(pos2(screen.right() - 18.0, screen.bottom() - 48.0))
        .default_width(toast_w)
        .interactable(true)
        .show(ctx, |ui| {
            ui.set_width(toast_w);
            ui.with_layout(Layout::bottom_up(Align::RIGHT), |ui| {
                ui.spacing_mut().item_spacing.y = 8.0;
                for toast in toasts.iter_mut().rev() {
                    let (opacity, y_offset, remaining, expired) = toast.sample(ctx);
                    if expired {
                        expired_ids.push(toast.id);
                        continue;
                    }
                    let (accent, tint, icon) = match toast.kind {
                        ToastKind::Success => (DARK_GREEN, PALE_GREEN, Icon::Check),
                        ToastKind::Info => (ACCENT, ACCENT_PALE, Icon::Info),
                        ToastKind::Warning => (DARK_AMBER, PALE_AMBER, Icon::AlertTriangle),
                        ToastKind::Error => (DANGER, PALE_RED, Icon::AlertTriangle),
                    };

                    if y_offset > 0.1 {
                        ui.add_space(y_offset);
                    }
                    ui.scope(|ui| {
                        ui.set_opacity(opacity);
                        let inner_w = (toast_w - 24.0).max(180.0);
                        let frame_resp = Frame::new()
                            .fill(SURFACE)
                            .stroke(Stroke::new(HAIRLINE, lerp_color(LINE, accent, 0.3)))
                            .corner_radius(10)
                            .inner_margin(Margin {
                                left: 12,
                                right: 10,
                                top: 10,
                                bottom: 11,
                            })
                            .shadow(toast_shadow())
                            .show(ui, |ui| {
                                ui.set_width(inner_w);
                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 10.0;
                                    let (well, _) =
                                        ui.allocate_exact_size(vec2(24.0, 24.0), Sense::hover());
                                    ui.painter().circle_filled(well.center(), 12.0, tint);
                                    paint_icon(ui, icon, well.center(), 12.5, accent);

                                    let msg_w = (inner_w - 64.0).max(120.0);
                                    ui.allocate_ui_with_layout(
                                        vec2(msg_w, 0.0),
                                        Layout::top_down(Align::LEFT),
                                        |ui| {
                                            ui.label(semibold_text(&toast.message, 12.5, INK));
                                        },
                                    );

                                    let (close_rect, close_resp) =
                                        ui.allocate_exact_size(vec2(20.0, 20.0), Sense::click());
                                    if close_resp.hovered() {
                                        ui.painter()
                                            .circle_filled(close_rect.center(), 9.0, SURFACE_ALT);
                                        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
                                    }
                                    paint_icon(
                                        ui,
                                        Icon::Close,
                                        close_rect.center(),
                                        10.0,
                                        if close_resp.hovered() { INK } else { SUBTLE },
                                    );
                                    if close_resp.clicked() {
                                        dismiss_ids.push(toast.id);
                                    }
                                });
                            });

                        toast.hovered = frame_resp.response.hovered();
                        // Subtle bottom countdown strip
                        if remaining > 0.02 {
                            let r = frame_resp.response.rect;
                            let bar_left = r.left() + 10.0;
                            let bar_full_w = (r.width() - 20.0).max(0.0);
                            let bar_rect = Rect::from_min_size(
                                pos2(bar_left, r.bottom() - 2.5),
                                vec2(bar_full_w * remaining, 2.0),
                            );
                            ui.painter().rect_filled(
                                bar_rect,
                                1.0,
                                Color32::from_rgba_unmultiplied(
                                    accent.r(),
                                    accent.g(),
                                    accent.b(),
                                    135,
                                ),
                            );
                        }
                    });
                }
            });
        });

    for id in dismiss_ids {
        if let Some(toast) = toasts.iter_mut().find(|t| t.id == id) {
            toast.dismiss(now);
        }
    }
    if !expired_ids.is_empty() {
        toasts.retain(|t| !expired_ids.contains(&t.id));
    }
}

/// Strictly fixed-width left-aligned table cell using `new_child` so parent cursor NEVER drifts.
pub(crate) fn table_cell(ui: &mut Ui, width: f32, height: f32, content: impl FnOnce(&mut Ui)) {
    let (rect, _) = ui.allocate_exact_size(vec2(width, height), Sense::hover());
    let mut child = ui.new_child(
        UiBuilder::new()
            .max_rect(rect)
            .layout(Layout::left_to_right(Align::Center)),
    );
    child.set_clip_rect(child.clip_rect().intersect(rect));
    content(&mut child);
}

/// Strictly fixed-width right-aligned table cell using `new_child` so parent cursor NEVER drifts.
pub(crate) fn table_cell_right(
    ui: &mut Ui,
    width: f32,
    height: f32,
    content: impl FnOnce(&mut Ui),
) {
    let (rect, _) = ui.allocate_exact_size(vec2(width, height), Sense::hover());
    let mut child = ui.new_child(
        UiBuilder::new()
            .max_rect(rect)
            .layout(Layout::right_to_left(Align::Center)),
    );
    child.set_clip_rect(child.clip_rect().intersect(rect));
    content(&mut child);
}

/// Renders a crisp 1px horizontal divider line spanning the container width.
pub(crate) fn divider(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 1.0), Sense::hover());
    ui.painter()
        .hline(rect.x_range(), rect.center().y, Stroke::new(HAIRLINE, LINE_SOFT));
}
