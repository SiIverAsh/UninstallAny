use std::time::Duration;

use eframe::egui::{Color32, Context, Id};

use super::Page;

/// Cubic ease-out curve for snappy, natural UI entrances.
pub(crate) fn ease_out_cubic(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    1.0 - (1.0 - t).powi(3)
}

/// Smooth cubic ease-in-out curve for sliding indicators and transitions.
pub(crate) fn ease_in_out_cubic(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    if t < 0.5 {
        4.0 * t * t * t
    } else {
        1.0 - (-2.0 * t + 2.0).powi(3) / 2.0
    }
}

/// Linearly interpolates between two `f32` values.
pub(crate) fn lerp_f32(a: f32, b: f32, t: f32) -> f32 {
    a + (b - a) * t.clamp(0.0, 1.0)
}

/// Linearly interpolates between two sRGB `Color32` colors.
pub(crate) fn lerp_color(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let blend = |x: u8, y: u8| -> u8 { (x as f32 + (y as f32 - x as f32) * t).round() as u8 };
    Color32::from_rgba_unmultiplied(
        blend(a.r(), b.r()),
        blend(a.g(), b.g()),
        blend(a.b(), b.b()),
        blend(a.a(), b.a()),
    )
}

/// Smoothly animates a boolean state with cubic ease-out.
pub(crate) fn smooth_bool(ctx: &Context, id: Id, value: bool, duration: f32) -> f32 {
    ease_out_cubic(ctx.animate_bool_with_time(id, value, duration))
}

/// Smoothly animates a scalar value with the given duration.
pub(crate) fn smooth_value(ctx: &Context, id: Id, target: f32, duration: f32) -> f32 {
    ctx.animate_value_with_time(id, target, duration)
}

/// Returns a gentle 0..=1 breathing pulse at ~0.75 Hz and schedules repaint.
pub(crate) fn pulse(ctx: &Context) -> f32 {
    let time = ctx.input(|i| i.time);
    ctx.request_repaint_after(Duration::from_millis(32));
    ((time * std::f64::consts::TAU * 0.75).sin() as f32 * 0.5 + 0.5).clamp(0.0, 1.0)
}

/// Returns a 0..=1 horizontal shimmer wave phase for loading skeletons.
pub(crate) fn shimmer_phase(ctx: &Context) -> f32 {
    let time = ctx.input(|i| i.time);
    ctx.request_repaint_after(Duration::from_millis(24));
    ((time * 0.9) % 1.0) as f32
}

/// Returns a continuous rotation angle in radians for compact button/status spinners.
pub(crate) fn spinner_angle(ctx: &Context) -> f32 {
    let time = ctx.input(|i| i.time);
    ctx.request_repaint_after(Duration::from_millis(16));
    ((time * std::f64::consts::TAU * 1.15) % std::f64::consts::TAU) as f32
}

/// Returns a 0..=1 phase for indeterminate progress bar sweeps.
pub(crate) fn indeterminate_phase(ctx: &Context) -> f32 {
    let time = ctx.input(|i| i.time);
    ctx.request_repaint_after(Duration::from_millis(20));
    ((time * 0.72) % 1.0) as f32
}

/// Semantic severity for floating toast feedback notifications.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ToastKind {
    Success,
    Info,
    Warning,
    Error,
}

/// A lightweight, auto-dismissing toast notification with smooth entrance/exit timing.
#[derive(Clone, Debug)]
pub(crate) struct Toast {
    pub id: u64,
    pub kind: ToastKind,
    pub message: String,
    pub created_at: Option<f64>,
    pub duration_secs: f64,
    pub elapsed_secs: f64,
    pub last_tick_at: Option<f64>,
    pub hovered: bool,
    pub dismissed_at: Option<f64>,
}

impl Toast {
    pub(crate) fn new(id: u64, kind: ToastKind, message: impl Into<String>) -> Self {
        let duration_secs = match kind {
            ToastKind::Error => 5.5,
            ToastKind::Warning => 4.5,
            ToastKind::Success | ToastKind::Info => 3.4,
        };
        Self {
            id,
            kind,
            message: message.into(),
            created_at: None,
            duration_secs,
            elapsed_secs: 0.0,
            last_tick_at: None,
            hovered: false,
            dismissed_at: None,
        }
    }

    /// Advances toast timing and returns `(opacity, y_offset, remaining_fraction, expired)`.
    pub(crate) fn sample(&mut self, ctx: &Context) -> (f32, f32, f32, bool) {
        const ENTER_SECS: f64 = 0.18;
        const EXIT_SECS: f64 = 0.18;

        let now = ctx.input(|i| i.time);
        let created = *self.created_at.get_or_insert(now);
        let dt = match self.last_tick_at {
            Some(prev) => (now - prev).clamp(0.0, 0.25),
            None => 0.0,
        };
        self.last_tick_at = Some(now);

        if self.dismissed_at.is_none() && !self.hovered {
            self.elapsed_secs += dt;
            if self.elapsed_secs >= self.duration_secs {
                self.dismissed_at = Some(now);
            }
        }

        let enter_t = ease_out_cubic(((now - created).max(0.0) / ENTER_SECS) as f32);
        let remaining = (1.0 - (self.elapsed_secs / self.duration_secs)).clamp(0.0, 1.0) as f32;

        if let Some(dismissed_at) = self.dismissed_at {
            let exit_elapsed = (now - dismissed_at).max(0.0);
            if exit_elapsed >= EXIT_SECS {
                return (0.0, 10.0, 0.0, true);
            }
            ctx.request_repaint();
            let exit_t = ease_out_cubic((exit_elapsed / EXIT_SECS) as f32);
            return (
                lerp_f32(1.0, 0.0, exit_t),
                lerp_f32(0.0, 10.0, exit_t),
                0.0,
                false,
            );
        }

        if (now - created) < ENTER_SECS {
            ctx.request_repaint();
        } else if !self.hovered {
            ctx.request_repaint_after(Duration::from_millis(50));
        }

        let opacity = lerp_f32(0.4, 1.0, enter_t);
        let y_offset = lerp_f32(10.0, 0.0, enter_t);
        (opacity, y_offset, remaining, false)
    }

    pub(crate) fn dismiss(&mut self, now: f64) {
        if self.dismissed_at.is_none() {
            self.dismissed_at = Some(now);
        }
    }
}

/// Tracks lightweight UI transition timestamps without interfering with app logic.
pub(crate) struct UiAnimations {
    last_page: Page,
    page_changed_at: Option<f64>,
    modal_open: bool,
    modal_opened_at: Option<f64>,
    next_toast_id: u64,
    pub toasts: Vec<Toast>,
}

impl UiAnimations {
    pub(crate) fn new(initial_page: Page) -> Self {
        Self {
            last_page: initial_page,
            page_changed_at: None,
            modal_open: false,
            modal_opened_at: None,
            next_toast_id: 1,
            toasts: Vec::new(),
        }
    }

    /// Pushes a new floating toast notification, keeping at most 3 visible at once.
    pub(crate) fn push_toast(&mut self, kind: ToastKind, message: impl Into<String>) {
        let message = message.into();
        if message.trim().is_empty() {
            return;
        }
        // Avoid duplicating an identical active toast back-to-back.
        if let Some(existing) = self
            .toasts
            .iter_mut()
            .rev()
            .find(|t| t.dismissed_at.is_none() && t.kind == kind && t.message == message)
        {
            existing.elapsed_secs = 0.0;
            return;
        }
        let id = self.next_toast_id;
        self.next_toast_id = self.next_toast_id.wrapping_add(1);
        self.toasts.push(Toast::new(id, kind, message));
        if self.toasts.len() > 3 {
            let overflow = self.toasts.len() - 3;
            self.toasts.drain(0..overflow);
        }
    }

    /// Updates page transition state and returns `(opacity, y_offset)`.
    pub(crate) fn page_transition(&mut self, ctx: &Context, current: Page) -> (f32, f32) {
        let now = ctx.input(|i| i.time);
        if current != self.last_page {
            self.last_page = current;
            self.page_changed_at = Some(now);
        }
        const DURATION: f64 = 0.18;
        let Some(start) = self.page_changed_at else {
            return (1.0, 0.0);
        };
        let elapsed = (now - start).max(0.0);
        if elapsed >= DURATION {
            self.page_changed_at = None;
            return (1.0, 0.0);
        }
        ctx.request_repaint();
        let t = ease_out_cubic((elapsed / DURATION) as f32);
        // Keep a floor on opacity so single-frame headless renders stay crisp.
        let opacity = lerp_f32(0.35, 1.0, t);
        let y_offset = lerp_f32(7.0, 0.0, t);
        (opacity, y_offset)
    }

    /// Updates modal entrance state and returns eased progress in `0.0..=1.0`.
    pub(crate) fn modal_progress(&mut self, ctx: &Context, is_open: bool) -> f32 {
        let now = ctx.input(|i| i.time);
        if is_open && !self.modal_open {
            self.modal_open = true;
            self.modal_opened_at = Some(now);
        } else if !is_open {
            self.modal_open = false;
            self.modal_opened_at = None;
            return 0.0;
        }
        const DURATION: f64 = 0.16;
        let Some(start) = self.modal_opened_at else {
            return 1.0;
        };
        let elapsed = (now - start).max(0.0);
        if elapsed >= DURATION {
            self.modal_opened_at = None;
            return 1.0;
        }
        ctx.request_repaint();
        ease_out_cubic((elapsed / DURATION) as f32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn easing_curves_stay_bounded_and_monotonic() {
        assert_eq!(ease_out_cubic(0.0), 0.0);
        assert_eq!(ease_out_cubic(1.0), 1.0);
        assert!(ease_out_cubic(0.5) > 0.5);

        assert_eq!(ease_in_out_cubic(0.0), 0.0);
        assert!((ease_in_out_cubic(0.5) - 0.5).abs() < 1e-5);
        assert_eq!(ease_in_out_cubic(1.0), 1.0);
    }

    #[test]
    fn lerp_color_interpolates_endpoints_and_midpoint() {
        let a = Color32::from_rgb(0, 100, 200);
        let b = Color32::from_rgb(100, 200, 0);
        assert_eq!(lerp_color(a, b, 0.0), a);
        assert_eq!(lerp_color(a, b, 1.0), b);
        assert_eq!(lerp_color(a, b, 0.5), Color32::from_rgb(50, 150, 100));
    }

    #[test]
    fn toast_queue_deduplicates_and_caps_at_three() {
        let mut anim = UiAnimations::new(Page::Applications);
        anim.push_toast(ToastKind::Success, "Saved");
        anim.push_toast(ToastKind::Success, "Saved");
        assert_eq!(anim.toasts.len(), 1);

        anim.push_toast(ToastKind::Info, "Second");
        anim.push_toast(ToastKind::Warning, "Third");
        anim.push_toast(ToastKind::Error, "Fourth");
        assert_eq!(anim.toasts.len(), 3);
        assert_eq!(anim.toasts[0].message, "Second");
        assert_eq!(anim.toasts[2].message, "Fourth");
    }
}
