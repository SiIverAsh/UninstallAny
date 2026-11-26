use std::{
    collections::BTreeMap,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use eframe::egui::{
    self, Align, Color32, CornerRadius, CursorIcon, FontId, Frame, Id, Layout, Margin, Rect,
    RichText, ScrollArea, Sense, Stroke, StrokeKind, TextEdit, Ui, Vec2, pos2, vec2,
};
use uninstallany_core::{
    Access, AppId, AppRecord, BackupSummary, Candidate, Category, ChangeResult, Confidence,
    MatchKind, OfficialOutcome, RecoveryState, Risk, ScanMode,
};
use uuid::Uuid;

use super::{
    CleanupView, DesktopApp, Language, Operation, Page, Review, SortField, Status,
    anim::{ToastKind, lerp_color, lerp_f32, pulse, smooth_bool, smooth_value},
    theme::{
        self, ACCENT, ACCENT_PALE, ACCENT_SOFT, APP_ROW, ButtonSpec, ButtonVariant, CANDIDATE_ROW,
        CONTROL_HEIGHT, DANGER, DARK_AMBER, DARK_GREEN, DISABLED_BG, DISABLED_TEXT, HAIRLINE, INK,
        Icon, LINE, MUTED, PAGE, PALE_AMBER, PALE_GREEN, PALE_RED, SIDEBAR,
        SIDEBAR_WIDTH, SUBTLE, SURFACE, SURFACE_ALT, action_button, app_glyph, badge, body_text,
        card, chip_button, collapsible_section, divider, empty_state, filter_pill, icon_badge,
        indeterminate_progress_bar, interactive_row_background, loading_skeleton, mark,
        measure_icon_button_width, measured_text_width, menu_item, metric_card, modal_card, notice,
        notice_with_action, numeric_stepper, paint_checkbox_box, paint_count_pill, paint_icon,
        paint_left_truncated, paint_right_truncated, paint_sort_indicator, paint_toast_overlay,
        paint_two_line_cell, secondary_button, section_heading, segmented_toggle,
        semibold_text, smooth_progress_bar, styled_checkbox, styled_text_input, table_cell,
        table_cell_right, title, toggle_switch_labeled, truncate,
    },
};
use crate::{fonts, worker::Request};

/// Action emitted from an application row's context menu.
enum RowAction {
    Scan(AppId),
    Uninstall(AppId),
    Force(AppId),
    CopyPath(String),
}

impl DesktopApp {
    pub(super) fn draw(&mut self, context: &egui::Context) {
        self.footer(context);
        self.sidebar(context);
        let (page_opacity, page_y_offset) = self.anim.page_transition(context, self.page);
        egui::CentralPanel::default()
            .frame(
                Frame::new()
                    .fill(PAGE)
                    .inner_margin(Margin::symmetric(24, 20)),
            )
            .show(context, |ui| {
                ui.set_opacity(page_opacity);
                if page_y_offset > 0.1 {
                    ui.add_space(page_y_offset);
                }
                if !self.backend_supported {
                    notice(
                        ui,
                        self.language.text(
                            "This build supports Windows inventory and cleanup. A backend for this platform is pending.",
                            "此版本支持 Windows 应用枚举与清理。当前系统的后端尚未接入。",
                        ),
                        DARK_AMBER,
                        PALE_AMBER,
                    );
                    ui.add_space(10.0);
                } else if let Some(Status::Error(error)) = &self.status {
                    let msg = error.clone();
                    let dismiss_tip = self.language.text("Dismiss", "关闭提示");
                    if notice_with_action(ui, &msg, DANGER, PALE_RED, Some(dismiss_tip)) {
                        self.status = None;
                    }
                    ui.add_space(10.0);
                }
                match self.page {
                    Page::Applications => self.applications(ui),
                    Page::Quarantine => self.quarantine(ui),
                    Page::Settings => self.settings(ui),
                    Page::Review => self.review(ui),
                }
            });
        self.dialog(context);
        paint_toast_overlay(context, &mut self.anim.toasts);
    }

    fn sidebar(&mut self, context: &egui::Context) {
        let language = self.language;
        let app_count = self
            .apps
            .inventory
            .as_ref()
            .map(|_| self.apps.total_in_scope())
            .filter(|&c| c > 0);
        let recoverable_count = self
            .quarantine
            .as_ref()
            .map(|q| {
                q.items
                    .iter()
                    .filter(|item| item.state == RecoveryState::Applied)
                    .count()
            })
            .filter(|&c| c > 0);
        let review_count = self.plans.len().gt(&0).then_some(self.plans.len());

        let panel_resp = egui::SidePanel::left("workspace_navigation")
            .exact_width(SIDEBAR_WIDTH)
            .resizable(false)
            .frame(Frame::new().fill(SIDEBAR).inner_margin(Margin::same(14)))
            .show(context, |ui| {
                ui.add_space(2.0);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 10.0;
                    mark(ui);
                    let (text_rect, _) =
                        ui.allocate_exact_size(vec2(ui.available_width(), 34.0), Sense::hover());
                    paint_two_line_cell(
                        ui,
                        text_rect,
                        "UninstallAny",
                        Some(language.text("Clean & Safe", "安全清理")),
                        FontId::new(15.5, fonts::semibold_family()),
                        FontId::proportional(11.5),
                        INK,
                        SUBTLE,
                        "",
                    );
                });

                ui.add_space(22.0);
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    ui.label(semibold_text(
                        language.text("WORKSPACE", "工作区"),
                        11.0,
                        SUBTLE,
                    ));
                });
                ui.add_space(6.0);

                ui.spacing_mut().item_spacing.y = 3.0;
                let mut active_center_y: Option<f32> = None;
                let mut nav_left = ui.cursor().left();

                let mut items: Vec<(Page, &str, Option<usize>)> = vec![
                    (
                        Page::Applications,
                        language.text("Applications", "应用程序"),
                        app_count,
                    ),
                    (
                        Page::Quarantine,
                        language.text("Quarantine", "隔离区"),
                        recoverable_count,
                    ),
                    (Page::Settings, language.text("Settings", "设置"), None),
                ];
                if self.has_review() || self.page == Page::Review {
                    items.push((
                        Page::Review,
                        language.text("Review & results", "预览与结果"),
                        review_count,
                    ));
                }

                for (page, label, count) in items {
                    let is_active = self.page == page;
                    let (clicked, rect) = nav_button(ui, label, page, is_active, count);
                    nav_left = rect.left();
                    if is_active {
                        active_center_y = Some(rect.center().y);
                    }
                    if clicked {
                        self.navigate(page);
                    }
                }

                if let Some(target_y) = active_center_y {
                    let indicator_y = smooth_value(
                        ui.ctx(),
                        Id::new("sidebar_active_pill_y"),
                        target_y,
                        0.18,
                    );
                    let pill = Rect::from_center_size(
                        pos2(nav_left + 2.5, indicator_y),
                        vec2(3.0, 18.0),
                    );
                    ui.painter().rect_filled(pill, 1.5, ACCENT);
                }

                ui.with_layout(Layout::bottom_up(Align::LEFT), |ui| {
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        ui.add_space(2.0);
                        ui.label(body_text(
                            concat!("Version ", env!("CARGO_PKG_VERSION")),
                            11.0,
                            SUBTLE,
                        ));
                    });
                    ui.add_space(8.0);
                    segmented_toggle(
                        ui,
                        Id::new("sidebar_lang_toggle"),
                        &mut self.language,
                        [(Language::English, "EN"), (Language::Chinese, "中文")],
                        (ui.available_width() - 6.0) * 0.5,
                        30.0,
                    );
                    ui.add_space(10.0);
                    divider(ui);
                });
            });

        let rect = panel_resp.response.rect;
        panel_resp
            .response
            .ctx
            .layer_painter(egui::LayerId::new(
                egui::Order::Middle,
                Id::new("sidebar_border"),
            ))
            .vline(rect.right(), rect.y_range(), Stroke::new(HAIRLINE, LINE));
    }

    fn footer(&mut self, context: &egui::Context) {
        let language = self.language;
        let panel_resp = egui::TopBottomPanel::bottom("operation_status")
            .exact_height(38.0)
            .frame(
                Frame::new()
                    .fill(SURFACE)
                    .inner_margin(Margin::symmetric(16, 4)),
            )
            .show(context, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    if let Some(active) = &self.active {
                        let p = pulse(ui.ctx());
                        let (dot_rect, _) =
                            ui.allocate_exact_size(vec2(10.0, 10.0), Sense::hover());
                        ui.painter().circle_filled(
                            dot_rect.center(),
                            lerp_f32(3.0, 4.8, p),
                            lerp_color(ACCENT_PALE, ACCENT, 0.35),
                        );
                        ui.painter().circle_filled(dot_rect.center(), 2.8, ACCENT);

                        let message = if active.cancellation_requested {
                            language.text(
                                "Stopping at the next safe point…",
                                "正在停止。已开始的单项操作会执行完毕。",
                            )
                        } else {
                            operation_text(language, active.name)
                        };
                        ui.label(body_text(message, 12.0, INK));
                        if let Some((done, total)) =
                            active.progress.filter(|(_, total)| *total > 0)
                        {
                            smooth_progress_bar(
                                ui,
                                Id::new("footer_op_progress"),
                                done as f32 / total as f32,
                                120.0,
                            );
                            ui.label(
                                RichText::new(format!("{done}/{total}"))
                                    .color(MUTED)
                                    .size(11.5)
                                    .monospace(),
                            );
                        } else {
                            indeterminate_progress_bar(ui, 86.0);
                        }
                        if action_button(
                            ui,
                            ButtonSpec::new(
                                language.text("Cancel", "取消"),
                                ButtonVariant::DangerSubtle,
                            )
                            .compact()
                            .enabled(!active.cancellation_requested),
                        )
                        .clicked()
                        {
                            self.cancel();
                        }
                    } else {
                        let (dot_color, message) = match self.status.as_ref() {
                            Some(Status::Cancelled) => (
                                DARK_AMBER,
                                language.text("Operation cancelled", "操作已取消"),
                            ),
                            Some(Status::RetentionSaved) => (
                                DARK_GREEN,
                                language.text("Retention updated", "保留期已更新"),
                            ),
                            Some(Status::RulesSaved(_)) => (
                                DARK_GREEN,
                                language.text("Rules saved", "规则已保存"),
                            ),
                            Some(Status::AuditExported) => (
                                DARK_GREEN,
                                language.text("Audit log exported", "日志已导出"),
                            ),
                            Some(Status::Error(_)) => (
                                DANGER,
                                language.text("An operation needs attention", "有一项操作需要处理"),
                            ),
                            None if !self.backend_supported => (
                                DARK_AMBER,
                                language.text("Backend unavailable", "后端尚不可用"),
                            ),
                            None => (DARK_GREEN, language.text("Ready", "就绪")),
                        };
                        let (dot_rect, _) =
                            ui.allocate_exact_size(vec2(8.0, 8.0), Sense::hover());
                        ui.painter()
                            .circle_filled(dot_rect.center(), 3.0, dot_color);
                        ui.label(body_text(message, 12.0, MUTED));
                    }

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.spacing_mut().item_spacing.x = 10.0;
                        icon_badge(
                            ui,
                            Icon::Shield,
                            language.text("Local processing", "本机处理"),
                            DARK_GREEN,
                            PALE_GREEN,
                        );
                        if ui.available_width() > 260.0 && self.active.is_none() {
                            let hint = if cfg!(target_os = "macos") {
                                language.text("⌘F Search · ⌘R Refresh", "⌘F 搜索 · ⌘R 刷新")
                            } else {
                                language.text("Ctrl+F Search · F5 Refresh", "Ctrl+F 搜索 · F5 刷新")
                            };
                            ui.label(body_text(hint, 11.5, SUBTLE));
                        }
                    });
                });
            });

        let rect = panel_resp.response.rect;
        panel_resp
            .response
            .ctx
            .layer_painter(egui::LayerId::new(
                egui::Order::Middle,
                Id::new("footer_border"),
            ))
            .hline(rect.x_range(), rect.top(), Stroke::new(HAIRLINE, LINE));
    }

    fn applications(&mut self, ui: &mut Ui) {
        let language = self.language;
        let busy = !self.can_submit();
        let refreshing = self.is_running(Operation::Inventory);

        // Page Header
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 10.0;
            title(ui, language.text("Applications", "应用程序"));
            if self.apps.inventory.is_some() {
                let total = self.apps.total_in_scope();
                let visible = self.apps.visible.len();
                let summary = if !self.apps.search.trim().is_empty() {
                    format!("{visible} / {total}")
                } else {
                    total.to_string()
                };
                badge(ui, &summary, MUTED, SURFACE_ALT);
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                if action_button(
                    ui,
                    ButtonSpec::new(language.text("Refresh", "刷新"), ButtonVariant::Secondary)
                        .icon(Icon::Refresh)
                        .enabled(!busy)
                        .busy(refreshing)
                        .disabled_hint(language.text(
                            "Wait for the current operation to finish.",
                            "请等待当前操作完成。",
                        )),
                )
                .clicked()
                {
                    self.submit(Request::Applications, Operation::Inventory);
                }
                let folder = if self.portable_open {
                    language.text("Hide folder scan", "收起目录扫描")
                } else {
                    language.text("Scan a folder", "扫描目录")
                };
                if action_button(
                    ui,
                    ButtonSpec::new(folder, ButtonVariant::Secondary)
                        .icon(Icon::Folder)
                        .enabled(self.backend_supported)
                        .active(self.portable_open),
                )
                .clicked()
                {
                    self.portable_open = !self.portable_open;
                }
            });
        });

        ui.add_space(10.0);

        let portable_t = smooth_bool(
            ui.ctx(),
            Id::new("portable_drawer_anim"),
            self.portable_open,
            0.18,
        );
        if portable_t > 0.01 {
            self.portable(ui, portable_t);
        }

        // Toolbar: Search + System Toggle + Active Filter Reset
        let search_kbd = if cfg!(target_os = "macos") {
            "⌘F"
        } else {
            "Ctrl+F"
        };
        let req_focus = std::mem::take(&mut self.focus_search_requested);
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 12.0;
            let avail = ui.available_width();
            let search_width = (avail * 0.46).clamp(180.0, 360.0);
            let res = styled_text_input(
                ui,
                Id::new("app_search_input"),
                &mut self.apps.search,
                language.text("Search name, publisher, or path", "搜索名称、发行商或路径"),
                search_width,
                Some(Icon::Search),
                Some(search_kbd),
                true,
                req_focus,
            );
            self.apps.dirty |= res.changed;

            self.apps.dirty |= toggle_switch_labeled(
                ui,
                Id::new("include_system_toggle"),
                &mut self.apps.include_system,
                language.text("Show system components", "显示系统组件"),
            )
            .changed();

            if !self.apps.search.trim().is_empty() && ui.available_width() > 86.0 {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if action_button(
                        ui,
                        ButtonSpec::new(language.text("Reset", "重置"), ButtonVariant::Ghost)
                            .compact()
                            .icon(Icon::Close),
                    )
                    .clicked()
                    {
                        self.apps.search.clear();
                        self.apps.dirty = true;
                    }
                });
            }
        });

        self.apps.update_visible();
        if let Some(inventory) = &self.apps.inventory {
            diagnostics(ui, language, &inventory.warnings, "inventory_warnings");
        }

        ui.add_space(8.0);
        let count = self.apps.visible.len();
        let selected = self.apps.selected_visible().len();
        let selected_bytes = self.apps.selected_total_bytes();
        let action_bar_reserve = 66.0;
        let table_height = (ui.available_height() - action_bar_reserve).max(120.0);
        self.inventory_table(ui, table_height);

        ui.add_space(10.0);

        // Elevated Bottom Action Bar
        let has_selection = selected > 0;
        let bar_t = smooth_bool(
            ui.ctx(),
            Id::new("app_action_bar_active"),
            has_selection,
            0.16,
        );
        let bar_fill = lerp_color(SURFACE, ACCENT_SOFT, bar_t * 0.72);
        let bar_border = lerp_color(LINE, ACCENT, bar_t * 0.35);

        Frame::new()
            .fill(bar_fill)
            .stroke(Stroke::new(HAIRLINE, bar_border))
            .corner_radius(10)
            .inner_margin(Margin::symmetric(16, 10))
            .shadow(theme::card_shadow())
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    if has_selection {
                        let sel_label = if language == Language::Chinese {
                            format!("已选 {selected} 项")
                        } else {
                            format!("{selected} selected")
                        };
                        badge(ui, &sel_label, ACCENT, ACCENT_PALE);
                        if let Some(bytes) = selected_bytes.filter(|_| ui.available_width() > 380.0)
                        {
                            let total_str = if language == Language::Chinese {
                                format!("约 {}", size_label(bytes))
                            } else {
                                format!("Total {}", size_label(bytes))
                            };
                            ui.label(body_text(total_str, 12.5, MUTED));
                        }
                        if action_button(
                            ui,
                            ButtonSpec::new(language.text("Clear", "清除"), ButtonVariant::Ghost)
                                .compact()
                                .icon(Icon::Close),
                        )
                        .clicked()
                        {
                            self.apps.clear_selection();
                        }
                    } else {
                        let count_text = if language == Language::Chinese {
                            format!("共 {count} 个应用")
                        } else {
                            format!("{count} shown")
                        };
                        ui.label(body_text(count_text, 13.0, MUTED));
                        if count > 0 && ui.available_width() > 470.0 {
                            ui.label(body_text("·", 13.0, LINE));
                            ui.label(body_text(
                                language.text(
                                    "Click rows or Shift+Click to select",
                                    "点击行或 Shift+点击 多选",
                                ),
                                12.0,
                                SUBTLE,
                            ));
                        }
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.spacing_mut().item_spacing.x = 8.0;
                        self.application_actions(ui)
                    });
                });
            });
    }

    fn portable(&mut self, ui: &mut Ui, anim_t: f32) {
        let language = self.language;
        let max_h = 116.0 * anim_t;
        ui.allocate_ui_with_layout(
            vec2(ui.available_width(), max_h),
            Layout::top_down(Align::LEFT),
            |ui| {
                ui.set_clip_rect(ui.clip_rect().intersect(Rect::from_min_size(
                    ui.cursor().min,
                    vec2(ui.available_width(), max_h),
                )));
                ui.set_opacity(anim_t);
                card(16).show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 8.0;
                        let (ic_rect, _) =
                            ui.allocate_exact_size(vec2(16.0, 18.0), Sense::hover());
                        paint_icon(ui, Icon::Folder, ic_rect.center(), 14.0, ACCENT);
                        ui.label(semibold_text(
                            language.text("Portable application folder", "便携应用目录"),
                            13.5,
                            INK,
                        ));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            let (close_rect, close_resp) =
                                ui.allocate_exact_size(vec2(22.0, 22.0), Sense::click());
                            if close_resp.hovered() {
                                ui.painter()
                                    .circle_filled(close_rect.center(), 10.0, SURFACE_ALT);
                                ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
                            }
                            paint_icon(
                                ui,
                                Icon::Close,
                                close_rect.center(),
                                10.5,
                                if close_resp.hovered() { INK } else { SUBTLE },
                            );
                            if close_resp
                                .on_hover_text(language.text("Close", "收起"))
                                .clicked()
                            {
                                self.portable_open = false;
                            }
                        });
                    });
                    ui.add_space(2.0);
                    ui.label(body_text(
                        language.text(
                            "Scan an unpacked directory for files and related entries",
                            "扫描绿色版或免安装目录的文件及相关记录",
                        ),
                        12.0,
                        MUTED,
                    ));
                    ui.add_space(8.0);
                    let btn_label = language.text("Preview scan", "预览扫描");
                    let btn_w = measure_icon_button_width(ui, btn_label, Icon::Search, 108.0);
                    let input_w = (ui.available_width() - btn_w - 8.0).max(140.0);
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 8.0;
                        let input = styled_text_input(
                            ui,
                            Id::new("portable_path_input"),
                            &mut self.portable_path,
                            language.text("Absolute path", "输入绝对路径"),
                            input_w,
                            Some(Icon::Folder),
                            None,
                            self.backend_supported,
                            false,
                        );
                        let can_scan =
                            self.can_submit() && !self.portable_path.trim().is_empty();
                        let submit = action_button(
                            ui,
                            ButtonSpec::new(btn_label, ButtonVariant::Tinted)
                                .icon(Icon::Search)
                                .enabled(can_scan)
                                .busy(self.is_running(Operation::Scan))
                                .disabled_hint(language.text(
                                    "Enter an absolute folder path to preview.",
                                    "请输入绝对目录路径以预览扫描。",
                                )),
                        )
                        .clicked();
                        if (submit || input.submitted) && can_scan {
                            let path = PathBuf::from(self.portable_path.trim());
                            self.submit(Request::Portable(path), Operation::Scan);
                        }
                    });
                });
            },
        );
        ui.add_space(8.0 * anim_t);
    }

    fn inventory_table(&mut self, ui: &mut Ui, height: f32) {
        let language = self.language;
        let mut row_action: Option<RowAction> = None;
        let mut click_toggle: Option<(AppId, bool)> = None;
        let mut clear_search = false;
        let mut trigger_refresh = false;
        let can_submit = self.can_submit();

        card(0).show(ui, |ui| {
            let total_width = ui.available_width();
            ui.set_min_width(total_width);
            let columns = column_widths(total_width);

            // Full-width top-rounded Table Header
            let header_height = 40.0;
            Frame::new()
                .fill(SURFACE_ALT)
                .corner_radius(CornerRadius {
                    nw: 10,
                    ne: 10,
                    sw: 0,
                    se: 0,
                })
                .inner_margin(Margin::ZERO)
                .show(ui, |ui| {
                    ui.set_min_width(total_width);
                    let selected_count = self.apps.selected_visible().len();
                    let visible_count = self.apps.visible.len();
                    let mut select_all = visible_count > 0 && selected_count == visible_count;
                    let indeterminate = selected_count > 0 && selected_count < visible_count;

                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 12.0;
                        ui.add_space(4.0); // + 12px spacing = 16px clean left inset
                        table_cell(ui, columns[0], header_height, |ui| {
                            let select = styled_checkbox(
                                ui,
                                Id::new("inventory_select_all"),
                                &mut select_all,
                                indeterminate,
                                visible_count > 0,
                            )
                            .on_hover_text(language.text(
                                "Select all visible applications",
                                "选择全部可见应用",
                            ));
                            if let Some(inventory) =
                                self.apps.inventory.as_ref().filter(|_| select.changed())
                            {
                                for index in &self.apps.visible {
                                    let id = &inventory.applications[*index].id;
                                    if select_all {
                                        self.apps.selected.insert(id.clone());
                                    } else {
                                        self.apps.selected.remove(id);
                                    }
                                }
                            }
                        });
                        let headings = [
                            (
                                SortField::Name,
                                language.text("Application", "应用程序"),
                                false,
                                columns[1],
                            ),
                            (
                                SortField::Publisher,
                                language.text("Publisher", "发行商"),
                                false,
                                columns[2],
                            ),
                            (
                                SortField::Size,
                                language.text("Size", "大小"),
                                true,
                                columns[3],
                            ),
                            (
                                SortField::Date,
                                language.text("Installed", "安装日期"),
                                false,
                                columns[4],
                            ),
                        ];
                        for (field, text, align_right, col_w) in headings {
                            if col_w <= 0.5 {
                                continue;
                            }
                            let active = self.apps.sort == field;
                            let (cell_rect, cell_resp) =
                                ui.allocate_exact_size(vec2(col_w, header_height), Sense::click());
                            if cell_resp.hovered() {
                                ui.painter().rect_filled(
                                    cell_rect.shrink2(vec2(-4.0, 6.0)),
                                    6.0,
                                    Color32::from_rgb(238, 241, 246),
                                );
                                ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
                            }
                            let color = if active {
                                ACCENT
                            } else if cell_resp.hovered() {
                                INK
                            } else {
                                MUTED
                            };
                            let font = FontId::new(12.0, fonts::semibold_family());
                            let probe = ui.painter().layout_no_wrap(text.to_owned(), font.clone(), color);
                            let text_w = measured_text_width(&probe);
                            let show_arrow = active || cell_resp.hovered();
                            let arrow_w = if show_arrow { 14.0 } else { 0.0 };

                            if align_right {
                                let text_rect = Rect::from_min_max(
                                    cell_rect.min,
                                    pos2((cell_rect.right() - arrow_w).max(cell_rect.left() + 8.0), cell_rect.bottom()),
                                );
                                paint_right_truncated(ui, text_rect, text, font, color);
                                if show_arrow {
                                    paint_sort_indicator(
                                        ui,
                                        pos2(cell_rect.right() - 5.0, cell_rect.center().y),
                                        active,
                                        self.apps.descending,
                                        if active { ACCENT } else { SUBTLE },
                                    );
                                }
                            } else {
                                let text_rect = Rect::from_min_max(
                                    cell_rect.min,
                                    pos2((cell_rect.right() - arrow_w).max(cell_rect.left() + 8.0), cell_rect.bottom()),
                                );
                                paint_left_truncated(ui, text_rect, text, font, color);
                                if show_arrow {
                                    let ax = (cell_rect.left() + text_w + 8.0).min(cell_rect.right() - 5.0);
                                    paint_sort_indicator(
                                        ui,
                                        pos2(ax, cell_rect.center().y),
                                        active,
                                        self.apps.descending,
                                        if active { ACCENT } else { SUBTLE },
                                    );
                                }
                            }
                            if cell_resp.clicked() {
                                self.apps.sort_on(field);
                            }
                        }
                        let (src_rect, _) =
                            ui.allocate_exact_size(vec2(columns[5], header_height), Sense::hover());
                        paint_right_truncated(
                            ui,
                            src_rect,
                            language.text("Source", "来源"),
                            FontId::new(12.0, fonts::semibold_family()),
                            MUTED,
                        );
                    });
                });

            divider(ui);

            let body_height = (height - header_height - 2.0).max(88.0);
            let Some(inventory) = &self.apps.inventory else {
                if self.worker.is_busy() {
                    loading_skeleton(
                        ui,
                        body_height,
                        APP_ROW,
                        language.text("Reading installed applications…", "正在枚举已安装应用…"),
                    );
                } else if empty_state(
                    ui,
                    body_height,
                    Icon::Info,
                    language.text(
                        "Application inventory is unavailable.",
                        "当前无法获取应用清单。",
                    ),
                    Some(language.text(
                        "Try refreshing to read installed applications again.",
                        "点击刷新以重新读取本机已安装应用。",
                    )),
                    self.backend_supported
                        .then_some(language.text("Refresh", "刷新")),
                ) {
                    trigger_refresh = true;
                }
                return;
            };
            if self.apps.visible.is_empty() {
                let has_query = !self.apps.search.trim().is_empty();
                if empty_state(
                    ui,
                    body_height,
                    Icon::Search,
                    language.text(
                        "No applications match the current filter.",
                        "没有符合当前筛选条件的应用。",
                    ),
                    has_query.then_some(language.text(
                        "Try another keyword or reset the search bar.",
                        "尝试更换关键词或清除搜索条件。",
                    )),
                    has_query.then_some(language.text("Clear search", "清除搜索")),
                ) {
                    clear_search = true;
                }
                return;
            }
            ui.spacing_mut().item_spacing.y = 0.0;
            let shift_held = ui.input(|i| i.modifiers.shift);
            ScrollArea::vertical()
                .id_salt("inventory_rows")
                .max_height(body_height)
                .auto_shrink([false, false])
                .show_rows(ui, APP_ROW, self.apps.visible.len(), |ui, rows| {
                    for index in rows {
                        let app = &inventory.applications[self.apps.visible[index]];
                        ui.push_id(&app.id, |ui| {
                            let selected = self.apps.selected.contains(&app.id);
                            let (toggled, menu_act) = application_row(
                                ui,
                                language,
                                app,
                                columns,
                                selected,
                                can_submit,
                            );
                            if toggled {
                                click_toggle = Some((app.id.clone(), shift_held));
                            }
                            if let Some(act) = menu_act {
                                row_action = Some(act);
                            }
                        });
                    }
                });
        });

        if clear_search {
            self.apps.search.clear();
            self.apps.dirty = true;
        }
        if trigger_refresh && self.can_submit() {
            self.submit(Request::Applications, Operation::Inventory);
        }
        if let Some((id, extend)) = click_toggle {
            self.apps.toggle_row(&id, extend);
        }
        if let Some(action) = row_action {
            match action {
                RowAction::Scan(id) => {
                    self.submit(Request::Scan(id), Operation::Scan);
                }
                RowAction::Uninstall(id) => {
                    self.submit(
                        Request::ReviewUninstall(vec![id]),
                        Operation::PrepareUninstall,
                    );
                }
                RowAction::Force(id) => {
                    self.submit(Request::Force(id), Operation::Scan);
                }
                RowAction::CopyPath(path) => {
                    let label = language.text("install path", "安装路径");
                    self.copy_to_clipboard(ui.ctx(), &path, label);
                }
            }
        }
    }

    fn application_actions(&mut self, ui: &mut Ui) {
        let language = self.language;
        let selected = self.apps.selected_visible();
        let ready = self.can_submit();
        let can_uninstall = !selected.is_empty()
            && selected
                .iter()
                .all(|app| app.official_uninstall_available && !app.system_component);

        let uninstall_label = if selected.len() > 1 {
            if language == Language::Chinese {
                format!("预览卸载 ({})", selected.len())
            } else {
                format!("Review uninstall ({})", selected.len())
            }
        } else {
            language.text("Review uninstall", "预览卸载").to_owned()
        };
        let uninstall_hint = if selected.is_empty() {
            language.text(
                "Select one or more applications first.",
                "请先选择一个或多个应用程序。",
            )
        } else if !can_uninstall {
            language.text(
                "One or more selected apps do not have an available official uninstaller.",
                "所选应用中包含无官方卸载程序或系统组件的项目。",
            )
        } else {
            language.text(
                "Wait for the current operation to finish.",
                "请等待当前操作完成。",
            )
        };
        if action_button(
            ui,
            ButtonSpec::new(&uninstall_label, ButtonVariant::Primary)
                .icon(Icon::Trash)
                .enabled(ready && can_uninstall)
                .busy(self.is_running(Operation::PrepareUninstall))
                .disabled_hint(uninstall_hint),
        )
        .clicked()
        {
            let ids = selected.iter().map(|app| app.id.clone()).collect();
            self.submit(Request::ReviewUninstall(ids), Operation::PrepareUninstall);
            return;
        }

        let scan_hint = match selected.len() {
            0 => language.text(
                "Select a single application to scan leftovers.",
                "请选择单个应用以扫描残留。",
            ),
            1 => language.text(
                "System components cannot be scanned directly.",
                "系统组件不支持直接扫描残留。",
            ),
            _ => language.text(
                "Leftover scan works on one application at a time.",
                "残留扫描每次仅针对单个应用程序。",
            ),
        };
        let [app] = selected.as_slice() else {
            action_button(
                ui,
                ButtonSpec::new(
                    language.text("Scan leftovers", "扫描残留"),
                    ButtonVariant::Secondary,
                )
                .icon(Icon::Search)
                .enabled(false)
                .disabled_hint(scan_hint),
            );
            return;
        };
        let id = app.id.clone();
        let eligible = ready && !app.system_component;
        let force_id = app.id.clone();
        if action_button(
            ui,
            ButtonSpec::new(
                language.text("Scan leftovers", "扫描残留"),
                ButtonVariant::Secondary,
            )
            .icon(Icon::Search)
            .enabled(eligible)
            .busy(self.is_running(Operation::Scan))
            .disabled_hint(scan_hint),
        )
        .clicked()
        {
            self.submit(Request::Scan(id), Operation::Scan);
        }

        // Uniform-styled popup menu button with trailing chevron & active state
        let popup_id = ui.make_persistent_id("app_more_actions_popup");
        let popup_open = ui.memory(|m| m.is_popup_open(popup_id));
        let more_resp = action_button(
            ui,
            ButtonSpec::new(language.text("More", "更多"), ButtonVariant::Secondary)
                .trailing_icon(Icon::ChevronDown)
                .enabled(eligible)
                .active(popup_open)
                .disabled_hint(scan_hint),
        );
        if more_resp.clicked() {
            ui.memory_mut(|m| m.toggle_popup(popup_id));
        }
        egui::popup_below_widget(
            ui,
            popup_id,
            &more_resp,
            egui::PopupCloseBehavior::CloseOnClickOutside,
            |ui| {
                ui.set_min_width(196.0);
                ui.spacing_mut().item_spacing.y = 4.0;
                if menu_item(
                    ui,
                    eligible,
                    language.text("Review force removal", "预览强制移除"),
                    Some(Icon::AlertTriangle),
                    true,
                )
                .clicked()
                {
                    self.submit(Request::Force(force_id), Operation::Scan);
                    ui.memory_mut(|m| m.close_popup());
                }
                ui.horizontal(|ui| {
                    ui.add_space(10.0);
                    ui.label(body_text(
                        language.text(
                            "Use when official uninstaller fails",
                            "仅在官方卸载失效时使用",
                        ),
                        11.0,
                        SUBTLE,
                    ));
                });
            },
        );
    }

    fn quarantine(&mut self, ui: &mut Ui) {
        let language = self.language;
        let refreshing = self.is_running(Operation::Backups);
        ui.horizontal(|ui| {
            title(ui, language.text("Quarantine", "隔离区"));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                if action_button(
                    ui,
                    ButtonSpec::new(language.text("Refresh", "刷新"), ButtonVariant::Secondary)
                        .icon(Icon::Refresh)
                        .enabled(self.can_submit())
                        .busy(refreshing),
                )
                .clicked()
                {
                    self.submit(Request::Backups, Operation::Backups);
                }
                if action_button(
                    ui,
                    ButtonSpec::new(
                        language.text("Review expired files", "检查到期文件"),
                        ButtonVariant::Secondary,
                    )
                    .icon(Icon::Clock)
                    .enabled(self.can_submit() && self.quarantine.is_some())
                    .busy(self.is_running(Operation::ExpiryPreview)),
                )
                .clicked()
                {
                    self.submit(Request::ReviewExpiry, Operation::ExpiryPreview);
                }
            });
        });
        ui.add_space(10.0);
        let Some(inventory) = &self.quarantine else {
            card(0).show(ui, |ui| {
                if self.worker.is_busy() {
                    loading_skeleton(
                        ui,
                        200.0,
                        48.0,
                        language.text("Reading recoverable backups…", "正在读取可恢复的备份…"),
                    );
                } else if empty_state(
                    ui,
                    170.0,
                    Icon::Archive,
                    language.text(
                        "Quarantine inventory is unavailable.",
                        "当前无法获取隔离区清单。",
                    ),
                    None,
                    self.backend_supported
                        .then_some(language.text("Refresh", "刷新")),
                ) {
                    self.submit(Request::Backups, Operation::Backups);
                }
            });
            return;
        };
        diagnostics(ui, language, &inventory.warnings, "backup_warnings");
        if inventory.items.is_empty() {
            card(16).show(ui, |ui| {
                if empty_state(
                    ui,
                    190.0,
                    Icon::Archive,
                    language.text("No items have been quarantined.", "还没有隔离项目。"),
                    Some(language.text(
                        "Files and backups isolated during cleanup appear here for safe restoration.",
                        "清理过程中隔离的文件与备份会显示在这里，随时可供还原。",
                    )),
                    Some(language.text("Go to Applications", "前往应用程序")),
                ) {
                    self.navigate(Page::Applications);
                }
            });
            return;
        }

        let mut batches = BTreeMap::<Uuid, Vec<&BackupSummary>>::new();
        for item in &inventory.items {
            batches.entry(item.batch_id).or_default().push(item);
        }
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |time| time.as_millis());
        let batch_count = batches.len();
        let recoverable_total = inventory
            .items
            .iter()
            .filter(|i| i.state == RecoveryState::Applied)
            .count();
        let reached_total = inventory
            .items
            .iter()
            .filter(|i| i.state == RecoveryState::Applied && u128::from(i.expires_unix_ms) <= now_ms)
            .count();

        // Compact 3-tile summary strip
        let strip_w = ui.available_width();
        let tile_w = ((strip_w - 20.0) / 3.0).max(120.0);
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 10.0;
            metric_card(
                ui,
                tile_w,
                language.text("Quarantine batches", "隔离批次"),
                &batch_count.to_string(),
                ACCENT,
                ACCENT_PALE,
                Icon::Archive,
            );
            metric_card(
                ui,
                tile_w,
                language.text("Recoverable items", "可还原项目"),
                &recoverable_total.to_string(),
                DARK_GREEN,
                PALE_GREEN,
                Icon::Restore,
            );
            let (exp_fg, exp_bg) = if reached_total > 0 {
                (DARK_AMBER, PALE_AMBER)
            } else {
                (SUBTLE, SURFACE_ALT)
            };
            metric_card(
                ui,
                tile_w,
                language.text("Retention reached", "已到保留期"),
                &reached_total.to_string(),
                exp_fg,
                exp_bg,
                Icon::Clock,
            );
        });
        ui.add_space(12.0);

        let busy = !self.can_submit();
        let mut restore = None;
        let mut copy_path: Option<String> = None;
        ScrollArea::vertical()
            .id_salt("quarantine_batches")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 10.0;
                for (batch, items) in batches {
                    let applied = items
                        .iter()
                        .filter(|item| item.state == RecoveryState::Applied)
                        .count();
                    let deadline = items
                        .iter()
                        .filter(|item| item.state == RecoveryState::Applied)
                        .map(|item| item.expires_unix_ms)
                        .min();
                    card(18).show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 8.0;
                            let short_id = &batch.to_string()[..8];
                            badge(ui, short_id, ACCENT, ACCENT_PALE);
                            let count = if language == Language::Chinese {
                                format!("{applied} 项可还原 · 共 {} 项", items.len())
                            } else {
                                format!("{applied} recoverable · {} total", items.len())
                            };
                            ui.label(semibold_text(count, 13.5, INK));
                            if let Some(deadline) = deadline {
                                let (fg, bg, remaining) = expires(language, deadline);
                                badge(ui, &remaining, fg, bg);
                            }
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if action_button(
                                    ui,
                                    ButtonSpec::new(
                                        language.text("Review restore", "预览还原"),
                                        if applied > 0 {
                                            ButtonVariant::Tinted
                                        } else {
                                            ButtonVariant::Secondary
                                        },
                                    )
                                    .icon(Icon::Restore)
                                    .enabled(!busy && applied > 0)
                                    .disabled_hint(language.text(
                                        "No recoverable items remain in this batch.",
                                        "此批次中没有可还原的项目。",
                                    )),
                                )
                                .clicked()
                                {
                                    restore = Some(batch);
                                }
                            });
                        });
                        ui.add_space(10.0);
                        divider(ui);
                        ui.add_space(6.0);
                        let meta = if language == Language::Chinese {
                            format!("{} 项", items.len())
                        } else {
                            format!("{} items", items.len())
                        };
                        collapsible_section(
                            ui,
                            Id::new(("quarantine_batch_items", batch)),
                            language.text("Files and backups", "文件与备份"),
                            Some(&meta),
                            false,
                            |ui| {
                                ui.spacing_mut().item_spacing.y = 6.0;
                                for item in items {
                                    let (fg, bg, text) = recovery_label(language, item.state);
                                    ui.horizontal(|ui| {
                                        ui.spacing_mut().item_spacing.x = 10.0;
                                        badge(ui, text, fg, bg);
                                        let text_w = (ui.available_width() - 34.0).max(80.0);
                                        let (row_rect, _) = ui.allocate_exact_size(
                                            vec2(text_w, 24.0),
                                            Sense::hover(),
                                        );
                                        paint_left_truncated(
                                            ui,
                                            row_rect,
                                            &item.target,
                                            FontId::proportional(12.5),
                                            INK,
                                        );
                                        ui.interact(
                                            row_rect,
                                            Id::new(("q_item_tip", item.id)),
                                            Sense::hover(),
                                        )
                                        .on_hover_text(&item.backup);

                                        let (cp_rect, cp_resp) =
                                            ui.allocate_exact_size(vec2(22.0, 22.0), Sense::click());
                                        if cp_resp.hovered() {
                                            ui.painter().rect_filled(cp_rect, 5.0, SURFACE_ALT);
                                            ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
                                        }
                                        paint_icon(
                                            ui,
                                            Icon::Copy,
                                            cp_rect.center(),
                                            12.0,
                                            if cp_resp.hovered() { INK } else { SUBTLE },
                                        );
                                        if cp_resp
                                            .on_hover_text(language.text("Copy path", "复制路径"))
                                            .clicked()
                                        {
                                            copy_path = Some(item.target.clone());
                                        }
                                    });
                                }
                            },
                        );
                    });
                }
            });
        if let Some(batch) = restore {
            self.submit(Request::ReviewRestore(batch), Operation::PrepareRestore);
        }
        if let Some(path) = copy_path {
            let label = language.text("path", "路径");
            self.copy_to_clipboard(ui.ctx(), &path, label);
        }
    }

    fn settings(&mut self, ui: &mut Ui) {
        title(ui, self.language.text("Settings", "设置"));
        ui.add_space(12.0);
        ScrollArea::vertical()
            .id_salt("settings_scroll")
            .show(ui, |ui| self.settings_contents(ui));
    }

    fn settings_contents(&mut self, ui: &mut Ui) {
        let language = self.language;
        let content_width = ui.available_width().min(720.0);
        ui.allocate_ui_with_layout(
            vec2(content_width, ui.available_height()),
            Layout::top_down(Align::LEFT),
            |ui| {
                ui.spacing_mut().item_spacing.y = 12.0;

                // Display Language Card
                card(18).show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    let toggle_w = 92.0;
                    let text_w = (ui.available_width() - (toggle_w * 2.0 + 26.0)).max(160.0);
                    ui.horizontal(|ui| {
                        ui.allocate_ui_with_layout(
                            vec2(text_w, 0.0),
                            Layout::top_down(Align::LEFT),
                            |ui| {
                                ui.spacing_mut().item_spacing.y = 4.0;
                                section_heading(ui, language.text("Display language", "显示语言"));
                                ui.label(body_text(
                                    language.text(
                                        "Switch interface text immediately without restarting.",
                                        "立即切换界面语言，无需重启应用。",
                                    ),
                                    12.5,
                                    MUTED,
                                ));
                            },
                        );
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            segmented_toggle(
                                ui,
                                Id::new("settings_lang_toggle"),
                                &mut self.language,
                                [(Language::English, "English"), (Language::Chinese, "简体中文")],
                                toggle_w,
                                CONTROL_HEIGHT,
                            );
                        });
                    });
                });

                // Quarantine Retention Card
                let retention_dirty = self.retention != self.saved_retention;
                card(18).show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 8.0;
                        section_heading(ui, language.text("Quarantine retention", "隔离保留期"));
                        if retention_dirty {
                            badge(
                                ui,
                                language.text("Unsaved", "未保存"),
                                DARK_AMBER,
                                PALE_AMBER,
                            );
                        }
                    });
                    ui.add_space(4.0);
                    ui.label(body_text(
                        language.text(
                            "Applies to future backups. Expired items remain available for restore.",
                            "新设置适用于后续备份。到期的隔离项仍可还原。",
                        ),
                        12.5,
                        MUTED,
                    ));
                    ui.add_space(10.0);
                    divider(ui);
                    ui.add_space(10.0);

                    ui.horizontal_wrapped(|ui| {
                        ui.spacing_mut().item_spacing = vec2(8.0, 8.0);
                        for days in [7u16, 14, 30, 90] {
                            let label = if language == Language::Chinese {
                                format!("{days} 天")
                            } else {
                                format!("{days}d")
                            };
                            if chip_button(ui, self.retention == days, &label).clicked() {
                                self.retention = days;
                            }
                        }

                        numeric_stepper(
                            ui,
                            Id::new("retention_stepper"),
                            &mut self.retention,
                            1,
                            u16::MAX,
                            language.text(" days", " 天"),
                        );

                        if retention_dirty
                            && action_button(
                                ui,
                                ButtonSpec::new(
                                    language.text("Reset", "还原"),
                                    ButtonVariant::Ghost,
                                ),
                            )
                            .clicked()
                        {
                            self.retention = self.saved_retention;
                        }

                        let can_save = self.can_submit() && retention_dirty;
                        if action_button(
                            ui,
                            ButtonSpec::new(language.text("Apply", "应用"), ButtonVariant::Primary)
                                .icon(Icon::Check)
                                .enabled(can_save)
                                .busy(self.is_running(Operation::Preferences)),
                        )
                        .clicked()
                        {
                            self.save_retention();
                        }
                    });
                });
                self.settings_rules(ui);
                self.settings_audit(ui);
                diagnostics(
                    ui,
                    self.language,
                    &self.preference_warnings,
                    "preference_diagnostics",
                );
            },
        );
    }

    fn settings_rules(&mut self, ui: &mut Ui) {
        let language = self.language;
        let rules_dirty = self.rule_text != self.saved_rule_text;
        card(18).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                section_heading(ui, language.text("Custom rules", "自定义规则"));
                if rules_dirty {
                    badge(
                        ui,
                        language.text("Unsaved", "未保存"),
                        DARK_AMBER,
                        PALE_AMBER,
                    );
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let bytes = self.rule_text.len();
                    let lines = if self.rule_text.is_empty() {
                        0
                    } else {
                        self.rule_text.lines().count()
                    };
                    let meta = if language == Language::Chinese {
                        format!("{lines} 行 · {bytes} B")
                    } else {
                        format!("{lines} lines · {bytes} B")
                    };
                    ui.label(body_text(meta, 11.5, SUBTLE));
                });
            });
            ui.add_space(4.0);
            ui.label(body_text(
                language.text(
                    "Paste your TOML rules. Leave it blank to use the built-in rules only.",
                    "在这里粘贴 TOML 规则。清空并保存即可只使用内置规则。",
                ),
                12.5,
                MUTED,
            ));
            ui.add_space(10.0);
            divider(ui);
            ui.add_space(10.0);
            let editable = self.can_submit();
            ui.add_enabled(
                editable,
                TextEdit::multiline(&mut self.rule_text)
                    .code_editor()
                    .desired_width(f32::INFINITY)
                    .desired_rows(6)
                    .margin(Margin::symmetric(12, 10))
                    .char_limit(uninstallany_core::MAX_RULE_FILE_BYTES),
            );
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if let Some(Status::RulesSaved(count)) = &self.status {
                    let summary = match language {
                        Language::English => format!("{count} custom rules"),
                        Language::Chinese => format!("{count} 条自定义规则"),
                    };
                    icon_badge(ui, Icon::Check, &summary, DARK_GREEN, PALE_GREEN);
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    let can_save = self.can_submit() && rules_dirty;
                    if action_button(
                        ui,
                        ButtonSpec::new(
                            language.text("Save rules", "保存规则"),
                            ButtonVariant::Primary,
                        )
                        .icon(Icon::Check)
                        .enabled(can_save)
                        .busy(self.is_running(Operation::Preferences)),
                    )
                    .clicked()
                    {
                        self.save_rules();
                    }
                    if rules_dirty
                        && action_button(
                            ui,
                            ButtonSpec::new(
                                language.text("Revert", "撤回修改"),
                                ButtonVariant::Ghost,
                            ),
                        )
                        .clicked()
                    {
                        self.rule_text = self.saved_rule_text.clone();
                    }
                });
            });
        });
    }

    fn settings_audit(&mut self, ui: &mut Ui) {
        let language = self.language;
        let mut copy_exported: Option<String> = None;
        card(18).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            section_heading(ui, language.text("Audit log", "操作日志"));
            ui.add_space(4.0);
            ui.label(body_text(
                language.text(
                    "Export a new JSON Lines file. Records can include local app names and paths.",
                    "导出新的 JSON Lines 文件。日志可能包含本机应用名称和路径。",
                ),
                12.5,
                MUTED,
            ));
            ui.add_space(10.0);
            divider(ui);
            ui.add_space(10.0);
            let editable = self.can_submit();
            let btn_label = language.text("Export log", "导出日志");
            let btn_w = measure_icon_button_width(ui, btn_label, Icon::Export, 106.0);
            let input_w = (ui.available_width() - btn_w - 8.0).max(140.0);
            let can_export = editable && !self.export_destination.trim().is_empty();
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                let res = styled_text_input(
                    ui,
                    Id::new("audit_export_path_input"),
                    &mut self.export_destination,
                    language.text(
                        "Absolute path to a new .jsonl file",
                        "新 .jsonl 文件的绝对路径",
                    ),
                    input_w,
                    Some(Icon::Folder),
                    None,
                    editable,
                    false,
                );
                let clicked = action_button(
                    ui,
                    ButtonSpec::new(btn_label, ButtonVariant::Primary)
                        .icon(Icon::Export)
                        .enabled(can_export)
                        .busy(self.is_running(Operation::AuditExport))
                        .disabled_hint(language.text(
                            "Enter an absolute path for the new .jsonl file.",
                            "请输入新的 .jsonl 文件绝对路径。",
                        )),
                )
                .clicked();
                if (clicked || res.submitted) && can_export {
                    self.export_audit();
                }
            });
            if let Some((path, report)) = &self.export_result {
                ui.add_space(10.0);
                let summary = match language {
                    Language::English => format!("{} records exported", report.written),
                    Language::Chinese => format!("已导出 {} 条记录", report.written),
                };
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    icon_badge(ui, Icon::Check, &summary, DARK_GREEN, PALE_GREEN);
                    let location = path.to_string_lossy().to_string();
                    let text_w = (ui.available_width() - 96.0).max(80.0);
                    let (loc_rect, _) =
                        ui.allocate_exact_size(vec2(text_w, 24.0), Sense::hover());
                    paint_left_truncated(
                        ui,
                        loc_rect,
                        &location,
                        FontId::proportional(12.0),
                        MUTED,
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if action_button(
                            ui,
                            ButtonSpec::new(
                                language.text("Copy path", "复制路径"),
                                ButtonVariant::Ghost,
                            )
                            .compact()
                            .icon(Icon::Copy),
                        )
                        .clicked()
                        {
                            copy_exported = Some(location);
                        }
                    });
                });
                diagnostics(ui, language, &report.warnings, "audit_export_diagnostics");
            }
        });
        if let Some(path) = copy_exported {
            let label = language.text("export path", "导出路径");
            self.copy_to_clipboard(ui.ctx(), &path, label);
        }
    }

    fn review(&mut self, ui: &mut Ui) {
        let language = self.language;
        let queued = self.plans.len();
        let headline = if queued > 0 {
            language.text("Cleanup preview", "清理预览")
        } else {
            language.text("Operation results", "操作结果")
        };
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 10.0;
            title(ui, headline);
            if queued > 1 {
                badge(
                    ui,
                    &if language == Language::Chinese {
                        format!("还有 {queued} 份清单")
                    } else {
                        format!("{queued} queued")
                    },
                    ACCENT,
                    ACCENT_PALE,
                );
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if action_button(
                    ui,
                    ButtonSpec::new(
                        language.text("Back to applications", "返回应用程序"),
                        ButtonVariant::Secondary,
                    )
                    .icon(Icon::Back),
                )
                .clicked()
                {
                    self.navigate(Page::Applications);
                }
            });
        });
        ui.add_space(8.0);

        let busy = !self.can_submit();
        let mut review = None;
        let mut discard = false;
        let mut feedback_toast: Option<(ToastKind, String)> = None;
        if let Some(plan) = self.plans.front_mut() {
            let has_other_results =
                self.change_result.is_some() || !self.uninstall_results.is_empty();
            let height =
                (ui.available_height() - if has_other_results { 236.0 } else { 156.0 }).max(98.0);
            let (r, d, toast_msg) = cleanup(ui, language, plan, queued, busy, height);
            review = r;
            discard = d;
            feedback_toast = toast_msg;
        }
        if let Some((kind, msg)) = feedback_toast {
            self.toast(kind, msg);
        }
        if discard {
            self.plans.pop_front();
        }
        if let Some(review) = review {
            self.confirmation = Some(review);
        }
        let mut copy_batch: Option<String> = None;
        if !self.uninstall_results.is_empty() || self.change_result.is_some() {
            ui.add_space(10.0);
            ScrollArea::vertical()
                .id_salt("operation_results")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 10.0;
                    self.uninstall_results(ui);
                    copy_batch = self.change_results(ui);
                });
        } else if queued == 0 && !busy {
            card(16).show(ui, |ui| {
                if empty_state(
                    ui,
                    160.0,
                    Icon::Info,
                    language.text("No operation results to display.", "暂无操作结果。"),
                    Some(language.text(
                        "Scan an application or run a cleanup to see results here.",
                        "扫描应用或执行清理后，结果会显示在此处。",
                    )),
                    Some(language.text("Go to Applications", "前往应用程序")),
                ) {
                    self.navigate(Page::Applications);
                }
            });
        }
        if let Some(batch_id) = copy_batch {
            let label = language.text("batch ID", "批次 ID");
            self.copy_to_clipboard(ui.ctx(), &batch_id, label);
        }
    }

    fn uninstall_results(&self, ui: &mut Ui) {
        let language = self.language;
        if self.uninstall_results.is_empty() {
            return;
        }
        let completed = self
            .uninstall_results
            .iter()
            .filter(|r| matches!(r.outcome, Ok(OfficialOutcome::Completed)))
            .count();
        card(18).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                section_heading(
                    ui,
                    language.text("Official uninstall results", "官方卸载结果"),
                );
                let summary = if language == Language::Chinese {
                    format!("{completed}/{} 已完成", self.uninstall_results.len())
                } else {
                    format!("{completed}/{} completed", self.uninstall_results.len())
                };
                badge(
                    ui,
                    &summary,
                    if completed == self.uninstall_results.len() {
                        DARK_GREEN
                    } else {
                        DARK_AMBER
                    },
                    if completed == self.uninstall_results.len() {
                        PALE_GREEN
                    } else {
                        PALE_AMBER
                    },
                );
            });
            ui.add_space(8.0);
            divider(ui);
            ui.add_space(8.0);
            ui.spacing_mut().item_spacing.y = 8.0;
            for row in &self.uninstall_results {
                let (fg, bg, text) = official_outcome(language, row.outcome.as_ref());
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 10.0;
                    badge(ui, &text, fg, bg);
                    ui.label(semibold_text(&row.application, 13.0, INK));
                });
                if let Err(reason) = &row.outcome {
                    ui.label(body_text(reason, 12.5, MUTED));
                }
                for warning in &row.warnings {
                    ui.label(body_text(warning, 12.5, DARK_AMBER));
                }
            }
        });
    }

    fn change_results(&self, ui: &mut Ui) -> Option<String> {
        let language = self.language;
        let report = self.change_result.as_ref()?;
        let mut copy_id = None;
        let ok_count = report
            .items
            .iter()
            .filter(|i| {
                matches!(
                    i.result,
                    ChangeResult::Applied | ChangeResult::Restored | ChangeResult::Purged
                )
            })
            .count();
        let warn_count = report.items.len().saturating_sub(ok_count);

        card(18).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                section_heading(
                    ui,
                    language.text("Cleanup or restore report", "清理或还原报告"),
                );
                if ok_count > 0 {
                    let s = if language == Language::Chinese {
                        format!("{ok_count} 项已处理")
                    } else {
                        format!("{ok_count} succeeded")
                    };
                    badge(ui, &s, DARK_GREEN, PALE_GREEN);
                }
                if warn_count > 0 {
                    let s = if language == Language::Chinese {
                        format!("{warn_count} 项跳过/复核")
                    } else {
                        format!("{warn_count} skipped/review")
                    };
                    badge(ui, &s, DARK_AMBER, PALE_AMBER);
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    if action_button(
                        ui,
                        ButtonSpec::new(language.text("Copy ID", "复制 ID"), ButtonVariant::Ghost)
                            .compact()
                            .icon(Icon::Copy),
                    )
                    .clicked()
                    {
                        copy_id = Some(report.batch_id.to_string());
                    }
                    let short = &report.batch_id.to_string()[..8];
                    ui.label(RichText::new(short).monospace().color(SUBTLE).size(11.5));
                });
            });
            ui.add_space(8.0);
            divider(ui);
            ui.add_space(8.0);
            ui.spacing_mut().item_spacing.y = 8.0;
            for item in &report.items {
                let (foreground, background, label, reason) = match &item.result {
                    ChangeResult::Applied => (
                        DARK_GREEN,
                        PALE_GREEN,
                        language.text("Quarantined or backed up", "已隔离或备份"),
                        None,
                    ),
                    ChangeResult::Restored => (
                        DARK_GREEN,
                        PALE_GREEN,
                        language.text("Restored", "已还原"),
                        None,
                    ),
                    ChangeResult::Purged => (
                        MUTED,
                        DISABLED_BG,
                        language.text("Permanently removed", "已永久清理"),
                        None,
                    ),
                    ChangeResult::Skipped(reason) => (
                        DARK_AMBER,
                        PALE_AMBER,
                        language.text("Skipped", "已跳过"),
                        Some(reason),
                    ),
                    ChangeResult::NeedsReview(reason) => (
                        DANGER,
                        PALE_RED,
                        language.text("Needs review", "需要复核"),
                        Some(reason),
                    ),
                };
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 10.0;
                    badge(ui, label, foreground, background);
                    truncate(ui, body_text(&item.target, 13.0, INK), &item.target);
                });
                if let Some(reason) = reason {
                    ui.label(body_text(reason, 12.0, MUTED));
                }
            }
        });
        copy_id
    }

    fn dialog(&mut self, context: &egui::Context) {
        let is_open = self.confirmation.is_some();
        let modal_t = self.anim.modal_progress(context, is_open);
        let Some(mut review) = self.confirmation.take() else {
            return;
        };
        let language = self.language;
        let backdrop_alpha = lerp_f32(25.0, 108.0, modal_t).round() as u8;
        let modal = egui::Modal::new(Id::new("confirmation"))
            .frame(modal_card(22))
            .backdrop_color(Color32::from_rgba_unmultiplied(16, 24, 40, backdrop_alpha))
            .show(context, |ui| {
                ui.set_opacity(lerp_f32(0.45, 1.0, modal_t));
                ui.set_min_width(440.0);
                ui.set_max_width(580.0);
                let (heading, action, positive_color, header_icon, icon_bg, cta_icon) =
                    match &review {
                        Review::Uninstall { .. } => (
                            language.text("Review official uninstall", "确认运行官方卸载"),
                            language.text("Start uninstall", "开始卸载"),
                            DANGER,
                            Icon::AlertTriangle,
                            PALE_RED,
                            Icon::Trash,
                        ),
                        Review::Cleanup { .. } => (
                            language.text("Confirm cleanup", "确认清理"),
                            language.text("Quarantine selected items", "隔离所选项目"),
                            ACCENT,
                            Icon::Shield,
                            ACCENT_PALE,
                            Icon::Shield,
                        ),
                        Review::Restore { .. } => (
                            language.text("Confirm restore", "确认还原"),
                            language.text("Restore batch", "还原此批次"),
                            ACCENT,
                            Icon::Restore,
                            ACCENT_PALE,
                            Icon::Restore,
                        ),
                        Review::Expiry { .. } => (
                            language.text("Expired quarantine files", "到期隔离文件"),
                            language.text("Permanently remove selected files", "永久清理所选文件"),
                            DANGER,
                            Icon::AlertTriangle,
                            PALE_RED,
                            Icon::Trash,
                        ),
                    };
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 12.0;
                    let (well, _) = ui.allocate_exact_size(vec2(34.0, 34.0), Sense::hover());
                    ui.painter().circle_filled(well.center(), 17.0, icon_bg);
                    paint_icon(ui, header_icon, well.center(), 16.0, positive_color);
                    title(ui, heading);
                });
                ui.add_space(10.0);
                divider(ui);
                ui.add_space(10.0);

                if let Review::Expiry {
                    entries,
                    warnings,
                    selected,
                    ..
                } = &mut review
                {
                    expiry_details(ui, language, entries, warnings, selected);
                } else if matches!(&review, Review::Cleanup { .. } | Review::Restore { .. }) {
                    confirmation_details(ui, language, &review);
                } else {
                    ScrollArea::vertical()
                        .id_salt("confirmation_details")
                        .auto_shrink([false, true])
                        .max_height(385.0)
                        .show(ui, |ui| confirmation_details(ui, language, &review));
                }
                let accepted = match &review {
                    Review::Uninstall { intents, .. } => !intents.is_empty(),
                    Review::Cleanup { items, .. } => !items.is_empty(),
                    Review::Restore { entries, .. } => !entries.is_empty(),
                    Review::Expiry { selected, .. } => !selected.is_empty(),
                };
                ui.add_space(14.0);
                divider(ui);
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if let Review::Expiry {
                        entries, selected, ..
                    } = &review
                    {
                        let ratio = if language == Language::Chinese {
                            format!("已选 {} / {} 项", selected.len(), entries.len())
                        } else {
                            format!("{} / {} selected", selected.len(), entries.len())
                        };
                        badge(
                            ui,
                            &ratio,
                            if selected.is_empty() { MUTED } else { DANGER },
                            if selected.is_empty() {
                                SURFACE_ALT
                            } else {
                                PALE_RED
                            },
                        );
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.spacing_mut().item_spacing.x = 8.0;
                        let variant = if positive_color == DANGER {
                            ButtonVariant::Danger
                        } else {
                            ButtonVariant::Primary
                        };
                        let proceed = action_button(
                            ui,
                            ButtonSpec::new(action, variant)
                                .icon(cta_icon)
                                .enabled(accepted && self.can_submit()),
                        )
                        .clicked();
                        let cancel =
                            secondary_button(ui, true, language.text("Cancel", "取消")).clicked();
                        (proceed, cancel)
                    })
                    .inner
                })
                .inner
            });
        let (proceed, canceled) = modal.inner;
        if proceed {
            self.approve(review);
        } else if !canceled && !modal.should_close() {
            self.confirmation = Some(review);
        }
    }
}

fn cleanup(
    ui: &mut Ui,
    language: Language,
    plan: &mut CleanupView,
    queued: usize,
    busy: bool,
    height: f32,
) -> (Option<Review>, bool, Option<(ToastKind, String)>) {
    let mut toast_msg = None;
    if plan.preview.mode == ScanMode::ForceRemoval {
        notice(
            ui,
            language.text(
                "Force removal only affects the selected listing and leftovers. The application may remain installed.",
                "强制移除仅处理所选卸载记录及残留。应用可能仍然安装在本机。",
            ),
            DARK_AMBER,
            PALE_AMBER,
        );
        ui.add_space(6.0);
    }
    diagnostics(ui, language, &plan.preview.warnings, "cleanup_warnings");

    // Top metadata + quick selection toolbar
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        if let Some(subject) = &plan.subject {
            badge(ui, subject, INK, SURFACE_ALT);
        }
        let count = plan.preview.candidates.len();
        let text = if language == Language::Chinese {
            format!("{count} 个候选项 · 共 {queued} 份待处理清单")
        } else {
            format!("{count} candidates · {queued} pending plans")
        };
        ui.label(body_text(text, 13.0, MUTED));

        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            if action_button(
                ui,
                ButtonSpec::new(language.text("Clear", "清空"), ButtonVariant::Ghost).compact(),
            )
            .clicked()
            {
                plan.selected.clear();
                plan.last_selected = None;
            }
            if action_button(
                ui,
                ButtonSpec::new(language.text("Select all", "全选"), ButtonVariant::Ghost)
                    .compact(),
            )
            .clicked()
            {
                plan.selected = plan
                    .preview
                    .candidates
                    .iter()
                    .filter(|item| item.access == Access::Allowed)
                    .map(|item| item.id)
                    .collect();
            }
            if action_button(
                ui,
                ButtonSpec::new(
                    language.text("Safe defaults", "推荐项"),
                    ButtonVariant::Tinted,
                )
                .compact()
                .icon(Icon::Sparkles),
            )
            .clicked()
            {
                plan.selected = plan
                    .preview
                    .candidates
                    .iter()
                    .filter(|item| item.default_selected())
                    .map(|item| item.id)
                    .collect();
                toast_msg = Some((
                    ToastKind::Info,
                    language
                        .text("Reset to safe defaults", "已恢复推荐勾选项")
                        .to_owned(),
                ));
            }
        });
    });

    // Category filter pill strip (shown when multiple categories exist)
    let all_categories = [
        Category::File,
        Category::Directory,
        Category::Shortcut,
        Category::Registry,
        Category::Startup,
        Category::Service,
        Category::ScheduledTask,
        Category::Firewall,
        Category::FileAssociation,
        Category::ShellExtension,
        Category::Com,
    ];
    let present_categories: Vec<(Category, usize)> = all_categories
        .into_iter()
        .filter_map(|kind| {
            let n = plan
                .preview
                .candidates
                .iter()
                .filter(|c| c.category == kind)
                .count();
            (n > 0).then_some((kind, n))
        })
        .collect();
    if present_categories.len() > 1 {
        ui.add_space(6.0);
        ScrollArea::horizontal()
            .id_salt(("candidate_cat_pills", plan.preview.id))
            .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    if filter_pill(
                        ui,
                        plan.category.is_none(),
                        language.text("All", "全部"),
                        Some(plan.preview.candidates.len()),
                    )
                    .clicked()
                    {
                        plan.category = None;
                    }
                    for (kind, count) in present_categories {
                        if filter_pill(
                            ui,
                            plan.category == Some(kind),
                            category_label(language, kind),
                            Some(count),
                        )
                        .clicked()
                        {
                            plan.category = Some(kind);
                        }
                    }
                });
            });
    }

    ui.add_space(6.0);
    let visible_ids: Vec<usize> = plan
        .preview
        .candidates
        .iter()
        .enumerate()
        .filter(|(_, item)| plan.category.is_none_or(|kind| item.category == kind))
        .map(|(i, _)| i)
        .collect();
    let visible_allowed_ids: Vec<usize> = visible_ids
        .iter()
        .map(|&idx| &plan.preview.candidates[idx])
        .filter(|c| c.access == Access::Allowed)
        .map(|c| c.id)
        .collect();
    let selected_visible_allowed = visible_allowed_ids
        .iter()
        .filter(|id| plan.selected.contains(id))
        .count();

    let mut toggle_candidate: Option<(usize, bool)> = None;
    let shift_held = ui.input(|i| i.modifiers.shift);

    card(0).show(ui, |ui| {
        let total_width = ui.available_width();
        ui.set_min_width(total_width);
        let header_height = 38.0;
        let check_w = 22.0;
        let cat_w = (total_width * 0.13).clamp(64.0, 108.0);
        let conf_w = (total_width * 0.17).clamp(96.0, 134.0);
        let risk_w = 82.0;
        let target_w = (total_width - 80.0 - check_w - cat_w - conf_w - risk_w).max(120.0);

        // Candidate Table Header
        Frame::new()
            .fill(SURFACE_ALT)
            .corner_radius(CornerRadius {
                nw: 10,
                ne: 10,
                sw: 0,
                se: 0,
            })
            .inner_margin(Margin::ZERO)
            .show(ui, |ui| {
                ui.set_min_width(total_width);
                let mut all_checked = !visible_allowed_ids.is_empty()
                    && selected_visible_allowed == visible_allowed_ids.len();
                let indeterminate = selected_visible_allowed > 0
                    && selected_visible_allowed < visible_allowed_ids.len();

                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 12.0;
                    ui.add_space(4.0);
                    table_cell(ui, check_w, header_height, |ui| {
                        let resp = styled_checkbox(
                            ui,
                            Id::new(("cand_select_all", plan.preview.id)),
                            &mut all_checked,
                            indeterminate,
                            !visible_allowed_ids.is_empty(),
                        )
                        .on_hover_text(language.text(
                            "Select all writable candidates",
                            "选择全部可写候选项",
                        ));
                        if resp.changed() {
                            for &cid in &visible_allowed_ids {
                                if all_checked {
                                    plan.selected.insert(cid);
                                } else {
                                    plan.selected.remove(&cid);
                                }
                            }
                        }
                    });
                    let hdr_font = FontId::new(12.0, fonts::semibold_family());
                    let (t_rect, _) =
                        ui.allocate_exact_size(vec2(target_w, header_height), Sense::hover());
                    paint_left_truncated(
                        ui,
                        t_rect,
                        language.text("Target & reason", "目标与命中理由"),
                        hdr_font.clone(),
                        MUTED,
                    );
                    let (c_rect, _) =
                        ui.allocate_exact_size(vec2(cat_w, header_height), Sense::hover());
                    paint_left_truncated(
                        ui,
                        c_rect,
                        language.text("Category", "类别"),
                        hdr_font.clone(),
                        MUTED,
                    );
                    let (cf_rect, _) =
                        ui.allocate_exact_size(vec2(conf_w, header_height), Sense::hover());
                    paint_left_truncated(
                        ui,
                        cf_rect,
                        language.text("Confidence", "置信度"),
                        hdr_font.clone(),
                        MUTED,
                    );
                    let (r_rect, _) =
                        ui.allocate_exact_size(vec2(risk_w, header_height), Sense::hover());
                    paint_right_truncated(
                        ui,
                        r_rect,
                        language.text("Access", "状态"),
                        hdr_font,
                        MUTED,
                    );
                });
            });

        divider(ui);

        let body_height = (height - header_height - 2.0).max(72.0);
        if visible_ids.is_empty() {
            if empty_state(
                ui,
                body_height.min(130.0),
                Icon::Filter,
                language.text(
                    "No leftovers found for this preview.",
                    "此预览未发现可展示的残留。",
                ),
                None,
                plan.category
                    .is_some()
                    .then_some(language.text("Show all categories", "显示全部类别")),
            ) {
                plan.category = None;
            }
            return;
        }
        ui.spacing_mut().item_spacing.y = 0.0;
        ScrollArea::vertical()
            .id_salt(plan.preview.id)
            .max_height(body_height)
            .auto_shrink([false, false])
            .show_rows(ui, CANDIDATE_ROW, visible_ids.len(), |ui, rows| {
                for row_idx in rows {
                    let candidate = &plan.preview.candidates[visible_ids[row_idx]];
                    let is_selected = plan.selected.contains(&candidate.id);
                    ui.push_id(candidate.id, |ui| {
                        if candidate_row(
                            ui,
                            language,
                            candidate,
                            is_selected,
                            [check_w, target_w, cat_w, conf_w, risk_w],
                        ) {
                            toggle_candidate = Some((candidate.id, shift_held));
                        }
                    });
                }
            });
    });

    if let Some((cid, extend)) = toggle_candidate {
        plan.toggle_candidate(&visible_allowed_ids, cid, extend);
    }

    let items = plan.approved_ids();
    let high_risk_count = plan.high_risk_selected_count();
    let mut review = None;
    let mut discard = false;
    ui.add_space(10.0);
    Frame::new()
        .fill(if items.is_empty() {
            SURFACE
        } else {
            ACCENT_SOFT
        })
        .stroke(Stroke::new(
            HAIRLINE,
            if items.is_empty() {
                LINE
            } else {
                lerp_color(LINE, ACCENT, 0.32)
            },
        ))
        .corner_radius(10)
        .inner_margin(Margin::symmetric(16, 10))
        .shadow(theme::card_shadow())
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                let text = if language == Language::Chinese {
                    format!("已选 {} 项", items.len())
                } else {
                    format!("{} selected", items.len())
                };
                badge(
                    ui,
                    &text,
                    if items.is_empty() { MUTED } else { ACCENT },
                    if items.is_empty() {
                        SURFACE_ALT
                    } else {
                        ACCENT_PALE
                    },
                );
                if high_risk_count > 0 {
                    let risk_text = if language == Language::Chinese {
                        format!("含 {high_risk_count} 项高风险")
                    } else {
                        format!("{high_risk_count} high risk")
                    };
                    icon_badge(ui, Icon::AlertTriangle, &risk_text, DANGER, PALE_RED);
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    if action_button(
                        ui,
                        ButtonSpec::new(
                            language.text("Review selection", "确认所选项目"),
                            ButtonVariant::Primary,
                        )
                        .icon(Icon::Shield)
                        .enabled(!busy && !items.is_empty())
                        .disabled_hint(language.text(
                            "Select at least one writable item to continue.",
                            "请至少选择一个可写项目以继续。",
                        )),
                    )
                    .clicked()
                    {
                        let mut selected = plan.preview.candidates.iter().filter(|item| {
                            item.access == Access::Allowed && plan.selected.contains(&item.id)
                        });
                        let targets = selected.clone().map(|item| item.target.display()).collect();
                        let has_high_risk = selected.any(|item| item.risk == Risk::High);
                        review = Some(Review::Cleanup {
                            plan_id: plan.preview.id,
                            items,
                            targets,
                            has_high_risk,
                        });
                    }
                    if secondary_button(
                        ui,
                        !busy,
                        language.text("Dismiss this plan", "关闭此清单"),
                    )
                    .clicked()
                    {
                        discard = true;
                    }
                });
            });
        });
    (review, discard, toast_msg)
}

fn candidate_row(
    ui: &mut Ui,
    language: Language,
    candidate: &Candidate,
    selected: bool,
    cols: [f32; 5],
) -> bool {
    let id = candidate.id;
    let allowed = candidate.access == Access::Allowed;
    let width = ui.available_width();
    let row_rect = Rect::from_min_size(ui.next_widget_position(), vec2(width, CANDIDATE_ROW));
    let row_id = ui.make_persistent_id(("cand_row", id));
    let row_sense = ui.interact(
        row_rect,
        row_id,
        if allowed { Sense::click() } else { Sense::hover() },
    );
    let toggled = allowed && row_sense.clicked();
    if allowed && row_sense.hovered() {
        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
    }

    let hover_t = smooth_bool(
        ui.ctx(),
        row_id.with("hover"),
        allowed && row_sense.hovered(),
        0.12,
    );
    let select_t = smooth_bool(ui.ctx(), row_id.with("sel"), selected && allowed, 0.16);
    let press_t = smooth_bool(
        ui.ctx(),
        row_id.with("prs"),
        allowed && row_sense.is_pointer_button_down_on(),
        0.07,
    );
    interactive_row_background(ui, row_rect, hover_t, select_t, press_t);

    let [check_w, target_w, cat_w, conf_w, risk_w] = cols;

    ui.allocate_ui_with_layout(
        vec2(width, CANDIDATE_ROW),
        Layout::left_to_right(Align::Center),
        |ui| {
            ui.spacing_mut().item_spacing.x = 12.0;
            ui.add_space(4.0);
            table_cell(ui, check_w, CANDIDATE_ROW, |ui| {
                let (box_rect, box_resp) =
                    ui.allocate_exact_size(vec2(18.0, 18.0), Sense::hover());
                paint_checkbox_box(
                    ui,
                    box_rect,
                    row_id.with("box"),
                    selected && allowed,
                    false,
                    allowed,
                    row_sense.hovered(),
                );
                if let Access::ReadOnly(reason) = &candidate.access {
                    box_resp.on_hover_text(reason);
                }
            });
            let (target_rect, _) =
                ui.allocate_exact_size(vec2(target_w, CANDIDATE_ROW), Sense::hover());
            let target = candidate.target.display();
            let reason = match &candidate.access {
                Access::Allowed => candidate.reason.clone(),
                Access::ReadOnly(reason) => format!("{} · {reason}", candidate.reason),
            };
            paint_two_line_cell(
                ui,
                target_rect,
                &target,
                Some(&reason),
                FontId::new(13.0, fonts::semibold_family()),
                FontId::proportional(11.5),
                if allowed { INK } else { MUTED },
                SUBTLE,
                &target,
            );
            let (cat_rect, _) =
                ui.allocate_exact_size(vec2(cat_w, CANDIDATE_ROW), Sense::hover());
            let category = category_label(language, candidate.category);
            paint_left_truncated(ui, cat_rect, category, FontId::proportional(12.5), MUTED);
            table_cell(ui, conf_w, CANDIDATE_ROW, |ui| {
                let (label, fg, bg) = confidence_label(language, candidate.confidence);
                badge(ui, label, fg, bg)
                    .on_hover_text(evidence_label(language, candidate.evidence));
            });
            table_cell_right(ui, risk_w, CANDIDATE_ROW, |ui| {
                if !allowed {
                    badge(ui, language.text("Read-only", "只读"), MUTED, DISABLED_BG);
                } else if candidate.risk == Risk::High {
                    badge(ui, language.text("High risk", "高风险"), DANGER, PALE_RED);
                }
            });
        },
    );
    toggled
}

fn expiry_details(
    ui: &mut Ui,
    language: Language,
    entries: &[BackupSummary],
    warnings: &[String],
    selected: &mut std::collections::HashSet<Uuid>,
) {
    diagnostics(ui, language, warnings, "expiry_warnings");
    if entries.is_empty() {
        ui.label(body_text(
            language.text(
                "No expired files are eligible for permanent removal.",
                "没有符合永久清理条件的到期文件。",
            ),
            13.0,
            MUTED,
        ));
        return;
    }
    notice(
        ui,
        language.text(
            "Select the expired quarantine copies to remove permanently. Restoring those copies will be unavailable.",
            "请选择要永久清理的到期备份。执行后将失去这些备份的还原能力。",
        ),
        DANGER,
        PALE_RED,
    );
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        let caption = if language == Language::Chinese {
            format!("共 {} 个到期备份", entries.len())
        } else {
            format!("{} expired copies", entries.len())
        };
        ui.label(body_text(caption, 12.0, MUTED));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            if action_button(
                ui,
                ButtonSpec::new(language.text("Clear", "清空"), ButtonVariant::Ghost)
                    .compact()
                    .enabled(!selected.is_empty()),
            )
            .clicked()
            {
                selected.clear();
            }
            if action_button(
                ui,
                ButtonSpec::new(language.text("Select all", "全选"), ButtonVariant::Ghost)
                    .compact()
                    .enabled(selected.len() < entries.len()),
            )
            .clicked()
            {
                for item in entries {
                    selected.insert(item.id);
                }
            }
        });
    });
    ui.add_space(4.0);
    Frame::new()
        .fill(SURFACE_ALT)
        .stroke(Stroke::new(HAIRLINE, LINE))
        .corner_radius(9)
        .inner_margin(Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ScrollArea::vertical()
                .id_salt("expiry_targets")
                .max_height(240.0)
                .auto_shrink([false, true])
                .show_rows(ui, 48.0, entries.len(), |ui, rows| {
                    for index in rows {
                        let item = &entries[index];
                        ui.push_id(item.id, |ui| {
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 10.0;
                                let mut checked = selected.contains(&item.id);
                                if styled_checkbox(
                                    ui,
                                    Id::new(("exp_chk", item.id)),
                                    &mut checked,
                                    false,
                                    true,
                                )
                                .on_hover_text(&item.target)
                                .changed()
                                {
                                    if checked {
                                        selected.insert(item.id);
                                    } else {
                                        selected.remove(&item.id);
                                    }
                                }
                                let (text_rect, _) = ui.allocate_exact_size(
                                    vec2(ui.available_width(), 44.0),
                                    Sense::hover(),
                                );
                                paint_two_line_cell(
                                    ui,
                                    text_rect,
                                    &item.target,
                                    Some(&item.backup),
                                    FontId::new(12.5, fonts::semibold_family()),
                                    FontId::proportional(11.5),
                                    INK,
                                    SUBTLE,
                                    &item.target,
                                );
                            });
                        });
                    }
                });
        });
}

fn confirmation_details(ui: &mut Ui, language: Language, review: &Review) {
    match review {
        Review::Expiry { .. } => {}
        Review::Uninstall {
            intents, warnings, ..
        } => {
            ui.label(body_text(
                language.text(
                    "The official uninstallers will run in order. A failed app will not stop the rest.",
                    "将依次运行官方卸载程序。单项失败后会继续处理其余应用。",
                ),
                13.0,
                MUTED,
            ));
            ui.add_space(8.0);
            ui.spacing_mut().item_spacing.y = 8.0;
            for intent in intents {
                Frame::new()
                    .fill(SURFACE_ALT)
                    .stroke(Stroke::new(HAIRLINE, LINE))
                    .corner_radius(9)
                    .inner_margin(Margin::symmetric(14, 12))
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.label(semibold_text(&intent.application, 13.5, INK));
                            if intent.quiet {
                                badge(
                                    ui,
                                    language.text("Quiet uninstall", "静默卸载"),
                                    ACCENT,
                                    ACCENT_PALE,
                                );
                            }
                        });
                        ui.label(body_text(&intent.method, 12.5, MUTED));
                        if !intent.notice.is_empty() {
                            ui.label(body_text(&intent.notice, 12.0, DARK_AMBER));
                        }
                    });
            }
            for warning in warnings {
                ui.label(body_text(warning, 12.5, DARK_AMBER));
            }
        }
        Review::Cleanup {
            items,
            targets,
            has_high_risk,
            ..
        } => {
            let text = if language == Language::Chinese {
                format!(
                    "将处理 {} 个所选项目。文件进入隔离区，注册表项在删除前备份。",
                    items.len()
                )
            } else {
                format!(
                    "{} selected items will be processed. Files go to quarantine and registry entries are backed up before deletion.",
                    items.len()
                )
            };
            ui.label(body_text(text, 13.0, MUTED));
            if *has_high_risk {
                ui.add_space(6.0);
                notice(
                    ui,
                    language.text(
                        "Your selection includes high-risk items. Review their effect before continuing.",
                        "所选项目含高风险项。请在继续前核对影响。",
                    ),
                    DANGER,
                    PALE_RED,
                );
            }
            ui.add_space(8.0);
            Frame::new()
                .fill(SURFACE_ALT)
                .stroke(Stroke::new(HAIRLINE, LINE))
                .corner_radius(9)
                .inner_margin(Margin::symmetric(14, 10))
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ScrollArea::vertical()
                        .id_salt("cleanup_targets")
                        .max_height(260.0)
                        .auto_shrink([false, true])
                        .show_rows(ui, 26.0, targets.len(), |ui, rows| {
                            for index in rows {
                                let target = &targets[index];
                                let (rect, _) = ui.allocate_exact_size(
                                    vec2(ui.available_width(), 26.0),
                                    Sense::hover(),
                                );
                                paint_left_truncated(
                                    ui,
                                    rect,
                                    target,
                                    FontId::proportional(12.5),
                                    INK,
                                );
                            }
                        });
                });
        }
        Review::Restore {
            entries, warnings, ..
        } => {
            ui.label(body_text(
                language.text(
                    "Items return to their original locations. Existing objects are preserved.",
                    "项目将回到原位置。已有的同名对象会保留。",
                ),
                13.0,
                MUTED,
            ));
            diagnostics(ui, language, warnings, "restore_warnings");
            ui.add_space(8.0);
            Frame::new()
                .fill(SURFACE_ALT)
                .stroke(Stroke::new(HAIRLINE, LINE))
                .corner_radius(9)
                .inner_margin(Margin::symmetric(14, 10))
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ScrollArea::vertical()
                        .id_salt("restore_targets")
                        .max_height(275.0)
                        .auto_shrink([false, true])
                        .show_rows(ui, 48.0, entries.len(), |ui, rows| {
                            for index in rows {
                                let item = &entries[index];
                                let (rect, _) = ui.allocate_exact_size(
                                    vec2(ui.available_width(), 46.0),
                                    Sense::hover(),
                                );
                                paint_two_line_cell(
                                    ui,
                                    rect,
                                    &item.target,
                                    Some(&item.backup),
                                    FontId::new(12.5, fonts::semibold_family()),
                                    FontId::proportional(11.5),
                                    INK,
                                    SUBTLE,
                                    &item.target,
                                );
                            }
                        });
                });
        }
    }
}

fn application_row(
    ui: &mut Ui,
    language: Language,
    app: &AppRecord,
    columns: [f32; 6],
    selected: bool,
    can_submit: bool,
) -> (bool, Option<RowAction>) {
    let width = ui.available_width();
    let row_rect = Rect::from_min_size(ui.next_widget_position(), vec2(width, APP_ROW));
    let row_id = ui.make_persistent_id("app_row_interact");
    let row_resp = ui.interact(row_rect, row_id, Sense::click());
    let toggled = row_resp.clicked();
    if row_resp.hovered() {
        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
    }

    let mut action = None;
    let eligible = can_submit && !app.system_component;
    let can_uninstall = eligible && app.official_uninstall_available;
    row_resp.context_menu(|ui| {
        ui.set_min_width(184.0);
        ui.spacing_mut().item_spacing.y = 2.0;
        if menu_item(
            ui,
            eligible,
            language.text("Scan leftovers", "扫描残留"),
            Some(Icon::Search),
            false,
        )
        .clicked()
        {
            action = Some(RowAction::Scan(app.id.clone()));
            ui.close_menu();
        }
        if menu_item(
            ui,
            can_uninstall,
            language.text("Review uninstall", "预览卸载"),
            Some(Icon::Trash),
            false,
        )
        .clicked()
        {
            action = Some(RowAction::Uninstall(app.id.clone()));
            ui.close_menu();
        }
        if menu_item(
            ui,
            eligible,
            language.text("Review force removal", "预览强制移除"),
            Some(Icon::AlertTriangle),
            true,
        )
        .clicked()
        {
            action = Some(RowAction::Force(app.id.clone()));
            ui.close_menu();
        }
        if let Some(loc) = &app.install_location {
            ui.add_space(4.0);
            divider(ui);
            ui.add_space(4.0);
            if menu_item(
                ui,
                true,
                language.text("Copy install path", "复制安装路径"),
                Some(Icon::Copy),
                false,
            )
            .clicked()
            {
                action = Some(RowAction::CopyPath(loc.display().to_string()));
                ui.close_menu();
            }
        }
    });

    let hover_t = smooth_bool(ui.ctx(), row_id.with("hover"), row_resp.hovered(), 0.12);
    let select_t = smooth_bool(ui.ctx(), row_id.with("sel"), selected, 0.16);
    let press_t = smooth_bool(
        ui.ctx(),
        row_id.with("prs"),
        row_resp.is_pointer_button_down_on(),
        0.07,
    );
    interactive_row_background(ui, row_rect, hover_t, select_t, press_t);

    ui.allocate_ui_with_layout(
        vec2(width, APP_ROW),
        Layout::left_to_right(Align::Center),
        |ui| {
            ui.spacing_mut().item_spacing.x = 12.0;
            ui.add_space(4.0); // + 12px spacing = 16px clean left inset
            table_cell(ui, columns[0], APP_ROW, |ui| {
                let (box_rect, _) = ui.allocate_exact_size(vec2(18.0, 18.0), Sense::hover());
                paint_checkbox_box(
                    ui,
                    box_rect,
                    row_id.with("box"),
                    selected,
                    false,
                    true,
                    row_resp.hovered(),
                );
            });
            table_cell(ui, columns[1], APP_ROW, |ui| {
                ui.spacing_mut().item_spacing.x = 10.0;
                let letter = app
                    .name
                    .chars()
                    .find(|character| character.is_alphanumeric())
                    .map_or('?', |letter| letter.to_ascii_uppercase());
                app_glyph(ui, &app.name, letter);
                let text_w = (columns[1] - 42.0).max(40.0);
                let (text_rect, _) = ui.allocate_exact_size(vec2(text_w, APP_ROW), Sense::hover());
                let location = app
                    .install_location
                    .as_ref()
                    .map_or_else(|| app.name.clone(), |path| path.display().to_string());
                paint_two_line_cell(
                    ui,
                    text_rect,
                    &app.name,
                    app.version.as_deref(),
                    FontId::new(13.5, fonts::semibold_family()),
                    FontId::proportional(11.5),
                    INK,
                    SUBTLE,
                    &location,
                );
            });
            if columns[2] > 0.5 {
                let (pub_rect, _) =
                    ui.allocate_exact_size(vec2(columns[2], APP_ROW), Sense::hover());
                let publisher = app.publisher.as_deref().unwrap_or("—");
                paint_left_truncated(
                    ui,
                    pub_rect,
                    publisher,
                    FontId::proportional(12.5),
                    if app.publisher.is_some() {
                        MUTED
                    } else {
                        DISABLED_TEXT
                    },
                );
            }
            let (size_rect, _) = ui.allocate_exact_size(vec2(columns[3], APP_ROW), Sense::hover());
            let size_text = app.size_bytes.map_or_else(|| "—".into(), size_label);
            paint_right_truncated(
                ui,
                size_rect,
                &size_text,
                FontId::proportional(12.5),
                if app.size_bytes.is_some() {
                    MUTED
                } else {
                    DISABLED_TEXT
                },
            );
            if columns[4] > 0.5 {
                let (date_rect, _) =
                    ui.allocate_exact_size(vec2(columns[4], APP_ROW), Sense::hover());
                let date_text = app
                    .install_date
                    .as_deref()
                    .map_or_else(|| "—".into(), date_label);
                paint_left_truncated(
                    ui,
                    date_rect,
                    &date_text,
                    FontId::proportional(12.5),
                    if app.install_date.is_some() {
                        MUTED
                    } else {
                        DISABLED_TEXT
                    },
                );
            }
            table_cell_right(ui, columns[5], APP_ROW, |ui| {
                let (label, raw_hint, fg, bg) = source_badge_meta(language, app);
                badge(ui, label, fg, bg).on_hover_text(raw_hint);
            });
        },
    );
    (toggled, action)
}

fn source_badge_meta(language: Language, app: &AppRecord) -> (&str, &str, Color32, Color32) {
    if app.system_component {
        let label = language.text("System", "系统组件");
        return (label, label, DARK_AMBER, PALE_AMBER);
    }
    match &app.id {
        AppId::WindowsRegistry(_) => ("Win32", "Windows Registry", ACCENT, ACCENT_PALE),
        AppId::WindowsPackage(_) => ("MSIX", "Windows MSIX", DARK_GREEN, PALE_GREEN),
        AppId::Package { manager, .. } => match manager.as_str() {
            "macos-bundle" => ("App", "macos-bundle", ACCENT, ACCENT_PALE),
            "homebrew-cask" => ("Homebrew", "homebrew-cask", DARK_GREEN, PALE_GREEN),
            "homebrew-formula" => ("Brew", "homebrew-formula", DARK_GREEN, PALE_GREEN),
            "apple-pkg-receipt" => (
                language.text("Installer", "安装包"),
                "apple-pkg-receipt",
                MUTED,
                DISABLED_BG,
            ),
            "flatpak" | "flatpak-user" | "flatpak-system" => {
                ("Flatpak", manager.as_str(), ACCENT, ACCENT_PALE)
            }
            "snap" => ("Snap", "snap", DARK_AMBER, PALE_AMBER),
            "dpkg" => ("DEB", "dpkg", ACCENT, ACCENT_PALE),
            "rpm" => ("RPM", "rpm", ACCENT, ACCENT_PALE),
            "pacman" => ("Pacman", "pacman", ACCENT, ACCENT_PALE),
            "appimage" => ("AppImage", "appimage", DARK_GREEN, PALE_GREEN),
            "desktop" => ("Desktop", "desktop", MUTED, DISABLED_BG),
            other => (other, other, MUTED, DISABLED_BG),
        },
    }
}

fn column_widths(total_width: f32) -> [f32; 6] {
    let checkbox_w = 22.0;
    let source_w = 104.0;
    if total_width < 660.0 {
        // Compact layout for narrow windows: Checkbox + Application + Size + Source
        // 16px left + 16px right + 3 gaps * 12px + 8px scrollbar = 76px
        let size_w = 72.0;
        let name_w = (total_width - 76.0 - checkbox_w - size_w - source_w).max(140.0);
        return [checkbox_w, name_w, 0.0, size_w, 0.0, source_w];
    }
    // 16px left inset + 16px right inset + 5 gaps * 12px (60px) + 8px scrollbar buffer = 100px
    let flexible = (total_width - 100.0 - checkbox_w - source_w).max(220.0);
    [
        checkbox_w,
        flexible * 0.48,
        flexible * 0.24,
        flexible * 0.13,
        flexible * 0.15,
        source_w,
    ]
}

fn nav_button(
    ui: &mut Ui,
    title: &str,
    page: Page,
    selected: bool,
    count: Option<usize>,
) -> (bool, Rect) {
    let desired = vec2(ui.available_width(), 36.0);
    let (rect, response) = ui.allocate_exact_size(desired, Sense::click());
    let id = ui.make_persistent_id(("nav_item", title));
    let hover_t = smooth_bool(
        ui.ctx(),
        id.with("hover"),
        !selected && response.hovered(),
        0.13,
    );
    let press_t = smooth_bool(
        ui.ctx(),
        id.with("press"),
        !selected && response.is_pointer_button_down_on(),
        0.07,
    );
    let active_t = smooth_bool(ui.ctx(), id.with("active"), selected, 0.16);

    let hover_bg = lerp_color(
        Color32::TRANSPARENT,
        Color32::from_rgb(232, 235, 241),
        hover_t,
    );
    let press_bg = lerp_color(hover_bg, Color32::from_rgb(224, 228, 236), press_t);
    let bg = lerp_color(press_bg, SURFACE, active_t);
    if active_t > 0.25 {
        ui.painter().rect_filled(
            rect.translate(vec2(0.0, 1.0)),
            8.0,
            Color32::from_rgba_unmultiplied(16, 24, 40, (12.0 * active_t) as u8),
        );
    }
    if bg.a() > 0 {
        ui.painter().rect_filled(rect, 8.0, bg);
    }
    if active_t > 0.05 {
        ui.painter().rect_stroke(
            rect,
            8.0,
            Stroke::new(HAIRLINE, lerp_color(Color32::TRANSPARENT, LINE, active_t)),
            StrokeKind::Inside,
        );
    }

    let color = lerp_color(lerp_color(MUTED, INK, hover_t), ACCENT, active_t);

    let origin = pos2(rect.left() + 20.0, rect.center().y);
    let stroke = Stroke::new(1.4_f32, color);
    match page {
        Page::Applications => {
            for (x, y) in [(-3.8, -3.8), (3.8, -3.8), (-3.8, 3.8), (3.8, 3.8)] {
                ui.painter().rect_stroke(
                    Rect::from_center_size(origin + vec2(x, y), Vec2::splat(4.8)),
                    1.4,
                    stroke,
                    StrokeKind::Inside,
                );
            }
        }
        Page::Quarantine => {
            ui.painter().rect_stroke(
                Rect::from_center_size(origin + vec2(0.0, 1.0), vec2(12.5, 10.5)),
                2.0,
                stroke,
                StrokeKind::Inside,
            );
            ui.painter()
                .hline(origin.x - 7.0..=origin.x + 7.0, origin.y - 2.8, stroke);
            ui.painter()
                .hline(origin.x - 2.0..=origin.x + 2.0, origin.y, stroke);
        }
        Page::Settings => {
            for (y, offset) in [(-3.8, -2.2), (0.0, 2.2), (3.8, -1.0)] {
                ui.painter()
                    .hline(origin.x - 5.8..=origin.x + 5.8, origin.y + y, stroke);
                ui.painter()
                    .circle_filled(origin + vec2(offset, y), 1.8, color);
            }
        }
        Page::Review => {
            ui.painter().rect_stroke(
                Rect::from_center_size(origin, vec2(10.5, 13.0)),
                2.0,
                stroke,
                StrokeKind::Inside,
            );
            ui.painter()
                .hline(origin.x - 2.3..=origin.x + 2.3, origin.y - 2.0, stroke);
            ui.painter()
                .hline(origin.x - 2.3..=origin.x + 2.3, origin.y + 2.0, stroke);
        }
    }

    let font = if selected {
        FontId::new(13.0, fonts::semibold_family())
    } else {
        FontId::proportional(13.0)
    };
    let right_reserve = if count.is_some() { 42.0 } else { 10.0 };
    let label_rect = Rect::from_min_max(
        pos2(rect.left() + 36.0, rect.top()),
        pos2(
            (rect.right() - right_reserve).max(rect.left() + 48.0),
            rect.bottom(),
        ),
    );
    paint_left_truncated(ui, label_rect, title, font, color);

    if let Some(n) = count {
        paint_count_pill(ui, pos2(rect.right() - 8.0, rect.center().y), n, selected);
    }

    if response.hovered() {
        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
    }
    (response.clicked(), rect)
}

fn diagnostics(ui: &mut Ui, language: Language, warnings: &[String], id: &'static str) {
    if warnings.is_empty() {
        return;
    }
    let caption = if language == Language::Chinese {
        format!("{} 条诊断信息", warnings.len())
    } else {
        format!("{} diagnostics", warnings.len())
    };
    ui.add_space(4.0);
    Frame::new()
        .fill(PALE_AMBER)
        .stroke(Stroke::new(HAIRLINE, lerp_color(PALE_AMBER, DARK_AMBER, 0.24)))
        .corner_radius(8)
        .inner_margin(Margin::symmetric(10, 4))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            collapsible_section(ui, Id::new(id), &caption, None, false, |ui| {
                ui.spacing_mut().item_spacing.y = 4.0;
                for warning in warnings {
                    ui.label(body_text(warning, 12.0, DARK_AMBER));
                }
                ui.add_space(4.0);
            });
        });
}

fn size_label(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * KIB;
    const GIB: u64 = MIB * KIB;
    match bytes {
        size if size >= GIB => format!("{:.1} GB", size as f64 / GIB as f64),
        size if size >= MIB => format!("{:.1} MB", size as f64 / MIB as f64),
        size if size >= KIB => format!("{} KB", size / KIB),
        size => format!("{size} B"),
    }
}

fn date_label(raw: &str) -> String {
    if raw.len() == 8 && raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return format!("{}-{}-{}", &raw[0..4], &raw[4..6], &raw[6..8]);
    }
    raw.to_owned()
}

fn operation_text(language: Language, operation: Operation) -> &'static str {
    match operation {
        Operation::Inventory => {
            language.text("Reading installed applications…", "正在枚举已安装应用…")
        }
        Operation::Scan => language.text("Scanning leftovers…", "正在扫描残留…"),
        Operation::PrepareUninstall => {
            language.text("Checking official uninstallers…", "正在核查官方卸载程序…")
        }
        Operation::Uninstall => language.text("Running uninstall queue…", "正在处理卸载队列…"),
        Operation::Backups => language.text("Reading quarantine…", "正在读取隔离区…"),
        Operation::PrepareRestore => language.text("Checking backup records…", "正在检查备份记录…"),
        Operation::Restore => language.text("Restoring selected batch…", "正在还原所选批次…"),
        Operation::Cleanup => language.text("Quarantining and backing up…", "正在隔离和备份…"),
        Operation::ExpiryPreview => language.text("Checking expired files…", "正在检查到期文件…"),
        Operation::PurgeExpired => {
            language.text("Removing selected expired files…", "正在清理所选到期文件…")
        }
        Operation::Preferences => language.text("Saving settings…", "正在保存设置…"),
        Operation::AuditExport => language.text("Exporting audit log…", "正在导出操作日志…"),
    }
}

fn category_label(language: Language, category: Category) -> &'static str {
    match category {
        Category::File => language.text("File", "文件"),
        Category::Directory => language.text("Directory", "目录"),
        Category::Shortcut => language.text("Shortcut", "快捷方式"),
        Category::Registry => language.text("Registry", "注册表"),
        Category::Startup => language.text("Startup", "启动项"),
        Category::Service => language.text("Service", "服务"),
        Category::ScheduledTask => language.text("Scheduled task", "计划任务"),
        Category::Firewall => language.text("Firewall", "防火墙"),
        Category::FileAssociation => language.text("File association", "文件关联"),
        Category::ShellExtension => language.text("Shell extension", "Shell 扩展"),
        Category::Com => language.text("COM", "COM"),
    }
}

fn confidence_label(
    language: Language,
    confidence: Confidence,
) -> (&'static str, Color32, Color32) {
    match confidence {
        Confidence::High => (
            language.text("High confidence", "高置信度"),
            DARK_GREEN,
            PALE_GREEN,
        ),
        Confidence::Medium => (
            language.text("Medium confidence", "中置信度"),
            DARK_AMBER,
            PALE_AMBER,
        ),
        Confidence::Low => (
            language.text("Low confidence", "低置信度"),
            MUTED,
            DISABLED_BG,
        ),
    }
}

fn evidence_label(language: Language, evidence: MatchKind) -> &'static str {
    match evidence {
        MatchKind::ExactIdentity => language.text("Exact identity match", "精确标识匹配"),
        MatchKind::PublisherAndApp => {
            language.text("Publisher and application match", "发行商与应用名同时匹配")
        }
        MatchKind::AppName => language.text("Application name match", "应用名匹配"),
        MatchKind::FuzzyName => language.text("Fuzzy name match", "应用名模糊匹配"),
        MatchKind::RuleHint => language.text("Rule hint", "规则线索"),
    }
}

fn official_outcome(
    language: Language,
    outcome: Result<&OfficialOutcome, &String>,
) -> (Color32, Color32, String) {
    match outcome {
        Ok(OfficialOutcome::Completed) => (
            DARK_GREEN,
            PALE_GREEN,
            language.text("Completed", "已完成").into(),
        ),
        Ok(OfficialOutcome::NeedsRestart) => (
            DARK_AMBER,
            PALE_AMBER,
            language.text("Restart needed", "需要重启").into(),
        ),
        Ok(OfficialOutcome::Cancelled) => (
            MUTED,
            DISABLED_BG,
            language.text("Cancelled", "已取消").into(),
        ),
        Ok(OfficialOutcome::Failed(code)) => (
            DANGER,
            PALE_RED,
            format!("{} · {code}", language.text("Failed", "失败")),
        ),
        Ok(OfficialOutcome::Unverified(code)) => (
            DARK_AMBER,
            PALE_AMBER,
            format!(
                "{} · {code}",
                language.text("Completion unverified", "无法确认完成")
            ),
        ),
        Err(_) => (
            DANGER,
            PALE_RED,
            language.text("Needs attention", "需要处理").into(),
        ),
    }
}

fn recovery_label(language: Language, state: RecoveryState) -> (Color32, Color32, &'static str) {
    match state {
        RecoveryState::Applied => (
            DARK_GREEN,
            PALE_GREEN,
            language.text("Recoverable", "可还原"),
        ),
        RecoveryState::Restored => (MUTED, DISABLED_BG, language.text("Restored", "已还原")),
        RecoveryState::Purged => (MUTED, DISABLED_BG, language.text("Purged", "已清理")),
        RecoveryState::Staged => (DARK_AMBER, PALE_AMBER, language.text("Pending", "待确认")),
        RecoveryState::NeedsReview => (DANGER, PALE_RED, language.text("Needs review", "需要复核")),
    }
}

fn expires(language: Language, unix_ms: u64) -> (Color32, Color32, String) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_millis());
    let target = u128::from(unix_ms);
    if target <= now {
        return (
            DARK_AMBER,
            PALE_AMBER,
            language.text("Retention reached", "已到保留期").into(),
        );
    }
    let days = (target - now).div_ceil(86_400_000);
    let text = if language == Language::Chinese {
        format!("距最近保留期 {days} 天")
    } else {
        format!("Next retention date in {days} days")
    };
    (MUTED, DISABLED_BG, text)
}
