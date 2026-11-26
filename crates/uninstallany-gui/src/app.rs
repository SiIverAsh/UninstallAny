//! Desktop presentation and workflow state.

mod anim;
mod theme;
mod views;

use std::{
    collections::{HashSet, VecDeque},
    num::NonZeroU16,
    path::PathBuf,
};

use eframe::egui;
use uninstallany_core::{
    Access, AppId, AppRecord, AuditExport, BackupInventory, BackupSummary, Category, ChangeReport,
    ChangeResult, Inventory, OfficialIntent, Risk,
};
use uuid::Uuid;

use crate::worker::{CleanupPreview, Event, Failure, OfficialRow, Request, Response, Worker};

#[derive(Clone, Copy, Eq, PartialEq)]
enum Language {
    English,
    Chinese,
}

impl Language {
    fn text<'a>(self, english: &'a str, chinese: &'a str) -> &'a str {
        match self {
            Self::English => english,
            Self::Chinese => chinese,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Page {
    Applications,
    Quarantine,
    Settings,
    Review,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SortField {
    Name,
    Publisher,
    Size,
    Date,
}

struct AppList {
    inventory: Option<Inventory>,
    selected: HashSet<AppId>,
    last_selected: Option<AppId>,
    visible: Vec<usize>,
    search: String,
    include_system: bool,
    sort: SortField,
    descending: bool,
    dirty: bool,
}

impl Default for AppList {
    fn default() -> Self {
        Self {
            inventory: None,
            selected: HashSet::new(),
            last_selected: None,
            visible: Vec::new(),
            search: String::new(),
            include_system: false,
            sort: SortField::Name,
            descending: false,
            dirty: true,
        }
    }
}

impl AppList {
    fn update_inventory(&mut self, inventory: Inventory) {
        let current: HashSet<_> = inventory.applications.iter().map(|app| &app.id).collect();
        self.selected.retain(|id| current.contains(id));
        if self
            .last_selected
            .as_ref()
            .is_some_and(|id| !current.contains(id))
        {
            self.last_selected = None;
        }
        self.inventory = Some(inventory);
        self.dirty = true;
    }

    fn update_visible(&mut self) {
        if !self.dirty {
            return;
        }
        self.dirty = false;
        let Some(inventory) = &self.inventory else {
            return;
        };
        let query = self.search.trim().to_lowercase();
        self.visible = inventory
            .applications
            .iter()
            .enumerate()
            .filter(|(_, app)| {
                (self.include_system || !app.system_component) && matches_search(app, &query)
            })
            .map(|(index, _)| index)
            .collect();
        let field = self.sort;
        let descending = self.descending;
        self.visible.sort_by_cached_key(|index| {
            let app = &inventory.applications[*index];
            (
                sort_value(app, field, descending),
                app.name.to_lowercase(),
                *index,
            )
        });
    }

    fn sort_on(&mut self, field: SortField) {
        self.descending = self.sort == field && !self.descending;
        self.sort = field;
        self.dirty = true;
    }

    fn toggle_row(&mut self, id: &AppId, extend_range: bool) {
        if extend_range {
            if let (Some(inventory), Some(anchor)) = (&self.inventory, &self.last_selected) {
                let anchor_pos = self
                    .visible
                    .iter()
                    .position(|idx| &inventory.applications[*idx].id == anchor);
                let target_pos = self
                    .visible
                    .iter()
                    .position(|idx| &inventory.applications[*idx].id == id);
                if let (Some(a), Some(b)) = (anchor_pos, target_pos) {
                    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
                    for idx in &self.visible[lo..=hi] {
                        self.selected.insert(inventory.applications[*idx].id.clone());
                    }
                    self.last_selected = Some(id.clone());
                    return;
                }
            }
        }
        if !self.selected.remove(id) {
            self.selected.insert(id.clone());
        }
        self.last_selected = Some(id.clone());
    }

    fn select_all_visible(&mut self) {
        if let Some(inventory) = &self.inventory {
            for idx in &self.visible {
                self.selected.insert(inventory.applications[*idx].id.clone());
            }
        }
    }

    fn clear_selection(&mut self) {
        self.selected.clear();
        self.last_selected = None;
    }

    fn total_in_scope(&self) -> usize {
        self.inventory.as_ref().map_or(0, |inv| {
            inv.applications
                .iter()
                .filter(|app| self.include_system || !app.system_component)
                .count()
        })
    }

    fn selected_visible(&self) -> Vec<&AppRecord> {
        let Some(inventory) = &self.inventory else {
            return Vec::new();
        };
        self.visible
            .iter()
            .map(|index| &inventory.applications[*index])
            .filter(|app| self.selected.contains(&app.id))
            .collect()
    }

    fn selected_total_bytes(&self) -> Option<u64> {
        let mut sum = 0u64;
        let mut any = false;
        for app in self.selected_visible() {
            if let Some(bytes) = app.size_bytes {
                sum = sum.saturating_add(bytes);
                any = true;
            }
        }
        any.then_some(sum)
    }
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
enum SortValue {
    Number(u64),
    NumberDescending(std::cmp::Reverse<u64>),
    Text(String),
    TextDescending(std::cmp::Reverse<String>),
    Missing,
}

fn sort_value(app: &AppRecord, field: SortField, descending: bool) -> SortValue {
    let ordered_text = |source: Option<&str>| {
        let Some(text) = source.filter(|value| !value.is_empty()) else {
            return SortValue::Missing;
        };
        if descending {
            SortValue::TextDescending(std::cmp::Reverse(text.to_lowercase()))
        } else {
            SortValue::Text(text.to_lowercase())
        }
    };
    match field {
        SortField::Name => ordered_text(Some(&app.name)),
        SortField::Publisher => ordered_text(app.publisher.as_deref()),
        SortField::Size => match app.size_bytes {
            Some(size) if descending => SortValue::NumberDescending(std::cmp::Reverse(size)),
            Some(size) => SortValue::Number(size),
            None => SortValue::Missing,
        },
        SortField::Date => ordered_text(app.install_date.as_deref()),
    }
}

fn matches_search(app: &AppRecord, query: &str) -> bool {
    query.is_empty()
        || app.name.to_lowercase().contains(query)
        || app
            .publisher
            .as_ref()
            .is_some_and(|value| value.to_lowercase().contains(query))
        || app
            .version
            .as_ref()
            .is_some_and(|value| value.to_lowercase().contains(query))
        || app
            .install_location
            .as_ref()
            .is_some_and(|path| path.to_string_lossy().to_lowercase().contains(query))
}

struct CleanupView {
    preview: CleanupPreview,
    selected: HashSet<usize>,
    last_selected: Option<usize>,
    category: Option<Category>,
    subject: Option<String>,
}

impl CleanupView {
    fn new(preview: CleanupPreview) -> Self {
        let selected = preview
            .candidates
            .iter()
            .filter(|item| item.default_selected())
            .map(|item| item.id)
            .collect();
        Self {
            preview,
            selected,
            last_selected: None,
            category: None,
            subject: None,
        }
    }

    fn approved_ids(&self) -> Vec<usize> {
        self.preview
            .candidates
            .iter()
            .filter(|item| item.access == Access::Allowed && self.selected.contains(&item.id))
            .map(|item| item.id)
            .collect()
    }

    fn high_risk_selected_count(&self) -> usize {
        self.preview
            .candidates
            .iter()
            .filter(|item| {
                item.access == Access::Allowed
                    && item.risk == Risk::High
                    && self.selected.contains(&item.id)
            })
            .count()
    }

    fn toggle_candidate(&mut self, visible_allowed_ids: &[usize], id: usize, extend_range: bool) {
        if extend_range {
            if let Some(anchor) = self.last_selected {
                let a = visible_allowed_ids.iter().position(|&v| v == anchor);
                let b = visible_allowed_ids.iter().position(|&v| v == id);
                if let (Some(i), Some(j)) = (a, b) {
                    let (lo, hi) = if i <= j { (i, j) } else { (j, i) };
                    for &cid in &visible_allowed_ids[lo..=hi] {
                        self.selected.insert(cid);
                    }
                    self.last_selected = Some(id);
                    return;
                }
            }
        }
        if !self.selected.remove(&id) {
            self.selected.insert(id);
        }
        self.last_selected = Some(id);
    }
}

enum Review {
    Uninstall {
        ticket: Uuid,
        intents: Vec<OfficialIntent>,
        warnings: Vec<String>,
    },
    Cleanup {
        plan_id: Uuid,
        items: Vec<usize>,
        targets: Vec<String>,
        has_high_risk: bool,
    },
    Restore {
        ticket: Uuid,
        entries: Vec<BackupSummary>,
        warnings: Vec<String>,
    },
    Expiry {
        ticket: Uuid,
        entries: Vec<BackupSummary>,
        warnings: Vec<String>,
        selected: HashSet<Uuid>,
    },
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Operation {
    Inventory,
    Scan,
    PrepareUninstall,
    Uninstall,
    Backups,
    PrepareRestore,
    Restore,
    Cleanup,
    ExpiryPreview,
    PurgeExpired,
    Preferences,
    AuditExport,
}

struct ActiveOperation {
    name: Operation,
    progress: Option<(usize, usize)>,
    cancellation_requested: bool,
}

enum Status {
    Error(String),
    Cancelled,
    RetentionSaved,
    RulesSaved(usize),
    AuditExported,
}

/// Stateful presentation. Worker-owned objects carry actual authorization.
pub(crate) struct DesktopApp {
    worker: Worker,
    backend_supported: bool,
    page: Page,
    language: Language,
    apps: AppList,
    applications_need_refresh: bool,
    portable_open: bool,
    portable_path: String,
    quarantine: Option<BackupInventory>,
    quarantine_needs_refresh: bool,
    confirmation: Option<Review>,
    plans: VecDeque<CleanupView>,
    uninstall_results: Vec<OfficialRow>,
    change_result: Option<ChangeReport>,
    active: Option<ActiveOperation>,
    status: Option<Status>,
    retention: u16,
    saved_retention: u16,
    rule_text: String,
    saved_rule_text: String,
    export_destination: String,
    export_result: Option<(PathBuf, AuditExport)>,
    preference_warnings: Vec<String>,
    focus_search_requested: bool,
    anim: anim::UiAnimations,
}

impl DesktopApp {
    /// Builds the native views and starts the first background inventory.
    pub(crate) fn new(context: &egui::Context, worker: Worker) -> Self {
        let mut app = Self::initialize(context, worker);
        app.submit(Request::Applications, Operation::Inventory);
        app
    }

    fn initialize(context: &egui::Context, worker: Worker) -> Self {
        theme::configure_style(context);
        let language = if sys_locale::get_locale().is_some_and(|locale| locale.starts_with("zh")) {
            Language::Chinese
        } else {
            Language::English
        };
        Self {
            worker,
            backend_supported: true,
            page: Page::Applications,
            language,
            apps: AppList::default(),
            applications_need_refresh: false,
            portable_open: false,
            portable_path: String::new(),
            quarantine: None,
            quarantine_needs_refresh: true,
            confirmation: None,
            plans: VecDeque::new(),
            uninstall_results: Vec::new(),
            change_result: None,
            active: None,
            status: None,
            retention: 14,
            saved_retention: 14,
            rule_text: String::new(),
            saved_rule_text: String::new(),
            export_destination: String::new(),
            export_result: None,
            preference_warnings: Vec::new(),
            focus_search_requested: false,
            anim: anim::UiAnimations::new(Page::Applications),
        }
    }

    fn can_submit(&self) -> bool {
        self.backend_supported && !self.worker.is_busy()
    }

    fn is_running(&self, op: Operation) -> bool {
        self.active.as_ref().is_some_and(|active| active.name == op)
    }

    fn toast(&mut self, kind: anim::ToastKind, message: impl Into<String>) {
        self.anim.push_toast(kind, message);
    }

    fn copy_to_clipboard(&mut self, ctx: &egui::Context, text: &str, label: &str) {
        ctx.copy_text(text.to_owned());
        let msg = if self.language == Language::Chinese {
            format!("已复制{label}")
        } else {
            format!("Copied {label}")
        };
        self.toast(anim::ToastKind::Success, msg);
    }

    fn submit(&mut self, request: Request, name: Operation) -> bool {
        match self.worker.submit(request) {
            Ok(()) => {
                self.active = Some(ActiveOperation {
                    name,
                    progress: None,
                    cancellation_requested: false,
                });
                self.status = None;
                true
            }
            Err(error) => {
                self.status = Some(Status::Error(error.clone()));
                self.toast(anim::ToastKind::Error, error);
                false
            }
        }
    }

    fn poll(&mut self) {
        while let Some(event) = self.worker.poll() {
            match event {
                Event::Progress { done, total } => {
                    if let Some(active) = &mut self.active {
                        active.progress = Some((done, total));
                    }
                }
                Event::Preferences(result) => match result {
                    Ok(preferences) => {
                        self.retention = preferences.retention_days.get();
                        self.saved_retention = self.retention;
                        self.saved_rule_text = preferences.custom_rules;
                        self.rule_text = self.saved_rule_text.clone();
                        self.preference_warnings = preferences.warnings;
                    }
                    Err(Failure::Message(error)) => self.preference_warnings.push(error),
                    Err(_) => {}
                },
                Event::Finished(result) => {
                    self.active = None;
                    match result {
                        Ok(response) => self.receive(response),
                        Err(Failure::Cancelled) => {
                            self.status = Some(Status::Cancelled);
                            let msg = self
                                .language
                                .text("Operation cancelled", "操作已取消")
                                .to_owned();
                            self.toast(anim::ToastKind::Warning, msg);
                        }
                        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
                        Err(Failure::UnsupportedPlatform) => self.backend_supported = false,
                        Err(Failure::Message(error)) => {
                            self.status = Some(Status::Error(error.clone()));
                            self.toast(anim::ToastKind::Error, error);
                        }
                    }
                }
            }
        }
    }

    fn receive(&mut self, response: Response) {
        let lang = self.language;
        match response {
            Response::Applications(inventory) => {
                self.apps.update_inventory(inventory);
                self.applications_need_refresh = false;
            }
            Response::Cleanup(preview) => {
                let count = preview.candidates.len();
                self.plans.clear();
                self.plans.push_back(CleanupView::new(preview));
                self.page = Page::Review;
                let msg = if lang == Language::Chinese {
                    format!("扫描完成，发现 {count} 个候选项")
                } else {
                    format!("Scan complete: {count} candidates found")
                };
                self.toast(anim::ToastKind::Info, msg);
            }
            Response::UninstallReview {
                ticket,
                intents,
                warnings,
            } => {
                self.confirmation = Some(Review::Uninstall {
                    ticket,
                    intents,
                    warnings,
                });
            }
            Response::Uninstalled(mut rows) => {
                self.plans.clear();
                let count = rows.len();
                for row in &mut rows {
                    if let Some(cleanup) = row.cleanup.take() {
                        let mut view = CleanupView::new(cleanup);
                        view.subject = Some(row.application.clone());
                        self.plans.push_back(view);
                    }
                }
                self.uninstall_results = rows;
                self.apps.clear_selection();
                self.applications_need_refresh = true;
                self.page = Page::Review;
                let msg = if lang == Language::Chinese {
                    format!("已完成 {count} 项卸载任务")
                } else {
                    format!("Finished {count} uninstall task(s)")
                };
                self.toast(anim::ToastKind::Info, msg);
            }
            Response::Backups(quarantine) => {
                self.quarantine = Some(quarantine);
                self.quarantine_needs_refresh = false;
            }
            Response::RestoreReview {
                ticket,
                entries,
                warnings,
            } => {
                self.confirmation = Some(Review::Restore {
                    ticket,
                    entries,
                    warnings,
                });
            }
            Response::ExpiryReview {
                ticket,
                entries,
                warnings,
            } => {
                self.confirmation = Some(Review::Expiry {
                    ticket,
                    entries,
                    warnings,
                    selected: HashSet::new(),
                });
            }
            Response::Changed(report) => {
                let needs_attention = report.items.iter().any(|item| {
                    matches!(
                        item.result,
                        ChangeResult::Skipped(_) | ChangeResult::NeedsReview(_)
                    )
                });
                let total = report.items.len();
                self.change_result = Some(report);
                self.applications_need_refresh = true;
                self.quarantine_needs_refresh = true;
                self.page = Page::Review;
                let (kind, msg) = if needs_attention {
                    (
                        anim::ToastKind::Warning,
                        if lang == Language::Chinese {
                            format!("已处理 {total} 个项目，部分需复核或跳过")
                        } else {
                            format!("Processed {total} item(s); some need review")
                        },
                    )
                } else {
                    (
                        anim::ToastKind::Success,
                        if lang == Language::Chinese {
                            format!("已安全处理 {total} 个项目")
                        } else {
                            format!("Safely processed {total} item(s)")
                        },
                    )
                };
                self.toast(kind, msg);
            }
            Response::RetentionSet(days) => {
                self.retention = days.get();
                self.saved_retention = days.get();
                self.status = Some(Status::RetentionSaved);
                let msg = if lang == Language::Chinese {
                    format!("隔离保留期已更新为 {} 天", days.get())
                } else {
                    format!("Retention updated to {} days", days.get())
                };
                self.toast(anim::ToastKind::Success, msg);
            }
            Response::RulesSet { text, count } => {
                self.saved_rule_text = text;
                self.status = Some(Status::RulesSaved(count));
                let msg = if count == 0 {
                    lang.text("Using built-in rules only", "已切换为仅使用内置规则")
                        .to_owned()
                } else if lang == Language::Chinese {
                    format!("已保存 {count} 条自定义规则")
                } else {
                    format!("Saved {count} custom rules")
                };
                self.toast(anim::ToastKind::Success, msg);
            }
            Response::AuditExported { path, report } => {
                let written = report.written;
                self.export_result = Some((path, report));
                self.status = Some(Status::AuditExported);
                let msg = if lang == Language::Chinese {
                    format!("已导出 {written} 条操作日志")
                } else {
                    format!("Exported {written} audit records")
                };
                self.toast(anim::ToastKind::Success, msg);
            }
        }
    }

    fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        if self.confirmation.is_some() {
            return;
        }
        let wants_kb = ctx.wants_keyboard_input();
        let (cmd_f, cmd_r, cmd_a, cmd_s, esc) = ctx.input(|i| {
            let cmd = i.modifiers.command;
            (
                cmd && i.key_pressed(egui::Key::F),
                (cmd && i.key_pressed(egui::Key::R)) || i.key_pressed(egui::Key::F5),
                cmd && i.key_pressed(egui::Key::A),
                cmd && i.key_pressed(egui::Key::S),
                i.key_pressed(egui::Key::Escape),
            )
        });

        if cmd_f {
            if self.page != Page::Applications {
                self.navigate(Page::Applications);
            }
            self.focus_search_requested = true;
            return;
        }
        if cmd_r && !wants_kb && self.can_submit() {
            match self.page {
                Page::Applications => {
                    self.submit(Request::Applications, Operation::Inventory);
                }
                Page::Quarantine => {
                    self.submit(Request::Backups, Operation::Backups);
                }
                _ => {}
            }
            return;
        }
        if cmd_a && !wants_kb && self.page == Page::Applications && !self.apps.visible.is_empty() {
            self.apps.select_all_visible();
            return;
        }
        if cmd_s && self.page == Page::Settings && self.can_submit() {
            if self.rule_text != self.saved_rule_text {
                self.save_rules();
            } else if self.retention != self.saved_retention {
                self.save_retention();
            }
            return;
        }
        if esc {
            if self.portable_open {
                self.portable_open = false;
            } else if matches!(self.status, Some(Status::Error(_))) {
                self.status = None;
            } else if self.page == Page::Applications && !self.apps.search.is_empty() {
                self.apps.search.clear();
                self.apps.dirty = true;
            } else if self.page == Page::Applications && !self.apps.selected.is_empty() {
                self.apps.clear_selection();
            }
        }
    }

    fn navigate(&mut self, page: Page) {
        self.page = page;
        if !self.can_submit() || self.confirmation.is_some() {
            return;
        }
        match page {
            Page::Applications if self.applications_need_refresh => {
                self.submit(Request::Applications, Operation::Inventory);
            }
            Page::Quarantine if self.quarantine_needs_refresh => {
                self.submit(Request::Backups, Operation::Backups);
            }
            _ => {}
        }
    }

    fn has_review(&self) -> bool {
        !self.plans.is_empty() || !self.uninstall_results.is_empty() || self.change_result.is_some()
    }

    fn approve(&mut self, review: Review) {
        match review {
            Review::Uninstall { ticket, .. } => {
                self.submit(Request::Uninstall(ticket), Operation::Uninstall);
            }
            Review::Cleanup { plan_id, items, .. } => {
                let submitted = self.submit(Request::Apply { plan_id, items }, Operation::Cleanup);
                if submitted {
                    self.plans.retain(|view| view.preview.id != plan_id);
                }
            }
            Review::Restore { ticket, .. } => {
                self.submit(Request::Restore(ticket), Operation::Restore);
            }
            Review::Expiry {
                ticket, selected, ..
            } => {
                self.submit(
                    Request::PurgeExpired {
                        ticket,
                        items: selected.into_iter().collect(),
                    },
                    Operation::PurgeExpired,
                );
            }
        }
    }

    fn save_retention(&mut self) {
        let Some(days) = NonZeroU16::new(self.retention) else {
            return;
        };
        self.submit(Request::SetRetention(days), Operation::Preferences);
    }

    fn save_rules(&mut self) {
        self.submit(
            Request::SetCustomRules(self.rule_text.clone()),
            Operation::Preferences,
        );
    }

    fn export_audit(&mut self) {
        let path = PathBuf::from(self.export_destination.trim());
        self.submit(Request::ExportAudit(path), Operation::AuditExport);
    }

    fn cancel(&mut self) {
        if let Some(active) = &mut self.active {
            self.worker.cancel();
            active.cancellation_requested = true;
        }
    }
}

impl eframe::App for DesktopApp {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        self.handle_shortcuts(context);
        self.draw(context);
    }
}

#[cfg(test)]
mod tests {
    use uninstallany_core::{
        Candidate, Category, Confidence, MatchKind, RecoveryState, Risk, ScanMode, Target,
    };

    use super::*;

    fn app(name: &str, size: Option<u64>, system_component: bool) -> AppRecord {
        AppRecord {
            id: AppId::Package {
                manager: "test".into(),
                id: name.into(),
            },
            name: name.into(),
            publisher: None,
            version: None,
            install_location: None,
            size_bytes: size,
            install_date: None,
            system_component,
            official_uninstall_available: !system_component,
        }
    }

    #[test]
    fn search_excludes_system_rows_and_size_sort_keeps_unknown_sizes_last() {
        let mut list = AppList::default();
        list.update_inventory(Inventory {
            applications: vec![
                app("Sample unknown", None, false),
                app("Sample large", Some(40), false),
                app("Sample small", Some(3), false),
                app("Sample system", Some(80), true),
            ],
            warnings: Vec::new(),
        });
        list.search = "sample".into();
        list.sort_on(SortField::Size);
        list.update_visible();
        assert_eq!(list.visible, vec![2, 1, 0]);
        list.sort_on(SortField::Size);
        list.update_visible();
        assert_eq!(list.visible, vec![1, 2, 0]);
    }

    #[test]
    fn shift_click_range_selection_selects_inclusive_visible_span() {
        let mut list = AppList::default();
        let apps = vec![
            app("Alpha", Some(10), false),
            app("Beta", Some(20), false),
            app("Gamma", Some(30), false),
            app("Delta", Some(40), false),
        ];
        let id_alpha = apps[0].id.clone();
        let id_gamma = apps[2].id.clone();
        list.update_inventory(Inventory {
            applications: apps,
            warnings: Vec::new(),
        });
        list.update_visible();
        // Visible sorted by name: Alpha, Beta, Delta, Gamma
        list.toggle_row(&id_alpha, false);
        assert_eq!(list.selected.len(), 1);
        list.toggle_row(&id_gamma, true);
        assert_eq!(list.selected.len(), 4);
        assert_eq!(list.selected_total_bytes(), Some(100));
    }

    #[test]
    fn cleanup_review_only_preselects_high_confidence_ordinary_writable_targets() {
        let candidate = |id, confidence, risk, access| Candidate {
            id,
            target: Target::Reference(format!("Fixture {id}")),
            category: Category::File,
            confidence,
            evidence: MatchKind::ExactIdentity,
            reason: "Fixture".into(),
            risk,
            access,
        };
        let mut view = CleanupView::new(CleanupPreview {
            id: Uuid::nil(),
            candidates: vec![
                candidate(0, Confidence::High, Risk::Normal, Access::Allowed),
                candidate(1, Confidence::High, Risk::High, Access::Allowed),
                candidate(2, Confidence::Low, Risk::Normal, Access::Allowed),
                candidate(
                    3,
                    Confidence::High,
                    Risk::Normal,
                    Access::ReadOnly("Protected".into()),
                ),
            ],
            mode: ScanMode::Leftovers,
            warnings: Vec::new(),
        });
        assert_eq!(view.approved_ids(), vec![0]);
        view.selected.insert(3);
        assert_eq!(view.approved_ids(), vec![0]);
        view.selected.insert(1);
        assert_eq!(view.high_risk_selected_count(), 1);
    }

    #[test]
    fn inventory_and_cleanup_draw_with_fixture_data_at_minimum_window_size() {
        let context = egui::Context::default();
        let mut desktop = DesktopApp::initialize(&context, Worker::idle_fixture());
        desktop.language = Language::English;
        desktop.receive(Response::Applications(Inventory {
            applications: vec![app("Sample Editor", Some(42), false)],
            warnings: Vec::new(),
        }));
        assert!(drawn_text(&context, &mut desktop, "Sample Editor"));

        desktop.receive(Response::Cleanup(CleanupPreview {
            id: Uuid::nil(),
            candidates: vec![Candidate {
                id: 0,
                target: Target::Reference("sample-cache.bin".into()),
                category: Category::File,
                confidence: Confidence::High,
                evidence: MatchKind::ExactIdentity,
                reason: "Fixture".into(),
                risk: Risk::Normal,
                access: Access::Allowed,
            }],
            mode: ScanMode::Leftovers,
            warnings: Vec::new(),
        }));
        assert!(drawn_text(&context, &mut desktop, "sample-cache.bin"));
        assert!(drawn_text(&context, &mut desktop, "Review selection"));

        desktop.confirmation = Some(Review::Cleanup {
            plan_id: Uuid::nil(),
            items: vec![0],
            targets: vec!["sample-cache.bin".into()],
            has_high_risk: false,
        });
        let _ = drawn_text(&context, &mut desktop, "Confirm cleanup");
        assert!(drawn_text(
            &context,
            &mut desktop,
            "Quarantine selected items"
        ));
    }

    #[test]
    fn settings_expose_offline_rules_at_minimum_window_size() {
        let context = egui::Context::default();
        let mut desktop = DesktopApp::initialize(&context, Worker::idle_fixture());
        desktop.language = Language::English;
        desktop.page = Page::Settings;
        assert!(drawn_text(&context, &mut desktop, "Custom rules"));
    }

    #[test]
    fn quarantine_summary_and_toast_feedback_render_cleanly() {
        let context = egui::Context::default();
        let mut desktop = DesktopApp::initialize(&context, Worker::idle_fixture());
        desktop.language = Language::English;
        desktop.receive(Response::Backups(BackupInventory {
            items: vec![BackupSummary {
                id: Uuid::new_v4(),
                batch_id: Uuid::new_v4(),
                target: "/tmp/demo-cache".into(),
                backup: "/tmp/quarantine/demo-cache".into(),
                expires_unix_ms: 1,
                state: RecoveryState::Applied,
            }],
            warnings: Vec::new(),
        }));
        desktop.page = Page::Quarantine;
        assert!(drawn_text(&context, &mut desktop, "Review restore"));
        desktop.receive(Response::RetentionSet(NonZeroU16::new(30).unwrap()));
        // First frame measures the bottom-right anchored toast area; second frame paints it.
        let _ = drawn_text(&context, &mut desktop, "Retention updated to 30 days");
        assert!(drawn_text(&context, &mut desktop, "Retention updated to 30 days"));
    }

    #[test]
    fn shortcuts_clear_drawer_search_and_selection_in_priority_order() {
        let context = egui::Context::default();
        let mut desktop = DesktopApp::initialize(&context, Worker::idle_fixture());
        desktop.receive(Response::Applications(Inventory {
            applications: vec![app("Alpha", Some(10), false), app("Beta", Some(20), false)],
            warnings: Vec::new(),
        }));
        desktop.apps.update_visible();
        desktop.apps.select_all_visible();
        desktop.apps.search = "alp".into();
        desktop.portable_open = true;

        let press_esc = |ctx: &egui::Context, d: &mut DesktopApp| {
            let mut input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1152.0, 744.0),
                )),
                ..Default::default()
            };
            input.events.push(egui::Event::Key {
                key: egui::Key::Escape,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            });
            let _ = ctx.run(input, |c| {
                d.handle_shortcuts(c);
                d.draw(c);
            });
        };

        // 1st Esc closes portable drawer
        press_esc(&context, &mut desktop);
        assert!(!desktop.portable_open);
        assert_eq!(desktop.apps.search, "alp");
        // 2nd Esc clears search
        press_esc(&context, &mut desktop);
        assert!(desktop.apps.search.is_empty());
        assert_eq!(desktop.apps.selected.len(), 2);
        // 3rd Esc clears selection
        press_esc(&context, &mut desktop);
        assert!(desktop.apps.selected.is_empty());
    }

    #[test]
    fn table_columns_align_and_buttons_fit_text_with_comfortable_padding() {
        let context = egui::Context::default();
        let mut desktop = DesktopApp::initialize(&context, Worker::idle_fixture());
        let _ = crate::fonts::load_sync_for_test(&context);

        let mut app1 = app("Adobe Photoshop 2025", Some(42_000_000), false);
        app1.version = Some("26.0.0".into());
        app1.id = AppId::Package {
            manager: "macos-bundle".into(),
            id: "ps".into(),
        };
        let mut app2 = app("Claude", Some(120_000), false);
        app2.version = Some("6.28899.6".into());
        app2.id = AppId::Package {
            manager: "homebrew-cask".into(),
            id: "claude".into(),
        };
        let mut app3 = app("com.example.pkg", None, false);
        app3.id = AppId::Package {
            manager: "apple-pkg-receipt".into(),
            id: "com.example.pkg".into(),
        };
        desktop.receive(Response::Applications(Inventory {
            applications: vec![app1, app2, app3],
            warnings: Vec::new(),
        }));
        desktop.apps.selected.insert(AppId::Package {
            manager: "homebrew-cask".into(),
            id: "claude".into(),
        });

        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1152.0, 744.0),
            )),
            ..Default::default()
        };

        for lang in [Language::Chinese, Language::English] {
            desktop.language = lang;
            desktop.page = Page::Applications;
            // Warm up frame so newly loaded font is active
            let _ = context.run(input.clone(), |ctx| desktop.draw(ctx));
            let frame = context.run(input.clone(), |ctx| desktop.draw(ctx));

            // 1) Verify columns align vertically across rows (size column right edges match)
            let mut size_right_edges = Vec::new();
            let mut badge_right_edges = Vec::new();
            let mut app_name_tops = Vec::new();
            let mut row_dividers_y = Vec::new();

            fn collect(
                shape: &egui::epaint::Shape,
                size_right_edges: &mut Vec<f32>,
                badge_right_edges: &mut Vec<f32>,
                app_name_tops: &mut Vec<(String, f32)>,
                row_dividers_y: &mut Vec<f32>,
                last_box: &mut Option<egui::Rect>,
            ) {
                match shape {
                    egui::epaint::Shape::Rect(r) => {
                        if r.rect.height() >= 20.0
                            && r.rect.height() <= 36.0
                            && r.rect.width() >= 20.0
                            && r.rect.width() <= 260.0
                            && r.stroke.width > 0.0
                        {
                            *last_box = Some(r.rect);
                        }
                    }
                    egui::epaint::Shape::LineSegment { points, .. } => {
                        if (points[0].y - points[1].y).abs() < 0.5
                            && (points[1].x - points[0].x) > 500.0
                        {
                            row_dividers_y.push(points[0].y);
                        }
                    }
                    egui::epaint::Shape::Text(t) => {
                        let txt = t.galley.text();
                        let m = t.galley.mesh_bounds.translate(t.pos.to_vec2());
                        if txt == "40.1 MB" || txt == "117 KB" {
                            size_right_edges.push(m.right());
                        }
                        if txt == "App" || txt == "Homebrew" || txt == "Installer" || txt == "安装包" {
                            if let Some(b) = *last_box {
                                if b.intersects(m) {
                                    badge_right_edges.push(b.right());
                                }
                            }
                        }
                        if txt == "Adobe Photoshop 2025" || txt == "Claude" {
                            app_name_tops.push((txt.to_owned(), m.top()));
                        }
                        // Check that every boxed button/badge has comfortable interior padding
                        if let Some(b) = *last_box {
                            if b.intersects(m) && b.height() <= 36.0 {
                                assert!(
                                    m.left() >= b.left() + 5.0 && m.right() <= b.right() - 5.0,
                                    "Horizontal overflow in {:?}: box={:?}, ink={:?}",
                                    txt,
                                    b,
                                    m
                                );
                                assert!(
                                    m.top() >= b.top() + 3.0 && m.bottom() <= b.bottom() - 3.0,
                                    "Vertical overflow/cramping in {:?}: box={:?}, ink={:?}",
                                    txt,
                                    b,
                                    m
                                );
                            }
                        }
                    }
                    egui::epaint::Shape::Vec(v) => {
                        for s in v {
                            collect(
                                s,
                                size_right_edges,
                                badge_right_edges,
                                app_name_tops,
                                row_dividers_y,
                                last_box,
                            );
                        }
                    }
                    _ => {}
                }
            }

            let mut last_box = None;
            for cs in &frame.shapes {
                collect(
                    &cs.shape,
                    &mut size_right_edges,
                    &mut badge_right_edges,
                    &mut app_name_tops,
                    &mut row_dividers_y,
                    &mut last_box,
                );
            }

            assert_eq!(size_right_edges.len(), 2);
            assert!(
                (size_right_edges[0] - size_right_edges[1]).abs() <= 1.5,
                "Size column drifted: {:?}",
                size_right_edges
            );
            assert!(badge_right_edges.len() >= 3);
            for w in badge_right_edges.windows(2) {
                assert!(
                    (w[0] - w[1]).abs() <= 1.5,
                    "Source badge column drifted: {:?}",
                    badge_right_edges
                );
            }
            // Verify app names have >= 8px clearance from any row divider above them
            for (name, top) in &app_name_tops {
                if let Some(above) = row_dividers_y
                    .iter()
                    .copied()
                    .filter(|&y| y <= *top + 1.0)
                    .max_by(|a, b| a.total_cmp(b))
                {
                    assert!(
                        *top - above >= 8.0,
                        "Row text {:?} hugs divider above: top={top}, divider={above}",
                        name
                    );
                }
            }
        }
    }

    #[test]
    fn expiry_review_starts_with_no_files_selected() {
        let context = egui::Context::default();
        let mut desktop = DesktopApp::initialize(&context, Worker::idle_fixture());
        desktop.receive(Response::ExpiryReview {
            ticket: Uuid::new_v4(),
            entries: vec![BackupSummary {
                id: Uuid::new_v4(),
                batch_id: Uuid::new_v4(),
                target: "sample-cache.bin".into(),
                backup: "isolated-cache.bin".into(),
                expires_unix_ms: 1,
                state: RecoveryState::Applied,
            }],
            warnings: Vec::new(),
        });
        assert!(matches!(
            desktop.confirmation,
            Some(Review::Expiry { entries, selected, .. })
                if entries.len() == 1 && selected.is_empty()
        ));
    }

    fn drawn_text(context: &egui::Context, app: &mut DesktopApp, text: &str) -> bool {
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(720.0, 560.0),
            )),
            ..Default::default()
        };
        let frame = context.run(input, |context| app.draw(context));
        frame
            .shapes
            .iter()
            .any(|item| includes_text(&item.shape, text))
    }

    fn includes_text(shape: &egui::epaint::Shape, expected: &str) -> bool {
        match shape {
            egui::epaint::Shape::Text(text) => text.galley.text().contains(expected),
            egui::epaint::Shape::Vec(items) => {
                items.iter().any(|shape| includes_text(shape, expected))
            }
            _ => false,
        }
    }
}
