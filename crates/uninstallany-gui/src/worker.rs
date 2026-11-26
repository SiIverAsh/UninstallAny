use std::{
    num::NonZeroU16,
    path::PathBuf,
    sync::mpsc::{self, Receiver, Sender, TryRecvError},
};

use eframe::egui;
use uninstallany_core::{
    AppId, AuditExport, BackupInventory, BackupSummary, Cancellation, Candidate, ChangeReport,
    Inventory, LoadedPreferences, OfficialIntent, OfficialOutcome, ScanMode,
};
use uuid::Uuid;

#[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
mod macos_backup_actions;
#[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
mod macos_backup_inventory;

/// Requests carry only identifiers and reviewed selections. Plans stay on the worker.
#[cfg_attr(
    not(any(windows, target_os = "macos", target_os = "linux")),
    allow(dead_code)
)]
pub(crate) enum Request {
    Applications,
    Scan(AppId),
    Force(AppId),
    Portable(PathBuf),
    ReviewUninstall(Vec<AppId>),
    Uninstall(Uuid),
    Backups,
    ReviewRestore(Uuid),
    Restore(Uuid),
    ReviewExpiry,
    PurgeExpired { ticket: Uuid, items: Vec<Uuid> },
    Apply { plan_id: Uuid, items: Vec<usize> },
    SetRetention(NonZeroU16),
    SetCustomRules(String),
    ExportAudit(PathBuf),
}

#[cfg_attr(
    not(any(windows, target_os = "macos", target_os = "linux")),
    allow(dead_code)
)]
pub(crate) enum Event {
    Progress { done: usize, total: usize },
    Preferences(Result<LoadedPreferences, Failure>),
    Finished(Result<Response, Failure>),
}

#[cfg_attr(
    not(any(windows, target_os = "macos", target_os = "linux")),
    allow(dead_code)
)]
pub(crate) enum Failure {
    Cancelled,
    Message(String),
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    UnsupportedPlatform,
}

#[cfg_attr(
    not(any(windows, target_os = "macos", target_os = "linux")),
    allow(dead_code)
)]
pub(crate) enum Response {
    Applications(Inventory),
    Cleanup(CleanupPreview),
    UninstallReview {
        ticket: Uuid,
        intents: Vec<OfficialIntent>,
        warnings: Vec<String>,
    },
    Uninstalled(Vec<OfficialRow>),
    Backups(BackupInventory),
    RestoreReview {
        ticket: Uuid,
        entries: Vec<BackupSummary>,
        warnings: Vec<String>,
    },
    ExpiryReview {
        ticket: Uuid,
        entries: Vec<BackupSummary>,
        warnings: Vec<String>,
    },
    Changed(ChangeReport),
    RetentionSet(NonZeroU16),
    RulesSet {
        text: String,
        count: usize,
    },
    AuditExported {
        path: PathBuf,
        report: AuditExport,
    },
}

/// Read-only copy of a cleanup plan for the desktop view.
pub(crate) struct CleanupPreview {
    pub id: Uuid,
    pub candidates: Vec<Candidate>,
    pub mode: ScanMode,
    pub warnings: Vec<String>,
}

pub(crate) struct OfficialRow {
    pub application: String,
    pub outcome: Result<OfficialOutcome, String>,
    pub cleanup: Option<CleanupPreview>,
    pub warnings: Vec<String>,
}

struct Job {
    #[cfg_attr(
        not(any(windows, target_os = "macos", target_os = "linux")),
        allow(dead_code)
    )]
    request: Request,
    cancel: Cancellation,
}

/// GUI endpoint for a single, cooperatively cancellable background session.
pub(crate) struct Worker {
    jobs: Sender<Job>,
    events: Receiver<Event>,
    cancellation: Option<Cancellation>,
}

impl Worker {
    pub(crate) fn start(context: egui::Context) -> Self {
        let (jobs, incoming) = mpsc::channel();
        let (outgoing, events) = mpsc::channel();
        std::thread::spawn(move || run(incoming, &outgoing, &context));
        Self {
            jobs,
            events,
            cancellation: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn idle_fixture() -> Self {
        let (jobs, _) = mpsc::channel();
        let (_, events) = mpsc::channel();
        Self {
            jobs,
            events,
            cancellation: None,
        }
    }

    pub(crate) fn submit(&mut self, request: Request) -> Result<(), String> {
        if self.is_busy() {
            return Err("An operation is already running.".into());
        }
        let cancel = Cancellation::default();
        self.jobs
            .send(Job {
                request,
                cancel: cancel.clone(),
            })
            .map_err(|_| "The background worker has stopped.".to_string())?;
        self.cancellation = Some(cancel);
        Ok(())
    }

    pub(crate) fn poll(&mut self) -> Option<Event> {
        match self.events.try_recv() {
            Ok(event) => {
                if matches!(event, Event::Finished(_)) {
                    self.cancellation = None;
                }
                Some(event)
            }
            Err(TryRecvError::Disconnected) if self.cancellation.take().is_some() => {
                Some(Event::Finished(Err(Failure::Message(
                    "The background worker has stopped.".into(),
                ))))
            }
            Err(_) => None,
        }
    }

    pub(crate) fn is_busy(&self) -> bool {
        self.cancellation.is_some()
    }

    pub(crate) fn cancel(&self) {
        if let Some(cancel) = &self.cancellation {
            cancel.cancel();
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.cancel();
    }
}

fn deliver(events: &Sender<Event>, context: &egui::Context, event: Event) -> bool {
    if events.send(event).is_err() {
        return false;
    }
    context.request_repaint();
    true
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn run(jobs: Receiver<Job>, events: &Sender<Event>, context: &egui::Context) {
    for job in jobs {
        let failure = if job.cancel.check().is_err() {
            Failure::Cancelled
        } else {
            Failure::UnsupportedPlatform
        };
        if !deliver(events, context, Event::Finished(Err(failure))) {
            return;
        }
    }
}

#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
fn run(jobs: Receiver<Job>, events: &Sender<Event>, context: &egui::Context) {
    #[cfg(target_os = "linux")]
    use uninstallany_linux as platform;
    #[cfg(target_os = "macos")]
    use uninstallany_macos as platform;
    #[cfg(windows)]
    use uninstallany_windows as platform;

    let mut session = platform::open().map(|mut engine| {
        let preferences = engine.restore_preferences().map_err(Failure::from);
        deliver(events, context, Event::Preferences(preferences));
        session::Session::new(engine)
    });
    for Job { request, cancel } in jobs {
        let response = match &mut session {
            Ok(session) => session.handle(request, &cancel, |done, total| {
                if !deliver(events, context, Event::Progress { done, total }) {
                    cancel.cancel();
                }
            }),
            Err(error) => Err(uninstallany_core::Error::Rejected(error.to_string())),
        };
        if !deliver(
            events,
            context,
            Event::Finished(response.map_err(Failure::from)),
        ) {
            return;
        }
    }
}

#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
impl From<uninstallany_core::Error> for Failure {
    fn from(error: uninstallany_core::Error) -> Self {
        match error {
            uninstallany_core::Error::Cancelled => Self::Cancelled,
            other => Self::Message(other.to_string()),
        }
    }
}

#[cfg(any(windows, target_os = "macos", target_os = "linux", test))]
struct Review<T> {
    id: Uuid,
    action: T,
}

#[cfg(any(windows, target_os = "macos", target_os = "linux", test))]
fn missing_review() -> uninstallany_core::Error {
    uninstallany_core::Error::Rejected(
        "This preview is no longer available. Review the current items again.".into(),
    )
}

#[cfg(any(windows, target_os = "macos", target_os = "linux", test))]
fn take_review<T>(slot: &mut Option<Review<T>>, id: Uuid) -> uninstallany_core::Result<T> {
    if slot.as_ref().is_some_and(|review| review.id == id) {
        return slot
            .take()
            .map(|review| review.action)
            .ok_or_else(missing_review);
    }
    Err(missing_review())
}

#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
mod session {
    use std::{collections::HashMap, path::Path};

    #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
    use std::collections::HashSet;

    use uninstallany_core::{
        CleanupPlan, Engine, Error, Journal, PlatformBackend, PreparedUninstall, RestorePlan,
        Result,
    };

    use super::*;

    enum CleanupAction {
        Local(CleanupPlan),
        #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
        Native(macos_backup_actions::NativeQuarantineReview),
    }

    enum RestoreAction {
        Local(RestorePlan),
        #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
        Native(macos_backup_actions::NativeRestoreReview),
    }

    #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
    type ExpiryAction = uninstallany_macos::MacExpiryPlan;

    #[cfg(not(all(target_os = "macos", feature = "macos-privileged-helper")))]
    type ExpiryAction = uninstallany_core::ExpiryCleanupPlan;

    #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
    fn backup_namespace(entries: &[BackupSummary]) -> HashSet<Uuid> {
        entries
            .iter()
            .flat_map(|entry| [entry.id, entry.batch_id])
            .collect()
    }

    pub(super) struct Session<P: PlatformBackend, J> {
        engine: Engine<P, J>,
        cleanup: HashMap<Uuid, CleanupAction>,
        uninstall: Option<Review<Vec<PreparedUninstall<P::Official>>>>,
        restore: Option<Review<RestoreAction>>,
        expiry: Option<Review<ExpiryAction>>,
        #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
        native_restore_batches: HashSet<Uuid>,
    }

    impl<P: PlatformBackend, J: Journal> Session<P, J> {
        pub(super) fn new(engine: Engine<P, J>) -> Self {
            Self {
                engine,
                cleanup: HashMap::new(),
                uninstall: None,
                restore: None,
                expiry: None,
                #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
                native_restore_batches: HashSet::new(),
            }
        }

        pub(super) fn handle(
            &mut self,
            request: Request,
            cancel: &Cancellation,
            progress: impl FnMut(usize, usize),
        ) -> Result<Response> {
            cancel.check()?;
            match request {
                Request::Applications => self
                    .engine
                    .inventory(true, cancel)
                    .map(Response::Applications),
                Request::Scan(app) => Ok(Response::Cleanup(
                    self.new_cleanup(self.engine.scan(&app, cancel)?),
                )),
                Request::Force(app) => Ok(Response::Cleanup(
                    self.new_cleanup(self.engine.force_removal(&app, cancel)?),
                )),
                Request::Portable(path) => self.scan_portable(&path, cancel),
                Request::ReviewUninstall(apps) => self.review_uninstall(apps, cancel),
                Request::Uninstall(ticket) => self.run_uninstall(ticket, cancel, progress),
                Request::Backups => self.backups(cancel),
                Request::ReviewRestore(batch) => self.review_restore(batch, cancel),
                Request::Restore(ticket) => self.restore(ticket, cancel),
                Request::ReviewExpiry => self.review_expiry(cancel),
                Request::PurgeExpired { ticket, items } => {
                    self.purge_expired(ticket, items, cancel)
                }
                Request::Apply { plan_id, items } => self.apply_cleanup(plan_id, &items, cancel),
                Request::SetRetention(days) => {
                    self.engine.persist_retention(days)?;
                    Ok(Response::RetentionSet(days))
                }
                Request::SetCustomRules(text) => {
                    let count = self.engine.persist_custom_rules(text.clone())?;
                    Ok(Response::RulesSet { text, count })
                }
                Request::ExportAudit(path) => {
                    let report = self.engine.export_audit(&path, cancel)?;
                    Ok(Response::AuditExported { path, report })
                }
            }
        }

        fn new_cleanup(&mut self, plan: CleanupPlan) -> CleanupPreview {
            self.cleanup.clear();
            self.remember_cleanup(plan)
        }

        fn scan_portable(&mut self, path: &Path, cancel: &Cancellation) -> Result<Response> {
            #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
            let system_review_error = match macos_backup_actions::prepare_quarantine(
                path,
                self.engine.retention_days(),
                cancel,
            ) {
                Ok(Some((preview, action))) => {
                    cancel.check()?;
                    self.engine
                        .record_external_audit_event(&action.audit_preview())?;
                    self.cleanup.clear();
                    self.cleanup
                        .insert(preview.id, CleanupAction::Native(action));
                    return Ok(Response::Cleanup(preview));
                }
                Ok(None) => None,
                Err(Error::Cancelled) => return Err(Error::Cancelled),
                Err(error) => Some(error),
            };

            let plan = self.engine.scan_portable(path, cancel);
            #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
            if let Some(error) = system_review_error {
                let warning = format!("System quarantine is unavailable for this app: {error}");
                let plan = plan.map_err(|scan_error| match scan_error {
                    Error::Cancelled => Error::Cancelled,
                    _ => Error::Rejected(format!("{warning} Residual scan: {scan_error}")),
                })?;
                let mut preview = self.new_cleanup(plan);
                preview.warnings.insert(0, warning);
                return Ok(Response::Cleanup(preview));
            }
            Ok(Response::Cleanup(self.new_cleanup(plan?)))
        }

        fn apply_cleanup(
            &mut self,
            plan_id: Uuid,
            items: &[usize],
            cancel: &Cancellation,
        ) -> Result<Response> {
            let action = self.cleanup.remove(&plan_id).ok_or_else(missing_review)?;
            match action {
                CleanupAction::Local(plan) => self.engine.apply(plan.confirm(items)?, cancel),
                #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
                CleanupAction::Native(review) => review.run(items, cancel, &|event| {
                    self.engine.record_external_audit_event(event)
                }),
            }
            .map(Response::Changed)
        }

        fn backups(&mut self, _cancel: &Cancellation) -> Result<Response> {
            let inventory = self.engine.backups()?;
            #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
            let inventory = self.merge_native_backups(inventory, _cancel)?;
            Ok(Response::Backups(inventory))
        }

        #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
        fn merge_native_backups(
            &mut self,
            mut local: BackupInventory,
            cancel: &Cancellation,
        ) -> Result<BackupInventory> {
            let macos_backup_inventory::NativeBackups {
                inventory: native,
                mut restore_ids,
                ..
            } = macos_backup_inventory::read(cancel)?;
            cancel.check()?;
            let local_ids = backup_namespace(&local.items);
            local.warnings.extend(native.warnings);
            for summary in native.items {
                if local_ids.contains(&summary.id) {
                    restore_ids.remove(&summary.id);
                    local.warnings.push(format!(
                        "System backup {} shares an identifier with a local backup and was omitted.",
                        summary.id,
                    ));
                    continue;
                }
                local.items.push(summary);
            }
            // An old UI row can outlive a refresh. Keep its source until the
            // worker exits so a stale native click never falls back to local.
            self.native_restore_batches.extend(restore_ids);
            Ok(local)
        }

        fn review_expiry(&mut self, cancel: &Cancellation) -> Result<Response> {
            self.expiry = None;
            #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
            let plan = ExpiryAction::prepare(&self.engine, cancel)?;
            #[cfg(not(all(target_os = "macos", feature = "macos-privileged-helper")))]
            let plan = self.engine.prepare_expiry_cleanup(cancel)?;
            #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
            let entries = plan.items().to_vec();
            #[cfg(not(all(target_os = "macos", feature = "macos-privileged-helper")))]
            let entries = plan.items().cloned().collect::<Vec<_>>();
            let warnings = plan.warnings().to_vec();
            let ticket = Uuid::new_v4();
            if !entries.is_empty() {
                self.expiry = Some(Review {
                    id: ticket,
                    action: plan,
                });
            }
            Ok(Response::ExpiryReview {
                ticket,
                entries,
                warnings,
            })
        }

        fn purge_expired(
            &mut self,
            ticket: Uuid,
            items: Vec<Uuid>,
            cancel: &Cancellation,
        ) -> Result<Response> {
            let action = take_review(&mut self.expiry, ticket)?;
            #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
            let report = action.apply(&self.engine, ticket, items, cancel)?;
            #[cfg(not(all(target_os = "macos", feature = "macos-privileged-helper")))]
            let report = self
                .engine
                .apply_expiry_cleanup(action.confirm(&items)?, cancel)?;
            Ok(Response::Changed(report))
        }

        fn remember_cleanup(&mut self, plan: CleanupPlan) -> CleanupPreview {
            let preview = CleanupPreview {
                id: plan.id(),
                candidates: plan.candidates().cloned().collect(),
                mode: plan.mode(),
                warnings: plan.warnings().to_vec(),
            };
            self.cleanup.insert(preview.id, CleanupAction::Local(plan));
            preview
        }

        fn review_uninstall(
            &mut self,
            apps: Vec<AppId>,
            cancel: &Cancellation,
        ) -> Result<Response> {
            self.uninstall = None;
            let mut actions = Vec::new();
            let mut warnings = Vec::new();
            let mut seen = std::collections::HashSet::new();
            for app in apps {
                if !seen.insert(app.clone()) {
                    continue;
                }
                match self.engine.prepare_uninstall(&app, cancel) {
                    Ok(action) => actions.push(action),
                    Err(Error::Cancelled) => return Err(Error::Cancelled),
                    Err(error) => warnings.push(error.to_string()),
                }
            }
            cancel.check()?;
            let ticket = Uuid::new_v4();
            let intents = actions
                .iter()
                .map(|action| action.intent().clone())
                .collect();
            if !actions.is_empty() {
                self.uninstall = Some(Review {
                    id: ticket,
                    action: actions,
                });
            }
            Ok(Response::UninstallReview {
                ticket,
                intents,
                warnings,
            })
        }

        fn run_uninstall(
            &mut self,
            ticket: Uuid,
            cancel: &Cancellation,
            mut progress: impl FnMut(usize, usize),
        ) -> Result<Response> {
            let actions = take_review(&mut self.uninstall, ticket)?;
            self.cleanup.clear();
            let total = actions.len();
            let mut rows = Vec::with_capacity(total);
            progress(0, total);
            for action in actions {
                let application = action.intent().application.clone();
                let result = cancel
                    .check()
                    .and_then(|()| action.confirm())
                    .and_then(|command| self.engine.run_uninstall(command, cancel));
                let row = match result {
                    Ok(report) => OfficialRow {
                        application,
                        outcome: Ok(report.outcome),
                        cleanup: report.cleanup.map(|plan| self.remember_cleanup(plan)),
                        warnings: report.warnings,
                    },
                    Err(Error::Cancelled) => OfficialRow {
                        application,
                        outcome: Ok(OfficialOutcome::Cancelled),
                        cleanup: None,
                        warnings: Vec::new(),
                    },
                    Err(error) => OfficialRow {
                        application,
                        outcome: Err(error.to_string()),
                        cleanup: None,
                        warnings: Vec::new(),
                    },
                };
                rows.push(row);
                progress(rows.len(), total);
            }
            Ok(Response::Uninstalled(rows))
        }

        fn review_restore(&mut self, batch: Uuid, _cancel: &Cancellation) -> Result<Response> {
            self.restore = None;
            #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
            if self.native_restore_batches.contains(&batch) {
                return self.review_native_restore(batch, _cancel);
            }
            let plan = self.engine.prepare_restore(batch)?;
            let entries = plan.entries().cloned().collect::<Vec<_>>();
            let warnings = plan.warnings().to_vec();
            let ticket = Uuid::new_v4();
            if !entries.is_empty() {
                self.restore = Some(Review {
                    id: ticket,
                    action: RestoreAction::Local(plan),
                });
            }
            Ok(Response::RestoreReview {
                ticket,
                entries,
                warnings,
            })
        }

        #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
        fn review_native_restore(
            &mut self,
            batch: Uuid,
            cancel: &Cancellation,
        ) -> Result<Response> {
            let local = self.engine.backups()?;
            if backup_namespace(&local.items).contains(&batch) {
                return Err(Error::Rejected(
                    "The selected system backup conflicts with a local backup ID.".into(),
                ));
            }
            cancel.check()?;
            let review = macos_backup_actions::prepare_restore(batch)?;
            cancel.check()?;
            self.engine
                .record_external_audit_event(&review.audit_preview())?;
            let ticket = Uuid::new_v4();
            let entries = vec![review.summary().clone()];
            self.restore = Some(Review {
                id: ticket,
                action: RestoreAction::Native(review),
            });
            Ok(Response::RestoreReview {
                ticket,
                entries,
                warnings: vec![
                    "Restoring this system backup requires macOS administrator approval.".into(),
                ],
            })
        }

        fn restore(&mut self, ticket: Uuid, cancel: &Cancellation) -> Result<Response> {
            match take_review(&mut self.restore, ticket)? {
                RestoreAction::Local(plan) => self
                    .engine
                    .restore(plan.confirm()?, cancel)
                    .map(Response::Changed),
                #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
                RestoreAction::Native(review) => Ok(Response::Changed(ChangeReport {
                    batch_id: review.summary().batch_id,
                    items: vec![review.run(cancel, &|event| {
                        self.engine.record_external_audit_event(event)
                    })],
                })),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ticket_cannot_run_a_different_or_consumed_review() {
        let id = Uuid::new_v4();
        let mut slot = Some(Review {
            id,
            action: "reviewed",
        });
        assert!(take_review(&mut slot, Uuid::new_v4()).is_err());
        assert_eq!(take_review(&mut slot, id).ok(), Some("reviewed"));
        assert!(take_review(&mut slot, id).is_err());
    }
}
