use std::{
    collections::{HashMap, HashSet},
    io,
    num::NonZeroU16,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    Access, AppId, AppRecord, ApplicationUninstall, Artifact, AuditEvent, BackupInventory,
    BackupSummary, Cancellation, Category, ChangeReport, ChangeResult, Confidence, Error,
    Inspection, Inventory, ItemResult, Journal, MatchKind, OfficialExecution, OfficialIntent,
    OfficialOutcome, PlatformBackend, PostUninstallCheck, PostUninstallScan, Proposal,
    RecoveryState, RegistryChangeReceipt, Result, Risk, Scan, ScanMode, Target,
    is_current_user_app_path_default_target, is_protected_registry_target,
    policy::valid_file_address,
    rules::RuleBook,
    state::{BackupRecord, put_json, read_json},
};

#[path = "expiry.rs"]
mod expiry;
pub use expiry::{ConfirmedExpiryCleanup, ExpiryCleanupPlan, ExpiryCleanupStatus};

const CONFIRMATION_LIFETIME: Duration = Duration::from_secs(15 * 60);
/// Default retention captured by newly created quarantine records.
pub const DEFAULT_RETENTION_DAYS: NonZeroU16 =
    NonZeroU16::new(14).expect("fourteen days is nonzero");

/// One reviewed dry-run entry with its UI selection rules.
#[derive(Clone, Debug, Serialize)]
pub struct Candidate {
    pub id: usize,
    pub target: Target,
    pub category: Category,
    pub confidence: Confidence,
    pub evidence: MatchKind,
    pub reason: String,
    pub risk: Risk,
    pub access: Access,
}

impl Candidate {
    /// Only high confidence, ordinary risk and a writable target is preselected.
    pub fn default_selected(&self) -> bool {
        self.confidence == Confidence::High
            && self.risk == Risk::Normal
            && self.access == Access::Allowed
    }
}

struct Reviewed {
    candidate: Candidate,
    fingerprint: Option<String>,
    observed_during_scan: bool,
    requires_post_uninstall_file_guard: bool,
}

enum CleanupSource {
    Installed(AppId),
    Uninstalled {
        app: Box<AppRecord>,
        observed_files: HashMap<PathBuf, String>,
        post_uninstall_check: Option<PostUninstallCheck>,
    },
    Portable(PathBuf),
    ReadOnly,
}

struct CleanupChecks<'a> {
    file_application: Option<&'a AppId>,
    post_uninstall: Option<PostUninstallCleanup<'a>>,
    force_removal: Option<(&'a AppId, &'a str)>,
}

struct PostUninstallCleanup<'a> {
    app: &'a AppRecord,
    observed_files: &'a HashMap<PathBuf, String>,
    completion_check: Option<&'a PostUninstallCheck>,
}

/// An in-memory, immutable preview. Serialized candidates are display only.
pub struct CleanupPlan {
    session: Uuid,
    id: Uuid,
    created: Instant,
    entries: Vec<Reviewed>,
    warnings: Vec<String>,
    mode: ScanMode,
    source: CleanupSource,
    file_cleanup_application: Option<AppId>,
    force_removal_binding: Option<String>,
}

impl CleanupPlan {
    /// Identifies the dry-run and any change events derived from it.
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Returns the scan mode for displaying any force-removal warning.
    pub fn mode(&self) -> ScanMode {
        self.mode
    }

    /// Returns the immutable entries to display alongside the confirmation.
    pub fn candidates(&self) -> impl Iterator<Item = &Candidate> {
        self.entries.iter().map(|entry| &entry.candidate)
    }

    /// Returns errors from individual sources that did not stop the scan.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Binds approval to the exact set chosen from this preview.
    pub fn confirm(self, selected: &[usize]) -> Result<ConfirmedCleanup> {
        check_age(self.created)?;
        let selected = self.select(selected)?;
        Ok(ConfirmedCleanup {
            plan: self,
            selected,
        })
    }

    fn select(&self, selected: &[usize]) -> Result<HashSet<usize>> {
        let ids: HashSet<_> = selected.iter().copied().collect();
        if ids.is_empty() || ids.len() != selected.len() {
            return Err(Error::Rejected(
                "select distinct items from the cleanup preview".into(),
            ));
        }
        for id in &ids {
            if !self
                .entries
                .get(*id)
                .is_some_and(|entry| entry.fingerprint.is_some())
            {
                return Err(Error::Rejected(format!(
                    "item {id} is not eligible for cleanup"
                )));
            }
        }
        Ok(ids)
    }
}

/// Single-use capability, obtainable only from a live cleanup plan.
pub struct ConfirmedCleanup {
    plan: CleanupPlan,
    selected: HashSet<usize>,
}

/// The result of an approved cleanup that can return an unused preview.
pub enum CleanupAttempt {
    /// The approval was consumed and each selected item has an outcome.
    Reported(ChangeReport),
    /// Cleanup did not start and the user can confirm again from the live preview.
    RetryableBeforeApply {
        /// The original preview, including its expiry and attribution evidence.
        plan: Box<CleanupPlan>,
        /// The selection, cancellation, or read error to report to the user.
        error: Error,
    },
}

/// Explicit preflight for a specific uninstall action.
pub struct PreparedUninstall<Command> {
    session: Uuid,
    created: Instant,
    app: AppRecord,
    intent: OfficialIntent,
    action: ApplicationUninstall<Command>,
}

impl<Command> PreparedUninstall<Command> {
    /// Shows the effect of the prepared command without exposing private arguments.
    pub fn intent(&self) -> &OfficialIntent {
        &self.intent
    }

    /// Gives the prepared command explicit single-use authorization.
    pub fn confirm(self) -> Result<ConfirmedUninstall<Command>> {
        check_age(self.created)?;
        Ok(ConfirmedUninstall(self))
    }
}

/// An uninstall action authorized by the caller.
pub struct ConfirmedUninstall<Command>(PreparedUninstall<Command>);

/// Uninstall result and optional independent dry-run for leftovers.
pub struct UninstallReport {
    pub outcome: OfficialOutcome,
    pub cleanup: Option<CleanupPlan>,
    pub warnings: Vec<String>,
}

/// One entry of the serial uninstall queue.
pub struct QueueResult {
    pub application: String,
    pub result: Result<UninstallReport>,
}

/// Recoverable entries for the user to review as a batch.
pub struct RestorePlan {
    session: Uuid,
    created: Instant,
    batch_id: Uuid,
    entries: Vec<(BackupSummary, BackupRecord)>,
    warnings: Vec<String>,
}

impl RestorePlan {
    /// Exact objects that will be considered for conflict-safe restoration.
    pub fn entries(&self) -> impl ExactSizeIterator<Item = &BackupSummary> {
        self.entries.iter().map(|(summary, _)| summary)
    }

    /// Reports backup records that could not be examined.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Approves restoration of this reviewed batch.
    pub fn confirm(self) -> Result<ConfirmedRestore> {
        check_age(self.created)?;
        if self.entries.is_empty() {
            return Err(Error::Rejected(
                "this batch has no recoverable objects".into(),
            ));
        }
        Ok(ConfirmedRestore(self))
    }
}

/// Single-use authorization for a reviewed restore.
pub struct ConfirmedRestore(RestorePlan);

/// UI-independent workflow and single authority for applying plans.
pub struct Engine<P, J> {
    platform: P,
    pub(crate) journal: J,
    session: Uuid,
    retention_days: NonZeroU16,
    rules: RuleBook,
}

impl<P: PlatformBackend, J: Journal> Engine<P, J> {
    /// Creates an independent session with fourteen-day backup retention.
    pub fn new(platform: P, journal: J) -> Self {
        Self {
            platform,
            journal,
            session: Uuid::new_v4(),
            retention_days: DEFAULT_RETENTION_DAYS,
            rules: RuleBook::new(),
        }
    }

    /// Configures retention for future backups before manual expiry cleanup is allowed.
    pub fn with_retention(mut self, days: NonZeroU16) -> Self {
        self.set_retention(days);
        self
    }

    /// Updates retention for backups created after this call.
    pub fn set_retention(&mut self, days: NonZeroU16) {
        self.retention_days = days;
    }

    /// Returns the configured retention for newly created backups.
    pub fn retention_days(&self) -> NonZeroU16 {
        self.retention_days
    }

    /// Atomically replaces custom rules after validating the full document.
    pub fn load_custom_rules(&mut self, reader: impl io::Read) -> Result<usize> {
        self.rules.load_custom(reader)
    }

    /// Reverts to built-in rules.
    pub fn clear_custom_rules(&mut self) {
        self.rules.clear_custom();
    }

    /// Records a diagnostic or result from an independently journaled operation.
    ///
    /// The event is available for audit export. Recovery still requires the
    /// operation's own backup and completion records.
    pub fn record_external_audit_event(&self, event: &AuditEvent) -> Result<()> {
        put_json(&self.journal, Uuid::new_v4(), Artifact::Event, event)
    }

    /// Saves audit events and operation receipts as a new local JSON Lines file.
    ///
    /// Invalid records are reported in the export summary. Cancellation keeps
    /// the requested destination unwritten, and an existing file is preserved.
    pub fn export_audit(
        &self,
        destination: &Path,
        cancel: &Cancellation,
    ) -> Result<crate::AuditExport> {
        let mut result = crate::audit::export(&self.journal, destination, cancel);
        let outcome = match &result {
            Ok(_) => "succeeded".into(),
            Err(error) => crate::audit::error_outcome(error),
        };
        let recorded = self.event("audit journal".into(), "audit_export", &outcome);
        if let (Ok(export), Err(_)) = (&mut result, recorded) {
            export
                .warnings
                .push("The export was saved but its audit record could not be written".into());
        }
        result
    }

    /// Reads the inventory. System components are omitted unless requested.
    pub fn inventory(&self, include_system: bool, cancel: &Cancellation) -> Result<Inventory> {
        let result = self.platform.inventory_for_display(cancel);
        self.event("inventory".into(), "inventory", status(&result))?;
        let mut inventory = result?;
        if !include_system {
            inventory.applications.retain(|app| !app.system_component);
        }
        Ok(inventory)
    }

    /// Generates a residual-only dry-run from a current inventory identity.
    pub fn scan(&self, app: &AppId, cancel: &Cancellation) -> Result<CleanupPlan> {
        self.scan_app(
            &self.find_app(app, cancel)?,
            ScanMode::Leftovers,
            CleanupSource::Installed(app.clone()),
            Vec::new(),
            cancel,
        )
    }

    /// Builds a stronger-warning dry-run for a missing or failed official uninstall.
    pub fn force_removal(&self, app: &AppId, cancel: &Cancellation) -> Result<CleanupPlan> {
        let mut plan = self.scan_app(
            &self.find_app(app, cancel)?,
            ScanMode::ForceRemoval,
            CleanupSource::Installed(app.clone()),
            Vec::new(),
            cancel,
        )?;
        plan.warnings.insert(0, "Force removal only handles the selected listing and leftovers. The application may remain installed.".into());
        Ok(plan)
    }

    /// Generates a dry-run from an explicitly chosen portable directory.
    pub fn scan_portable(&self, directory: &Path, cancel: &Cancellation) -> Result<CleanupPlan> {
        if !valid_file_address(directory) {
            return Err(Error::Rejected(
                "choose an absolute application directory without traversal".into(),
            ));
        }
        let scan = self.platform.scan_portable(directory, cancel);
        self.event(
            directory.display().to_string(),
            "scan_portable",
            status(&scan),
        )?;
        self.review(
            scan?,
            ScanMode::Leftovers,
            CleanupSource::Portable(directory.to_path_buf()),
            cancel,
        )
    }

    /// Prepares an uninstall action from current inventory without changing it.
    pub fn prepare_uninstall(
        &self,
        app: &AppId,
        cancel: &Cancellation,
    ) -> Result<PreparedUninstall<P::Official>> {
        let app = self.find_app(app, cancel)?;
        if app.system_component || !app.official_uninstall_available {
            return Err(Error::Rejected(format!(
                "{} has no supported uninstall action",
                app.name
            )));
        }
        let prepared =
            self.platform
                .prepare_application_uninstall(&app, self.retention_days, cancel);
        let action = match &prepared {
            Ok((_, ApplicationUninstall::QuarantineBundle { .. })) => {
                "prepare_quarantine_uninstall"
            }
            Ok((_, ApplicationUninstall::PlatformQuarantine(_))) => {
                "prepare_platform_quarantine_uninstall"
            }
            _ => "prepare_official_uninstall",
        };
        self.event(app.name.clone(), action, status(&prepared))?;
        let (intent, action) = prepared?;
        Ok(PreparedUninstall {
            session: self.session,
            created: Instant::now(),
            app,
            intent,
            action,
        })
    }

    /// Runs one authorized uninstall and scans after verified completion.
    pub fn run_uninstall(
        &self,
        confirmed: ConfirmedUninstall<P::Official>,
        cancel: &Cancellation,
    ) -> Result<UninstallReport> {
        let prepared = confirmed.0;
        self.check_session(prepared.session, prepared.created)?;
        cancel.check()?;
        let _mutation = self.platform.begin_mutation(cancel)?;
        let current = self.find_app(&prepared.app.id, cancel)?;
        if current.system_component
            || current.name != prepared.app.name
            || current.version != prepared.app.version
            || current.publisher != prepared.app.publisher
            || current.install_location != prepared.app.install_location
        {
            return Err(Error::Rejected(
                "application inventory changed since confirmation".into(),
            ));
        }
        if !current.official_uninstall_available {
            let reason = match &prepared.action {
                ApplicationUninstall::QuarantineBundle { .. } => {
                    "the application cannot be quarantined now"
                }
                _ => "the application no longer has an available uninstall action",
            };
            return Err(Error::Rejected(reason.into()));
        }
        let is_official = matches!(&prepared.action, ApplicationUninstall::Official(_));
        let (action, verify_after_cancel) = match &prepared.action {
            ApplicationUninstall::Official(_) => (
                "official_uninstall",
                self.platform.verify_finished_official_after_cancel(),
            ),
            ApplicationUninstall::PlatformQuarantine(_) => ("platform_quarantine_uninstall", true),
            ApplicationUninstall::QuarantineBundle { .. } => ("quarantine_uninstall", true),
        };
        self.event(prepared.app.name.clone(), action, "starting")?;
        let execution = match prepared.action {
            ApplicationUninstall::Official(command)
            | ApplicationUninstall::PlatformQuarantine(command) => {
                self.platform.run_official_with_cancel(command, cancel)
            }
            ApplicationUninstall::QuarantineBundle {
                fingerprint,
                observed_files,
            } => self
                .platform
                .run_bundle_uninstall(&current, observed_files, cancel, || {
                    self.quarantine_application_bundle(&prepared.app, &fingerprint, cancel)
                }),
        };
        let description = match &execution {
            Ok(execution) => format!("{:?}", execution.outcome),
            Err(error) => crate::audit::error_outcome(error),
        };
        let outcome_audit = self.event(prepared.app.name.clone(), action, &description);
        let (execution, outcome_audit_error) = match (execution, outcome_audit) {
            (Ok(execution), recorded) => (execution, recorded.err()),
            (Err(error), Ok(())) => return Err(error),
            (Err(error), Err(audit_error)) => {
                return Err(Error::Rejected(format!(
                    "Uninstall error: {error}. Could not record the uninstall outcome: {audit_error}"
                )));
            }
        };
        if is_official && outcome_audit_error.is_none() {
            self.platform
                .record_audited_official_outcome(&current, &execution.outcome);
        }
        // Cancellation can stop the scan while completion verification still
        // establishes the outcome of an operation that has already finished.
        let completion_verification = Cancellation::default();
        let verification_cancel = if verify_after_cancel {
            &completion_verification
        } else {
            cancel
        };
        self.scan_after_uninstall(
            &prepared.app,
            execution,
            outcome_audit_error,
            verification_cancel,
            cancel,
        )
    }

    fn quarantine_application_bundle(
        &self,
        app: &AppRecord,
        fingerprint: &str,
        cancel: &Cancellation,
    ) -> Result<()> {
        let path = app
            .install_location
            .as_ref()
            .filter(|path| valid_file_address(path))
            .ok_or_else(|| Error::Rejected("application installation path is invalid".into()))?;
        self.apply_item(
            (Uuid::new_v4(), Uuid::new_v4()),
            Target::File(path.clone()),
            (fingerprint, false),
            &CleanupChecks {
                file_application: Some(&app.id),
                post_uninstall: None,
                force_removal: None,
            },
            cancel,
        )
    }

    /// Runs an authorized queue sequentially. A failed item does not stop others.
    pub fn run_uninstall_queue(
        &self,
        confirmed: impl IntoIterator<Item = ConfirmedUninstall<P::Official>>,
        cancel: &Cancellation,
    ) -> Vec<QueueResult> {
        confirmed
            .into_iter()
            .map(|command| {
                let application = command.0.app.name.clone();
                QueueResult {
                    application,
                    result: self.run_uninstall(command, cancel),
                }
            })
            .collect()
    }

    /// Applies only the approved dry-run items and returns one result per item.
    pub fn apply(
        &self,
        confirmed: ConfirmedCleanup,
        cancel: &Cancellation,
    ) -> Result<ChangeReport> {
        self.check_session(confirmed.plan.session, confirmed.plan.created)?;
        let _mutation = self.platform.begin_mutation(cancel)?;
        let allowed = self.cleanup_preflight(&confirmed.plan, &confirmed.selected, cancel)??;
        Ok(self.apply_rechecked_cleanup(confirmed, &allowed, cancel))
    }

    /// Applies the user's selected cleanup items with a recoverable preflight.
    /// The caller must get fresh approval before retrying with a returned preview.
    pub fn apply_cleanup_preview(
        &self,
        plan: CleanupPlan,
        selected: &[usize],
        cancel: &Cancellation,
    ) -> Result<CleanupAttempt> {
        self.check_session(plan.session, plan.created)?;
        let selected = match plan.select(selected) {
            Ok(selected) => selected,
            Err(error) => {
                return Ok(CleanupAttempt::RetryableBeforeApply {
                    plan: Box::new(plan),
                    error,
                });
            }
        };
        let allowed = match self.platform.begin_mutation(cancel) {
            Ok(mutation) => self
                .cleanup_preflight(&plan, &selected, cancel)?
                .and_then(|ids| {
                    cancel.check()?;
                    Ok((mutation, ids))
                }),
            Err(error) => Err(error),
        };
        match allowed {
            Ok((_mutation, ids)) => Ok(CleanupAttempt::Reported(self.apply_rechecked_cleanup(
                ConfirmedCleanup { plan, selected },
                &ids,
                cancel,
            ))),
            // The mutable phase can stage a backup even if the subsequent
            // move is cancelled. Only preflight may return the original plan.
            Err(error @ (Error::Cancelled | Error::Io(_))) => {
                self.check_session(plan.session, plan.created)?;
                Ok(CleanupAttempt::RetryableBeforeApply {
                    plan: Box::new(plan),
                    error,
                })
            }
            Err(error) => Err(error),
        }
    }

    fn cleanup_preflight(
        &self,
        plan: &CleanupPlan,
        selected: &HashSet<usize>,
        cancel: &Cancellation,
    ) -> Result<Result<HashSet<usize>>> {
        let fresh = self.recheck_cleanup(plan, selected, cancel);
        // Keep audit errors outside the rescan result so an unrecorded
        // preflight can never return a preview for retry.
        self.event(
            "cleanup candidates".into(),
            "recheck_cleanup",
            status(&fresh),
        )?;
        if fresh.is_ok() {
            self.check_session(plan.session, plan.created)?;
        }
        Ok(fresh)
    }

    fn apply_rechecked_cleanup(
        &self,
        confirmed: ConfirmedCleanup,
        allowed: &HashSet<usize>,
        cancel: &Cancellation,
    ) -> ChangeReport {
        let ConfirmedCleanup { plan, selected } = confirmed;
        let CleanupPlan {
            id: batch_id,
            mut entries,
            mode,
            source,
            file_cleanup_application,
            force_removal_binding,
            ..
        } = plan;
        entries.retain(|entry| selected.contains(&entry.candidate.id));
        let mut report = ChangeReport {
            batch_id,
            items: Vec::new(),
        };
        let force_removal = match (&source, mode, force_removal_binding.as_deref()) {
            (CleanupSource::Installed(app), ScanMode::ForceRemoval, Some(binding)) => {
                Some((app, binding))
            }
            _ => None,
        };
        let original_registration = match force_removal {
            Some((AppId::WindowsRegistry(key), _)) => Some(key),
            _ => None,
        };
        entries.sort_by_cached_key(|entry| {
            // Bound writes still need the original uninstall registration.
            let is_original_registration = matches!(&entry.candidate.target, Target::Registry(target)
                if original_registration == Some(target));
            // Startup entries and App Paths need their executable present during isolation.
            let requires_executable = match &entry.candidate.target {
                Target::Registry(target) => {
                    entry.candidate.category == Category::Startup
                        || is_current_user_app_path_default_target(target)
                }
                Target::File(path) if entry.candidate.category == Category::Startup => entry
                    .fingerprint
                    .as_deref()
                    .is_some_and(|fingerprint| {
                        self.platform.restore_file_after_ordinary_files(path, fingerprint)
                    }),
                _ => false,
            };
            (is_original_registration, !requires_executable)
        });
        let checks = CleanupChecks {
            file_application: file_cleanup_application.as_ref(),
            force_removal,
            post_uninstall: match &source {
                CleanupSource::Uninstalled {
                    app,
                    observed_files,
                    post_uninstall_check,
                } => Some(PostUninstallCleanup {
                    app,
                    observed_files,
                    completion_check: post_uninstall_check.as_ref(),
                }),
                _ => None,
            },
        };
        let mut can_continue = true;
        for entry in entries {
            let target = entry.candidate.target.display();
            if !can_continue {
                report.items.push(self.report_unattempted(
                    report.batch_id,
                    target,
                    "cleanup",
                    None,
                ));
                continue;
            }
            let id = Uuid::new_v4();
            let result = cancel.check().and_then(|()| {
                if !allowed.contains(&entry.candidate.id) {
                    return Err(Error::Rejected(
                        "application ownership or risk changed after the preview".into(),
                    ));
                }
                let fingerprint = entry
                    .fingerprint
                    .as_deref()
                    .ok_or_else(|| Error::Rejected("target has no authorized identity".into()))?;
                self.apply_item(
                    (batch_id, id),
                    entry.candidate.target,
                    (fingerprint, entry.requires_post_uninstall_file_guard),
                    &checks,
                    cancel,
                )
            });
            let (backup_id, result, audit_ok) = self.report_item(
                (report.batch_id, id),
                &target,
                "cleanup",
                result,
                ChangeResult::Applied,
            );
            can_continue = audit_ok;
            report.items.push(ItemResult {
                target,
                backup_id,
                result,
            });
        }
        report
    }

    fn recheck_cleanup(
        &self,
        plan: &CleanupPlan,
        selected: &HashSet<usize>,
        cancel: &Cancellation,
    ) -> Result<HashSet<usize>> {
        let scan = match &plan.source {
            CleanupSource::Installed(id) => {
                let app = self.find_app(id, cancel)?;
                if app.system_component {
                    return Err(Error::Rejected("application is now protected".into()));
                }
                self.platform
                    .scan_for_cleanup_recheck(&app, plan.mode, cancel)?
            }
            CleanupSource::Uninstalled {
                app,
                observed_files,
                post_uninstall_check,
            } => {
                self.require_post_uninstall_state(app, post_uninstall_check.as_ref(), cancel)?;
                self.require_post_uninstall_cleanup_state(app, observed_files, cancel)?;
                self.platform.scan_after_official_uninstall(
                    app,
                    observed_files,
                    PostUninstallScan::Recheck,
                    cancel,
                )?
            }
            CleanupSource::Portable(directory) => self.platform.scan_portable(directory, cancel)?,
            CleanupSource::ReadOnly => {
                return Err(Error::Rejected("this residual preview is read-only".into()));
            }
        };
        if scan.file_cleanup_application != plan.file_cleanup_application {
            return Err(Error::Rejected(
                "the application attributed to this cleanup changed after preview".into(),
            ));
        }
        if scan.force_removal_binding != plan.force_removal_binding {
            return Err(Error::Rejected(
                "the evidence authorizing force removal changed after preview".into(),
            ));
        }
        let reviewed: HashMap<_, _> = plan
            .entries
            .iter()
            .filter(|entry| selected.contains(&entry.candidate.id))
            .map(|entry| (&entry.candidate.target, entry))
            .collect();
        let mut allowed = HashSet::new();
        let mut blocked = HashSet::new();
        for proposal in scan.proposals {
            cancel.check()?;
            let Some(entry) = reviewed.get(&proposal.target) else {
                continue;
            };
            let previous = &entry.candidate;
            let observation_matches = match scan.observations.get(&proposal.target) {
                Some(fingerprint) => fingerprint.is_some() && fingerprint == &entry.fingerprint,
                None => !entry.observed_during_scan,
            };
            let requires_guard = matches!(&proposal.target, Target::File(path)
                if scan.post_uninstall_file_guards.contains(path));
            // A restrictive duplicate vetoes writes just as it does in the preview.
            if !observation_matches
                || requires_guard != entry.requires_post_uninstall_file_guard
                || proposal.access != Access::Allowed
                || proposal.risk > previous.risk
            {
                blocked.insert(previous.id);
            } else if proposal.category == previous.category
                && proposal.evidence == previous.evidence
                && proposal.reason == previous.reason
            {
                allowed.insert(previous.id);
            }
        }
        allowed.retain(|id| !blocked.contains(id));
        Ok(allowed)
    }

    /// Reconciles retained backups with their independently recorded outcomes.
    pub fn backups(&self) -> Result<BackupInventory> {
        let mut inventory = BackupInventory::default();
        for id in self.journal.manifests()? {
            let record = match BackupRecord::load(&self.journal, id) {
                Ok(record) => record,
                Err(error) => {
                    inventory.warnings.push(format!("backup {id}: {error}"));
                    continue;
                }
            };
            match self.summarize(&record) {
                Ok(summary) => inventory.items.push(summary),
                Err(error) => {
                    // A valid manifest still identifies a backup whose native
                    // state cannot be verified. Keep it visible for review.
                    inventory
                        .items
                        .push(record.summary(RecoveryState::NeedsReview));
                    inventory.warnings.push(format!("backup {id}: {error}"));
                }
            }
        }
        Ok(inventory)
    }

    /// Previews still-recoverable objects from one prior change batch.
    pub fn prepare_restore(&self, original_batch: Uuid) -> Result<RestorePlan> {
        let mut entries = Vec::new();
        let mut warnings = Vec::new();
        for id in self.journal.manifests()? {
            let record = match BackupRecord::load(&self.journal, id) {
                Ok(record) => record,
                Err(error) => {
                    warnings.push(format!("backup {id}: {error}"));
                    continue;
                }
            };
            if record.batch_id != original_batch {
                continue;
            }
            match self.summarize(&record) {
                Ok(summary) if summary.state == RecoveryState::Applied => {
                    let priority = match &record.target {
                        Target::File(path) => (
                            false,
                            self.platform
                                .restore_file_after_ordinary_files(path, &record.fingerprint),
                        ),
                        _ => (true, false),
                    };
                    entries.push((priority, summary, record));
                }
                Ok(_) => {}
                Err(error) => warnings.push(format!("backup {id}: {error}")),
            }
        }
        // Restore executables before files or registry values that reference them.
        entries.sort_by(|(left_priority, left, _), (right_priority, right, _)| {
            left_priority
                .cmp(right_priority)
                .then_with(|| left.target.cmp(&right.target))
        });
        Ok(RestorePlan {
            session: self.session,
            created: Instant::now(),
            batch_id: original_batch,
            entries: entries
                .into_iter()
                .map(|(_, summary, record)| (summary, record))
                .collect(),
            warnings,
        })
    }

    /// Restores the approved batch without replacing destination conflicts.
    pub fn restore(
        &self,
        confirmed: ConfirmedRestore,
        cancel: &Cancellation,
    ) -> Result<ChangeReport> {
        let plan = confirmed.0;
        self.check_session(plan.session, plan.created)?;
        let _mutation = self.platform.begin_mutation(cancel)?;
        let mut report = ChangeReport {
            batch_id: plan.batch_id,
            items: Vec::new(),
        };
        let mut can_continue = true;
        for (entry, record) in plan.entries {
            if !can_continue {
                report.items.push(self.report_unattempted(
                    report.batch_id,
                    entry.target,
                    "restore",
                    Some((entry.id, &record.backup)),
                ));
                continue;
            }
            let result = cancel.check().and_then(|()| self.restore_item(record));
            let (_, result, audit_ok) = self.report_item(
                (report.batch_id, entry.id),
                &entry.target,
                "restore",
                result,
                ChangeResult::Restored,
            );
            can_continue = audit_ok;
            report.items.push(ItemResult {
                target: entry.target,
                backup_id: Some(entry.id),
                result,
            });
        }
        Ok(report)
    }

    fn find_app(&self, id: &AppId, cancel: &Cancellation) -> Result<AppRecord> {
        cancel.check()?;
        self.platform
            .lookup_application(id, cancel)?
            .filter(|app| &app.id == id)
            .ok_or_else(|| Error::Rejected("application is no longer present in inventory".into()))
    }

    fn scan_app(
        &self,
        app: &AppRecord,
        mode: ScanMode,
        source: CleanupSource,
        read_only_residuals: Vec<Proposal>,
        cancel: &Cancellation,
    ) -> Result<CleanupPlan> {
        cancel.check()?;
        if app.system_component {
            return Err(Error::Rejected(
                "system components cannot be scanned for removal".into(),
            ));
        }
        let scan = match &source {
            CleanupSource::Uninstalled { observed_files, .. } => self
                .require_post_uninstall_cleanup_state(app, observed_files, cancel)
                .and_then(|()| {
                    self.platform.scan_after_official_uninstall(
                        app,
                        observed_files,
                        PostUninstallScan::Preview,
                        cancel,
                    )
                }),
            _ => self.platform.scan(app, mode, cancel),
        };
        let scan = scan.and_then(|mut scan| {
            self.rules.suggest(&self.platform, app, &mut scan, cancel)?;
            scan.proposals.extend(read_only_residuals);
            Ok(scan)
        });
        self.event(app.name.clone(), "scan", status(&scan))?;
        self.review(scan?, mode, source, cancel)
    }

    fn require_post_uninstall_state(
        &self,
        app: &AppRecord,
        check: Option<&PostUninstallCheck>,
        cancel: &Cancellation,
    ) -> Result<()> {
        if !self
            .platform
            .verify_official_uninstall_absence(app, cancel)?
        {
            return Err(Error::Rejected(
                "the original installation could not be verified as absent".into(),
            ));
        }
        if let Some(check) = check {
            check(cancel)?;
        }
        Ok(())
    }

    fn require_post_uninstall_cleanup_state(
        &self,
        app: &AppRecord,
        observed_files: &HashMap<PathBuf, String>,
        cancel: &Cancellation,
    ) -> Result<()> {
        self.platform.check_cleanup_after_uninstall(app, cancel)?;
        self.platform
            .check_cleanup_observations(app, observed_files, cancel)
    }

    fn scan_after_uninstall(
        &self,
        app: &AppRecord,
        mut execution: OfficialExecution,
        outcome_audit_error: Option<Error>,
        verification_cancel: &Cancellation,
        cancel: &Cancellation,
    ) -> Result<UninstallReport> {
        // Supplemental display evidence never adds write access.
        for proposal in &mut execution.read_only_residuals {
            if proposal.access == Access::Allowed {
                proposal.access =
                    Access::ReadOnly("post-uninstall evidence is display-only".into());
            }
        }
        let mut report = UninstallReport {
            outcome: execution.outcome,
            cleanup: None,
            warnings: execution.warnings,
        };
        let mut audit_complete = outcome_audit_error.is_none();
        if let Some(error) = outcome_audit_error {
            report
                .warnings
                .push(format!("Could not record the uninstall outcome: {error}"));
        }
        if report.outcome == OfficialOutcome::Completed {
            let status = match self.require_post_uninstall_state(
                app,
                execution.post_uninstall_check.as_ref(),
                verification_cancel,
            ) {
                Ok(()) => "completed",
                Err(error) => {
                    report.outcome = OfficialOutcome::Unverified(0);
                    report.warnings.push(error.to_string());
                    "completion unverified"
                }
            };
            if let Err(error) = self.event(app.name.clone(), "verify_official_uninstall", status) {
                audit_complete = false;
                report.warnings.push(format!(
                    "Could not record the uninstall verification: {error}"
                ));
            }
        }
        // Native evidence establishes the reported outcome. Keep it visible
        // even when an incomplete audit prevents issuing a cleanup plan.
        if !audit_complete {
            report
                .warnings
                .push("Leftover cleanup is unavailable for this operation because its audit could not be saved.".into());
            return Ok(report);
        }
        if report.outcome != OfficialOutcome::Completed {
            if matches!(report.outcome, OfficialOutcome::Unverified(_))
                && !execution.read_only_residuals.is_empty()
            {
                let scan = Scan::new(
                    execution.read_only_residuals,
                    vec![
                        "The uninstall could not be verified. This preview is for inspection only."
                            .into(),
                    ],
                );
                match self.review(scan, ScanMode::Leftovers, CleanupSource::ReadOnly, cancel) {
                    Ok(plan) => report.cleanup = Some(plan),
                    Err(error) => report.warnings.push(error.to_string()),
                }
            }
            return Ok(report);
        }
        match self.scan_app(
            app,
            ScanMode::AfterOfficialUninstall,
            CleanupSource::Uninstalled {
                app: Box::new(app.clone()),
                observed_files: execution.observed_files,
                post_uninstall_check: execution.post_uninstall_check,
            },
            execution.read_only_residuals,
            cancel,
        ) {
            Ok(plan) => report.cleanup = Some(plan),
            Err(Error::Cancelled) => report
                .warnings
                .push("Leftover scan cancelled after uninstall completed.".into()),
            Err(error) => report.warnings.push(error.to_string()),
        }
        Ok(report)
    }

    fn review(
        &self,
        scan: Scan,
        mode: ScanMode,
        source: CleanupSource,
        cancel: &Cancellation,
    ) -> Result<CleanupPlan> {
        let mut entries: Vec<Reviewed> = Vec::new();
        let mut indices = HashMap::new();
        for proposal in scan.proposals {
            cancel.check()?;
            if let Some(index) = indices.get(&proposal.target).copied() {
                let existing: &mut Reviewed = &mut entries[index];
                if let Access::ReadOnly(reason) = proposal.access {
                    existing.candidate.access = Access::ReadOnly(reason);
                    existing.fingerprint = None;
                }
                existing.candidate.risk = existing.candidate.risk.max(proposal.risk);
                if proposal.evidence > existing.candidate.evidence {
                    existing.candidate.evidence = proposal.evidence;
                    existing.candidate.confidence = proposal.evidence.confidence();
                    existing.candidate.reason = proposal.reason;
                }
                continue;
            }
            indices.insert(proposal.target.clone(), entries.len());
            let observation = scan.observations.get(&proposal.target);
            let requires_guard = matches!(&proposal.target, Target::File(path)
                if scan.post_uninstall_file_guards.contains(path));
            entries.push(self.review_item(entries.len(), proposal, observation, requires_guard));
        }
        let id = Uuid::new_v4();
        let mut event = AuditEvent::new("cleanup candidates".into(), "dry_run", "ready");
        event.batch_id = Some(id);
        put_json(&self.journal, Uuid::new_v4(), Artifact::Event, &event)?;
        Ok(CleanupPlan {
            session: self.session,
            id,
            created: Instant::now(),
            entries,
            warnings: scan.warnings,
            mode,
            source,
            file_cleanup_application: scan.file_cleanup_application,
            force_removal_binding: scan.force_removal_binding,
        })
    }

    fn review_item(
        &self,
        id: usize,
        proposal: Proposal,
        observation: Option<&Option<String>>,
        requires_post_uninstall_file_guard: bool,
    ) -> Reviewed {
        let mut access = proposal.access;
        let mut fingerprint = None;
        if access == Access::Allowed {
            match self.inspect(&proposal.target) {
                Ok(inspection) => {
                    access = inspection.access;
                    if access == Access::Allowed {
                        if observation.is_none_or(|observed| {
                            observed.as_deref() == Some(inspection.fingerprint.as_str())
                        }) {
                            fingerprint = Some(inspection.fingerprint);
                        } else {
                            access = Access::ReadOnly(
                                "the inspected object differed from the scan observation".into(),
                            );
                        }
                    }
                }
                Err(error) => access = Access::ReadOnly(error.to_string()),
            }
        }
        let candidate = Candidate {
            id,
            target: proposal.target,
            category: proposal.category,
            evidence: proposal.evidence,
            confidence: proposal.evidence.confidence(),
            reason: proposal.reason,
            risk: proposal.risk,
            access,
        };
        Reviewed {
            candidate,
            fingerprint,
            observed_during_scan: observation.is_some(),
            requires_post_uninstall_file_guard,
        }
    }

    fn inspect(&self, target: &Target) -> Result<Inspection> {
        match target {
            Target::File(path) if valid_file_address(path) => {
                Ok(self.platform.inspect_file(path)?)
            }
            Target::Registry(key) if !is_protected_registry_target(key) => {
                Ok(self.platform.inspect_registry(key)?)
            }
            _ => Err(Error::Rejected(
                "target is protected or has no supported write address".into(),
            )),
        }
    }

    fn apply_item(
        &self,
        (batch, id): (Uuid, Uuid),
        target: Target,
        (fingerprint, requires_post_uninstall_file_guard): (&str, bool),
        checks: &CleanupChecks<'_>,
        cancel: &Cancellation,
    ) -> Result<()> {
        let current = self.inspect(&target)?;
        if current.access != Access::Allowed || current.fingerprint != fingerprint {
            return Err(Error::Rejected(
                "target identity or permission changed after preview".into(),
            ));
        }
        let backup_path = match &target {
            Target::File(path) => self.platform.file_backup_path(path, fingerprint, id)?,
            Target::Registry(_) => self.journal.location(id, Artifact::RegistryExport),
            Target::Reference(_) => return Err(Error::Rejected("references are read-only".into())),
        };
        let mut record = BackupRecord::new(
            (batch, id),
            target.clone(),
            fingerprint.into(),
            backup_path.display().to_string(),
            self.retention_days,
        );
        cancel.check()?;
        match &target {
            Target::File(path) => {
                self.stage_backup(&record)?;
                // Preparing durable intent can take time. Check the current
                // application state after it and before attempting a move.
                cancel.check()?;
                if let Some(application) = checks.file_application {
                    self.platform.check_file_cleanup_application(application)?;
                }
                if let Some(cleanup) = &checks.post_uninstall {
                    if cleanup.completion_check.is_some()
                        || self.platform.recheck_uninstall_absence_before_each_file()
                    {
                        self.require_post_uninstall_state(
                            cleanup.app,
                            cleanup.completion_check,
                            cancel,
                        )?;
                    }
                    self.require_post_uninstall_cleanup_state(
                        cleanup.app,
                        cleanup.observed_files,
                        cancel,
                    )?;
                }
                if let Some((app, binding)) = checks.force_removal {
                    self.platform
                        .check_force_removal_file(app, binding, path, cancel)?;
                }
                let _post_uninstall_file_guard = if requires_post_uninstall_file_guard {
                    let cleanup = checks.post_uninstall.as_ref().ok_or_else(|| {
                        Error::Rejected("the file guard requires a verified uninstall".into())
                    })?;
                    Some(self.platform.pin_post_uninstall_file(
                        cleanup.app,
                        path,
                        cleanup.observed_files,
                        cancel,
                    )?)
                } else {
                    None
                };
                if let Err(error) =
                    self.platform
                        .quarantine_file_with_cancel(path, &record.fingerprint, id, cancel)
                {
                    let reason = match file_move_error(error) {
                        Error::FileChangeNeedsReview(reason) => reason,
                        error => {
                            match self
                                .platform
                                .file_is_quarantined(path, &record.fingerprint, id)
                            {
                                Ok(false) => return Err(error),
                                Ok(true) => error.to_string(),
                                Err(check) => format!("{error}; backup check: {check}"),
                            }
                        }
                    };
                    // Standalone bundle quarantine also reaches this path,
                    // without the per-item batch reporter.
                    let event = record.event("cleanup", "needs_review");
                    if let Err(audit) =
                        put_json(&self.journal, id, Artifact::QuarantineNeedsReview, &event)
                    {
                        return Err(Error::FileChangeNeedsReview(format!(
                            "{reason}; could not record quarantine review state: {audit}"
                        )));
                    }
                    return Err(Error::FileChangeNeedsReview(reason));
                }
            }
            Target::Registry(key) => {
                if let Some(cleanup) = &checks.post_uninstall {
                    self.require_post_uninstall_cleanup_state(
                        cleanup.app,
                        cleanup.observed_files,
                        cancel,
                    )?;
                }
                if let Some((app, binding)) = checks.force_removal {
                    self.platform
                        .check_force_removal_binding(app, binding, cancel)?;
                }
                self.platform.remove_registry_with_receipt(
                    key,
                    fingerprint,
                    id,
                    &mut |export, snapshot| {
                        self.journal.create(id, Artifact::RegistryExport, export)?;
                        self.journal
                            .create(id, Artifact::RegistrySnapshot, snapshot)?;
                        record.registry_snapshot_digest = Some(Sha256::digest(snapshot).into());
                        self.stage_backup(&record).map_err(io::Error::other)?;
                        // Staging can take time. Recheck bound completion evidence
                        // before the backend attempts a registry mutation.
                        if let Some(cleanup) = &checks.post_uninstall {
                            if cleanup.completion_check.is_some() {
                                self.require_post_uninstall_state(
                                    cleanup.app,
                                    cleanup.completion_check,
                                    cancel,
                                )
                                .map_err(io::Error::other)?;
                            }
                            self.platform
                                .check_registry_cleanup_application(
                                    &cleanup.app.id,
                                    ScanMode::AfterOfficialUninstall,
                                    key,
                                    cancel,
                                )
                                .map_err(io::Error::other)?;
                        } else if let Some((app, _)) = checks.force_removal {
                            self.platform
                                .check_registry_cleanup_application(
                                    app,
                                    ScanMode::ForceRemoval,
                                    key,
                                    cancel,
                                )
                                .map_err(io::Error::other)?;
                        }
                        Ok(())
                    },
                )?;
            }
            Target::Reference(_) => return Err(Error::Rejected("references are read-only".into())),
        }
        self.record_outcome(&record, Artifact::Applied, "cleanup", "applied")
    }

    fn restore_item(&self, record: BackupRecord) -> Result<()> {
        let id = record.id;
        if BackupRecord::load(&self.journal, id)? != record {
            return Err(Error::Rejected(
                "backup manifest changed after preview".into(),
            ));
        }
        if self.summarize(&record)?.state != RecoveryState::Applied {
            return Err(Error::Rejected("backup state changed after preview".into()));
        }
        // Keep the first file restore intent addressable by backup ID so a
        // later session can distinguish an interrupted restore from a lost slot.
        let event_id = if matches!(&record.target, Target::File(_))
            && !self.has_receipt(&record, Artifact::Event, "restore", "starting")?
        {
            id
        } else {
            Uuid::new_v4()
        };
        put_json(
            &self.journal,
            event_id,
            Artifact::Event,
            &record.event("restore", "starting"),
        )?;
        match &record.target {
            Target::File(path) if valid_file_address(path) => {
                if let Err(error) = self.platform.restore_file(path, &record.fingerprint, id) {
                    let error = file_move_error(error.into());
                    if matches!(error, Error::FileChangeNeedsReview(_)) {
                        return Err(error);
                    }
                    let backup_intact = self
                        .platform
                        .file_is_quarantined(path, &record.fingerprint, id)
                        .and_then(|present| {
                            if present {
                                return Ok(true);
                            }
                            self.platform
                                .recoverable_detached_file_backup(path, &record.fingerprint, id)
                                .map(|path| path.is_some())
                        });
                    match backup_intact {
                        Ok(true) => return Err(error),
                        Ok(false) => return Err(Error::FileChangeNeedsReview(error.to_string())),
                        Err(check) => {
                            return Err(Error::FileChangeNeedsReview(format!(
                                "{error}; backup check: {check}"
                            )));
                        }
                    }
                }
            }
            Target::Registry(key) if !is_protected_registry_target(key) => {
                let snapshot = self.checked_registry_snapshot(&record)?;
                self.platform
                    .restore_registry_with_receipt(key, &snapshot, id)?;
            }
            _ => return Err(Error::Rejected("restore target is protected".into())),
        }
        self.record_outcome(&record, Artifact::Restored, "restore", "restored")
    }

    fn checked_registry_snapshot(&self, record: &BackupRecord) -> Result<Vec<u8>> {
        let snapshot = self
            .journal
            .read(record.id, Artifact::RegistrySnapshot)?
            .ok_or_else(|| Error::Rejected("the typed registry snapshot is missing".into()))?;
        if record.registry_snapshot_digest != Some(Sha256::digest(&snapshot).into()) {
            return Err(Error::Rejected(
                "registry backup failed its integrity check".into(),
            ));
        }
        Ok(snapshot)
    }

    fn summarize(&self, record: &BackupRecord) -> Result<BackupSummary> {
        let restored = self.has_receipt(record, Artifact::Restored, "restore", "restored")?;
        let applied = self.has_receipt(record, Artifact::Applied, "cleanup", "applied")?;
        let purged = self.has_receipt(record, Artifact::Purged, expiry::ACTION, expiry::PURGED)?;
        let mut detached_backup = None;
        let state = match &record.target {
            _ if purged && (!applied || restored) => RecoveryState::NeedsReview,
            _ if restored => RecoveryState::Restored,
            Target::File(path) if valid_file_address(path) => {
                let present =
                    self.platform
                        .file_is_quarantined(path, &record.fingerprint, record.id)?;
                if !present && applied && !purged {
                    detached_backup = self.platform.recoverable_detached_file_backup(
                        path,
                        &record.fingerprint,
                        record.id,
                    )?;
                }
                match (purged, present || detached_backup.is_some(), applied) {
                    (true, false, _) => RecoveryState::Purged,
                    (false, true, _) => RecoveryState::Applied,
                    (false, false, _)
                        if self.has_receipt(record, Artifact::Event, "restore", "starting")? =>
                    {
                        if self.platform.verify_file_restored(
                            path,
                            &record.fingerprint,
                            record.id,
                        )? {
                            self.record_outcome(record, Artifact::Restored, "restore", "restored")?;
                            RecoveryState::Restored
                        } else {
                            RecoveryState::NeedsReview
                        }
                    }
                    (_, _, true) => RecoveryState::NeedsReview,
                    _ if self.has_receipt(
                        record,
                        Artifact::QuarantineNeedsReview,
                        "cleanup",
                        "needs_review",
                    )? =>
                    {
                        RecoveryState::NeedsReview
                    }
                    _ => RecoveryState::Staged,
                }
            }
            Target::Registry(key) if !purged && !is_protected_registry_target(key) => {
                let snapshot = self.checked_registry_snapshot(record)?;
                match self
                    .platform
                    .registry_change_receipt(key, &snapshot, record.id)?
                {
                    Some(RegistryChangeReceipt::Restored) => RecoveryState::Restored,
                    Some(RegistryChangeReceipt::Applied) => RecoveryState::Applied,
                    None if applied => RecoveryState::Applied,
                    None => RecoveryState::NeedsReview,
                }
            }
            _ => RecoveryState::NeedsReview,
        };
        let mut summary = record.summary(state);
        if let Some(detached_backup) = detached_backup {
            summary.backup = detached_backup.display().to_string();
        }
        Ok(summary)
    }

    fn has_receipt(
        &self,
        record: &BackupRecord,
        artifact: Artifact,
        action: &str,
        result: &str,
    ) -> Result<bool> {
        let Some(event) = read_json::<AuditEvent>(&self.journal, record.id, artifact)? else {
            return Ok(false);
        };
        let matches =
            record.matches_event(&event) && event.action == action && event.result == result;
        if !matches && artifact == Artifact::Purged {
            return Err(Error::Rejected(
                "the purge receipt does not match this backup".into(),
            ));
        }
        if !matches && artifact == Artifact::QuarantineNeedsReview {
            return Err(Error::Rejected(
                "the quarantine review record does not match this backup".into(),
            ));
        }
        if !matches
            && matches!(&record.target, Target::Registry(_))
            && matches!(artifact, Artifact::Applied | Artifact::Restored)
        {
            return Err(Error::Rejected(
                "the registry change receipt does not match this backup".into(),
            ));
        }
        Ok(matches)
    }

    fn stage_backup(&self, record: &BackupRecord) -> Result<()> {
        put_json(&self.journal, record.id, Artifact::Manifest, record)?;
        put_json(
            &self.journal,
            Uuid::new_v4(),
            Artifact::Event,
            &record.event("cleanup", "staged"),
        )
    }

    fn record_outcome(
        &self,
        record: &BackupRecord,
        artifact: Artifact,
        action: &str,
        result: &str,
    ) -> Result<()> {
        let event = record.event(action, result);
        let written = put_json(&self.journal, record.id, artifact, &event);
        // Recovery can publish a terminal receipt while the original
        // operation is finishing. Require the same bound outcome.
        if matches!(artifact, Artifact::Restored | Artifact::Purged)
            && matches!(&written, Err(Error::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists)
            && self
                .has_receipt(record, artifact, action, result)
                .map_err(|error| Error::AuditAfterChange(error.to_string()))?
        {
            return Ok(());
        }
        written.map_err(|error| Error::AuditAfterChange(error.to_string()))
    }

    fn report_item(
        &self,
        ids: (Uuid, Uuid),
        target: &str,
        action: &str,
        result: Result<()>,
        success: ChangeResult,
    ) -> (Option<Uuid>, ChangeResult, bool) {
        let (batch, id) = ids;
        let Err(error) = result else {
            return (Some(id), success, true);
        };
        let after_change = matches!(
            error,
            Error::AuditAfterChange(_) | Error::FileChangeNeedsReview(_)
        );
        let message = error.to_string();
        let mut event =
            AuditEvent::new(target.into(), action, &crate::audit::error_outcome(&error));
        event.batch_id = Some(batch);
        event.operation_id = Some(id);
        let manifest = BackupRecord::load(&self.journal, id).ok();
        event.backup = manifest.as_ref().map(|record| record.backup.clone());
        let already_recorded = action == "cleanup"
            && matches!(error, Error::FileChangeNeedsReview(_))
            && manifest.as_ref().is_some_and(|record| {
                self.has_receipt(
                    record,
                    Artifact::QuarantineNeedsReview,
                    "cleanup",
                    "needs_review",
                )
                .is_ok_and(|present| present)
            });
        let audit = if already_recorded {
            Ok(())
        } else {
            put_json(&self.journal, Uuid::new_v4(), Artifact::Event, &event)
        };
        let audit_ok = audit.is_ok() && !after_change;
        let result = if let Err(error) = audit {
            ChangeResult::NeedsReview(format!("{message}; audit write failed: {error}"))
        } else if after_change {
            ChangeResult::NeedsReview(message)
        } else {
            ChangeResult::Skipped(message)
        };
        (manifest.map(|record| record.id), result, audit_ok)
    }

    fn report_unattempted(
        &self,
        batch_id: Uuid,
        target: String,
        action: &str,
        backup: Option<(Uuid, &str)>,
    ) -> ItemResult {
        let mut event = AuditEvent::new(
            target.clone(),
            action,
            AuditEvent::SKIPPED_AFTER_UNRESOLVED_CHANGE,
        );
        let backup_id = backup.map(|(id, _)| id);
        event.batch_id = Some(batch_id);
        event.operation_id = Some(backup_id.unwrap_or_else(Uuid::new_v4));
        event.backup = backup.map(|(_, path)| path.to_owned());
        let mut result = ChangeResult::skipped_after_unresolved_change();
        // A failed audit write leaves this object's outcome known. Nothing
        // attempted to change it or create another backup.
        if let (ChangeResult::Skipped(message), Err(error)) =
            (&mut result, self.record_external_audit_event(&event))
        {
            message.push_str(&format!(". Could not record the skip: {error}"));
        }
        ItemResult {
            target,
            backup_id,
            result,
        }
    }

    fn check_session(&self, session: Uuid, created: Instant) -> Result<()> {
        if session != self.session {
            return Err(Error::Rejected(
                "confirmation belongs to another session".into(),
            ));
        }
        check_age(created)
    }

    fn event(&self, object: String, action: &str, result: &str) -> Result<()> {
        put_json(
            &self.journal,
            Uuid::new_v4(),
            Artifact::Event,
            &AuditEvent::new(object, action, result),
        )
    }
}

fn file_move_error(error: Error) -> Error {
    if let Error::Io(cause) = &error {
        if let Some(Error::FileChangeNeedsReview(reason)) = cause
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<Error>())
        {
            return Error::FileChangeNeedsReview(reason.clone());
        }
    }
    error
}

fn check_age(created: Instant) -> Result<()> {
    if created.elapsed() >= CONFIRMATION_LIFETIME {
        return Err(Error::Rejected(
            "confirmation expired, generate a new preview".into(),
        ));
    }
    Ok(())
}

fn status<T>(result: &Result<T>) -> &str {
    if result.is_ok() {
        "succeeded"
    } else {
        "failed"
    }
}
