use std::{
    collections::{HashMap, HashSet},
    num::NonZeroU16,
    path::Path,
};

#[cfg(windows)]
use uninstallany_core::Access;
#[cfg(not(all(target_os = "macos", feature = "macos-privileged-helper")))]
use uninstallany_core::ExpiryCleanupPlan as ExpiryPlan;
use uninstallany_core::{
    AppId, Cancellation, ChangeReport, ChangeResult, CleanupAttempt, CleanupPlan, Engine, Error,
    Journal, LoadedPreferences, OfficialOutcome, PlatformBackend, PreparedUninstall, RestorePlan,
    Result,
};
#[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
use uninstallany_core::{BackupInventory, RecoveryState};
#[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
use uninstallany_macos::{
    MacExpiryPlan as ExpiryPlan, SystemRestoreReview, prepare_system_helper_activation,
    prepare_system_restore, read_system_backups,
};
use uuid::Uuid;

use crate::dto::{
    AuditExportedPayload, BackupInventoryPayload, ChangeReportPayload, CleanupPreview,
    ExpiryReviewPayload, InventoryPayload, LoadedPreferencesPayload, OfficialRow,
    RestoreReviewPayload, RulesSavedPayload, UninstallReviewPayload,
};
#[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
use crate::helper_activation::{
    HelperActivationPreviewPayload, HelperActivationReportPayload, HelperActivationTicket,
};

#[cfg(test)]
mod tests;

struct UninstallReview<Command> {
    ticket: Uuid,
    actions: Vec<PreparedUninstall<Command>>,
}

struct RestoreReview {
    ticket: Uuid,
    action: RestoreAction,
}

struct ExpiryReview {
    ticket: Uuid,
    plan: ExpiryPlan,
}

enum RestoreAction {
    Local(RestorePlan),
    #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
    System(Box<SystemRestoreReview>),
}

/// Owns the native engine and the previews that can authorize its operations.
pub(crate) struct Session<P: PlatformBackend, J> {
    engine: Engine<P, J>,
    preferences: std::result::Result<LoadedPreferences, String>,
    uninstall: Option<UninstallReview<P::Official>>,
    cleanup: HashMap<Uuid, CleanupPlan>,
    restore: Option<RestoreReview>,
    expiry: Option<ExpiryReview>,
    #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
    system_backup_ids: HashSet<Uuid>,
    #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
    helper_activation: Option<HelperActivationTicket>,
}

impl<P: PlatformBackend, J: Journal> Session<P, J> {
    /// Opens the session even if preferences are temporarily unreadable.
    pub(crate) fn new(mut engine: Engine<P, J>) -> Self {
        let preferences = read_preferences(&mut engine);
        Self {
            engine,
            preferences,
            uninstall: None,
            cleanup: HashMap::new(),
            restore: None,
            expiry: None,
            #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
            system_backup_ids: HashSet::new(),
            #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
            helper_activation: None,
        }
    }

    /// Lists applications, including marked system components for UI filtering.
    pub(crate) fn list_applications(&mut self, cancel: &Cancellation) -> Result<InventoryPayload> {
        cancel.check()?;
        if self.preferences.is_err() {
            self.preferences = read_preferences(&mut self.engine);
        }
        let mut inventory = self.engine.inventory(true, cancel)?;
        if let Err(error) = &self.preferences {
            for app in &mut inventory.applications {
                app.official_uninstall_available = false;
            }
            inventory.warnings.push(error.clone());
        }
        Ok(inventory.into())
    }

    /// Returns the active startup settings and any warnings from loading them.
    pub(crate) fn load_preferences(
        &self,
        cancel: &Cancellation,
    ) -> Result<LoadedPreferencesPayload> {
        cancel.check()?;
        self.require_preferences().map(Into::into)
    }

    /// Persists the retention period for newly quarantined items.
    pub(crate) fn set_retention(&mut self, days: NonZeroU16, cancel: &Cancellation) -> Result<u16> {
        cancel.check()?;
        let preferences = self
            .preferences
            .as_mut()
            .map_err(|error| Error::Rejected(error.clone()))?;
        self.engine.persist_retention(days)?;
        if preferences.retention_days != days {
            // A signed-helper uninstall review may promise the previous deadline.
            self.uninstall = None;
        }
        preferences.retention_days = days;
        Ok(days.get())
    }

    /// Validates and saves rules for future scans.
    pub(crate) fn set_custom_rules(
        &mut self,
        text: String,
        cancel: &Cancellation,
    ) -> Result<RulesSavedPayload> {
        cancel.check()?;
        let preferences = self
            .preferences
            .as_mut()
            .map_err(|error| Error::Rejected(error.clone()))?;
        let count = self.engine.persist_custom_rules(text.clone())?;
        preferences.custom_rules = if text.trim().is_empty() {
            String::new()
        } else {
            text.clone()
        };
        // Echo the accepted input so a whitespace-only edit is marked saved.
        Ok(RulesSavedPayload { text, count })
    }

    /// Exports the local audit journal to a new file.
    pub(crate) fn export_audit(
        &self,
        path: &Path,
        cancel: &Cancellation,
    ) -> Result<AuditExportedPayload> {
        cancel.check()?;
        self.require_preferences()?;
        let report = self.engine.export_audit(path, cancel)?;
        Ok(AuditExportedPayload::new(path, report))
    }

    /// Previews only the helper registration needed by a selected system app.
    #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
    pub(crate) fn review_helper_activation(
        &mut self,
        app: &AppId,
        cancel: &Cancellation,
    ) -> Result<HelperActivationPreviewPayload> {
        cancel.check()?;
        self.require_preferences()?;
        self.helper_activation = None;
        let activation =
            HelperActivationTicket::new(prepare_system_helper_activation(app, cancel)?);
        cancel.check()?;
        self.engine
            .record_external_audit_event(&activation.audit_preview())?;
        let preview = activation.preview();
        self.helper_activation = Some(activation);
        Ok(preview)
    }

    /// Consumes the separate activation approval without running an uninstall.
    #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
    pub(crate) fn run_helper_activation(
        &mut self,
        ticket: Uuid,
        cancel: &Cancellation,
    ) -> Result<HelperActivationReportPayload> {
        cancel.check()?;
        self.require_preferences()?;
        let activation = self
            .helper_activation
            .take_if(|review| review.id() == ticket)
            .ok_or_else(missing_review)?;
        // Any subsequent system uninstall needs a fresh signed-helper preview.
        self.uninstall = None;
        activation.run(cancel, &|event| {
            self.engine.record_external_audit_event(event)
        })
    }

    /// Reviews distinct application IDs and retains the resulting native actions.
    pub(crate) fn review_uninstall(
        &mut self,
        apps: Vec<AppId>,
        cancel: &Cancellation,
    ) -> Result<UninstallReviewPayload> {
        cancel.check()?;
        self.require_preferences()?;
        self.uninstall = None;
        let mut actions = Vec::new();
        let mut warnings = Vec::new();
        let mut seen = HashSet::new();
        for app in &apps {
            if !seen.insert(app) {
                continue;
            }
            match self.engine.prepare_uninstall(app, cancel) {
                Ok(action) => actions.push(action),
                Err(Error::Cancelled) => return Err(Error::Cancelled),
                Err(error) => warnings.push(error.to_string()),
            }
        }
        cancel.check()?;
        if actions.is_empty() {
            let reason = if warnings.is_empty() {
                "Select at least one application to uninstall.".into()
            } else {
                warnings.join("\n")
            };
            return Err(Error::Rejected(reason));
        }
        let ticket = Uuid::new_v4();
        let preview = UninstallReviewPayload::new(
            ticket,
            actions.iter().map(PreparedUninstall::intent),
            warnings,
        );
        self.uninstall = Some(UninstallReview { ticket, actions });
        Ok(preview)
    }

    /// Consumes the approved queue and returns each outcome and leftover preview.
    pub(crate) fn run_uninstall(
        &mut self,
        ticket: Uuid,
        cancel: &Cancellation,
        mut progress: impl FnMut(usize, usize),
    ) -> Result<Vec<OfficialRow>> {
        cancel.check()?;
        self.require_preferences()?;
        let review = self
            .uninstall
            .take_if(|review| review.ticket == ticket)
            .ok_or_else(missing_review)?;
        self.cleanup.clear();
        let total = review.actions.len();
        let mut rows = Vec::with_capacity(total);
        progress(0, total);
        for action in review.actions {
            let application = action.intent().application.clone();
            let result = cancel
                .check()
                .and_then(|()| action.confirm())
                .and_then(|confirmed| self.engine.run_uninstall(confirmed, cancel));
            let (outcome, cleanup, warnings) = match result {
                Ok(report) => {
                    let mut warnings = report.warnings;
                    let cleanup = match report.cleanup {
                        Some(plan) if plan.candidates().next().is_some() => {
                            let preview = CleanupPreview::new(&plan, Some(application.clone()));
                            self.cleanup.insert(plan.id(), plan);
                            Some(preview)
                        }
                        Some(plan) => {
                            // The existing UI queues every preview for a decision.
                            // Keep scan diagnostics visible without an empty step.
                            warnings.extend_from_slice(plan.warnings());
                            None
                        }
                        None => None,
                    };
                    (Ok(report.outcome), cleanup, warnings)
                }
                Err(Error::Cancelled) => (Ok(OfficialOutcome::Cancelled), None, Vec::new()),
                Err(error) => (Err(error.to_string()), None, Vec::new()),
            };
            rows.push(OfficialRow::new(application, outcome, cleanup, warnings));
            progress(rows.len(), total);
        }
        Ok(rows)
    }

    /// Previews leftovers in a Windows portable directory without changing files.
    #[cfg(windows)]
    pub(crate) fn scan_portable(
        &mut self,
        path: &Path,
        cancel: &Cancellation,
    ) -> Result<CleanupPreview> {
        cancel.check()?;
        self.require_preferences()?;
        let plan = self.engine.scan_portable(path, cancel)?;
        let subject = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned());
        self.replace_cleanup_preview(plan, subject, cancel)
    }

    /// Previews Windows force removal without running a vendor uninstaller.
    #[cfg(windows)]
    pub(crate) fn scan_force_removal(
        &mut self,
        app: &AppId,
        cancel: &Cancellation,
    ) -> Result<CleanupPreview> {
        cancel.check()?;
        self.require_preferences()?;
        let plan = self.engine.force_removal(app, cancel)?;
        self.replace_cleanup_preview(plan, None, cancel)
    }

    #[cfg(windows)]
    fn replace_cleanup_preview(
        &mut self,
        plan: CleanupPlan,
        subject: Option<String>,
        cancel: &Cancellation,
    ) -> Result<CleanupPreview> {
        let preview = CleanupPreview::new(&plan, subject);
        let has_writable = plan
            .candidates()
            .any(|candidate| candidate.access == Access::Allowed);
        cancel.check()?;
        // A successful standalone scan replaces the frontend's cleanup queue.
        self.cleanup.clear();
        if has_writable {
            self.cleanup.insert(plan.id(), plan);
        }
        Ok(preview)
    }

    /// Applies approved items and keeps a live preview when preflight can be retried.
    pub(crate) fn apply_cleanup(
        &mut self,
        plan_id: Uuid,
        items: &[usize],
        cancel: &Cancellation,
    ) -> Result<ChangeReportPayload> {
        cancel.check()?;
        self.require_preferences()?;
        let plan = self.cleanup.remove(&plan_id).ok_or_else(missing_review)?;
        match self.engine.apply_cleanup_preview(plan, items, cancel)? {
            CleanupAttempt::Reported(report) => Ok(report.into()),
            CleanupAttempt::RetryableBeforeApply { plan, error } => {
                self.cleanup.insert(plan_id, *plan);
                Err(error)
            }
        }
    }

    /// Lists retained backups and warnings from recovery inspection.
    pub(crate) fn list_backups(&mut self, cancel: &Cancellation) -> Result<BackupInventoryPayload> {
        cancel.check()?;
        let inventory = self.engine.backups()?;
        #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
        let inventory =
            self.merge_system_backups(inventory, read_system_backups(cancel)?.inventory);
        Ok(inventory.into())
    }

    /// Reviews expired backups without deleting their contents.
    pub(crate) fn review_expiry(&mut self, cancel: &Cancellation) -> Result<ExpiryReviewPayload> {
        cancel.check()?;
        self.require_preferences()?;
        self.expiry = None;
        #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
        let plan = ExpiryPlan::prepare(&self.engine, cancel)?;
        #[cfg(not(all(target_os = "macos", feature = "macos-privileged-helper")))]
        let plan = self.engine.prepare_expiry_cleanup(cancel)?;
        cancel.check()?;
        let ticket = Uuid::new_v4();
        #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
        let entries = plan.items().iter();
        #[cfg(not(all(target_os = "macos", feature = "macos-privileged-helper")))]
        let entries = plan.items();
        let has_entries = entries.len() != 0;
        let preview = ExpiryReviewPayload::new(ticket, entries, plan.warnings());
        if has_entries {
            self.expiry = Some(ExpiryReview { ticket, plan });
        }
        Ok(preview)
    }

    /// Consumes the review and removes only the explicitly selected backups.
    pub(crate) fn purge_expired(
        &mut self,
        ticket: Uuid,
        items: Vec<Uuid>,
        cancel: &Cancellation,
    ) -> Result<ChangeReportPayload> {
        cancel.check()?;
        self.require_preferences()?;
        let review = self
            .expiry
            .take_if(|review| review.ticket == ticket)
            .ok_or_else(missing_review)?;
        #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
        let report = review.plan.apply(&self.engine, ticket, items, cancel)?;
        #[cfg(not(all(target_os = "macos", feature = "macos-privileged-helper")))]
        let report = self
            .engine
            .apply_expiry_cleanup(review.plan.confirm(&items)?, cancel)?;
        expiry_response(report)
    }

    /// Previews the recoverable entries of a single backup batch.
    pub(crate) fn review_restore(
        &mut self,
        batch_id: Uuid,
        cancel: &Cancellation,
    ) -> Result<RestoreReviewPayload> {
        cancel.check()?;
        self.restore = None;
        #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
        if self.system_backup_ids.contains(&batch_id) {
            return self.review_system_restore(batch_id, cancel);
        }
        let plan = self.engine.prepare_restore(batch_id)?;
        cancel.check()?;
        let ticket = Uuid::new_v4();
        let preview = RestoreReviewPayload::new(ticket, &plan);
        if plan.entries().next().is_some() {
            self.restore = Some(RestoreReview {
                ticket,
                action: RestoreAction::Local(plan),
            });
        }
        Ok(preview)
    }

    /// Consumes a confirmed restore ticket and restores the reviewed entries.
    pub(crate) fn run_restore(
        &mut self,
        ticket: Uuid,
        cancel: &Cancellation,
    ) -> Result<ChangeReportPayload> {
        cancel.check()?;
        let review = self
            .restore
            .take_if(|review| review.ticket == ticket)
            .ok_or_else(missing_review)?;
        match review.action {
            RestoreAction::Local(plan) => self.engine.restore(plan.confirm()?, cancel),
            #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
            RestoreAction::System(review) => self.run_system_restore(*review, cancel),
        }
        .map(Into::into)
    }

    #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
    fn merge_system_backups(
        &mut self,
        mut local: BackupInventory,
        system: BackupInventory,
    ) -> BackupInventory {
        let local_ids = local
            .items
            .iter()
            .flat_map(|backup| [backup.id, backup.batch_id])
            .collect::<HashSet<_>>();
        for backup in &mut local.items {
            if self.system_backup_ids.contains(&backup.batch_id) {
                backup.state = RecoveryState::NeedsReview;
            }
        }
        local.warnings.extend(system.warnings);
        for backup in system.items {
            if local_ids.contains(&backup.id) {
                local.warnings.push(format!(
                    "System backup {} shares an identifier with a local backup and was omitted.",
                    backup.id,
                ));
                continue;
            }
            // Remember the origin of old previews so a refresh cannot route
            // a stale system backup click to a local restore.
            self.system_backup_ids.insert(backup.id);
            local.items.push(backup);
        }
        local
    }

    #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
    fn review_system_restore(
        &mut self,
        operation: Uuid,
        cancel: &Cancellation,
    ) -> Result<RestoreReviewPayload> {
        if self
            .engine
            .backups()?
            .items
            .iter()
            .any(|backup| backup.id == operation || backup.batch_id == operation)
        {
            return Err(Error::Rejected(
                "The selected system backup conflicts with a local backup ID.".into(),
            ));
        }
        cancel.check()?;
        let review = prepare_system_restore(operation)?;
        cancel.check()?;
        self.engine
            .record_external_audit_event(&review.audit_preview())?;
        let ticket = Uuid::new_v4();
        let preview = RestoreReviewPayload::from_entries(
            ticket,
            [review.summary().clone()],
            vec!["Restoring this system backup requires macOS administrator approval.".into()],
        );
        self.restore = Some(RestoreReview {
            ticket,
            action: RestoreAction::System(Box::new(review)),
        });
        Ok(preview)
    }

    #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
    fn run_system_restore(
        &self,
        review: SystemRestoreReview,
        cancel: &Cancellation,
    ) -> Result<ChangeReport> {
        let batch_id = review.summary().batch_id;
        let item = review.run(cancel, &|event| {
            self.engine.record_external_audit_event(event)
        });
        // The existing frontend treats a successful IPC response as a restore.
        // Only return one after the helper and local audit confirm completion.
        match item.result {
            ChangeResult::Restored => Ok(ChangeReport {
                batch_id,
                items: vec![item],
            }),
            ChangeResult::Skipped(reason) | ChangeResult::NeedsReview(reason) => {
                Err(Error::Rejected(reason))
            }
            ChangeResult::Applied | ChangeResult::Purged => Err(Error::Rejected(
                "The system backup restore did not return a restore result.".into(),
            )),
        }
    }

    // Loaded policy is required for new removals. Restore targets are bound
    // to an existing backup manifest and independently checked by the engine.
    fn require_preferences(&self) -> Result<&LoadedPreferences> {
        self.preferences
            .as_ref()
            .map_err(|error| Error::Rejected(error.clone()))
    }
}

fn read_preferences<P: PlatformBackend, J: Journal>(
    engine: &mut Engine<P, J>,
) -> std::result::Result<LoadedPreferences, String> {
    engine.restore_preferences().map_err(|error| {
        format!(
            "Could not load preferences: {error}. Uninstall and cleanup are unavailable. \
             Refresh the application list to retry."
        )
    })
}

fn missing_review() -> Error {
    Error::Rejected("This preview is no longer available. Review the current items again.".into())
}

fn expiry_response(report: ChangeReport) -> Result<ChangeReportPayload> {
    let (mut purged, mut skipped, mut needs_review) = (0, 0, 0);
    for item in &report.items {
        match item.result {
            ChangeResult::Purged => purged += 1,
            ChangeResult::Skipped(_) => skipped += 1,
            _ => needs_review += 1,
        }
    }
    // The current frontend counts every item in a success response as deleted.
    // An incomplete batch must report the observed counts instead.
    if purged > 0 && skipped == 0 && needs_review == 0 {
        return Ok(report.into());
    }
    Err(Error::Rejected(format!(
        "Expired backup cleanup: {purged} permanently removed, {skipped} skipped, \
         {needs_review} require review. Refresh the quarantine list before retrying."
    )))
}
