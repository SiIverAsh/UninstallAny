use std::{collections::HashSet, path::Path, time::Instant};

use uuid::Uuid;

use crate::{
    Artifact, AuditEvent, BackupSummary, Cancellation, ChangeReport, ChangeResult, Engine, Error,
    ItemResult, Journal, PlatformBackend, RecoveryState, Result, Target,
    policy::valid_file_address,
    state::{BackupRecord, now, put_json},
};

pub(super) const ACTION: &str = "purge_quarantine";
pub(super) const PURGED: &str = "purged";

/// Dry-run of expired backups eligible for permanent, individual removal.
pub struct ExpiryCleanupPlan {
    session: Uuid,
    batch_id: Uuid,
    created: Instant,
    entries: Vec<(BackupSummary, BackupRecord)>,
    warnings: Vec<String>,
}

impl ExpiryCleanupPlan {
    /// Lists the deletions that may be chosen from this review.
    pub fn items(&self) -> impl ExactSizeIterator<Item = &BackupSummary> {
        self.entries.iter().map(|(summary, _)| summary)
    }

    /// Reports individual backups that could not be checked.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Approves only the distinct reviewed backup IDs explicitly selected.
    pub fn confirm(mut self, selected: &[Uuid]) -> Result<ConfirmedExpiryCleanup> {
        super::check_age(self.created)?;
        let ids: HashSet<_> = selected.iter().copied().collect();
        if ids.is_empty() || ids.len() != selected.len() {
            return Err(Error::Rejected("select distinct expired backups".into()));
        }
        self.entries
            .retain(|(summary, _)| ids.contains(&summary.id));
        if self.entries.len() != ids.len() {
            return Err(Error::Rejected(
                "a selected backup is not in this expiry preview".into(),
            ));
        }
        Ok(ConfirmedExpiryCleanup(self))
    }
}

/// Single-use authorization for selected expired quarantine objects.
pub struct ConfirmedExpiryCleanup(ExpiryCleanupPlan);

/// The recorded expiry results and whether a later phase can safely run.
pub struct ExpiryCleanupStatus {
    /// An outcome for each selected backup, including unattempted entries.
    pub report: ChangeReport,
    /// Whether this batch avoided unresolved changes and audit write failures.
    pub can_continue: bool,
}

impl<P: PlatformBackend, J: Journal> Engine<P, J> {
    /// Reviews eligible expired backups without changing their contents.
    pub fn prepare_expiry_cleanup(&self, cancel: &Cancellation) -> Result<ExpiryCleanupPlan> {
        cancel.check()?;
        let mut entries = Vec::new();
        let mut warnings = Vec::new();
        let observed_at = now();
        for id in self.journal.manifests()? {
            cancel.check()?;
            match self.review_expired_backup(id, observed_at) {
                Ok(Some(entry)) => entries.push(entry),
                Ok(None) => {}
                Err(error) => warnings.push(format!("backup {id}: {error}")),
            }
        }
        entries.sort_unstable_by(|(left, _), (right, _)| {
            (&left.target, left.id).cmp(&(&right.target, right.id))
        });
        let batch_id = Uuid::new_v4();
        let mut event = AuditEvent::new(
            "expired quarantine backups".into(),
            "dry_run_expiry",
            "ready",
        );
        event.batch_id = Some(batch_id);
        put_json(&self.journal, Uuid::new_v4(), Artifact::Event, &event)?;
        Ok(ExpiryCleanupPlan {
            session: self.session,
            batch_id,
            created: Instant::now(),
            entries,
            warnings,
        })
    }

    /// Permanently removes the approved expired backups and records each result.
    pub fn apply_expiry_cleanup(
        &self,
        confirmed: ConfirmedExpiryCleanup,
        cancel: &Cancellation,
    ) -> Result<ChangeReport> {
        self.apply_expiry_cleanup_with_status(confirmed, cancel)
            .map(|outcome| outcome.report)
    }

    /// Applies newly confirmed expiry changes and preserves the batch stop decision.
    pub fn apply_expiry_cleanup_with_status(
        &self,
        confirmed: ConfirmedExpiryCleanup,
        cancel: &Cancellation,
    ) -> Result<ExpiryCleanupStatus> {
        let plan = confirmed.0;
        self.check_session(plan.session, plan.created)?;
        let _mutation = self.platform.begin_mutation(cancel)?;
        let mut report = ChangeReport {
            batch_id: plan.batch_id,
            items: Vec::new(),
        };
        let mut can_continue = true;
        for (summary, record) in plan.entries {
            if !can_continue {
                report.items.push(self.report_unattempted(
                    report.batch_id,
                    summary.target,
                    ACTION,
                    Some((record.id, &record.backup)),
                ));
                continue;
            }
            let outcome = cancel.check().and_then(|()| {
                let path = self.recheck_expiry_target(&record)?;
                let mut staged = record.event(ACTION, "starting");
                staged.batch_id = Some(plan.batch_id);
                if let Err(error) =
                    put_json(&self.journal, Uuid::new_v4(), Artifact::Event, &staged)
                {
                    // Do not continue to another deletion with a journal
                    // that could not durably record the required intent.
                    can_continue = false;
                    return Err(error);
                }
                self.purge_item(path, &record)
            });
            let (backup_id, result, audit_ok) = self.report_item(
                (plan.batch_id, record.id),
                &summary.target,
                ACTION,
                outcome,
                ChangeResult::Purged,
            );
            can_continue &= audit_ok;
            report.items.push(ItemResult {
                target: summary.target,
                backup_id,
                result,
            });
        }
        Ok(ExpiryCleanupStatus {
            report,
            can_continue,
        })
    }

    fn review_expired_backup(
        &self,
        id: Uuid,
        timestamp: u64,
    ) -> Result<Option<(BackupSummary, BackupRecord)>> {
        let record = BackupRecord::load(&self.journal, id)?;
        Ok(self
            .check_expiry(&record, timestamp)?
            .map(|summary| (summary, record)))
    }

    fn check_expiry(&self, record: &BackupRecord, timestamp: u64) -> Result<Option<BackupSummary>> {
        let Target::File(path) = &record.target else {
            return Ok(None);
        };
        if record.expires_unix_ms == 0
            || record.expires_unix_ms > timestamp
            || !valid_file_address(path)
        {
            return Ok(None);
        }
        // Recovery can infer a completed quarantine from the file alone after a crash.
        // Permanent removal requires the original operation receipt as separate evidence.
        if !self.has_receipt(record, Artifact::Applied, "cleanup", "applied")? {
            return Ok(None);
        }
        let summary = self.summarize(record)?;
        let eligible = match summary.state {
            RecoveryState::Applied => {
                self.platform
                    .can_purge_quarantined(path, &record.fingerprint, record.id)?
                    || self.platform.has_pending_quarantine_purge(
                        path,
                        &record.fingerprint,
                        record.id,
                    )?
            }
            // Once a backend detaches a directory for disposal, the ordinary
            // slot cannot prove restoration. Only its durable state can
            // qualify the interrupted purge for a new confirmation.
            RecoveryState::NeedsReview => {
                self.journal.read(record.id, Artifact::Purged)?.is_none()
                    && self.journal.read(record.id, Artifact::Restored)?.is_none()
                    && self.platform.has_pending_quarantine_purge(
                        path,
                        &record.fingerprint,
                        record.id,
                    )?
            }
            _ => false,
        };
        if !eligible {
            return Ok(None);
        }
        // The backend resolves the private slot from the operation ID and
        // validates the held object. The manifest's display path is audit data.
        Ok(Some(summary))
    }

    fn recheck_expiry_target<'a>(&self, record: &'a BackupRecord) -> Result<&'a Path> {
        let Target::File(path) = &record.target else {
            return Err(Error::Rejected(
                "this backup has no purgeable file address".into(),
            ));
        };
        if BackupRecord::load(&self.journal, record.id)? != *record {
            return Err(Error::Rejected(
                "backup manifest changed after preview".into(),
            ));
        }
        if self.check_expiry(record, now())?.is_none() {
            return Err(Error::Rejected(
                "backup is no longer eligible for expiry cleanup".into(),
            ));
        }
        Ok(path)
    }

    fn purge_item(&self, path: &Path, record: &BackupRecord) -> Result<()> {
        if let Err(error) = self
            .platform
            .purge_quarantined(path, &record.fingerprint, record.id)
        {
            match self
                .platform
                .file_is_quarantined(path, &record.fingerprint, record.id)
            {
                Ok(true) => return Err(error.into()),
                Ok(false) => return Err(Error::FileChangeNeedsReview(error.to_string())),
                Err(check) => {
                    return Err(Error::FileChangeNeedsReview(format!(
                        "{error}; backup check: {check}"
                    )));
                }
            }
        }
        self.record_outcome(record, Artifact::Purged, ACTION, PURGED)
    }
}
