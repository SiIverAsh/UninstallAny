//! Adapts signed macOS quarantine reviews to the desktop worker.

use std::{fmt, io, num::NonZeroU16, path::Path};

use uninstallany_core::{
    Access, AuditEvent, Cancellation, Candidate, Category, ChangeReport, ChangeResult, Error,
    ItemResult, MatchKind, Result, Risk, ScanMode, Target,
};
use uninstallany_macos::{
    PrivilegedQuarantineOutcome, PrivilegedQuarantineStatus, PrivilegedStandaloneQuarantinePreview,
    prepare_selected_system_application, quarantine_privileged_standalone_application,
};
use uuid::Uuid;

use super::CleanupPreview;

pub(super) use uninstallany_macos::{
    SystemRestoreReview as NativeRestoreReview, prepare_system_restore as prepare_restore,
};

const SELECTED_BUNDLE_ITEM: usize = 0;
const QUARANTINE_ACTION: &str = "macos_system_quarantine";

pub(super) struct NativeQuarantineReview(PrivilegedStandaloneQuarantinePreview);

pub(super) fn prepare_quarantine(
    path: &Path,
    retention_days: NonZeroU16,
    cancel: &Cancellation,
) -> Result<Option<(CleanupPreview, NativeQuarantineReview)>> {
    let Some(review) = prepare_selected_system_application(path, retention_days, cancel)? else {
        return Ok(None);
    };
    let evidence = MatchKind::ExactIdentity;
    let preview = CleanupPreview {
        id: review.operation_id(),
        candidates: vec![Candidate {
            id: SELECTED_BUNDLE_ITEM,
            target: Target::File(review.path().to_owned()),
            category: Category::Directory,
            confidence: evidence.confidence(),
            evidence,
            reason: format!(
                "System-owned app requiring macOS administrator approval ({}).",
                review.bundle_identifier(),
            ),
            risk: Risk::High,
            access: Access::Allowed,
        }],
        mode: ScanMode::Leftovers,
        warnings: vec![format!(
            "Quarantine moves the complete application bundle and keeps it for {} days. Confirm this was installed as a standalone app.",
            review.retention_days(),
        )],
    };
    Ok(Some((preview, NativeQuarantineReview(review))))
}

impl NativeQuarantineReview {
    pub(super) fn audit_preview(&self) -> AuditEvent {
        let target = self.0.path().display().to_string();
        quarantine_audit(self.0.operation_id(), &target).event("reviewed")
    }

    pub(super) fn run(
        self,
        items: &[usize],
        cancel: &Cancellation,
        record: &impl Fn(&AuditEvent) -> Result<()>,
    ) -> Result<ChangeReport> {
        if items != [SELECTED_BUNDLE_ITEM] {
            return Err(Error::Rejected(
                "select the reviewed application bundle".into(),
            ));
        }
        let operation = self.0.operation_id();
        let target = self.0.path().display().to_string();
        let result = quarantine_audit(operation, &target).run(
            cancel,
            record,
            || {
                self.0
                    .confirm()
                    .and_then(quarantine_privileged_standalone_application)
            },
            quarantine_result,
        );
        let backup_id = (!matches!(&result, ChangeResult::Skipped(_))).then_some(operation);
        Ok(ChangeReport {
            batch_id: operation,
            items: vec![ItemResult {
                target,
                backup_id,
                result,
            }],
        })
    }
}

fn quarantine_audit(operation: Uuid, target: &str) -> NativeBackupAudit<'_> {
    NativeBackupAudit {
        operation,
        action: QUARANTINE_ACTION,
        target,
        backup: None,
    }
}

fn quarantine_result(outcome: PrivilegedQuarantineOutcome, event: &mut AuditEvent) -> ChangeResult {
    match outcome {
        PrivilegedQuarantineOutcome::Quarantined(receipt) => {
            event.result = "applied".into();
            record_backup(event, &receipt);
            ChangeResult::Applied
        }
        PrivilegedQuarantineOutcome::ReviewRequired(receipt) => {
            event.result = "needs_review".into();
            record_backup(event, &receipt);
            review_receipt(receipt, "The quarantine outcome is ambiguous.")
        }
        PrivilegedQuarantineOutcome::ReplyUncertain {
            operation_id,
            error,
        } => {
            event.result = "reply_uncertain".into();
            needs_review(operation_id, error)
        }
    }
}

struct NativeBackupAudit<'a> {
    operation: Uuid,
    action: &'static str,
    target: &'a str,
    backup: Option<&'a str>,
}

impl<'a> NativeBackupAudit<'a> {
    fn event(&self, status: &str) -> AuditEvent {
        let mut event = AuditEvent::new(self.target.to_owned(), self.action, status);
        event.batch_id = Some(self.operation);
        event.operation_id = Some(self.operation);
        event.backup = self.backup.map(str::to_owned);
        event
    }

    fn run<T>(
        &self,
        cancel: &Cancellation,
        record: &impl Fn(&AuditEvent) -> Result<()>,
        apply: impl FnOnce() -> io::Result<T>,
        summarize: impl FnOnce(T, &mut AuditEvent) -> ChangeResult,
    ) -> ChangeResult {
        if let Err(error) = cancel.check() {
            return self.finish(
                self.event("cancelled"),
                ChangeResult::Skipped(error.to_string()),
                record,
            );
        }
        // Keep durable intent before invoking the independent signed helper.
        if let Err(error) = record(&self.event("starting")) {
            return ChangeResult::Skipped(format!(
                "Could not record the start of the change: {error}"
            ));
        }
        let outcome = cancel.check().and_then(|()| apply().map_err(Error::from));
        let mut event = self.event("skipped");
        let result = match outcome {
            Ok(outcome) => summarize(outcome, &mut event),
            Err(Error::Cancelled) => {
                event.result = "cancelled".into();
                ChangeResult::Skipped(Error::Cancelled.to_string())
            }
            Err(error) => ChangeResult::Skipped(error.to_string()),
        };
        self.finish(event, result, record)
    }

    fn finish(
        &self,
        event: AuditEvent,
        result: ChangeResult,
        record: &impl Fn(&AuditEvent) -> Result<()>,
    ) -> ChangeResult {
        let Err(error) = record(&event) else {
            return result;
        };
        let audit_failure = format!("The local audit write failed: {error}");
        match result {
            ChangeResult::Skipped(detail) => {
                ChangeResult::Skipped(format!("{detail} {audit_failure}"))
            }
            ChangeResult::NeedsReview(detail) => {
                ChangeResult::NeedsReview(format!("{detail} {audit_failure}"))
            }
            ChangeResult::Applied | ChangeResult::Restored | ChangeResult::Purged => needs_review(
                self.operation,
                format_args!(
                    "The helper reported completion ({}). {audit_failure}",
                    event.result
                ),
            ),
        }
    }
}

fn record_backup(event: &mut AuditEvent, receipt: &PrivilegedQuarantineStatus) {
    if let Some(record) = &receipt.record {
        event.backup = Some(record.backup_path.display().to_string());
    }
}

fn review_receipt(receipt: PrivilegedQuarantineStatus, detail: &str) -> ChangeResult {
    if receipt.os_error > 0 {
        let error = io::Error::from_raw_os_error(receipt.os_error);
        needs_review(receipt.operation_id, format_args!("{detail} {error}"))
    } else {
        needs_review(receipt.operation_id, detail)
    }
}

fn needs_review(operation_id: Uuid, detail: impl fmt::Display) -> ChangeResult {
    ChangeResult::NeedsReview(format!(
        "{detail} Review backup {operation_id} before retrying."
    ))
}
