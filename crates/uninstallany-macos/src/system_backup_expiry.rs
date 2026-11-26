//! Review and audit adapter for expiry through the signed macOS helper.

use std::{fmt, io};

use uninstallany_core::{
    AuditEvent, BackupSummary, Cancellation, ChangeResult, Error, ItemResult, RecoveryState, Result,
};
use uuid::Uuid;

use crate::{
    ConfirmedPrivilegedExpiry, PrivilegedExpiryOutcome, PrivilegedExpiryPreview,
    PrivilegedQuarantineStatus, expire_privileged_quarantine, preview_privileged_expiry,
};

const EXPIRY_ACTION: &str = "macos_system_purge_quarantine";

/// Display metadata and the private, single-use helper preview it describes.
pub struct SystemExpiryReview {
    summary: BackupSummary,
    preview: PrivilegedExpiryPreview,
}

/// Reviews one expired system backup without requesting administrator approval.
pub fn prepare_system_expiry(operation: Uuid) -> io::Result<SystemExpiryReview> {
    let preview = preview_privileged_expiry(operation)?;
    let summary = BackupSummary {
        id: preview.operation_id(),
        batch_id: preview.operation_id(),
        target: preview.original_path().to_string_lossy().into_owned(),
        backup: preview.backup_path().to_string_lossy().into_owned(),
        expires_unix_ms: preview.expires_at_unix_ms(),
        state: if preview.is_pending() {
            RecoveryState::Staged
        } else {
            RecoveryState::Applied
        },
    };
    Ok(SystemExpiryReview { summary, preview })
}

impl SystemExpiryReview {
    /// Borrows the display metadata bound to the helper preview.
    pub fn summary(&self) -> &BackupSummary {
        &self.summary
    }

    /// Returns the event to record before showing the review to the user.
    pub fn audit_preview(&self) -> AuditEvent {
        expiry_event(&self.summary, "reviewed")
    }

    /// Consumes the approved preview or returns an audited skip if it expired.
    pub fn confirm(
        self,
        record: &impl Fn(&AuditEvent) -> Result<()>,
    ) -> std::result::Result<SystemExpiryConfirmation, ItemResult> {
        let Self { summary, preview } = self;
        match preview.confirm() {
            Ok(confirmed) => Ok(SystemExpiryConfirmation { summary, confirmed }),
            Err(error) => {
                let result = finish(
                    summary.id,
                    expiry_event(&summary, "skipped"),
                    ChangeResult::Skipped(error.to_string()),
                    record,
                );
                Err(item_result(summary, result))
            }
        }
    }
}

/// An approved expiry preview that still needs macOS administrator authorization.
pub struct SystemExpiryConfirmation {
    summary: BackupSummary,
    confirmed: ConfirmedPrivilegedExpiry,
}

impl SystemExpiryConfirmation {
    /// Records that this item was untouched after an unresolved batch result.
    pub fn skip_after_unresolved_change(
        self,
        batch_id: Uuid,
        record: &impl Fn(&AuditEvent) -> Result<()>,
    ) -> ItemResult {
        let mut event = expiry_event(&self.summary, AuditEvent::SKIPPED_AFTER_UNRESOLVED_CHANGE);
        event.batch_id = Some(batch_id);
        let result = finish(
            self.summary.id,
            event,
            ChangeResult::skipped_after_unresolved_change(),
            record,
        );
        item_result(self.summary, result)
    }

    /// Consumes this confirmation and records one signed-helper outcome.
    pub fn run(
        self,
        cancel: &Cancellation,
        record: &impl Fn(&AuditEvent) -> Result<()>,
    ) -> ItemResult {
        let Self { summary, confirmed } = self;
        let result = run_expiry(&summary, confirmed, cancel, record);
        item_result(summary, result)
    }
}

fn run_expiry(
    summary: &BackupSummary,
    confirmed: ConfirmedPrivilegedExpiry,
    cancel: &Cancellation,
    record: &impl Fn(&AuditEvent) -> Result<()>,
) -> ChangeResult {
    let outcome = match cancel.check() {
        Err(error) => Err(error),
        Ok(()) => {
            // Retain intent before the helper can independently remove data.
            if let Err(error) = record(&expiry_event(summary, "starting")) {
                return ChangeResult::Skipped(format!(
                    "Could not record the start of the change: {error}"
                ));
            }
            cancel
                .check()
                .and_then(|()| expire_privileged_quarantine(confirmed).map_err(Error::from))
        }
    };
    let mut event = expiry_event(summary, "skipped");
    let result = match outcome {
        Ok(outcome) => expiry_result(outcome, &mut event),
        Err(Error::Cancelled) => {
            event.result = "cancelled".into();
            ChangeResult::Skipped(Error::Cancelled.to_string())
        }
        Err(error) => ChangeResult::Skipped(error.to_string()),
    };
    finish(summary.id, event, result, record)
}

fn expiry_result(outcome: PrivilegedExpiryOutcome, event: &mut AuditEvent) -> ChangeResult {
    match outcome {
        PrivilegedExpiryOutcome::Purged(_) => {
            event.result = "purged".into();
            ChangeResult::Purged
        }
        PrivilegedExpiryOutcome::Pending(receipt) => {
            event.result = "pending".into();
            review_receipt(receipt, "Backup removal stopped before completion.", event)
        }
        PrivilegedExpiryOutcome::ReviewRequired(receipt) => {
            event.result = "needs_review".into();
            review_receipt(receipt, "The backup removal outcome is ambiguous.", event)
        }
        PrivilegedExpiryOutcome::ReplyUncertain {
            operation_id,
            error,
        } => {
            event.result = "reply_uncertain".into();
            needs_review(operation_id, error)
        }
    }
}

fn expiry_event(summary: &BackupSummary, status: &str) -> AuditEvent {
    let mut event = AuditEvent::new(summary.target.clone(), EXPIRY_ACTION, status);
    event.batch_id = Some(summary.id);
    event.operation_id = Some(summary.id);
    event.backup = Some(summary.backup.clone());
    event
}

fn finish(
    operation: Uuid,
    event: AuditEvent,
    result: ChangeResult,
    record: &impl Fn(&AuditEvent) -> Result<()>,
) -> ChangeResult {
    let Err(error) = record(&event) else {
        return result;
    };
    let audit_failure = format!("The local audit write failed: {error}");
    match result {
        ChangeResult::Skipped(detail) => ChangeResult::Skipped(format!("{detail} {audit_failure}")),
        ChangeResult::NeedsReview(detail) => {
            ChangeResult::NeedsReview(format!("{detail} {audit_failure}"))
        }
        ChangeResult::Applied | ChangeResult::Restored | ChangeResult::Purged => needs_review(
            operation,
            format_args!(
                "The helper reported completion ({}). {audit_failure}",
                event.result
            ),
        ),
    }
}

fn item_result(summary: BackupSummary, result: ChangeResult) -> ItemResult {
    ItemResult {
        target: summary.target,
        backup_id: Some(summary.id),
        result,
    }
}

fn review_receipt(
    receipt: PrivilegedQuarantineStatus,
    detail: &str,
    event: &mut AuditEvent,
) -> ChangeResult {
    if let Some(record) = receipt.record {
        event.backup = Some(record.backup_path.display().to_string());
    }
    if receipt.os_error > 0 {
        let error = io::Error::from_raw_os_error(receipt.os_error);
        needs_review(receipt.operation_id, format_args!("{detail} {error}"))
    } else {
        needs_review(receipt.operation_id, detail)
    }
}

fn needs_review(operation: Uuid, detail: impl fmt::Display) -> ChangeResult {
    ChangeResult::NeedsReview(format!(
        "{detail} Review backup {operation} before retrying."
    ))
}
