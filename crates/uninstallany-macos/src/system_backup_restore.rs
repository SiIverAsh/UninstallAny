//! Review and audit adapter for one restore through the signed macOS helper.

use std::{fmt, io};

use uninstallany_core::{
    AuditEvent, BackupSummary, Cancellation, ChangeResult, Error, ItemResult, RecoveryState, Result,
};
use uuid::Uuid;

use crate::{
    PrivilegedRestoreOutcome, PrivilegedRestorePreview, prepare_privileged_restore,
    restore_privileged_application,
};

const RESTORE_ACTION: &str = "macos_system_restore";

/// Display metadata and the private, single-use helper preview it describes.
pub struct SystemRestoreReview {
    summary: BackupSummary,
    preview: PrivilegedRestorePreview,
}

/// Reviews an eligible system backup without requesting administrator approval.
pub fn prepare_system_restore(operation: Uuid) -> io::Result<SystemRestoreReview> {
    let preview = prepare_privileged_restore(operation)?;
    let record = preview.record();
    let expires_unix_ms = record
        .expires_at_unix_ms
        .filter(|deadline| *deadline > 0)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the desktop restore preview requires a recorded retention deadline",
            )
        })?;
    let summary = BackupSummary {
        id: preview.operation_id(),
        batch_id: preview.operation_id(),
        target: record.original_path.to_string_lossy().into_owned(),
        backup: record.backup_path.to_string_lossy().into_owned(),
        expires_unix_ms,
        state: RecoveryState::Applied,
    };
    Ok(SystemRestoreReview { summary, preview })
}

impl SystemRestoreReview {
    /// Borrows the display metadata bound to the private helper preview.
    pub fn summary(&self) -> &BackupSummary {
        &self.summary
    }

    /// Returns the audit event for the review shown to the user.
    pub fn audit_preview(&self) -> AuditEvent {
        restore_event(&self.summary, "reviewed")
    }

    /// Consumes the approved review and records the result of one restore.
    pub fn run(
        self,
        cancel: &Cancellation,
        record: &impl Fn(&AuditEvent) -> Result<()>,
    ) -> ItemResult {
        let Self { summary, preview } = self;
        let result = run_restore(&summary, preview, cancel, record);
        ItemResult {
            target: summary.target,
            backup_id: Some(summary.id),
            result,
        }
    }
}

fn run_restore(
    summary: &BackupSummary,
    preview: PrivilegedRestorePreview,
    cancel: &Cancellation,
    record: &impl Fn(&AuditEvent) -> Result<()>,
) -> ChangeResult {
    let outcome = match cancel.check() {
        Err(error) => Err(error),
        Ok(()) => {
            // The local journal must retain intent before the helper can
            // make its independently authorized change.
            if let Err(error) = record(&restore_event(summary, "starting")) {
                return ChangeResult::Skipped(format!(
                    "Could not record the start of the change: {error}"
                ));
            }
            cancel.check().and_then(|()| {
                preview
                    .confirm()
                    .and_then(restore_privileged_application)
                    .map_err(Error::from)
            })
        }
    };
    let mut event = restore_event(summary, "skipped");
    let result = match outcome {
        Ok(PrivilegedRestoreOutcome::Restored(_)) => {
            event.result = "restored".into();
            ChangeResult::Restored
        }
        Ok(PrivilegedRestoreOutcome::ReviewRequired(receipt)) => {
            event.result = "needs_review".into();
            if let Some(record) = receipt.record {
                event.backup = Some(record.backup_path.display().to_string());
            }
            let detail = "The restore outcome is ambiguous.";
            if receipt.os_error > 0 {
                let error = io::Error::from_raw_os_error(receipt.os_error);
                needs_review(receipt.operation_id, format_args!("{detail} {error}"))
            } else {
                needs_review(receipt.operation_id, detail)
            }
        }
        Ok(PrivilegedRestoreOutcome::ReplyUncertain {
            operation_id,
            error,
        }) => {
            event.result = "reply_uncertain".into();
            needs_review(operation_id, error)
        }
        Err(Error::Cancelled) => {
            event.result = "cancelled".into();
            ChangeResult::Skipped(Error::Cancelled.to_string())
        }
        Err(error) => ChangeResult::Skipped(error.to_string()),
    };
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
            summary.id,
            format_args!(
                "The helper reported completion ({}). {audit_failure}",
                event.result
            ),
        ),
    }
}

fn restore_event(summary: &BackupSummary, status: &str) -> AuditEvent {
    let mut event = AuditEvent::new(summary.target.clone(), RESTORE_ACTION, status);
    event.batch_id = Some(summary.id);
    event.operation_id = Some(summary.id);
    event.backup = Some(summary.backup.clone());
    event
}

fn needs_review(operation: Uuid, detail: impl fmt::Display) -> ChangeResult {
    ChangeResult::NeedsReview(format!(
        "{detail} Review backup {operation} before retrying."
    ))
}
