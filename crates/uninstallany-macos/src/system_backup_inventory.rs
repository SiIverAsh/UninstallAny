//! Validates the signed macOS helper's system backup catalog.

use std::{collections::HashSet, io, path::Path};

use uninstallany_core::{BackupInventory, BackupSummary, Cancellation, RecoveryState, Result};
use uuid::Uuid;

use crate::helper_client::{
    PrivilegedHelperServiceState, PrivilegedQuarantineRecord, PrivilegedQuarantineState,
    PrivilegedQuarantineStatus, list_privileged_quarantine_page, privileged_helper_service_state,
};

/// A complete helper catalog and the available actions observed in it.
#[derive(Default)]
pub struct SystemBackups {
    /// Validated backup summaries and catalog diagnostics.
    pub inventory: BackupInventory,
    /// Operation IDs eligible for a fresh restore preview.
    pub restore_ids: HashSet<Uuid>,
    /// Operation IDs eligible for a fresh expiry preview.
    pub expiry_ids: Vec<Uuid>,
}

impl SystemBackups {
    fn unavailable(warning: impl Into<String>) -> Self {
        Self {
            inventory: BackupInventory {
                warnings: vec![warning.into()],
                ..BackupInventory::default()
            },
            ..Self::default()
        }
    }

    fn add(&mut self, entry: &PrivilegedQuarantineStatus, can_expire: bool) {
        let operation = entry.operation_id;
        let Some(record) = entry.record.as_ref() else {
            let reason = match entry.status {
                PrivilegedQuarantineState::Busy => "another operation holds the record",
                PrivilegedQuarantineState::IncompletePreparation => "preparation is incomplete",
                PrivilegedQuarantineState::Missing => "the backup slot is missing",
                _ => "the helper could not verify the journal record",
            };
            self.warn(operation, reason, entry.os_error);
            return;
        };
        let Some((target, backup)) = display_paths(record, operation) else {
            self.warn(
                operation,
                "the journal contains an invalid path",
                entry.os_error,
            );
            return;
        };

        let (state, warning) = recovery_state(entry, record);
        if let Some(warning) = warning {
            self.warn(operation, warning, entry.os_error);
        }
        if state == RecoveryState::Applied {
            self.restore_ids.insert(operation);
        }
        if can_expire {
            self.expiry_ids.push(operation);
        }

        // Only Applied entries display a deadline in the desktop catalog.
        self.inventory.items.push(BackupSummary {
            id: operation,
            batch_id: operation,
            target: target.to_owned(),
            backup: backup.to_owned(),
            expires_unix_ms: record.expires_at_unix_ms.unwrap_or_default(),
            state,
        });
    }

    fn warn(&mut self, operation: Uuid, reason: &str, errno: i32) {
        let mut warning = format!("System backup {operation}: {reason}");
        if errno != 0 {
            warning.push_str(&format!(" ({})", io::Error::from_raw_os_error(errno)));
        }
        self.inventory.warnings.push(warning);
    }
}

/// Reads the current user's system backup catalog from the signed helper.
///
/// Eligibility observations still require fresh operation previews for approval.
pub fn read_system_backups(cancel: &Cancellation) -> Result<SystemBackups> {
    cancel.check()?;
    let service_state = privileged_helper_service_state();
    cancel.check()?;
    match service_state {
        Ok(PrivilegedHelperServiceState::Enabled) => {}
        Ok(PrivilegedHelperServiceState::NotRegistered) => {
            return Ok(SystemBackups::unavailable(
                "System backups: the macOS helper service is not registered.",
            ));
        }
        Ok(PrivilegedHelperServiceState::RequiresApproval) => {
            return Ok(SystemBackups::unavailable(
                "System backups: the macOS helper is awaiting administrator approval.",
            ));
        }
        Ok(PrivilegedHelperServiceState::NotFound) => {
            return Ok(SystemBackups::unavailable(
                "System backups: the installed app is missing its macOS helper.",
            ));
        }
        Err(error) => {
            return Ok(SystemBackups::unavailable(format!(
                "System backups: could not check the macOS helper service: {error}"
            )));
        }
    }

    let mut result = SystemBackups::default();
    let mut can_check_expiry = true;
    let mut page = list_privileged_quarantine_page(None);
    let mut first_page = true;
    loop {
        cancel.check()?;
        let current = match page {
            Ok(page) => page,
            Err(error) => {
                // A cursor failure invalidates the partial snapshot and all
                // actions derived from it.
                return Ok(SystemBackups::unavailable(format!(
                    "System backups: could not finish reading the catalog: {error}. Refresh to try again."
                )));
            }
        };
        if first_page && current.ignored_entries() != 0 {
            result.inventory.warnings.push(format!(
                "System backups: {} unrecognized catalog entries require review.",
                current.ignored_entries()
            ));
        }
        first_page = false;

        let mut expired = HashSet::new();
        if can_check_expiry {
            match current.expired_entries() {
                Ok(entries) => expired.extend(entries.map(|entry| entry.operation_id)),
                Err(error) => {
                    can_check_expiry = false;
                    result.expiry_ids.clear();
                    result.inventory.warnings.push(format!(
                        "System backups: could not verify retention deadlines: {error}"
                    ));
                }
            }
        }
        for entry in current.entries() {
            result.add(entry, expired.contains(&entry.operation_id));
        }
        cancel.check()?;
        let Some(next) = current.next_cursor() else {
            return Ok(result);
        };
        page = list_privileged_quarantine_page(Some(next));
    }
}

fn display_paths(record: &PrivilegedQuarantineRecord, operation: Uuid) -> Option<(&str, &str)> {
    let target = &record.original_path;
    let backup = &record.backup_path;
    let slot = backup.parent()?;
    if target.parent() != Some(Path::new("/Applications"))
        || !target
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("app"))
        || !backup.is_absolute()
        || !backup.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
        || slot.file_name()?.to_str()? != operation.hyphenated().to_string()
        || !matches!(
            backup.file_name()?.to_str()?,
            "payload.app" | "expiry.pending"
        )
    {
        return None;
    }
    Some((target.to_str()?, backup.to_str()?))
}

fn recovery_state(
    entry: &PrivilegedQuarantineStatus,
    record: &PrivilegedQuarantineRecord,
) -> (RecoveryState, Option<&'static str>) {
    use PrivilegedQuarantineState as State;
    if entry.os_error != 0 {
        return (
            RecoveryState::NeedsReview,
            Some("the helper reported a backup error"),
        );
    }
    match entry.status {
        State::Quarantined if record.destination_occupied => (
            RecoveryState::NeedsReview,
            Some("the original restore destination is occupied"),
        ),
        State::Quarantined if record.expires_at_unix_ms.is_none_or(|expiry| expiry == 0) => (
            RecoveryState::NeedsReview,
            Some("the backup has no recorded retention deadline"),
        ),
        State::Quarantined if !record.restore_stamp.as_deref().is_some_and(valid_stamp) => (
            RecoveryState::NeedsReview,
            Some("the restore identity could not be verified"),
        ),
        State::Quarantined => (RecoveryState::Applied, None),
        State::ExpiryPending => (
            RecoveryState::Staged,
            Some("expiry cleanup is pending. Review expired files to continue"),
        ),
        State::NotQuarantined | State::IncompletePreparation | State::Busy => {
            (RecoveryState::Staged, None)
        }
        State::Restored => (RecoveryState::Restored, None),
        State::Purged => (RecoveryState::Purged, None),
        State::Ambiguous | State::Missing | State::StoreUnavailable => (
            RecoveryState::NeedsReview,
            Some("the helper could not verify the backup state"),
        ),
    }
}

fn valid_stamp(stamp: &str) -> bool {
    stamp.len() == 64
        && stamp
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
