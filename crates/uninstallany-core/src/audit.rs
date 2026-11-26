use std::{
    fs::{self, Metadata},
    io::{self, BufWriter, Write},
    path::{Component, Path, PathBuf},
};

use serde::Serialize;
use uuid::Uuid;

use crate::{Artifact, AuditEvent, Cancellation, Error, Journal, Result, policy, state};

const MACOS_QUARANTINE: &str = "macos_system_quarantine";
const MACOS_RESTORE: &str = "macos_system_restore";
const MACOS_EXPIRY: &str = "macos_system_purge_quarantine";
const MACOS_HELPER_REGISTRATION: &str = "macos_helper_registration";

/// The number of audit records saved and diagnostics for skipped records.
#[derive(Debug)]
pub struct AuditExport {
    pub written: usize,
    pub warnings: Vec<String>,
}

#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RecordKind {
    Event,
    Applied,
    Restored,
    Purged,
    QuarantineNeedsReview,
}

impl RecordKind {
    fn artifact(self) -> Artifact {
        match self {
            Self::Event => Artifact::Event,
            Self::Applied => Artifact::Applied,
            Self::Restored => Artifact::Restored,
            Self::Purged => Artifact::Purged,
            Self::QuarantineNeedsReview => Artifact::QuarantineNeedsReview,
        }
    }

    fn valid(self, id: Uuid, event: &AuditEvent) -> bool {
        let (action, result) = match self {
            Self::Event => return true,
            Self::Applied => ("cleanup", "applied"),
            Self::Restored => ("restore", "restored"),
            Self::Purged => ("purge_quarantine", "purged"),
            Self::QuarantineNeedsReview => ("cleanup", "needs_review"),
        };
        event.operation_id == Some(id)
            && event.batch_id.is_some()
            && event.backup.is_some()
            && event.action == action
            && event.result == result
    }
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
enum BackupPhase {
    Quarantine,
    Restore,
    Expiry,
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
enum EventStage {
    Review,
    Start,
    Outcome,
    Receipt,
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct RecordIndex {
    time: u64,
    group: Uuid,
    phase: BackupPhase,
    stage: EventStage,
    artifact: RecordKind,
    id: Uuid,
}

impl RecordIndex {
    fn of(event: &AuditEvent, artifact: RecordKind, id: Uuid) -> Self {
        let phase = match (artifact, event.action.as_str()) {
            (RecordKind::Restored, _) | (RecordKind::Event, "restore" | MACOS_RESTORE) => {
                BackupPhase::Restore
            }
            (RecordKind::Purged, _) | (RecordKind::Event, "purge_quarantine" | MACOS_EXPIRY) => {
                BackupPhase::Expiry
            }
            _ => BackupPhase::Quarantine,
        };
        // Related events can share a millisecond. Random record IDs should
        // break ties only after their operation phase and stage.
        let stage = match (artifact, event.result.as_str()) {
            (RecordKind::Event, "reviewed") => EventStage::Review,
            (RecordKind::Event, "starting" | "staged") => EventStage::Start,
            (RecordKind::Event | RecordKind::QuarantineNeedsReview, _) => EventStage::Outcome,
            _ => EventStage::Receipt,
        };
        Self {
            time: event.time_unix_ms,
            group: event.operation_id.or(event.batch_id).unwrap_or(id),
            phase,
            stage,
            artifact,
            id,
        }
    }
}

#[derive(Serialize)]
struct ExportRecord<'a> {
    record_id: Uuid,
    record_kind: RecordKind,
    #[serde(flatten)]
    event: &'a AuditEvent,
}

pub(crate) fn export(
    journal: &impl Journal,
    destination: &Path,
    cancel: &Cancellation,
) -> Result<AuditExport> {
    cancel.check()?;
    let destination = export_path(journal, destination)?;
    match fs::symlink_metadata(&destination) {
        Ok(_) => return Err(io::Error::from(io::ErrorKind::AlreadyExists).into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = parent_directory(&destination)?;
    let mut report = AuditExport {
        written: 0,
        warnings: Vec::new(),
    };
    let records = index(journal, cancel, &mut report.warnings)?;
    journal.check_export_path(&destination)?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".uninstallany-audit-")
        .tempfile_in(parent)?;
    {
        let mut writer = BufWriter::new(temporary.as_file_mut());
        for record in records {
            cancel.check()?;
            match read_event(journal, record.artifact, record.id) {
                Ok(mut event) if RecordIndex::of(&event, record.artifact, record.id) == record => {
                    event.result = safe_outcome(&event.action, &event.result).into();
                    let line = ExportRecord {
                        record_id: record.id,
                        record_kind: record.artifact,
                        event: &event,
                    };
                    serde_json::to_writer(&mut writer, &line)?;
                    writer.write_all(b"\n")?;
                    report.written += 1;
                }
                Ok(_) => warn(
                    &mut report.warnings,
                    record.artifact,
                    record.id,
                    "record changed during export",
                ),
                Err(error) => warn(
                    &mut report.warnings,
                    record.artifact,
                    record.id,
                    &error_outcome(&error),
                ),
            }
        }
        writer.flush()?;
    }
    temporary.as_file().sync_all()?;
    cancel.check()?;
    journal.check_export_path(&destination)?;
    temporary
        .persist_noclobber(destination)
        .map_err(|error| error.error)?;
    Ok(report)
}

fn index(
    journal: &impl Journal,
    cancel: &Cancellation,
    warnings: &mut Vec<String>,
) -> Result<Vec<RecordIndex>> {
    // Keep only order keys in memory, then stream the existing immutable records.
    let mut records = Vec::new();
    for kind in [
        RecordKind::Event,
        RecordKind::Applied,
        RecordKind::Restored,
        RecordKind::Purged,
        RecordKind::QuarantineNeedsReview,
    ] {
        cancel.check()?;
        for id in journal.list(kind.artifact())? {
            cancel.check()?;
            match read_event(journal, kind, id) {
                Ok(event) => records.push(RecordIndex::of(&event, kind, id)),
                Err(error) => warn(warnings, kind, id, &error_outcome(&error)),
            }
        }
    }
    records.sort_unstable();
    records.dedup();
    Ok(records)
}

fn read_event(journal: &impl Journal, kind: RecordKind, id: Uuid) -> Result<AuditEvent> {
    let event: AuditEvent = state::read_json(journal, id, kind.artifact())?
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    let action = event.action.as_bytes();
    if !kind.valid(id, &event)
        || action.is_empty()
        || action.len() > 64
        || !action
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
    {
        return Err(Error::Rejected("invalid audit record".into()));
    }
    if kind == RecordKind::QuarantineNeedsReview
        && !state::BackupRecord::load(journal, id)?.matches_event(&event)
    {
        return Err(Error::Rejected("invalid quarantine review record".into()));
    }
    Ok(event)
}

fn warn(warnings: &mut Vec<String>, kind: RecordKind, id: Uuid, reason: &str) {
    warnings.push(format!("Skipped audit {kind:?} {id}: {reason}"));
}

pub(crate) fn error_outcome(error: &Error) -> String {
    match error {
        Error::Rejected(_) => "rejected".into(),
        Error::Cancelled => "cancelled".into(),
        Error::Io(error) => error.raw_os_error().map_or_else(
            || match error.kind() {
                io::ErrorKind::NotFound => "missing_record".into(),
                io::ErrorKind::PermissionDenied => "permission_denied".into(),
                _ => "io_error".into(),
            },
            |code| format!("io_error({code})"),
        ),
        Error::Data(_) => "invalid_data".into(),
        Error::AuditAfterChange(_) | Error::FileChangeNeedsReview(_) => "needs_review".into(),
    }
}

fn safe_outcome<'a>(action: &str, value: &'a str) -> &'a str {
    let fixed = matches!(
        value,
        "succeeded"
            | "failed"
            | "starting"
            | "staged"
            | "applied"
            | "restored"
            | "purged"
            | "completed"
            | "ready"
            | "completion unverified"
            | "rejected"
            | "cancelled"
            | "missing_record"
            | "permission_denied"
            | "io_error"
            | "invalid_data"
            | "needs_review"
            | "Completed"
            | "NeedsRestart"
            | "Cancelled"
    );
    let operation_status = matches!(
        (action, value),
        (
            MACOS_QUARANTINE | MACOS_RESTORE | MACOS_EXPIRY,
            "reviewed" | "skipped" | "reply_uncertain"
        ) | (MACOS_EXPIRY, "pending")
            | (
                MACOS_HELPER_REGISTRATION,
                "reviewed" | "enabled" | "requires_approval" | "not_registered" | "not_found"
            )
            | (
                "cleanup" | "restore" | "purge_quarantine" | MACOS_EXPIRY,
                AuditEvent::SKIPPED_AFTER_UNRESOLVED_CHANGE
            )
    );
    let numeric = |name: &str| {
        value
            .strip_prefix(name)
            .and_then(|code| code.strip_suffix(')'))
    };
    if fixed
        || operation_status
        || ["Failed(", "Unverified("]
            .iter()
            .any(|name| numeric(name).is_some_and(|code| code.parse::<u32>().is_ok()))
        || numeric("io_error(").is_some_and(|code| code.parse::<i32>().is_ok())
    {
        value
    } else {
        // Older records can contain raw diagnostics from package-management tools.
        "details_omitted"
    }
}

fn export_path(journal: &impl Journal, path: &Path) -> Result<PathBuf> {
    let ends_in_separator = path
        .as_os_str()
        .as_encoded_bytes()
        .last()
        .is_some_and(|byte| *byte == b'/' || cfg!(windows) && *byte == b'\\');
    if !policy::valid_file_address(path) || ends_in_separator {
        return Err(Error::Rejected(
            "choose an absolute audit report path without traversal".into(),
        ));
    }
    #[cfg(windows)]
    {
        use std::{os::windows::ffi::OsStrExt, path::Prefix};
        let mut components = path.components();
        let Some(Component::Prefix(prefix)) = components.next() else {
            return Err(Error::Rejected("choose a local audit report path".into()));
        };
        if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
            || components.any(|part| {
                part.as_os_str()
                    .encode_wide()
                    .any(|unit| unit == u16::from(b':'))
            })
        {
            return Err(Error::Rejected(
                "choose a local audit report path without a file stream".into(),
            ));
        }
    }
    let name = path
        .file_name()
        .ok_or_else(|| Error::Rejected("choose a file name for the audit report".into()))?;
    let artifact_name = [
        Artifact::Event,
        Artifact::Manifest,
        Artifact::Applied,
        Artifact::Restored,
        Artifact::Purged,
        Artifact::QuarantineNeedsReview,
        Artifact::QuarantinePurgePlan,
        Artifact::QuarantinePurgeCommitted,
        Artifact::RegistryExport,
        Artifact::RegistrySnapshot,
        Artifact::Preferences,
    ];
    if name
        .to_str()
        .map(str::to_ascii_lowercase)
        .is_some_and(|name| artifact_name.iter().any(|kind| kind.id(&name).is_some()))
    {
        return Err(Error::Rejected(
            "choose a report name distinct from private journal artifacts".into(),
        ));
    }
    let parent = parent_directory(path)?;
    journal.check_export_path(path)?;
    check_ancestors(parent)?;
    Ok(fs::canonicalize(parent)?.join(name))
}

fn parent_directory(path: &Path) -> Result<&Path> {
    path.parent()
        .ok_or_else(|| Error::Rejected("choose an existing directory for the audit report".into()))
}

fn check_ancestors(path: &Path) -> Result<()> {
    let ancestors: Vec<_> = path
        .ancestors()
        .filter(|path| path.components().any(|part| part == Component::RootDir))
        .collect();
    for ancestor in ancestors.into_iter().rev() {
        check_directory(ancestor)?;
    }
    Ok(())
}

fn check_directory(path: &Path) -> Result<()> {
    let entry = fs::symlink_metadata(path)?;
    if !entry.is_dir() || is_link(&entry) {
        return Err(Error::Rejected(format!(
            "audit report directory contains a link or non-directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn is_link(entry: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        entry.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        entry.file_type().is_symlink()
    }
}
