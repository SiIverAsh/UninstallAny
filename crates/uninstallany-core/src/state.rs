use std::{
    io,
    num::NonZeroU16,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use uuid::Uuid;

use crate::{Cancellation, Error, Result, Target};

/// An immutable local state artifact. A slot never overwrites an existing file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Artifact {
    Event,
    /// Snap's recorded data snapshot, saved before native removal.
    SnapSnapshot,
    Manifest,
    Applied,
    Restored,
    Purged,
    /// A known uncertainty in a file quarantine associated with its backup.
    QuarantineNeedsReview,
    /// Private backend record of the entries approved for directory disposal.
    QuarantinePurgePlan,
    /// Private backend proof that the object was detached before disposal.
    QuarantinePurgeCommitted,
    RegistryExport,
    RegistrySnapshot,
    Preferences,
}

impl Artifact {
    /// Returns the only filename accepted for this artifact and operation ID.
    pub fn file_name(self, id: Uuid) -> String {
        format!("{id}.{}", self.suffix())
    }

    fn suffix(self) -> &'static str {
        match self {
            Self::Event => "event.json",
            Self::SnapSnapshot => "snap-snapshot.json",
            Self::Manifest => "manifest.json",
            Self::Applied => "applied.json",
            Self::Restored => "restored.json",
            Self::Purged => "purged.json",
            Self::QuarantineNeedsReview => "quarantine-needs-review.json",
            Self::QuarantinePurgePlan => "quarantine-purge-plan.json",
            Self::QuarantinePurgeCommitted => "quarantine-purge-committed.json",
            Self::RegistryExport => "reg",
            Self::RegistrySnapshot => "registry.json",
            Self::Preferences => "preferences.json",
        }
    }

    /// Extracts a canonical identifier for an artifact of this kind.
    pub fn id(self, name: &str) -> Option<Uuid> {
        let (id, suffix) = name.split_once('.')?;
        if suffix != self.suffix() {
            return None;
        }
        let id = Uuid::parse_str(id).ok()?;
        (self.file_name(id) == name).then_some(id)
    }

    /// Extracts only a well-formed manifest identifier from a directory entry.
    pub fn manifest_id(name: &str) -> Option<Uuid> {
        Self::Manifest.id(name)
    }
}

/// Storage in a private application directory, independent of display and export.
pub trait Journal {
    /// Creates a complete, durable artifact or fails before reporting success.
    fn create(&self, id: Uuid, artifact: Artifact, bytes: &[u8]) -> io::Result<()>;
    /// Reads an artifact by exact ID. Absent artifacts return None.
    fn read(&self, id: Uuid, artifact: Artifact) -> io::Result<Option<Vec<u8>>>;
    /// Lists canonical IDs of published artifacts of the supplied kind.
    fn list(&self, artifact: Artifact) -> io::Result<Vec<Uuid>>;
    /// Lists the IDs of recovery manifests.
    fn manifests(&self) -> io::Result<Vec<Uuid>> {
        self.list(Artifact::Manifest)
    }
    /// Returns the location for display without creating it.
    fn location(&self, id: Uuid, artifact: Artifact) -> PathBuf;
    /// Verifies that a user-selected export destination is on supported local storage.
    fn check_export_path(&self, path: &Path) -> io::Result<()>;

    /// Stages and publishes a new audit file without replacing an existing name.
    ///
    /// The engine passes the original path after validating its syntax and
    /// report name. The callback streams the records into the staged file.
    /// Validate the destination before calling it and check cancellation
    /// immediately before publishing. Platforms can bind both operations
    /// to native directory and file handles.
    fn write_audit_export(
        &self,
        path: &Path,
        cancel: &Cancellation,
        write: impl FnOnce(&mut dyn io::Write) -> Result<()>,
    ) -> Result<()>
    where
        Self: Sized,
    {
        crate::audit::write_export_file(self, path, cancel, write)
    }
}

/// One structured audit event, with sensitive native command arguments omitted.
#[derive(Debug, Deserialize, Serialize)]
pub struct AuditEvent {
    pub time_unix_ms: u64,
    pub batch_id: Option<Uuid>,
    pub operation_id: Option<Uuid>,
    pub object: String,
    pub action: String,
    pub result: String,
    pub backup: Option<String>,
}

impl AuditEvent {
    /// An approved item was left untouched because an earlier change needs review.
    pub const SKIPPED_AFTER_UNRESOLVED_CHANGE: &str = "skipped_after_unresolved_change";

    /// Creates an event timestamped now, with optional linkage left unset.
    pub fn new(object: String, action: &str, result: &str) -> Self {
        Self {
            time_unix_ms: now(),
            batch_id: None,
            operation_id: None,
            object,
            action: action.into(),
            result: result.into(),
            backup: None,
        }
    }
}

/// Whether a backup has confirmed change evidence and can be restored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryState {
    Staged,
    Applied,
    Restored,
    Purged,
    NeedsReview,
}

/// User-facing summary of one retained backup.
#[derive(Clone, Debug)]
pub struct BackupSummary {
    pub id: Uuid,
    pub batch_id: Uuid,
    pub target: String,
    pub backup: String,
    pub expires_unix_ms: u64,
    pub state: RecoveryState,
}

/// Recoverable backups and independent audit record errors.
#[derive(Debug, Default)]
pub struct BackupInventory {
    pub items: Vec<BackupSummary>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct BackupRecord {
    version: u8,
    pub(crate) id: Uuid,
    pub(crate) batch_id: Uuid,
    pub(crate) target: Target,
    pub(crate) fingerprint: String,
    pub(crate) backup: String,
    pub(crate) expires_unix_ms: u64,
    pub(crate) registry_snapshot_digest: Option<[u8; 32]>,
    #[serde(default)]
    pub(crate) application_installation: bool,
}

impl BackupRecord {
    pub(crate) fn summary(&self, state: RecoveryState) -> BackupSummary {
        BackupSummary {
            id: self.id,
            batch_id: self.batch_id,
            target: self.target.display(),
            backup: self.backup.clone(),
            expires_unix_ms: self.expires_unix_ms,
            state,
        }
    }

    pub(crate) fn new(
        ids: (Uuid, Uuid),
        target: Target,
        fingerprint: String,
        backup: String,
        retention_days: NonZeroU16,
    ) -> Self {
        let lifetime = Duration::from_secs(u64::from(retention_days.get()) * 24 * 60 * 60);
        Self {
            version: 1,
            batch_id: ids.0,
            id: ids.1,
            target,
            fingerprint,
            backup,
            expires_unix_ms: now().saturating_add(millis(lifetime)),
            registry_snapshot_digest: None,
            application_installation: false,
        }
    }

    pub(crate) fn load(journal: &impl Journal, id: Uuid) -> Result<Self> {
        let record: Self = read_json(journal, id, Artifact::Manifest)?
            .ok_or_else(|| Error::Rejected(format!("no backup is recorded for {id}")))?;
        if record.id != id || record.version != 1 {
            return Err(Error::Rejected(format!("invalid backup manifest for {id}")));
        }
        Ok(record)
    }

    pub(crate) fn event(&self, action: &str, result: &str) -> AuditEvent {
        let mut event = AuditEvent::new(self.target.display(), action, result);
        event.batch_id = Some(self.batch_id);
        event.operation_id = Some(self.id);
        event.backup = Some(self.backup.clone());
        event
    }

    pub(crate) fn matches_event(&self, event: &AuditEvent) -> bool {
        event.batch_id == Some(self.batch_id)
            && event.operation_id == Some(self.id)
            && event.object == self.target.display()
            && event.backup.as_deref() == Some(self.backup.as_str())
    }
}

pub(crate) fn put_json(
    journal: &impl Journal,
    id: Uuid,
    artifact: Artifact,
    item: &impl Serialize,
) -> Result<()> {
    journal.create(id, artifact, &serde_json::to_vec(item)?)?;
    Ok(())
}

pub(crate) fn read_json<T: DeserializeOwned>(
    journal: &impl Journal,
    id: Uuid,
    artifact: Artifact,
) -> Result<Option<T>> {
    journal
        .read(id, artifact)?
        .map(|blob| serde_json::from_slice(&blob).map_err(Error::from))
        .transpose()
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, millis)
}
