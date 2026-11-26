use std::{
    collections::{HashMap, hash_map::Entry},
    io,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Failure of an individual operation or of the audit state needed to authorize it.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The request cannot be approved or the target changed after review.
    #[error("{0}")]
    Rejected(String),
    /// The caller cancelled before the next operation began.
    #[error("the operation was cancelled")]
    Cancelled,
    /// An essential native operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// A local audit or recovery record is invalid.
    #[error(transparent)]
    Data(#[from] serde_json::Error),
    /// A native change succeeded but its audit receipt could not be recorded.
    #[error("change completed but its outcome could not be recorded: {0}")]
    AuditAfterChange(String),
    /// A failed filesystem operation may have already moved its target.
    #[error("the file operation needs review before retrying: {0}")]
    FileChangeNeedsReview(String),
}

/// Result from the core API.
pub type Result<T> = std::result::Result<T, Error>;

/// Concrete Windows registry hive, including the caller's current-user hive.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum RegistryHive {
    CurrentUser,
    LocalMachine,
}

/// Logical registry view used for every lookup and mutation of an object.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum RegistryView {
    Native,
    Registry32,
    Registry64,
}

/// An exact key, or one named value within that key.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RegistryTarget {
    pub hive: RegistryHive,
    pub view: RegistryView,
    pub key: String,
    pub value: Option<String>,
}

/// Platform-specific application identity, independent of its display name.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum AppId {
    WindowsRegistry(RegistryTarget),
    WindowsPackage(String),
    Package { manager: String, id: String },
}

/// Inventory entry with optional metadata and explicit uninstall capability.
#[derive(Clone, Debug)]
pub struct AppRecord {
    pub id: AppId,
    pub name: String,
    pub publisher: Option<String>,
    pub version: Option<String>,
    pub install_location: Option<PathBuf>,
    pub size_bytes: Option<u64>,
    pub install_date: Option<String>,
    pub system_component: bool,
    /// Availability of a reviewed uninstall action, including guarded quarantine.
    pub official_uninstall_available: bool,
}

/// Application inventory and failures from independent sources.
#[derive(Debug, Default)]
pub struct Inventory {
    pub applications: Vec<AppRecord>,
    pub warnings: Vec<String>,
}

/// Kind of candidate presented to the user.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Category {
    File,
    Directory,
    Shortcut,
    Registry,
    Startup,
    Service,
    ScheduledTask,
    Firewall,
    FileAssociation,
    ShellExtension,
    Com,
}

/// A precise file or registry object, or a native reference for display only.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Target {
    File(#[serde(with = "platform_path")] PathBuf),
    Registry(RegistryTarget),
    Reference(String),
}

impl Target {
    /// Identifies the object in a diagnostic or audit event.
    pub fn display(&self) -> String {
        match self {
            Self::File(path) => path.to_string_lossy().into_owned(),
            Self::Registry(target) => {
                let mut description = format!("{:?}/{:?}/{}", target.hive, target.view, target.key);
                if let Some(value) = &target.value {
                    description.push_str(&format!(" [value {value:?}]"));
                }
                description
            }
            Self::Reference(description) => description.clone(),
        }
    }
}

/// Strength of attribution to the selected application.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// Source of the match, in order of increasing reliability.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum MatchKind {
    RuleHint,
    FuzzyName,
    AppName,
    PublisherAndApp,
    ExactIdentity,
}

impl MatchKind {
    /// Derives confidence centrally so callers cannot mark a fuzzy match as high.
    pub fn confidence(self) -> Confidence {
        match self {
            Self::RuleHint | Self::FuzzyName => Confidence::Low,
            Self::AppName | Self::PublisherAndApp => Confidence::Medium,
            Self::ExactIdentity => Confidence::High,
        }
    }
}

/// Risk rating independent of attribution confidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Risk {
    Normal,
    High,
}

/// A writable target or the reason it must be kept.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Access {
    Allowed,
    ReadOnly(String),
}

/// Read-only platform discovery result before safety checks and inspection.
#[derive(Debug)]
pub struct Proposal {
    pub target: Target,
    pub category: Category,
    pub evidence: MatchKind,
    pub reason: String,
    pub risk: Risk,
    pub access: Access,
}

/// Tagged candidates and warnings from a scan that could only partially complete.
#[derive(Debug, Default)]
pub struct Scan {
    pub proposals: Vec<Proposal>,
    pub warnings: Vec<String>,
    pub(crate) file_cleanup_application: Option<AppId>,
    // A present key with no fingerprint records conflicting observations.
    pub(crate) observations: HashMap<Target, Option<String>>,
}

impl Scan {
    /// Builds a discovery result for targets attributed without reading their contents.
    pub fn new(proposals: Vec<Proposal>, warnings: Vec<String>) -> Self {
        Self {
            proposals,
            warnings,
            ..Self::default()
        }
    }

    /// Binds file cleanup to the exact application attributed during this scan.
    ///
    /// Approval requires the same association on rescan. The platform can then
    /// check that application when each approved file is about to be moved.
    pub fn bind_file_cleanup_application(&mut self, application: AppId) {
        self.file_cleanup_application = Some(application);
    }

    /// Binds the proposal to the native fingerprint of the object used for attribution.
    pub fn push_observed(&mut self, proposal: Proposal, fingerprint: String) {
        match self.observations.entry(proposal.target.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(Some(fingerprint));
            }
            Entry::Occupied(mut entry) if entry.get().as_deref() != Some(fingerprint.as_str()) => {
                entry.insert(None);
            }
            Entry::Occupied(_) => {}
        }
        self.proposals.push(proposal);
    }
}

/// Scanning modes have independent authorization boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanMode {
    Leftovers,
    ForceRemoval,
    AfterOfficialUninstall,
}

/// A user-cancellable request shared between a worker and its caller.
#[derive(Clone, Debug, Default)]
pub struct Cancellation(Arc<AtomicBool>);

impl Cancellation {
    /// Signals cancellation at the next operation boundary.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    /// Stops preparation or iteration when the caller cancels the request.
    pub fn check(&self) -> Result<()> {
        if self.0.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        Ok(())
    }
}

/// Uninstall effect shown before obtaining explicit confirmation.
#[derive(Clone, Debug)]
pub struct OfficialIntent {
    pub application: String,
    pub method: String,
    pub quiet: bool,
    pub notice: String,
}

/// Native result before any residual cleanup.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum OfficialOutcome {
    Completed,
    NeedsRestart,
    Cancelled,
    Failed(u32),
    Unverified(u32),
}

/// Independent result for one target in a cleanup, restore, or expiry batch.
#[derive(Debug)]
pub struct ItemResult {
    pub target: String,
    pub backup_id: Option<Uuid>,
    pub result: ChangeResult,
}

/// Durable change status returned to a frontend.
#[derive(Debug)]
pub enum ChangeResult {
    Applied,
    Restored,
    /// An explicitly selected expired quarantine object was permanently removed.
    Purged,
    Skipped(String),
    NeedsReview(String),
}

impl ChangeResult {
    /// Reports an untouched item after the batch stopped for review.
    pub fn skipped_after_unresolved_change() -> Self {
        Self::Skipped("a previous change needs review before continuing".into())
    }
}

/// Results for one batch, including independent failures.
#[derive(Debug)]
pub struct ChangeReport {
    pub batch_id: Uuid,
    pub items: Vec<ItemResult>,
}

// The JSON recovery record must round-trip native paths, including ill-formed
// UTF-16 on Windows and non-UTF-8 bytes on Unix.
mod platform_path {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::{ffi::OsString, path::PathBuf};

    #[cfg(unix)]
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    #[cfg(windows)]
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    #[cfg(windows)]
    pub fn serialize<S: Serializer>(
        path: &std::path::Path,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        path.as_os_str()
            .encode_wide()
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    #[cfg(unix)]
    pub fn serialize<S: Serializer>(
        path: &std::path::Path,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        path.as_os_str().as_bytes().serialize(serializer)
    }

    #[cfg(windows)]
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<PathBuf, D::Error> {
        Vec::<u16>::deserialize(deserializer).map(|units| OsString::from_wide(&units).into())
    }

    #[cfg(unix)]
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<PathBuf, D::Error> {
        Vec::<u8>::deserialize(deserializer).map(|bytes| OsString::from_vec(bytes).into())
    }
}
