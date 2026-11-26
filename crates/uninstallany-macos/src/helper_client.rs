//! Reviewed bundle isolation and recovery via the signed helper.

use std::{
    ffi::{CStr, CString, c_char},
    io,
    num::NonZeroU16,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use serde::Deserialize;
use uninstallany_core::DEFAULT_RETENTION_DAYS;
use uuid::Uuid;

use crate::{bundle, vendor};

#[path = "helper_catalog.rs"]
mod catalog;
#[path = "helper_expiry.rs"]
mod expiry;
#[path = "helper_service.rs"]
mod service;

pub use catalog::{
    PrivilegedQuarantineCursor, PrivilegedQuarantinePage, list_privileged_quarantine_page,
};
pub use expiry::{
    ConfirmedPrivilegedExpiry, PrivilegedExpiryOutcome, PrivilegedExpiryPreview,
    expire_privileged_quarantine, preview_privileged_expiry,
};
pub use service::{
    ConfirmedPrivilegedHelperRegistration, PrivilegedHelperRegistrationPreview,
    PrivilegedHelperServiceState, prepare_privileged_helper_registration,
    privileged_helper_service_state, register_privileged_helper,
};

const GUI_SIGNING_ID: &str = "io.github.siiverash.uninstallany";
const MAX_REPLY_BYTES: usize = 4_096;
const OUTCOME_UNKNOWN: i32 = -1;
const PREVIEW_LIFETIME: Duration = Duration::from_secs(15 * 60);
const STAMP_BUFFER_BYTES: usize = 65;

#[repr(C)]
struct StandaloneQuarantineRequest {
    basename: *const c_char,
    bundle_identifier: *const c_char,
    review_stamp: *const c_char,
    operation_id: *const c_char,
    retention_days: u16,
}

unsafe extern "C" {
    fn UAInspectThroughSignedHelper(
        team: *const c_char,
        basename: *const c_char,
        bundle_identifier: *const c_char,
        response: *mut c_char,
        response_capacity: usize,
    ) -> i32;
    fn UAVerifyQuarantineThroughSignedHelper(
        team: *const c_char,
        basename: *const c_char,
        bundle_identifier: *const c_char,
        root_stamp: *const c_char,
    ) -> i32;
    fn UAQueryQuarantineThroughSignedHelper(
        team: *const c_char,
        operation_id: *const c_char,
        response: *mut c_char,
        response_capacity: usize,
    ) -> i32;
    fn UARestoreThroughSignedHelper(
        team: *const c_char,
        operation_id: *const c_char,
        restore_stamp: *const c_char,
        response: *mut c_char,
        response_capacity: usize,
    ) -> i32;
    fn UAPreviewStandaloneQuarantineThroughSignedHelper(
        team: *const c_char,
        basename: *const c_char,
        bundle_identifier: *const c_char,
        stamp: *mut c_char,
        stamp_capacity: usize,
    ) -> i32;
    fn UAQuarantineStandaloneThroughSignedHelper(
        team: *const c_char,
        request: *const StandaloneQuarantineRequest,
        response: *mut c_char,
        response_capacity: usize,
    ) -> i32;
}

/// Result of the helper's filesystem inspection, before ownership review.
#[derive(Debug, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum PrivilegedBundleInspection {
    /// The helper read matching root-owned bundle metadata.
    Verified {
        /// Filesystem device of the opened bundle.
        device: u64,
        /// Inode of the opened bundle.
        inode: u64,
        /// Whole seconds of the filesystem birth timestamp.
        birth_seconds: i64,
        /// Nanosecond component of the filesystem birth timestamp.
        birth_nanoseconds: i64,
        /// Binds the reviewed root, Contents and raw Info.plist.
        root_stamp: String,
    },
    /// The target address or bundle identifier was ineligible.
    InvalidTarget,
    /// The application directory could not be trusted for privileged writes.
    UntrustedApplicationsDirectory,
    /// The requested direct child no longer exists.
    TargetMissing,
    /// The bundle did not meet the required root ownership or access rules.
    TargetNotPrivateRootBundle,
    /// The bundle manifest did not contain the reviewed bundle identifier.
    BundleIdentifierMismatch,
    /// An inspected object changed during preflight.
    EntryChanged,
}

/// Requests read-only inspection of one direct bundle under `/Applications`.
///
/// Returns an I/O error when the signed installation or helper is unavailable.
/// Successful inspection only describes the filesystem object.
pub fn inspect_privileged_application(
    path: &Path,
    bundle_identifier: &str,
) -> io::Result<PrivilegedBundleInspection> {
    let request = BundleRequest::new(path, bundle_identifier)?;
    let mut response = [0u8; MAX_REPLY_BYTES];
    // SAFETY: The three strings are live NUL-terminated inputs. The bridge
    // receives a writable buffer of the declared length and never retains it.
    let status = unsafe {
        UAInspectThroughSignedHelper(
            request.team.as_ptr(),
            request.basename.as_ptr(),
            request.identifier.as_ptr(),
            response.as_mut_ptr().cast(),
            response.len(),
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    let payload = CStr::from_bytes_until_nul(&response).map_err(io::Error::other)?;
    serde_json::from_slice(payload.to_bytes()).map_err(io::Error::other)
}

/// State observed in the helper's per-user quarantine journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegedQuarantineState {
    /// The operation slot is absent.
    Missing,
    /// The store or slot could not be opened safely.
    StoreUnavailable,
    /// A slot exists without a published journal record.
    IncompletePreparation,
    /// A transaction still holds the journal lock.
    Busy,
    /// Observed data does not establish a safe recovery state.
    Ambiguous,
    /// The expected bundle is present in the quarantine slot.
    Quarantined,
    /// The expected bundle is at its original path and no move was recorded.
    NotQuarantined,
    /// The expected bundle is back at its original path after a restore intent.
    Restored,
    /// The approved backup is detached and the remaining tree awaits review.
    ExpiryPending,
    /// The recorded backup was removed from the private slot.
    Purged,
}

/// Recovery details from a validated, durable journal record.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivilegedQuarantineRecord {
    /// Reviewed path before quarantine.
    pub original_path: PathBuf,
    /// Expected payload path in the helper's private store.
    pub backup_path: PathBuf,
    /// Reviewed bundle identifier.
    pub bundle_id: String,
    /// Original preflight stamp.
    pub root_stamp: String,
    /// Unix seconds at journal preparation, including a fractional part.
    pub prepared_at_epoch_seconds: f64,
    /// A different object currently occupies the original path.
    pub destination_occupied: bool,
    /// Identifies the reviewed slot when the original path is free.
    pub restore_stamp: Option<String>,
    /// Unix seconds from the durable quarantine completion marker.
    pub quarantine_completed_at_epoch_seconds: Option<f64>,
    /// Unix seconds from the durable completion marker, when present.
    pub restore_completed_at_epoch_seconds: Option<f64>,
    /// The retention policy captured when this backup was prepared.
    pub retention_days: Option<NonZeroU16>,
    /// Recorded expiry in Unix milliseconds. Legacy records may lack it.
    pub expires_at_unix_ms: Option<u64>,
    /// Unix seconds from the durable expired-backup removal marker.
    pub purged_at_epoch_seconds: Option<f64>,
}

/// Recovery response for one operation in the authenticated user's store.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivilegedQuarantineStatus {
    /// Operation identifier from the reviewed plan.
    pub operation_id: Uuid,
    /// Result of reconciling the journal and filesystem.
    pub status: PrivilegedQuarantineState,
    /// Operating system error number, or zero for a normal observed state.
    #[serde(rename = "errno")]
    pub os_error: i32,
    /// Metadata when the helper could validate the journal record.
    pub record: Option<PrivilegedQuarantineRecord>,
}

/// Reads quarantine status after an interrupted or completed helper request.
///
/// Returns an I/O error if the signed helper is unavailable or its reply does
/// not match the requested operation. The query cannot create or move files.
pub fn query_privileged_quarantine(operation_id: Uuid) -> io::Result<PrivilegedQuarantineStatus> {
    let team = signed_helper_team()?;
    let identifier = operation_identifier(operation_id)?;
    let mut response = [0u8; MAX_REPLY_BYTES];
    // SAFETY: Inputs are live NUL-terminated strings and the bridge writes
    // only to the declared buffer before returning.
    let status = unsafe {
        UAQueryQuarantineThroughSignedHelper(
            team.as_ptr(),
            identifier.as_ptr(),
            response.as_mut_ptr().cast(),
            response.len(),
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    decode_quarantine_status(&response, operation_id)
}

fn decode_quarantine_status(
    response: &[u8],
    operation_id: Uuid,
) -> io::Result<PrivilegedQuarantineStatus> {
    let payload = CStr::from_bytes_until_nul(response).map_err(io::Error::other)?;
    let result: PrivilegedQuarantineStatus =
        serde_json::from_slice(payload.to_bytes()).map_err(io::Error::other)?;
    if result.operation_id != operation_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "quarantine response did not match the requested operation",
        ));
    }
    Ok(result)
}

/// A read-only proposal to quarantine a single standalone system app.
///
/// The helper checks the signed bundle and known installation records. The
/// caller explicitly selects a standalone app before requesting this preview.
pub struct PrivilegedStandaloneQuarantinePreview {
    operation_id: Uuid,
    path: PathBuf,
    bundle_identifier: String,
    retention_days: NonZeroU16,
    stamp: CString,
    created: Instant,
}

impl PrivilegedStandaloneQuarantinePreview {
    /// Identifies the operation for the future journal and status query.
    pub fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    /// The exact bundle path the helper reviewed.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The bundle identifier confirmed by the local code signature.
    pub fn bundle_identifier(&self) -> &str {
        &self.bundle_identifier
    }

    /// Retention that will be captured by the resulting backup record.
    pub fn retention_days(&self) -> NonZeroU16 {
        self.retention_days
    }

    /// Consumes the preview after the user confirms this one bundle.
    pub fn confirm(self) -> io::Result<ConfirmedStandaloneQuarantine> {
        require_fresh_preview(self.created)?;
        Ok(ConfirmedStandaloneQuarantine(self))
    }
}

/// A confirmed standalone bundle move that still requires administrator approval.
pub struct ConfirmedStandaloneQuarantine(PrivilegedStandaloneQuarantinePreview);

/// Result of a submitted standalone quarantine operation.
#[derive(Debug)]
pub enum PrivilegedQuarantineOutcome {
    /// The expected bundle is in its journaled quarantine slot.
    Quarantined(PrivilegedQuarantineStatus),
    /// The helper found an ambiguous filesystem or journal state.
    ReviewRequired(PrivilegedQuarantineStatus),
    /// The reply did not establish a result. Query the operation ID first.
    ReplyUncertain {
        /// Identifier for the read-only quarantine query.
        operation_id: Uuid,
        /// Reason the caller could not establish the result.
        error: io::Error,
    },
}

/// Asks the signed helper to read and verify a selected standalone bundle.
///
/// Call from a worker because the helper also checks package and runtime
/// evidence. This request creates neither a backup nor an authorization.
pub fn prepare_privileged_standalone_quarantine(
    path: &Path,
    bundle_identifier: &str,
) -> io::Result<PrivilegedStandaloneQuarantinePreview> {
    prepare_privileged_standalone_quarantine_with_retention(
        path,
        bundle_identifier,
        DEFAULT_RETENTION_DAYS,
    )
}

/// Previews a standalone bundle with the active backup retention preference.
///
/// Pass the value from the existing [`uninstallany_core::LoadedPreferences`].
/// The signed helper records a deadline from this value when preparing the move.
pub fn prepare_privileged_standalone_quarantine_with_retention(
    path: &Path,
    bundle_identifier: &str,
    retention_days: NonZeroU16,
) -> io::Result<PrivilegedStandaloneQuarantinePreview> {
    let request = BundleRequest::new(path, bundle_identifier)?;
    let mut stamp = [0u8; STAMP_BUFFER_BYTES];
    // SAFETY: The inputs are live C strings, and the synchronous bridge
    // may only write up to the given buffer length before returning.
    let status = unsafe {
        UAPreviewStandaloneQuarantineThroughSignedHelper(
            request.team.as_ptr(),
            request.basename.as_ptr(),
            request.identifier.as_ptr(),
            stamp.as_mut_ptr().cast(),
            stamp.len(),
        )
    };
    if status != 0 {
        return Err(standalone_quarantine_error(status));
    }
    let stamp = CStr::from_bytes_until_nul(&stamp).map_err(io::Error::other)?;
    if !stamp.to_str().is_ok_and(valid_stamp) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid quarantine preview stamp",
        ));
    }
    Ok(PrivilegedStandaloneQuarantinePreview {
        operation_id: Uuid::new_v4(),
        path: path.to_owned(),
        bundle_identifier: bundle_identifier.to_owned(),
        retention_days,
        stamp: stamp.to_owned(),
        created: Instant::now(),
    })
}

/// Quarantines the confirmed standalone app after independent administrator authorization.
///
/// A lost or ambiguous result requires a read-only query by the operation ID.
/// Generate and confirm a new preview before retrying a proven no-move result.
pub fn quarantine_privileged_standalone_application(
    confirmed: ConfirmedStandaloneQuarantine,
) -> io::Result<PrivilegedQuarantineOutcome> {
    let preview = confirmed.0;
    require_fresh_preview(preview.created)?;
    let operation_id = preview.operation_id;
    let request = BundleRequest::new(&preview.path, &preview.bundle_identifier)?;
    let operation = operation_identifier(operation_id)?;
    let native = StandaloneQuarantineRequest {
        basename: request.basename.as_ptr(),
        bundle_identifier: request.identifier.as_ptr(),
        review_stamp: preview.stamp.as_ptr(),
        operation_id: operation.as_ptr(),
        retention_days: preview.retention_days.get(),
    };
    let mut response = [0u8; MAX_REPLY_BYTES];
    // SAFETY: The request and strings remain live through this call. The
    // bridge copies at most the given buffer capacity before returning.
    let status = unsafe {
        UAQuarantineStandaloneThroughSignedHelper(
            request.team.as_ptr(),
            &native,
            response.as_mut_ptr().cast(),
            response.len(),
        )
    };
    if status == OUTCOME_UNKNOWN {
        return Ok(PrivilegedQuarantineOutcome::ReplyUncertain {
            operation_id,
            error: io::Error::other("the signed helper did not establish the quarantine outcome"),
        });
    }
    if status != 0 {
        return Err(standalone_quarantine_error(status));
    }
    match decode_quarantine_status(&response, operation_id) {
        Ok(result) if confirmed_quarantine_result(&preview, &result) => {
            Ok(PrivilegedQuarantineOutcome::Quarantined(result))
        }
        Ok(result) if result.status == PrivilegedQuarantineState::Ambiguous => {
            Ok(PrivilegedQuarantineOutcome::ReviewRequired(result))
        }
        Ok(_) => Ok(PrivilegedQuarantineOutcome::ReplyUncertain {
            operation_id,
            error: io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid quarantine completion record",
            ),
        }),
        Err(error) => Ok(PrivilegedQuarantineOutcome::ReplyUncertain {
            operation_id,
            error,
        }),
    }
}

fn confirmed_quarantine_result(
    reviewed: &PrivilegedStandaloneQuarantinePreview,
    result: &PrivilegedQuarantineStatus,
) -> bool {
    result.status == PrivilegedQuarantineState::Quarantined
        && result.os_error == 0
        && result.record.as_ref().is_some_and(|record| {
            record
                .quarantine_completed_at_epoch_seconds
                .is_some_and(f64::is_finite)
                && record.original_path == reviewed.path
                && record.bundle_id == reviewed.bundle_identifier
                && record.retention_days == Some(reviewed.retention_days)
                && record.expires_at_unix_ms.is_some_and(|expiry| expiry > 0)
        })
}

fn standalone_quarantine_error(status: i32) -> io::Error {
    let error = io::Error::from_raw_os_error(status);
    match error.kind() {
        io::ErrorKind::AlreadyExists => io::Error::new(
            error.kind(),
            "an Installer receipt or existing quarantine record claims this operation",
        ),
        io::ErrorKind::ResourceBusy | io::ErrorKind::WouldBlock => io::Error::new(
            error.kind(),
            "a busy application, service, package catalog, or helper stopped the quarantine check",
        ),
        _ => error,
    }
}

/// An immutable preview for restoring one helper-owned quarantine slot.
pub struct PrivilegedRestorePreview {
    operation_id: Uuid,
    record: PrivilegedQuarantineRecord,
    stamp: String,
    created: Instant,
}

impl PrivilegedRestorePreview {
    /// Identifies the quarantined operation to display and reconcile.
    pub fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    /// Returns the backup and destination reviewed for restoration.
    pub fn record(&self) -> &PrivilegedQuarantineRecord {
        &self.record
    }

    /// Consumes this preview after the user confirms the displayed action.
    pub fn confirm(self) -> io::Result<ConfirmedPrivilegedRestore> {
        require_fresh_preview(self.created)?;
        Ok(ConfirmedPrivilegedRestore(self))
    }
}

/// A single explicitly confirmed restore, still subject to administrator approval.
pub struct ConfirmedPrivilegedRestore(PrivilegedRestorePreview);

/// Outcome after submitting one restore to the signed helper.
#[derive(Debug)]
pub enum PrivilegedRestoreOutcome {
    /// The expected bundle was restored and the helper returned its journal state.
    Restored(PrivilegedQuarantineStatus),
    /// The helper reported an ambiguous filesystem or journal state.
    ReviewRequired(PrivilegedQuarantineStatus),
    /// The reply could not establish the result. Query the operation before retrying.
    ReplyUncertain {
        /// Identifier to pass to the read-only quarantine query.
        operation_id: Uuid,
        /// Reason the reply could not be used as a result.
        error: io::Error,
    },
}

/// Previews a system restore using the signed helper's read-only query.
///
/// The preview is eligible only when the recorded bundle is still in its slot
/// and the original destination is vacant. No authorization dialog is opened.
pub fn prepare_privileged_restore(operation_id: Uuid) -> io::Result<PrivilegedRestorePreview> {
    let result = query_privileged_quarantine(operation_id)?;
    if result.status != PrivilegedQuarantineState::Quarantined {
        return Err(if result.os_error != 0 {
            io::Error::from_raw_os_error(result.os_error)
        } else {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "the operation has no restorable bundle",
            )
        });
    }
    let record = result.record.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing quarantine journal details",
        )
    })?;
    if record.destination_occupied {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "the original restore destination is occupied",
        ));
    }
    let stamp = record
        .restore_stamp
        .as_deref()
        .filter(|stamp| valid_stamp(stamp))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing or invalid restore preview stamp",
            )
        })?;
    Ok(PrivilegedRestorePreview {
        operation_id,
        stamp: stamp.to_owned(),
        record,
        created: Instant::now(),
    })
}

/// Requests a single restore under the helper's independent administrator right.
///
/// Call from a worker with a confirmed preview. For an uncertain result, read
/// the operation status and require a fresh confirmation before any retry.
pub fn restore_privileged_application(
    confirmed: ConfirmedPrivilegedRestore,
) -> io::Result<PrivilegedRestoreOutcome> {
    let preview = confirmed.0;
    require_fresh_preview(preview.created)?;
    let operation_id = preview.operation_id;
    let team = signed_helper_team()?;
    let identifier = operation_identifier(operation_id)?;
    let stamp = CString::new(preview.stamp).map_err(io::Error::other)?;
    let mut response = [0u8; MAX_REPLY_BYTES];
    // SAFETY: All inputs remain valid through the call. The bridge copies
    // the bounded reply into this buffer before returning.
    let status = unsafe {
        UARestoreThroughSignedHelper(
            team.as_ptr(),
            identifier.as_ptr(),
            stamp.as_ptr(),
            response.as_mut_ptr().cast(),
            response.len(),
        )
    };
    if status == OUTCOME_UNKNOWN {
        return Ok(PrivilegedRestoreOutcome::ReplyUncertain {
            operation_id,
            error: io::Error::other("the signed helper did not establish the restore outcome"),
        });
    }
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    match decode_quarantine_status(&response, operation_id) {
        Ok(result) if confirmed_restore_result(&preview.record, &result) => {
            Ok(PrivilegedRestoreOutcome::Restored(result))
        }
        Ok(result) if result.status == PrivilegedQuarantineState::Ambiguous => {
            Ok(PrivilegedRestoreOutcome::ReviewRequired(result))
        }
        Ok(_) => Ok(PrivilegedRestoreOutcome::ReplyUncertain {
            operation_id,
            error: io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid restore completion record",
            ),
        }),
        Err(error) => Ok(PrivilegedRestoreOutcome::ReplyUncertain {
            operation_id,
            error,
        }),
    }
}

fn confirmed_restore_result(
    reviewed: &PrivilegedQuarantineRecord,
    result: &PrivilegedQuarantineStatus,
) -> bool {
    result.status == PrivilegedQuarantineState::Restored
        && result.os_error == 0
        && result.record.as_ref().is_some_and(|record| {
            record
                .restore_completed_at_epoch_seconds
                .is_some_and(f64::is_finite)
                && !record.destination_occupied
                && record.original_path == reviewed.original_path
                && record.backup_path == reviewed.backup_path
                && record.bundle_id == reviewed.bundle_id
                && record.root_stamp == reviewed.root_stamp
        })
}

fn require_fresh_preview(created: Instant) -> io::Result<()> {
    if created.elapsed() >= PREVIEW_LIFETIME {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "confirmation expired, generate a new preview",
        ));
    }
    Ok(())
}

fn operation_identifier(operation_id: Uuid) -> io::Result<CString> {
    CString::new(operation_id.hyphenated().to_string()).map_err(io::Error::other)
}

fn valid_stamp(stamp: &str) -> bool {
    stamp.len() == 64
        && stamp
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// Verifies one independent administrator approval for a reviewed bundle.
///
/// Call from a worker after the user confirms the reviewed action. Existing
/// Installer receipt claims and indeterminate checks stop approval. Success
/// consumes the approval in this helper request and returns no mutation permit.
pub fn verify_privileged_quarantine_authorization(
    path: &Path,
    bundle_identifier: &str,
    reviewed: &PrivilegedBundleInspection,
) -> io::Result<()> {
    let PrivilegedBundleInspection::Verified { root_stamp, .. } = reviewed else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "quarantine authorization requires a verified application preview",
        ));
    };
    if !valid_stamp(root_stamp) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid application identity stamp",
        ));
    }
    let request = BundleRequest::new(path, bundle_identifier)?;
    let stamp = CString::new(root_stamp.as_str()).map_err(io::Error::other)?;
    // SAFETY: The strings stay alive and NUL-terminated until the bridge ends.
    let status = unsafe {
        UAVerifyQuarantineThroughSignedHelper(
            request.team.as_ptr(),
            request.basename.as_ptr(),
            request.identifier.as_ptr(),
            stamp.as_ptr(),
        )
    };
    if status != 0 {
        let error = io::Error::from_raw_os_error(status);
        if error.kind() == io::ErrorKind::AlreadyExists {
            return Err(io::Error::new(
                error.kind(),
                "an Installer receipt claims the reviewed application bundle",
            ));
        }
        return Err(error);
    }
    Ok(())
}

struct BundleRequest {
    team: CString,
    basename: CString,
    identifier: CString,
}

impl BundleRequest {
    fn new(path: &Path, bundle_identifier: &str) -> io::Result<Self> {
        if path.parent() != Some(Path::new("/Applications"))
            || !bundle::is_app(path)
            || !bundle::valid_identifier(bundle_identifier)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a direct application bundle and its literal bundle identifier are required",
            ));
        }
        let basename = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid application bundle name",
                )
            })?;
        Ok(Self {
            team: signed_helper_team()?,
            basename: CString::new(basename).map_err(io::Error::other)?,
            identifier: CString::new(bundle_identifier).map_err(io::Error::other)?,
        })
    }
}

fn signed_helper_team() -> io::Result<CString> {
    let team = vendor::current_signing_team(GUI_SIGNING_ID).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "privileged operations require the signed desktop application",
        )
    })?;
    CString::new(team).map_err(io::Error::other)
}
