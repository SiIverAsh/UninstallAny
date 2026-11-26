//! Explicit expiry confirmation for helper-owned quarantine backups.

use std::{
    ffi::{CStr, CString, c_char},
    io,
    path::{Path, PathBuf},
    time::Instant,
};

use serde::Deserialize;
use uuid::Uuid;

use super::{
    MAX_REPLY_BYTES, OUTCOME_UNKNOWN, PrivilegedQuarantineState, PrivilegedQuarantineStatus,
    decode_quarantine_status, operation_identifier, require_fresh_preview, signed_helper_team,
    valid_stamp,
};

unsafe extern "C" {
    fn UAPreviewExpiryThroughSignedHelper(
        team: *const c_char,
        operation_id: *const c_char,
        response: *mut c_char,
        response_capacity: usize,
    ) -> i32;
    fn UAExpireThroughSignedHelper(
        team: *const c_char,
        operation_id: *const c_char,
        expiry_stamp: *const c_char,
        response: *mut c_char,
        response_capacity: usize,
    ) -> i32;
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpiryReview {
    operation_id: Uuid,
    expiry_stamp: String,
    original_path: PathBuf,
    backup_path: PathBuf,
    bundle_id: String,
    expires_at_unix_ms: u64,
    remaining_entries: usize,
    is_pending: bool,
}

/// An immutable preview of one expired quarantine backup and its remaining tree.
pub struct PrivilegedExpiryPreview {
    review: ExpiryReview,
    created: Instant,
}

impl PrivilegedExpiryPreview {
    /// The recorded backup operation to display and reconcile.
    pub fn operation_id(&self) -> Uuid {
        self.review.operation_id
    }

    /// The application's original path, used for identification.
    pub fn original_path(&self) -> &Path {
        &self.review.original_path
    }

    /// The private payload or pending directory subject to removal.
    pub fn backup_path(&self) -> &Path {
        &self.review.backup_path
    }

    /// The recorded identifier of the quarantined application.
    pub fn bundle_identifier(&self) -> &str {
        &self.review.bundle_id
    }

    /// The deadline captured before the original quarantine move.
    pub fn expires_at_unix_ms(&self) -> u64 {
        self.review.expires_at_unix_ms
    }

    /// Number of reviewed filesystem entries still subject to removal.
    pub fn remaining_entries(&self) -> usize {
        self.review.remaining_entries
    }

    /// Whether the backup is already detached following an earlier attempt.
    pub fn is_pending(&self) -> bool {
        self.review.is_pending
    }

    /// Consumes this preview after the user approves permanent backup removal.
    pub fn confirm(self) -> io::Result<ConfirmedPrivilegedExpiry> {
        require_fresh_preview(self.created)?;
        Ok(ConfirmedPrivilegedExpiry(self))
    }
}

/// One confirmed expiry action requiring separate administrator approval.
pub struct ConfirmedPrivilegedExpiry(PrivilegedExpiryPreview);

/// Outcome of a submitted expiry action.
#[derive(Debug)]
pub enum PrivilegedExpiryOutcome {
    /// The helper returned a matching durable completion record.
    Purged(PrivilegedQuarantineStatus),
    /// An interrupted removal may continue after a fresh preview and review.
    Pending(PrivilegedQuarantineStatus),
    /// The helper identified an ambiguous filesystem or journal state.
    ReviewRequired(PrivilegedQuarantineStatus),
    /// Query the operation before deciding whether to start a new request.
    ReplyUncertain {
        /// Identifier for the read-only quarantine query.
        operation_id: Uuid,
        /// Reason the result could not be established through the reply.
        error: io::Error,
    },
}

/// Asks the signed helper to preview permanent removal of one expired backup.
///
/// Call from a worker. The helper verifies expiry using its persisted record
/// and fingerprints the remaining tree before it offers a preview.
pub fn preview_privileged_expiry(operation_id: Uuid) -> io::Result<PrivilegedExpiryPreview> {
    let team = signed_helper_team()?;
    let operation = operation_identifier(operation_id)?;
    let mut response = [0u8; MAX_REPLY_BYTES + 1];
    // SAFETY: Both input strings remain live through the synchronous call.
    // The bridge writes at most the given capacity to the response buffer.
    let status = unsafe {
        UAPreviewExpiryThroughSignedHelper(
            team.as_ptr(),
            operation.as_ptr(),
            response.as_mut_ptr().cast(),
            response.len(),
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    let payload = CStr::from_bytes_until_nul(&response).map_err(io::Error::other)?;
    let review: ExpiryReview =
        serde_json::from_slice(payload.to_bytes()).map_err(io::Error::other)?;
    let slot_matches = review
        .backup_path
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|slot| slot.as_encoded_bytes() == operation.as_bytes());
    if review.operation_id != operation_id
        || !valid_stamp(&review.expiry_stamp)
        || review.expires_at_unix_ms == 0
        || (!review.is_pending && review.remaining_entries == 0)
        || review.original_path.parent() != Some(Path::new("/Applications"))
        || !slot_matches
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid quarantine expiry preview",
        ));
    }
    Ok(PrivilegedExpiryPreview {
        review,
        created: Instant::now(),
    })
}

/// Permanently removes the confirmed expired backup through the signed helper.
///
/// An uncertain or pending outcome requires the read-only query and a new
/// confirmation before another request. The helper applies no automatic retry.
pub fn expire_privileged_quarantine(
    confirmed: ConfirmedPrivilegedExpiry,
) -> io::Result<PrivilegedExpiryOutcome> {
    let preview = confirmed.0;
    require_fresh_preview(preview.created)?;
    let review = preview.review;
    let operation_id = review.operation_id;
    let team = signed_helper_team()?;
    let operation = operation_identifier(operation_id)?;
    let stamp = CString::new(review.expiry_stamp.as_str()).map_err(io::Error::other)?;
    let mut response = [0u8; MAX_REPLY_BYTES + 1];
    // SAFETY: The strings remain live during the call. The bridge copies
    // the bounded reply into the supplied buffer before returning.
    let status = unsafe {
        UAExpireThroughSignedHelper(
            team.as_ptr(),
            operation.as_ptr(),
            stamp.as_ptr(),
            response.as_mut_ptr().cast(),
            response.len(),
        )
    };
    if status == OUTCOME_UNKNOWN {
        return Ok(PrivilegedExpiryOutcome::ReplyUncertain {
            operation_id,
            error: io::Error::other("the signed helper did not establish the expiry outcome"),
        });
    }
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    match decode_quarantine_status(&response, operation_id) {
        Ok(result) if confirmed_expiry_result(&review, &result) => {
            Ok(PrivilegedExpiryOutcome::Purged(result))
        }
        Ok(result) if result.status == PrivilegedQuarantineState::ExpiryPending => {
            Ok(PrivilegedExpiryOutcome::Pending(result))
        }
        Ok(result) if result.status == PrivilegedQuarantineState::Ambiguous => {
            Ok(PrivilegedExpiryOutcome::ReviewRequired(result))
        }
        Ok(_) => Ok(PrivilegedExpiryOutcome::ReplyUncertain {
            operation_id,
            error: io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid expiry completion record",
            ),
        }),
        Err(error) => Ok(PrivilegedExpiryOutcome::ReplyUncertain {
            operation_id,
            error,
        }),
    }
}

fn confirmed_expiry_result(review: &ExpiryReview, result: &PrivilegedQuarantineStatus) -> bool {
    result.status == PrivilegedQuarantineState::Purged
        && result.os_error == 0
        && result.record.as_ref().is_some_and(|record| {
            record
                .purged_at_epoch_seconds
                .is_some_and(|time| time.is_finite() && time > 0.0)
                && record.original_path == review.original_path
                && record.backup_path.parent() == review.backup_path.parent()
                && record.bundle_id == review.bundle_id
                && record.expires_at_unix_ms == Some(review.expires_at_unix_ms)
        })
}
