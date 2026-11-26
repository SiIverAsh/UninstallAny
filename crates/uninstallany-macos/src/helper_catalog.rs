//! Read-only catalog and retention previews for helper-owned backups.

use std::{
    ffi::{CStr, CString, c_char},
    io, ptr,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;
use uuid::Uuid;

use super::{
    PrivilegedQuarantineState, PrivilegedQuarantineStatus, operation_identifier,
    signed_helper_team, valid_stamp,
};

const PAGE_BYTES: usize = 32_768;
const PAGE_ENTRIES: usize = 12;

unsafe extern "C" {
    fn UAListQuarantineThroughSignedHelper(
        team: *const c_char,
        after_operation_id: *const c_char,
        catalog_stamp: *const c_char,
        response: *mut c_char,
        response_capacity: usize,
    ) -> i32;
}

/// A continuation for the same authenticated quarantine catalog snapshot.
pub struct PrivilegedQuarantineCursor {
    after: Uuid,
    stamp: CString,
}

/// One page of system backup records for the authenticated desktop account.
pub struct PrivilegedQuarantinePage {
    entries: Vec<PrivilegedQuarantineStatus>,
    next: Option<PrivilegedQuarantineCursor>,
    ignored_entries: usize,
}

impl PrivilegedQuarantinePage {
    /// Returns sampled states for the operation IDs on this page.
    pub fn entries(&self) -> &[PrivilegedQuarantineStatus] {
        &self.entries
    }

    /// Returns the continuation if the catalog contains more operations.
    pub fn next_cursor(&self) -> Option<&PrivilegedQuarantineCursor> {
        self.next.as_ref()
    }

    /// Counts unrecognized catalog entries outside the result list.
    pub fn ignored_entries(&self) -> usize {
        self.ignored_entries
    }

    /// Previews expired backups and resumable expiry operations on this page.
    ///
    /// Uses the deadline stored with each backup. An interrupted move without
    /// a completion marker or an older backup without expiry stays available
    /// for status queries and remains outside the expiry preview.
    pub fn expired_entries(&self) -> io::Result<impl Iterator<Item = &PrivilegedQuarantineStatus>> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?;
        let now_ms = u64::try_from(elapsed.as_millis()).map_err(io::Error::other)?;
        let now_seconds = elapsed.as_secs_f64();
        Ok(self.entries.iter().filter(move |entry| {
            matches!(
                entry.status,
                PrivilegedQuarantineState::Quarantined | PrivilegedQuarantineState::ExpiryPending
            ) && entry.os_error == 0
                && entry.record.as_ref().is_some_and(|record| {
                    record.retention_days.is_some()
                        && record
                            .expires_at_unix_ms
                            .is_some_and(|expiry| expiry > 0 && expiry <= now_ms)
                        && record
                            .quarantine_completed_at_epoch_seconds
                            .is_some_and(|seconds| {
                                seconds.is_finite() && seconds > 0.0 && seconds <= now_seconds
                            })
                })
        }))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuarantinePageReply {
    catalog_stamp: String,
    entries: Vec<PrivilegedQuarantineStatus>,
    next_operation_id: Option<Uuid>,
    ignored_entries: usize,
}

/// Lists signed helper backups without requiring a known operation ID.
///
/// Call from a worker. The catalog may change between pages, in which case
/// the helper rejects the cursor and the caller starts from the first page.
/// Each backup's state is observed independently of the directory snapshot.
pub fn list_privileged_quarantine_page(
    cursor: Option<&PrivilegedQuarantineCursor>,
) -> io::Result<PrivilegedQuarantinePage> {
    let team = signed_helper_team()?;
    let after = cursor
        .map(|cursor| operation_identifier(cursor.after))
        .transpose()?;
    let after_ptr = after.as_ref().map_or(ptr::null(), |value| value.as_ptr());
    let stamp_ptr = cursor.map_or(ptr::null(), |cursor| cursor.stamp.as_ptr());
    let mut response = [0u8; PAGE_BYTES + 1];
    // SAFETY: Inputs are live C strings or null for the first page. The
    // synchronous bridge writes only to the declared output buffer.
    let status = unsafe {
        UAListQuarantineThroughSignedHelper(
            team.as_ptr(),
            after_ptr,
            stamp_ptr,
            response.as_mut_ptr().cast(),
            response.len(),
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    let payload = CStr::from_bytes_until_nul(&response).map_err(io::Error::other)?;
    let page = serde_json::from_slice(payload.to_bytes()).map_err(io::Error::other)?;
    decode_quarantine_page(page, cursor)
}

fn decode_quarantine_page(
    page: QuarantinePageReply,
    cursor: Option<&PrivilegedQuarantineCursor>,
) -> io::Result<PrivilegedQuarantinePage> {
    let first = page.entries.first();
    let last = page.entries.last();
    if !valid_stamp(&page.catalog_stamp)
        || page.entries.len() > PAGE_ENTRIES
        || cursor.is_some_and(|cursor| {
            cursor.stamp.as_bytes() != page.catalog_stamp.as_bytes()
                || first.is_none_or(|entry| entry.operation_id <= cursor.after)
        })
        || page
            .entries
            .windows(2)
            .any(|pair| pair[0].operation_id >= pair[1].operation_id)
        || page.next_operation_id.is_some_and(|next| {
            page.entries.len() != PAGE_ENTRIES
                || last.is_none_or(|entry| entry.operation_id != next)
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid quarantine catalog page",
        ));
    }
    let next = if let Some(after) = page.next_operation_id {
        let stamp = CString::new(page.catalog_stamp).map_err(io::Error::other)?;
        Some(PrivilegedQuarantineCursor { after, stamp })
    } else {
        None
    };
    Ok(PrivilegedQuarantinePage {
        entries: page.entries,
        next,
        ignored_entries: page.ignored_entries,
    })
}
