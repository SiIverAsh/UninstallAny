//! Explicit Service Management registration for the bundled macOS helper.

use std::{
    ffi::{CString, c_char},
    io,
    time::Instant,
};

use super::{require_fresh_preview, signed_helper_team};

unsafe extern "C" {
    fn UAQueryHelperService(team: *const c_char, service_state: *mut i32) -> i32;
    fn UARegisterHelperService(team: *const c_char, service_state: *mut i32) -> i32;
}

/// Registration state reported by macOS for the bundled launch daemon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivilegedHelperServiceState {
    /// The release includes a verified helper that can be registered.
    NotRegistered,
    /// macOS has approved the registered daemon for launch.
    Enabled,
    /// A system administrator still needs to approve the daemon in settings.
    RequiresApproval,
    /// The installed app lacks a complete helper or service definition.
    NotFound,
}

/// A read-only preview of enabling the system helper for privileged operations.
pub struct PrivilegedHelperRegistrationPreview {
    team: CString,
    created: Instant,
}

impl PrivilegedHelperRegistrationPreview {
    /// Consumes the preview after the user authorizes requesting registration.
    pub fn confirm(self) -> io::Result<ConfirmedPrivilegedHelperRegistration> {
        require_fresh_preview(self.created)?;
        Ok(ConfirmedPrivilegedHelperRegistration(self))
    }
}

/// One explicit request to register the installed, signed helper service.
pub struct ConfirmedPrivilegedHelperRegistration(PrivilegedHelperRegistrationPreview);

/// Reads the installed helper's state without opening a Mach connection.
///
/// An enabled service still needs a signed handshake for any helper operation.
pub fn privileged_helper_service_state() -> io::Result<PrivilegedHelperServiceState> {
    query_service_state(&signed_helper_team()?)
}

/// Previews a one-time registration request for the signed system helper.
///
/// Explain that the daemon handles backups requiring system permissions.
/// macOS may require administrator approval to launch it. Any privileged
/// isolation, restore, or expiry action still needs its own confirmation.
pub fn prepare_privileged_helper_registration() -> io::Result<PrivilegedHelperRegistrationPreview> {
    let team = signed_helper_team()?;
    let state = query_service_state(&team)?;
    match state {
        PrivilegedHelperServiceState::NotRegistered => Ok(PrivilegedHelperRegistrationPreview {
            team,
            created: Instant::now(),
        }),
        PrivilegedHelperServiceState::Enabled => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "the system helper is already enabled",
        )),
        PrivilegedHelperServiceState::RequiresApproval => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "the registered system helper is awaiting administrator approval",
        )),
        PrivilegedHelperServiceState::NotFound => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "the installed app is missing the system helper or its launch definition",
        )),
    }
}

/// Registers the packaged system helper after the user confirms the preview.
///
/// This request does not perform a privileged file operation. The returned
/// state distinguishes registration from the operating system's approval.
pub fn register_privileged_helper(
    confirmed: ConfirmedPrivilegedHelperRegistration,
) -> io::Result<PrivilegedHelperServiceState> {
    let preview = confirmed.0;
    require_fresh_preview(preview.created)?;
    let mut state = -1;
    // SAFETY: The team is a live NUL-terminated string and the native
    // registration returns its state through the supplied i32.
    let status = unsafe { UARegisterHelperService(preview.team.as_ptr(), &mut state) };
    decode_service_state(status, state)
}

fn query_service_state(team: &CString) -> io::Result<PrivilegedHelperServiceState> {
    let mut state = -1;
    // SAFETY: The string and the writable state are valid for the call.
    let status = unsafe { UAQueryHelperService(team.as_ptr(), &mut state) };
    decode_service_state(status, state)
}

fn decode_service_state(status: i32, state: i32) -> io::Result<PrivilegedHelperServiceState> {
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    match state {
        0 => Ok(PrivilegedHelperServiceState::NotRegistered),
        1 => Ok(PrivilegedHelperServiceState::Enabled),
        2 => Ok(PrivilegedHelperServiceState::RequiresApproval),
        3 => Ok(PrivilegedHelperServiceState::NotFound),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unknown macOS helper service state",
        )),
    }
}
