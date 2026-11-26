//! One-shot launcher and entry point for a separately installed Windows MSI helper.

use std::{
    ffi::OsStr,
    io,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{FromRawHandle, OwnedHandle},
    },
    time::Duration,
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use windows::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize,
};
use windows_sys::Win32::{
    Foundation::ERROR_CANCELLED,
    System::Threading::GetCurrentProcessId,
    UI::{
        Shell::{
            SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
            ShellExecuteExW,
        },
        WindowsAndMessaging::SW_SHOWNORMAL,
    },
};

use crate::{
    helper_ipc,
    helper_msi::MachineMsiRequest,
    helper_trust::{self, TrustedExecutable},
    registry::InstalledEntry,
    uninstall::OfficialOutcome,
};

const PROTOCOL: &str = "--msi-worker-v1";
const INSTALLER_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Reply {
    Outcome(OfficialOutcome),
    Rejected(String),
}

/// Authorization material captured alongside the ordinary MSI command.
pub(super) struct PreparedMsi {
    request: MachineMsiRequest,
    helper: TrustedExecutable,
}

impl PreparedMsi {
    pub(super) fn prepare(entry: &InstalledEntry) -> io::Result<Self> {
        helper_trust::pin_gui()?.verify_current_process()?;
        Ok(Self {
            request: MachineMsiRequest::preflight(entry)?,
            helper: helper_trust::pin_helper()?,
        })
    }

    pub(super) fn execute(self) -> io::Result<OfficialOutcome> {
        let gui = helper_trust::pin_gui()?;
        gui.verify_current_process()?;
        let request = serde_json::to_vec(&self.request).map_err(io::Error::other)?;
        let token = Uuid::new_v4();
        let process = match launch_helper(&self.helper, token) {
            Ok(process) => process,
            Err(error) if error.raw_os_error() == Some(ERROR_CANCELLED as i32) => {
                return Ok(OfficialOutcome::Cancelled);
            }
            Err(error) => return Err(error),
        };
        self.helper.verify_process(&process)?;
        let mut channel = helper_ipc::connect(token, &process)?;
        channel.send(&request)?;
        let response = channel.receive(INSTALLER_TIMEOUT).map_err(|error| {
            io::Error::other(format!(
                "the elevated installer outcome is unknown ({error})"
            ))
        })?;
        match serde_json::from_slice(&response).map_err(io::Error::other)? {
            Reply::Outcome(outcome) => Ok(outcome),
            Reply::Rejected(reason) => Err(io::Error::other(format!("MSI helper: {reason}"))),
        }
    }
}

fn launch_helper(helper: &TrustedExecutable, token: Uuid) -> io::Result<OwnedHandle> {
    let _apartment = ShellApartment::enter()?;
    let verb = wide(OsStr::new("runas"));
    // SAFETY: GetCurrentProcessId needs no arguments or caller-owned memory.
    let pid = unsafe { GetCurrentProcessId() };
    let parameters = wide(OsStr::new(&format!("{PROTOCOL} {pid} {token}")));
    let image = wide(helper.path().as_os_str());
    let parent = helper
        .path()
        .parent()
        .ok_or_else(|| denied("missing helper directory"))?;
    let directory = wide(parent.as_os_str());
    let mut launch = SHELLEXECUTEINFOW {
        cbSize: u32::try_from(size_of::<SHELLEXECUTEINFOW>()).map_err(io::Error::other)?,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        lpVerb: verb.as_ptr(),
        lpFile: image.as_ptr(),
        lpParameters: parameters.as_ptr(),
        lpDirectory: directory.as_ptr(),
        nShow: SW_SHOWNORMAL,
        ..Default::default()
    };
    // SAFETY: Buffers and pinned image live across the call. The only arguments
    // identify a local peer and nonce, and carry no command or uninstall target.
    if unsafe { ShellExecuteExW(&mut launch) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if launch.hProcess.is_null() {
        return Err(denied(
            "Windows did not return a verifier handle for the MSI helper",
        ));
    }
    // SAFETY: SEE_MASK_NOCLOSEPROCESS transfers the process handle to this caller.
    Ok(unsafe { OwnedHandle::from_raw_handle(launch.hProcess) })
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain([0]).collect()
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

struct ShellApartment;

impl ShellApartment {
    fn enter() -> io::Result<Self> {
        // SAFETY: The reserved pointer is null and this guard balances a success.
        unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) }
            .ok()
            .map_err(io::Error::other)?;
        Ok(Self)
    }
}

impl Drop for ShellApartment {
    fn drop(&mut self) {
        // SAFETY: This private guard is created and dropped on the calling worker.
        unsafe { CoUninitialize() };
    }
}

/// Handles one authenticated machine MSI request from the installed desktop app.
#[cfg(feature = "privileged-helper")]
pub fn run_privileged_helper() -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{
        Foundation::WAIT_TIMEOUT, Globalization::GetUserDefaultUILanguage,
        System::Threading::WaitForSingleObject,
    };

    const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
    let mut args = std::env::args_os().skip(1);
    let discriminator = args.next();
    let caller_pid = args
        .next()
        .and_then(|arg| arg.to_str()?.parse::<u32>().ok());
    let nonce = args
        .next()
        .and_then(|arg| Uuid::parse_str(arg.to_str()?).ok());
    let (Some(pid), Some(nonce)) = (caller_pid, nonce) else {
        return Err(denied("invalid MSI helper rendezvous"));
    };
    if discriminator.as_deref() != Some(OsStr::new(PROTOCOL))
        || pid == 0
        || nonce.get_version_num() != 4
        || args.next().is_some()
    {
        return Err(denied("invalid MSI helper rendezvous"));
    }
    if !crate::platform::elevated()? {
        return Err(denied(
            "the Windows MSI helper requires the native administrator prompt",
        ));
    }
    let helper = helper_trust::pin_helper()?;
    helper.verify_current_process()?;
    let gui = helper_trust::pin_gui()?;
    let caller = helper_trust::open_caller(pid)?;
    gui.verify_process(&caller)?;
    let caller_sid = helper_trust::caller_sid(&caller)?;
    let mut channel = helper_ipc::Server::create(nonce, &caller_sid)?.accept(&caller)?;
    let bytes = channel.receive(REQUEST_TIMEOUT)?;
    let request: MachineMsiRequest = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    // SAFETY: this function takes no arguments. The low ten bits of a LANGID
    // are its primary language and 0x04 is Chinese.
    let chinese = unsafe { GetUserDefaultUILanguage() } & 0x03ff == 0x04;
    let result = request.confirmation_text(chinese).and_then(|text| {
        if !confirm_product(&text) {
            return Ok(OfficialOutcome::Cancelled);
        }
        // Revalidate both the caller and the registered product after the prompt.
        // SAFETY: caller is a held process handle opened with synchronization access.
        if unsafe { WaitForSingleObject(caller.as_raw_handle(), 0) } != WAIT_TIMEOUT {
            return Err(denied("the desktop requester is no longer running"));
        }
        gui.verify_process(&caller)?;
        request.execute()
    });
    let reply = match result {
        Ok(outcome) => Reply::Outcome(outcome),
        Err(error) => Reply::Rejected(error.to_string().chars().take(512).collect()),
    };
    channel.send(&serde_json::to_vec(&reply).map_err(io::Error::other)?)
}

#[cfg(feature = "privileged-helper")]
fn confirm_product(details: &str) -> bool {
    use std::ptr::null_mut;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_TOPMOST, MB_YESNO, MessageBoxW,
    };
    let title = wide(OsStr::new("UninstallAny · Windows Installer"));
    let detail = wide(OsStr::new(details));
    // SAFETY: Both strings are NUL-terminated and the helper has no parent window.
    let answer = unsafe {
        MessageBoxW(
            null_mut(),
            detail.as_ptr(),
            title.as_ptr(),
            MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING | MB_TOPMOST,
        )
    };
    answer == IDYES
}
