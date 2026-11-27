use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uninstallany_core::{Cancellation, MatchKind};
use uuid::Uuid;
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_APPHELP_BLOCK, ERROR_CALL_NOT_IMPLEMENTED,
    ERROR_CANCELLED, ERROR_ELEVATION_REQUIRED, ERROR_FILE_NOT_FOUND, ERROR_INSTALL_ALREADY_RUNNING,
    ERROR_INSTALL_FAILURE, ERROR_INSTALL_REJECTED, ERROR_INSTALL_REMOTE_DISALLOWED,
    ERROR_INSTALL_SUSPEND, ERROR_INSTALL_USEREXIT, ERROR_INVALID_DATA, ERROR_INVALID_FIELD,
    ERROR_INVALID_PARAMETER, ERROR_PATCH_TARGET_NOT_FOUND, ERROR_SUCCESS,
    ERROR_SUCCESS_REBOOT_INITIATED, ERROR_SUCCESS_REBOOT_REQUIRED, ERROR_UNKNOWN_PRODUCT,
    GetLastError, HANDLE, SetLastError, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_GENERIC_READ, FILE_NAME_NORMALIZED, FILE_SHARE_READ, FILE_SHARE_WRITE, GetBinaryTypeW,
    GetFinalPathNameByHandleW, VOLUME_NAME_GUID,
};
use windows_sys::Win32::System::ApplicationInstallationAndServicing::{
    INSTALLPROPERTY_PRODUCTSTATE, MSIINSTALLCONTEXT, MSIINSTALLCONTEXT_MACHINE,
    MSIINSTALLCONTEXT_USERMANAGED, MSIINSTALLCONTEXT_USERUNMANAGED, MsiGetProductInfoExW,
};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation,
    OpenJobObjectW, QueryInformationJobObject,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::SystemServices::JOB_OBJECT_QUERY;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
    GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION, STARTUPINFOEXW, STARTUPINFOW,
    UpdateProcThreadAttribute, WaitForSingleObject,
};
use windows_sys::Win32::System::WindowsProgramming::{SCS_32BIT_BINARY, SCS_64BIT_BINARY};

use super::files::WindowsFiles;
use super::files::native::{self, DirectoryIdentity, Identity, LocalPath, OpenPath, PathWalk};
use super::registry::{self, SystemUninstallWait, SystemUninstaller};
use super::shortcuts::ShortcutTarget;

const MAX_WINDOWS_COMMAND_UNITS: usize = 32_767;
const MAX_UNINSTALLER_BYTES: u64 = 512 * 1024 * 1024;
const HASH_BUFFER_BYTES: usize = 64 * 1024;
const DESCENDANT_POLL: Duration = Duration::from_millis(100);
const PROCESS_POLL_MS: u32 = 100;
const DESCENDANT_WAIT: Duration = Duration::from_secs(30);
const EXIT_OBSERVATION_POLL: Duration = Duration::from_millis(500);
const MSI_CONTEXTS: [MSIINSTALLCONTEXT; 3] = [
    MSIINSTALLCONTEXT_MACHINE,
    MSIINSTALLCONTEXT_USERMANAGED,
    MSIINSTALLCONTEXT_USERUNMANAGED,
];
const BLOCKED_EXECUTABLES: &[&str] = &[
    "cmd",
    "command",
    "control",
    "cscript",
    "explorer",
    "hh",
    "mshta",
    "msiexec",
    "powershell",
    "pwsh",
    "reg",
    "regasm",
    "regedit",
    "regsvr32",
    "rundll32",
    "schtasks",
    "wmic",
    "wscript",
];

/// Result of an official uninstaller, before any residual cleanup.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OfficialOutcome {
    /// The native provider reported and independently verified removal.
    Completed,
    /// A restart is required or Windows Installer already requested it.
    NeedsRestart,
    /// The operation was declined or cancelled by the native provider.
    Cancelled,
    /// The native provider returned an unsuccessful exit or status code.
    Failed(u32),
    /// The native provider returned, but final removal could not be established.
    Unverified(u32),
}

pub(super) struct NativeExecution {
    pub outcome: OfficialOutcome,
    pub detached: Option<PendingUninstall>,
    pub terminal_win32_failure: Option<OfficialUninstall>,
    pub warnings: Vec<String>,
}

pub(super) struct PendingUninstall {
    pub process: OfficialProcess,
    pub warning: String,
}

enum PendingReason {
    StoppedWaiting,
    DescendantsTimedOut,
    DescendantsRunningAfterFailure,
    ObservationFailed(io::Error),
}

impl PendingReason {
    fn warning(self) -> String {
        let reason = match self {
            Self::StoppedWaiting => "Stopped waiting for the Windows uninstaller. It or its child processes may still be running.".into(),
            Self::DescendantsTimedOut => "Timed out waiting for the Windows uninstaller's child processes.".into(),
            Self::DescendantsRunningAfterFailure => "The Windows uninstaller reported a failure while its child processes were still running.".into(),
            Self::ObservationFailed(error) => format!("Could not verify that the Windows uninstaller or its child processes exited ({error})."),
        };
        format!(
            "{reason} Uninstall and cleanup are available again once the tracked processes are confirmed to have exited."
        )
    }
}

impl NativeExecution {
    pub(super) fn finished(outcome: OfficialOutcome) -> Self {
        Self {
            outcome,
            detached: None,
            terminal_win32_failure: None,
            warnings: Vec::new(),
        }
    }

    pub(super) fn with_warning(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }

    fn pending(process: OfficialProcess, outcome: OfficialOutcome, reason: PendingReason) -> Self {
        Self {
            outcome,
            detached: Some(PendingUninstall {
                process,
                warning: reason.warning(),
            }),
            terminal_win32_failure: None,
            warnings: Vec::new(),
        }
    }
}

/// Stable executable and ancestor identities plus a digest of the file contents.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct ExecutableIdentity {
    // A new ancestor could redirect resolution even when the leaf is unchanged.
    chain: Vec<Identity>,
    contents: [u8; 32],
}

/// Retains no-follow executable and ancestor handles while a change commits.
pub(super) struct PinnedExecutable {
    chain: Vec<Identity>,
    native_name: Vec<u16>,
    // Keep the directory chain and file open without delete sharing through launch.
    path: OpenPath,
}

enum Provider {
    Win32 { quiet_rejected: bool },
    Msi { product_code: String, machine: bool },
}

#[derive(Clone, Copy)]
enum LaunchAuthority {
    Desktop,
    #[cfg(feature = "privileged-helper")]
    AuthenticatedHelper,
}

/// Validated official uninstall intent. Arguments are not exposed for editing or logging.
pub struct OfficialUninstall {
    program: PathBuf,
    arguments: String,
    is_quiet: bool,
    provider: Provider,
    identity: ExecutableIdentity,
    inferred_icon: Option<(PathBuf, ExecutableIdentity)>,
}

impl OfficialUninstall {
    /// Returns whether the native command is configured for unattended interaction.
    pub fn is_quiet(&self) -> bool {
        self.is_quiet
    }

    /// Returns a display summary without embedding potentially private arguments.
    pub fn summary(&self) -> String {
        let interaction = if self.is_quiet {
            "quiet"
        } else {
            "interactive"
        };
        match &self.provider {
            Provider::Win32 {
                quiet_rejected: true,
            } => {
                format!(
                    "{} (interactive, quiet command rejected)",
                    self.program.display()
                )
            }
            Provider::Win32 {
                quiet_rejected: false,
            } => {
                format!("{} ({interaction})", self.program.display())
            }
            Provider::Msi { product_code, .. } => {
                format!("Windows Installer {product_code} ({interaction})")
            }
        }
    }

    /// Runs the confirmed intent on an ordinary worker thread and waits for exit.
    #[cfg(feature = "privileged-helper")]
    pub fn execute(self) -> io::Result<OfficialOutcome> {
        self.execute_with_authority(
            &Cancellation::default(),
            LaunchAuthority::AuthenticatedHelper,
        )
        .map(|result| result.outcome)
    }

    pub(super) fn msi_product_code(&self) -> Option<&str> {
        match &self.provider {
            Provider::Msi { product_code, .. } => Some(product_code),
            Provider::Win32 { .. } => None,
        }
    }

    fn verify_executables(&self) -> io::Result<(PinnedExecutable, Option<PinnedExecutable>)> {
        let pinned = pin_executable(&self.program)?;
        if pinned.identity()? != self.identity {
            return Err(invalid(
                "the official uninstaller or its containing directory changed; preview again",
            ));
        }
        let icon_pin = self
            .inferred_icon
            .as_ref()
            .map(|(path, approved)| {
                let (icon, identity) = pin_inferred_icon(&self.program, &pinned, path)?;
                if &identity != approved {
                    return Err(invalid(
                        "the registered application icon executable changed; preview again",
                    ));
                }
                Ok(icon)
            })
            .transpose()?;
        Ok((pinned, icon_pin))
    }

    /// Checks that a reported failure still identifies the same native images.
    pub(super) fn revalidate_failed_images(&self) -> io::Result<()> {
        self.verify_executables().map(|_| ())
    }

    pub(super) fn execute_with_cancel(self, cancel: &Cancellation) -> io::Result<NativeExecution> {
        self.execute_with_authority(cancel, LaunchAuthority::Desktop)
    }

    fn execute_with_authority(
        self,
        cancel: &Cancellation,
        authority: LaunchAuthority,
    ) -> io::Result<NativeExecution> {
        let (pinned, icon_pin) = self.verify_executables()?;
        if let Provider::Msi {
            product_code,
            machine,
        } = &self.provider
        {
            verify_msi_context(product_code, *machine)?;
        }
        let process = start_process(&self, &pinned, cancel, authority);
        // Some uninstallers remove themselves after starting. Release the pins once
        // Windows has opened the exact executable and returned a process handle.
        drop(pinned);
        drop(icon_pin);
        let mut process = match process {
            Ok(process) => process,
            Err(error) if error.raw_os_error() == Some(ERROR_CANCELLED as i32) => {
                return Ok(NativeExecution::finished(OfficialOutcome::Cancelled));
            }
            Err(error) => return Err(error),
        };
        if let Some(error) = process.tracking_error.take() {
            return Ok(NativeExecution::pending(
                process,
                OfficialOutcome::Unverified(0),
                PendingReason::ObservationFailed(error),
            ));
        }
        // MSI can still be committing work in the installer service when the
        // caller cancels. Only the tracked Win32 wait can be detached.
        let wait_cancel = process.job.as_ref().map(|_| cancel);
        let code = match wait_for_exit(&process.root, wait_cancel) {
            Ok(Some(code)) => code,
            Ok(None) => {
                return Ok(NativeExecution::pending(
                    process,
                    OfficialOutcome::Unverified(WAIT_TIMEOUT),
                    PendingReason::StoppedWaiting,
                ));
            }
            Err(error) if process.job.is_some() => {
                if matches!(process.is_finished(), Ok(true)) && process.clear_tracking().is_ok() {
                    return Err(error);
                }
                let status = error
                    .raw_os_error()
                    .and_then(|code| u32::try_from(code).ok())
                    .unwrap_or(0);
                return Ok(NativeExecution::pending(
                    process,
                    OfficialOutcome::Unverified(status),
                    PendingReason::ObservationFailed(error),
                ));
            }
            Err(error) if process.msi_wait.is_some() => {
                let status = error
                    .raw_os_error()
                    .and_then(|code| u32::try_from(code).ok())
                    .unwrap_or(0);
                return Ok(NativeExecution::finished(OfficialOutcome::Unverified(status))
                    .with_warning(format!("Windows Installer could not be observed to completion ({error}). Restart Windows before making changes.")));
            }
            Err(error) => return Err(error),
        };

        let Provider::Msi { product_code, .. } = &self.provider else {
            let Some(job) = process.job.as_ref() else {
                return Ok(NativeExecution::finished(classify_win32(code, false)));
            };
            let completion = if code == ERROR_SUCCESS {
                wait_for_job(&job.handle, cancel)
            } else {
                // The root exit code is known, but its children may still be running.
                match job_is_empty(&job.handle) {
                    Ok(true) => JobCompletion::Finished,
                    Ok(false) => {
                        JobCompletion::Pending(PendingReason::DescendantsRunningAfterFailure)
                    }
                    Err(error) => JobCompletion::Pending(PendingReason::ObservationFailed(error)),
                }
            };
            return Ok(match completion {
                JobCompletion::Finished => {
                    if let Err(error) = process.clear_tracking() {
                        return Ok(NativeExecution::pending(
                            process,
                            classify_win32(code, false),
                            PendingReason::ObservationFailed(error),
                        ));
                    }
                    let mut execution = NativeExecution::finished(classify_win32(code, true));
                    if eligible_win32_failure(code) && cancel.check().is_ok() {
                        execution.terminal_win32_failure = Some(self);
                    }
                    execution
                }
                JobCompletion::Pending(reason) => {
                    NativeExecution::pending(process, classify_win32(code, false), reason)
                }
            });
        };
        let outcome = classify_msi(code);
        if let Some(execution) = unsettled_msi_execution(outcome) {
            // Client exit alone does not establish that the Installer service
            // settled the operation. Keep the desktop user's pending marker.
            return Ok(execution);
        }
        let release = process.msi_wait.take().map(SystemUninstallWait::finish);
        let execution = if outcome == OfficialOutcome::Completed {
            match verify_msi_product_absent(product_code) {
                Ok(true) => NativeExecution::finished(outcome),
                Ok(false) => NativeExecution::finished(OfficialOutcome::Unverified(code))
                    .with_warning("Windows Installer still reports the product as registered."),
                Err(error) => NativeExecution::finished(OfficialOutcome::Unverified(code))
                    .with_warning(format!(
                        "Could not verify Windows Installer product removal ({error})."
                    )),
            }
        } else {
            NativeExecution::finished(outcome)
        };
        if let Some(Err(error)) = release {
            return Ok(execution.with_warning(format!(
                "Windows Installer returned its result, but its pending record could not be cleared ({error})"
            )));
        }
        Ok(execution)
    }
}

/// Validates a Win32 uninstall command beneath the backend-verified application directory.
pub fn prepare_win32(
    quiet: Option<&str>,
    interactive: Option<&str>,
    install_location: Option<&Path>,
) -> io::Result<OfficialUninstall> {
    let directory = install_location
        .ok_or_else(|| invalid("no verified application directory for this uninstaller"))?;
    if LocalPath::parse(directory)?.depth() == 0 {
        return Err(invalid(
            "a drive root cannot establish the ownership of an uninstaller",
        ));
    }
    let intent = |command, is_quiet| prepare_win32_command(command, is_quiet, directory, None);
    match (quiet, interactive) {
        (Some(quiet), Some(interactive)) => match intent(quiet, true) {
            Ok(prepared) => Ok(prepared),
            Err(_) => {
                let mut prepared = intent(interactive, false)?;
                prepared.provider = Provider::Win32 {
                    quiet_rejected: true,
                };
                Ok(prepared)
            }
        },
        (Some(quiet), None) => intent(quiet, true),
        (None, Some(interactive)) => intent(interactive, false),
        (None, None) => Err(invalid(
            "there is no official uninstall command for this application",
        )),
    }
}

/// Prepares the literal interactive action with two verified sibling executables.
pub(super) fn prepare_inferred_win32(
    command: &str,
    icon: &Path,
    directory: &Path,
) -> io::Result<OfficialUninstall> {
    prepare_win32_command(command, false, directory, Some(icon))
}

/// Prepares removal for one installed MSI ProductCode in its verified registry scope.
pub fn prepare_msi(
    product_code: &str,
    machine: bool,
    quiet: bool,
) -> io::Result<OfficialUninstall> {
    let product_code = normalize_product_code(product_code)?;
    verify_msi_context(&product_code, machine)?;
    let program = system_directory()?.join("msiexec.exe");
    let pinned = pin_executable(&program)?;
    let quiet_option = if quiet { " /quiet" } else { "" };
    Ok(OfficialUninstall {
        program,
        arguments: format!("/x {product_code} /norestart{quiet_option}"),
        is_quiet: quiet,
        provider: Provider::Msi {
            product_code,
            machine,
        },
        identity: pinned.identity()?,
        inferred_icon: None,
    })
}

fn prepare_win32_command(
    command: &str,
    is_quiet: bool,
    directory: &Path,
    icon: Option<&Path>,
) -> io::Result<OfficialUninstall> {
    let (program, arguments) = split_command(command)?;
    if icon.is_some() && !arguments.is_empty() {
        return Err(invalid(
            "an uninstall command without a declared directory cannot have arguments",
        ));
    }
    let program = PathBuf::from(program);
    if is_system_command_wrapper(&program) {
        return Err(invalid(
            "the registered uninstall command uses a shell or a system command wrapper",
        ));
    }

    let pinned = pin_executable_in_directory(&program, directory)?;
    let inferred_icon = icon
        .map(|path| {
            let (_pin, identity) = pin_inferred_icon(&program, &pinned, path)?;
            Ok::<_, io::Error>((path.to_path_buf(), identity))
        })
        .transpose()?;
    Ok(OfficialUninstall {
        program,
        arguments: arguments.to_owned(),
        is_quiet,
        provider: Provider::Win32 {
            quiet_rejected: false,
        },
        identity: pinned.identity()?,
        inferred_icon,
    })
}

pub(super) fn is_system_command_wrapper(path: &Path) -> bool {
    path.file_stem().and_then(OsStr::to_str).is_none_or(|stem| {
        BLOCKED_EXECUTABLES
            .iter()
            .any(|name| stem.eq_ignore_ascii_case(name))
    })
}

fn pin_inferred_icon(
    program: &Path,
    uninstaller: &PinnedExecutable,
    icon_path: &Path,
) -> io::Result<(PinnedExecutable, ExecutableIdentity)> {
    uninstaller
        .path
        .verify_address_under(&LocalPath::parse(program)?)?;
    native::regular(uninstaller.path.leaf())?;
    let (icon, identity) = pin_startup_executable(icon_path)?;
    let Some(((program_id, program_parent), (icon_id, icon_parent))) =
        uninstaller.chain.split_last().zip(icon.chain.split_last())
    else {
        return Err(invalid("could not verify the two executable paths"));
    };
    if program_parent != icon_parent || program_id == icon_id {
        return Err(invalid(
            "the icon and uninstaller must be distinct executables in the same directory",
        ));
    }
    Ok((icon, identity))
}

/// No-follow directory identity captured before the native uninstall starts.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct FormerInstallation {
    anchor_depth: usize,
    directories: Vec<DirectoryIdentity>,
}

impl FormerInstallation {
    pub(super) fn capture(directory: &Path, trusted_root: &Path) -> io::Result<Self> {
        let location = LocalPath::parse(directory)?;
        let anchor_depth = former_anchor_depth(&location, trusted_root)?;
        let opened = native::open(&location, 0, FILE_SHARE_READ | FILE_SHARE_WRITE)?;
        opened.verify_address_under(&location)?;
        let directories = opened
            .handles()
            .iter()
            .map(native::directory_identity)
            .collect::<io::Result<_>>()?;
        Ok(Self {
            anchor_depth,
            directories,
        })
    }

    pub(super) fn verify(&self, directory: &Path) -> io::Result<()> {
        self.reopen(&LocalPath::parse(directory)?).map(|_| ())
    }

    fn reopen(&self, location: &LocalPath) -> io::Result<PathWalk> {
        if self.directories.len() != location.depth() + 1
            || self.anchor_depth == 0
            || self.anchor_depth >= location.depth()
        {
            return Err(invalid(
                "installation observation does not match the authorized path",
            ));
        }
        let walked = native::walk(location, 0, FILE_SHARE_READ | FILE_SHARE_WRITE)?;
        match &walked {
            PathWalk::Present(directory)
            | PathWalk::Missing {
                parent: directory, ..
            } => {
                directory.verify_address_under(location)?;
                self.verify_prefix(directory)?;
            }
        }
        Ok(walked)
    }

    fn verify_prefix(&self, opened: &OpenPath) -> io::Result<()> {
        if opened.handles().len() <= self.anchor_depth {
            return Err(invalid(
                "could not reach the originally verified installation root",
            ));
        }
        // When the uninstaller removed the folder, only the surviving prefix
        // must match. A same-path replacement is not evidence of absence.
        for (handle, expected) in opened.handles().iter().zip(&self.directories) {
            if native::directory_identity(handle)? != *expected {
                return Err(invalid(
                    "the original installation directory or one of its ancestors was replaced",
                ));
            }
        }
        Ok(())
    }
}

fn former_anchor_depth(location: &LocalPath, trusted_root: &Path) -> io::Result<usize> {
    let anchor = LocalPath::parse(trusted_root)?;
    let depth = anchor.depth();
    if depth == 0 || location.depth() <= depth || !location.starts_with(&anchor) {
        return Err(invalid(
            "the former installation is outside the trusted root",
        ));
    }
    Ok(depth)
}

/// Directory scope for references from Windows registrations.
pub(super) struct RegisteredScope {
    location: LocalPath,
    location_id: Option<Identity>,
    anchor_depth: usize,
    anchor_id: Identity,
    former: Option<(PathBuf, FormerInstallation)>,
}

impl RegisteredScope {
    /// Uses an existing verified install directory and requires the target to exist.
    pub(super) fn existing(directory: &Path) -> io::Result<Self> {
        let location = LocalPath::parse(directory)?;
        if location.depth() == 0 {
            return Err(invalid("the registration scope cannot be a drive root"));
        }
        let root = native::open(&location, 0, FILE_SHARE_READ | FILE_SHARE_WRITE)?;
        native::require_directory(root.leaf())?;
        root.verify_address_under(&location)?;
        let anchor_depth = location.depth();
        let anchor_id = native::identity(root.leaf())?;
        Ok(Self {
            location,
            location_id: Some(anchor_id.clone()),
            anchor_depth,
            anchor_id,
            former: None,
        })
    }

    /// Allows missing paths below the former install location after verified uninstall.
    pub(super) fn after_uninstall(
        directory: &Path,
        trusted_root: &Path,
        observed: &FormerInstallation,
    ) -> io::Result<Self> {
        let location = LocalPath::parse(directory)?;
        let anchor_depth = former_anchor_depth(&location, trusted_root)?;
        if observed.anchor_depth != anchor_depth {
            return Err(invalid(
                "the trusted installation root changed after uninstall",
            ));
        }
        let (opened, location_id) = match observed.reopen(&location)? {
            PathWalk::Present(directory) => {
                let id = native::identity(directory.leaf())?;
                (directory, Some(id))
            }
            PathWalk::Missing { parent, .. } => (parent, None),
        };
        let anchor_id = native::identity(&opened.handles()[anchor_depth])?;
        Ok(Self {
            location,
            location_id,
            anchor_depth,
            anchor_id,
            former: Some((directory.to_path_buf(), observed.clone())),
        })
    }

    fn verify_ancestors(&self, path: &OpenPath, requested: &LocalPath) -> io::Result<()> {
        verify_registration_anchor(path, self.anchor_depth, &self.anchor_id)?;
        if let Some((_, proof)) = &self.former {
            proof.verify_prefix(path)?;
        }
        let observed = path
            .handles()
            .get(self.location.depth())
            .map(native::identity)
            .transpose()?;
        if observed != self.location_id {
            return Err(invalid(
                "the verified installation location changed during discovery",
            ));
        }
        path.verify_address_under(requested)
    }

    /// Reports whether this scope was verified after official uninstall.
    pub(super) fn is_former_installation(&self) -> bool {
        self.former.is_some()
    }

    /// Proves that a literal uninstaller is missing below the verified directory.
    pub(super) fn missing_uninstaller(&self, program: &Path) -> io::Result<bool> {
        let Some(child) = registration_child(program, &self.location, "exe") else {
            return Ok(false);
        };
        match native::walk(&child, 0, FILE_SHARE_READ | FILE_SHARE_WRITE)? {
            PathWalk::Present(_) => Ok(false),
            PathWalk::Missing { parent, .. } => {
                self.verify_ancestors(&parent, &child)?;
                Ok(true)
            }
        }
    }

    /// Checks whether a literal uninstaller path is inside the approved directory.
    pub(super) fn contains_uninstaller(&self, program: &Path) -> bool {
        registration_child(program, &self.location, "exe").is_some()
    }

    /// Identifies an executable in the verified installation scope.
    pub(super) fn executable_identity(
        &self,
        program: &Path,
    ) -> io::Result<Option<ExecutableIdentity>> {
        let Some(child) = registration_child(program, &self.location, "exe") else {
            return Ok(None);
        };
        let pinned = pin_executable(program)?;
        self.verify_ancestors(&pinned.path, &child)?;
        native::regular(pinned.path.leaf())?;
        pinned.identity().map(Some)
    }

    /// Attributes a startup shortcut's exact executable within this installation.
    pub(super) fn startup_shortcut_identity(
        &self,
        target: &ShortcutTarget,
    ) -> io::Result<Option<ExecutableIdentity>> {
        let Some(child) = registration_child(&target.path, &self.location, "exe") else {
            return Ok(None);
        };
        let (pinned, identity) = pin_startup_shortcut_target(target)?;
        self.verify_ancestors(&pinned.path, &child)?;
        Ok(Some(identity))
    }

    /// Observes a literal shortcut's local executable within this installation.
    pub(super) fn observe_direct_shortcut_executable(
        &self,
        target: &ShortcutTarget,
        bytes_remaining: &mut u64,
    ) -> io::Result<Option<ExecutableIdentity>> {
        if !target.direct || is_system_command_wrapper(&target.path) || *bytes_remaining == 0 {
            return Ok(None);
        }
        let Some(child) = registration_child(&target.path, &self.location, "exe") else {
            return Ok(None);
        };
        let PathWalk::Present(path) = native::walk(&child, FILE_GENERIC_READ, FILE_SHARE_READ)?
        else {
            return Ok(None);
        };
        self.verify_ancestors(&path, &child)?;
        let leaf = path.leaf();
        // Ordinary shortcuts can name files that the scanner must not recall
        // or consult by path for a PE check.
        if !native::metadata(leaf)?.is_single_local_file()
            || native::volume_serial(leaf)? != target.volume_serial
        {
            return Ok(None);
        }
        let size = File::from(leaf.try_clone()?).metadata()?.len();
        if size > (*bytes_remaining).min(MAX_UNINSTALLER_BYTES) {
            return Ok(None);
        }
        // Reserve the file's size even if inspection fails partway through.
        *bytes_remaining -= size;
        pin_open_executable(path)?.identity().map(Some)
    }

    /// Holds the last present parent of a verified former shortcut executable.
    pub(super) fn pin_missing_shortcut_executable(
        &self,
        target: &ShortcutTarget,
        original: &ExecutableIdentity,
    ) -> io::Result<Option<OpenPath>> {
        if self.former.is_none() || !target.direct || is_system_command_wrapper(&target.path) {
            return Ok(None);
        }
        let Some(child) = registration_child(&target.path, &self.location, "exe") else {
            return Ok(None);
        };
        if original.chain.len() != child.depth() + 1 {
            return Ok(None);
        }
        let PathWalk::Missing { parent, .. } = native::walk(&child, 0, FILE_SHARE_READ)? else {
            return Ok(None);
        };
        self.verify_ancestors(&parent, &child)?;
        if native::volume_serial(parent.leaf())? != target.volume_serial {
            return Ok(None);
        }
        // A missing leaf inside a replaced intermediate directory does not
        // establish absence under the original executable's parent chain.
        for (handle, expected) in parent.handles().iter().zip(&original.chain) {
            if native::identity(handle)? != *expected {
                return Ok(None);
            }
        }
        Ok(Some(parent))
    }
}

fn verify_registration_anchor(
    path: &OpenPath,
    depth: usize,
    identity: &Identity,
) -> io::Result<()> {
    let anchor = path
        .handles()
        .get(depth)
        .ok_or_else(|| invalid("could not reach the verified registration root"))?;
    native::require_directory(anchor)?;
    if native::identity(anchor)? != *identity {
        return Err(invalid(
            "the verified registration root changed during discovery",
        ));
    }
    Ok(())
}

/// Attribution for a verified present file or a missing file under a former installation.
pub(super) struct RegisteredReference {
    pub(super) path: PathBuf,
    pub(super) evidence: MatchKind,
    missing_from: Option<PathBuf>,
}

impl RegisteredReference {
    pub(super) fn reason(&self, present_reason: &str) -> String {
        if let Some(directory) = self.missing_from.as_deref() {
            format!(
                "the referenced file {} is missing from the application's previously registered installation at {}",
                self.path.display(),
                directory.display()
            )
        } else {
            present_reason.into()
        }
    }
}

/// Reads a direct executable from a service or startup command without launching it.
pub(super) fn service_image(
    command: &str,
    scope: &RegisteredScope,
) -> io::Result<Option<RegisteredReference>> {
    let Ok((program, _)) = split_command(command) else {
        return Ok(None);
    };
    registered_image(Path::new(program), scope)
}

/// Resolves a registration's literal executable without expanding or running it.
pub(super) fn registered_image(
    program: &Path,
    scope: &RegisteredScope,
) -> io::Result<Option<RegisteredReference>> {
    resolve_registration(program, scope, RegistrationFile::Executable(None))
}

/// Matches a shortcut's executable or verified former directory on the recorded volume.
pub(super) fn registered_shortcut_image(
    program: &Path,
    scope: &RegisteredScope,
    volume_serial: u32,
) -> io::Result<Option<RegisteredReference>> {
    resolve_registration(
        program,
        scope,
        RegistrationFile::Executable(Some(volume_serial)),
    )
}

/// Resolves a literal in-process library to a regular, unshared file in the installation.
pub(super) fn registered_library(
    program: &Path,
    scope: &RegisteredScope,
) -> io::Result<Option<RegisteredReference>> {
    resolve_registration(program, scope, RegistrationFile::Library)
}

enum RegistrationFile {
    Executable(Option<u32>),
    Library,
}

fn resolve_registration(
    program: &Path,
    scope: &RegisteredScope,
    kind: RegistrationFile,
) -> io::Result<Option<RegisteredReference>> {
    let (extension, access, share) = match kind {
        RegistrationFile::Executable(_) => ("exe", FILE_GENERIC_READ, FILE_SHARE_READ),
        RegistrationFile::Library => ("dll", 0, FILE_SHARE_READ | FILE_SHARE_WRITE),
    };
    let Some(child) = registration_child(program, &scope.location, extension) else {
        return Ok(None);
    };
    let (evidence, missing_from) = match native::walk(&child, access, share)? {
        PathWalk::Present(file) => {
            scope.verify_ancestors(&file, &child)?;
            native::regular(file.leaf())?;
            if let RegistrationFile::Executable(expected_volume) = kind {
                if let Some(serial) = expected_volume {
                    if native::volume_serial(file.leaf())? != serial {
                        return Ok(None);
                    }
                }
                require_binary_type(&final_name(file.leaf())?)?;
            }
            (MatchKind::ExactIdentity, None)
        }
        PathWalk::Missing { parent, .. } => {
            let Some((directory, _)) = &scope.former else {
                return Ok(None);
            };
            scope.verify_ancestors(&parent, &child)?;
            if let RegistrationFile::Executable(Some(serial)) = kind {
                // With no executable handle, the last pinned ancestor verifies the volume.
                if native::volume_serial(parent.leaf())? != serial {
                    return Ok(None);
                }
            }
            (MatchKind::AppName, Some(directory.clone()))
        }
    };
    Ok(Some(RegisteredReference {
        path: program.to_path_buf(),
        evidence,
        missing_from,
    }))
}

fn registration_child(program: &Path, root: &LocalPath, extension: &str) -> Option<LocalPath> {
    if !program
        .extension()
        .and_then(OsStr::to_str)
        .is_some_and(|ext| ext.eq_ignore_ascii_case(extension))
        || program.to_str().is_none_or(|text| {
            text.ends_with(['\\', '/'])
                || text.contains(['%', '"'])
                || text.chars().any(char::is_control)
        })
    {
        return None;
    }
    let program = LocalPath::parse(program).ok()?;
    (program.depth() > root.depth() && program.starts_with(root)).then_some(program)
}

fn pin_executable_in_directory(program: &Path, directory: &Path) -> io::Result<PinnedExecutable> {
    let pinned = pin_executable(program)?;
    let directory = native::open(
        &LocalPath::parse(directory)?,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    )?;
    native::require_directory(directory.leaf())?;
    let directory_id = native::identity(directory.leaf())?;
    let program_ancestors = &pinned.chain[..pinned.chain.len() - 1];
    if !program_ancestors.contains(&directory_id) {
        return Err(invalid(
            "the executable is outside the verified application directory",
        ));
    }
    Ok(pinned)
}

pub(super) fn split_command(command: &str) -> io::Result<(&str, &str)> {
    if command.encode_utf16().count() >= MAX_WINDOWS_COMMAND_UNITS
        || command.chars().any(|ch| ch.is_control() && ch != '\t')
    {
        return Err(invalid(
            "the uninstall command has invalid or oversized text",
        ));
    }
    let command = command.trim_start_matches([' ', '\t']);
    let (program, arguments) = if let Some(quoted) = command.strip_prefix('"') {
        let (program, rest) = quoted
            .split_once('"')
            .ok_or_else(|| invalid("the quoted uninstaller path is missing its closing quote"))?;
        if !rest.is_empty() && !rest.starts_with([' ', '\t']) {
            return Err(invalid(
                "the uninstaller path and arguments are not separated",
            ));
        }
        (program, rest)
    } else {
        let end = command.find([' ', '\t']).unwrap_or(command.len());
        command.split_at(end)
    };
    let Some(ext) = Path::new(program).extension().and_then(OsStr::to_str) else {
        return Err(invalid(
            "expected a fully qualified .exe path; quote paths containing spaces",
        ));
    };
    if program.ends_with(['\\', '/']) || !ext.eq_ignore_ascii_case("exe") {
        return Err(invalid("expected a fully qualified .exe path"));
    }
    LocalPath::parse(Path::new(program))?;
    Ok((program, arguments.trim_start_matches([' ', '\t'])))
}

pub(super) fn display_icon_path(value: &str) -> Option<&Path> {
    let path = match value.rsplit_once(',') {
        Some((path, index)) => {
            index.trim().parse::<i32>().ok()?;
            path.trim()
        }
        None => value.trim(),
    };
    let path = match path.strip_prefix('"') {
        Some(quoted) => quoted.strip_suffix('"')?,
        None => path,
    };
    if path.ends_with(['\\', '/'])
        || path.contains(['%', '"', ','])
        || path.chars().any(char::is_control)
    {
        return None;
    }
    let path = Path::new(path);
    LocalPath::parse(path).ok()?;
    Some(path)
}

fn pin_executable(path: &Path) -> io::Result<PinnedExecutable> {
    let path = native::open(&LocalPath::parse(path)?, FILE_GENERIC_READ, FILE_SHARE_READ)?;
    let metadata = native::metadata(path.leaf())?;
    if metadata.is_directory || metadata.is_reparse {
        return Err(invalid(
            "the uninstaller is not an ordinary executable file",
        ));
    }
    pin_open_executable(path)
}

fn pin_open_executable(path: OpenPath) -> io::Result<PinnedExecutable> {
    let native_name = final_name(path.leaf())?;
    require_binary_type(&native_name)?;
    Ok(PinnedExecutable {
        chain: path
            .handles()
            .iter()
            .map(native::identity)
            .collect::<io::Result<_>>()?,
        native_name,
        path,
    })
}

/// Pins and identifies a startup image so restoring its entry cannot target a replacement.
pub(super) fn pin_startup_executable(
    program: &Path,
) -> io::Result<(PinnedExecutable, ExecutableIdentity)> {
    let pinned = pin_executable(program)?;
    let requested = LocalPath::parse(program)?;
    pinned.path.verify_address_under(&requested)?;
    native::regular(pinned.path.leaf())?;
    let identity = pinned.identity()?;
    Ok((pinned, identity))
}

/// Pins the exact native binary and checks the volume stored by the link.
pub(super) fn pin_startup_shortcut_target(
    target: &ShortcutTarget,
) -> io::Result<(PinnedExecutable, ExecutableIdentity)> {
    if is_system_command_wrapper(&target.path) {
        return Err(invalid(
            "the startup shortcut uses a system command wrapper",
        ));
    }
    let (pinned, identity) = pin_startup_executable(&target.path)?;
    if native::volume_serial(pinned.path.leaf())? != target.volume_serial {
        return Err(invalid(
            "the startup executable is on a different volume than the shortcut recorded",
        ));
    }
    Ok((pinned, identity))
}

fn require_binary_type(native_name: &[u16]) -> io::Result<()> {
    let mut kind = 0;
    // SAFETY: native_name is NUL-terminated and kind is writable. All ancestors
    // and the leaf are held open without delete sharing and no reparse point was opened.
    if unsafe { GetBinaryTypeW(native_name.as_ptr(), &mut kind) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if !matches!(kind, SCS_32BIT_BINARY | SCS_64BIT_BINARY) {
        return Err(invalid(
            "the uninstaller is not a native Windows executable",
        ));
    }
    Ok(())
}

impl PinnedExecutable {
    fn identity(&self) -> io::Result<ExecutableIdentity> {
        let mut executable = File::from(self.path.leaf().try_clone()?);
        // This is checked only for a single selected uninstaller, never during
        // inventory. Hashing binds confirmation to its contents even if its
        // file identity survives an in-place replacement between the two calls.
        if executable.metadata()?.len() > MAX_UNINSTALLER_BYTES {
            return Err(invalid(
                "the official uninstaller exceeds the size limit for content verification",
            ));
        }
        let mut hasher = Sha256::new();
        let mut buffer = [0; HASH_BUFFER_BYTES];
        loop {
            let read = executable.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(ExecutableIdentity {
            chain: self.chain.clone(),
            contents: hasher.finalize().into(),
        })
    }

    fn working_directory(&self) -> io::Result<Vec<u16>> {
        let [.., parent, _exe] = self.path.handles() else {
            return Err(invalid(
                "the official uninstaller has no containing directory",
            ));
        };
        final_name(parent)
    }

    fn recheck_handles(&self) -> io::Result<()> {
        let [parents @ .., leaf] = self.path.handles() else {
            return Err(invalid("the official uninstaller path has no open file"));
        };
        for parent in parents {
            native::require_directory(parent)?;
        }
        let metadata = native::metadata(leaf)?;
        if metadata.is_directory || metadata.is_reparse {
            return Err(invalid(
                "the official uninstaller file type changed; preview again",
            ));
        }
        Ok(())
    }
}

fn final_name(file: &OwnedHandle) -> io::Result<Vec<u16>> {
    let mut buffer = vec![0; MAX_WINDOWS_COMMAND_UNITS];
    // SAFETY: file owns a live handle. buffer is writable for the reported capacity.
    let written = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_GUID,
        )
    } as usize;
    if written == 0 {
        return Err(io::Error::last_os_error());
    }
    if written >= buffer.len() {
        return Err(invalid(
            "the normalized uninstaller path exceeds the Windows length limit",
        ));
    }
    buffer.truncate(written + 1);
    Ok(buffer)
}

fn start_process(
    intent: &OfficialUninstall,
    executable: &PinnedExecutable,
    cancel: &Cancellation,
    authority: LaunchAuthority,
) -> io::Result<OfficialProcess> {
    let mut command_line = format!("\"{}\"", intent.program.display());
    if !intent.arguments.is_empty() {
        command_line.push(' ');
        command_line.push_str(&intent.arguments);
    }
    let mut command_line = wide(OsStr::new(&command_line));
    if command_line.len() > MAX_WINDOWS_COMMAND_UNITS {
        return Err(invalid(
            "the confirmed command exceeds the Windows length limit",
        ));
    }
    let work_dir = executable.working_directory()?;
    let job = match intent.provider {
        Provider::Win32 { .. } => Some(create_tracking_job()?),
        Provider::Msi { .. } => None,
    };
    let mut attributes = job
        .as_ref()
        .map(|job| JobAttributes::new(&job.handle))
        .transpose()?;
    let mut startup = STARTUPINFOEXW::default();
    let creation_flags = if let Some(attributes) = attributes.as_mut() {
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.lpAttributeList = attributes.as_raw();
        EXTENDED_STARTUPINFO_PRESENT
    } else {
        startup.StartupInfo.cb = size_of::<STARTUPINFOW>() as u32;
        0
    };
    let mut process = PROCESS_INFORMATION::default();
    executable.recheck_handles()?;
    if cancel.check().is_err() {
        return Err(io::Error::from_raw_os_error(ERROR_CANCELLED as i32));
    }
    let mut msi_wait = None;
    if let Some(job) = &job {
        // Reserve the launch before asking Windows to admit any process. A
        // vanished launcher alone does not establish the Job was never used.
        registry::begin_win32_launch(job.id)?;
    } else if matches!(authority, LaunchAuthority::Desktop) {
        // The authenticated helper is tracked by the desktop that sent its
        // request. In an alternate administrator account it has a different hive.
        msi_wait = Some(SystemUninstallWait::begin(SystemUninstaller::DirectMsi)?);
    }
    if cancel.check().is_err() {
        if let Some(job) = &job {
            registry::clear_win32_launch(job.id)?;
        }
        if let Some(wait) = msi_wait {
            wait.finish()?;
        }
        return Err(io::Error::from_raw_os_error(ERROR_CANCELLED as i32));
    }
    // SAFETY: pointers are valid for the call, including the mutable NUL-terminated
    // command line and job attribute storage. The executable path comes from the
    // pinned file handle. StartupInfo is the first field of STARTUPINFOEXW.
    let started = unsafe {
        CreateProcessW(
            executable.native_name.as_ptr(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            0,
            creation_flags,
            null(),
            work_dir.as_ptr(),
            &startup.StartupInfo,
            &mut process,
        )
    };
    if started == 0 {
        let error = io::Error::last_os_error();
        if let Some(job) = &job {
            if !job_is_empty(&job.handle)? {
                return Err(io::Error::other(
                    "Windows did not confirm process creation, but the uninstall job is active",
                ));
            }
            registry::clear_win32_launch(job.id)?;
        }
        if let Some(wait) = msi_wait {
            // No client process was created to deliver the installer request.
            wait.finish()?;
        }
        return Err(error);
    }
    // SAFETY: the successful call owns two new handles. Only the process handle
    // must outlive this function, so the primary-thread handle is closed here.
    let thread = unsafe { OwnedHandle::from_raw_handle(process.hThread) };
    drop(thread);
    // SAFETY: ownership of the valid process handle is transferred exactly once.
    let root = unsafe { OwnedHandle::from_raw_handle(process.hProcess) };
    let tracking_error = job
        .as_ref()
        .and_then(|job| registry::commit_win32_launch(job.id).err());
    Ok(OfficialProcess {
        root,
        job,
        tracking_error,
        msi_wait,
    })
}

pub(super) struct OfficialProcess {
    root: OwnedHandle,
    job: Option<TrackedJob>,
    tracking_error: Option<io::Error>,
    msi_wait: Option<SystemUninstallWait>,
}

pub(super) fn local_pending_uninstall() -> io::Result<MutexGuard<'static, Option<OfficialProcess>>>
{
    static PENDING: Mutex<Option<OfficialProcess>> = Mutex::new(None);
    PENDING
        .lock()
        .map_err(|_| io::Error::other("could not access the Windows uninstaller observation"))
}

/// Retains the desktop's last detached uninstall after the windows have closed.
pub struct ExitObservation {
    process: OfficialProcess,
    id: Uuid,
}

/// Captures only a job this desktop launched, before event-loop teardown.
pub fn capture_exit_observation() -> io::Result<Option<ExitObservation>> {
    let pending = local_pending_uninstall()?;
    let Some((process, job)) = pending
        .as_ref()
        .and_then(|process| process.job.as_ref().map(|job| (process, job)))
    else {
        return Ok(None);
    };
    let id = job.id;
    Ok(Some(ExitObservation {
        process: OfficialProcess {
            root: process.root.try_clone()?,
            job: Some(TrackedJob {
                id,
                handle: job.handle.try_clone()?,
            }),
            tracking_error: None,
            msi_wait: None,
        },
        id,
    }))
}

impl ExitObservation {
    /// Waits without an open window. Never terminates the publisher's processes.
    pub fn finish(self) -> io::Result<()> {
        while !self.process.is_finished()? {
            thread::sleep(EXIT_OBSERVATION_POLL);
        }
        let files = WindowsFiles::new()?;
        loop {
            if registry::pending_win32_launch()?.map(|(id, _)| id) != Some(self.id) {
                return Ok(());
            }
            match files.lock_mutations() {
                Ok(_lock) => {
                    // A replacement desktop can also clear a finished Job.
                    // Never remove a newer launch marker after waiting for its lock.
                    if registry::pending_win32_launch()?.map(|(id, _)| id) == Some(self.id) {
                        registry::clear_win32_launch(self.id)?;
                    }
                    return Ok(());
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(EXIT_OBSERVATION_POLL);
                }
                Err(error) => return Err(error),
            }
        }
    }
}

impl OfficialProcess {
    pub(super) fn is_finished(&self) -> io::Result<bool> {
        if !process_finished_in(&self.root, 0)? {
            return Ok(false);
        }
        match &self.job {
            Some(job) => job_is_empty(&job.handle),
            None => Ok(true),
        }
    }

    /// Returns the identity used to match this handle to the recorded launch.
    pub(super) fn job_id(&self) -> Option<Uuid> {
        self.job.as_ref().map(|job| job.id)
    }

    fn clear_tracking(&self) -> io::Result<()> {
        if let Some(id) = self.job_id() {
            registry::clear_win32_launch(id)?;
        }
        Ok(())
    }
}

struct TrackedJob {
    id: Uuid,
    handle: OwnedHandle,
}

fn tracking_job_name(id: Uuid) -> Vec<u16> {
    wide(OsStr::new(&format!(r"Global\UninstallAny.Win32.{id}")))
}

fn create_tracking_job() -> io::Result<TrackedJob> {
    let id = Uuid::new_v4();
    let name = tracking_job_name(id);
    // SAFETY: the name is terminated, and default attributes create a
    // non-inheritable handle secured by the caller's token. No kill-on-close.
    let (job, status) = unsafe {
        SetLastError(ERROR_SUCCESS);
        let job = CreateJobObjectW(null(), name.as_ptr());
        (job, GetLastError())
    };
    if job.is_null() {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    // SAFETY: the API returned a new owned job handle on success.
    let handle = unsafe { OwnedHandle::from_raw_handle(job) };
    if status == ERROR_ALREADY_EXISTS {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "the Windows uninstall job name is already in use",
        ));
    }
    Ok(TrackedJob { id, handle })
}

/// Establishes completion from an extant Job after an observed successful dispatch.
pub(super) fn require_finished_win32_job(id: Uuid, committed: bool) -> io::Result<()> {
    let unavailable = || {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            "the previous Win32 uninstall cannot be verified. If the original UninstallAny window is closed, restart Windows before making changes",
        )
    };
    if !committed {
        return Err(unavailable());
    }
    let name = tracking_job_name(id);
    // SAFETY: the terminated name is valid. The handle can only query the Job.
    let handle = unsafe { OpenJobObjectW(JOB_OBJECT_QUERY, 0, name.as_ptr()) };
    if handle.is_null() {
        let error = io::Error::last_os_error();
        return Err(
            if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) {
                // Windows can remove the name while member processes are still alive.
                unavailable()
            } else {
                error
            },
        );
    }
    // SAFETY: the query handle was returned by a successful open.
    let job = unsafe { OwnedHandle::from_raw_handle(handle) };
    if !job_is_empty(&job)? {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "the previous Windows uninstaller is still running",
        ));
    }
    Ok(())
}

struct JobAttributes {
    storage: Vec<usize>,
    handles: Box<[HANDLE; 1]>,
}

impl JobAttributes {
    fn new(job: &OwnedHandle) -> io::Result<Self> {
        let mut bytes = 0;
        // SAFETY: null storage asks Windows for the required allocation size.
        unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut bytes) };
        if bytes == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        // SAFETY: storage is aligned and sized according to the sizing call.
        if unsafe {
            InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), 1, 0, &mut bytes)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut attributes = Self {
            storage,
            handles: Box::new([job.as_raw_handle()]),
        };
        // SAFETY: the list is initialized, and handles is heap-backed storage
        // that outlives the list. The owning job handle also remains open.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                attributes.as_raw(),
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                attributes.handles.as_ptr().cast(),
                size_of::<HANDLE>(),
                null_mut(),
                null(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(attributes)
    }

    fn as_raw(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
}

impl Drop for JobAttributes {
    fn drop(&mut self) {
        // SAFETY: storage contains the successfully initialized attribute list.
        unsafe { DeleteProcThreadAttributeList(self.as_raw()) };
    }
}

enum JobCompletion {
    Finished,
    Pending(PendingReason),
}

fn wait_for_job(job: &OwnedHandle, cancel: &Cancellation) -> JobCompletion {
    let start = Instant::now();
    loop {
        match job_is_empty(job) {
            Ok(true) => return JobCompletion::Finished,
            Ok(false) => {}
            Err(error) => return JobCompletion::Pending(PendingReason::ObservationFailed(error)),
        }
        if cancel.check().is_err() {
            return JobCompletion::Pending(PendingReason::StoppedWaiting);
        }
        if start.elapsed() >= DESCENDANT_WAIT {
            return JobCompletion::Pending(PendingReason::DescendantsTimedOut);
        }
        // Closing the job leaves any externally managed or long-running child alone.
        thread::sleep(DESCENDANT_POLL);
    }
}

fn job_is_empty(job: &OwnedHandle) -> io::Result<bool> {
    let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
    // SAFETY: job is an open job handle, and info matches the accounting class.
    let ok = unsafe {
        QueryInformationJobObject(
            job.as_raw_handle(),
            JobObjectBasicAccountingInformation,
            (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
            size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info.ActiveProcesses == 0)
}

fn wait_for_exit(process: &OwnedHandle, cancel: Option<&Cancellation>) -> io::Result<Option<u32>> {
    if !wait_for_signal(process, cancel)? {
        return Ok(None);
    }
    let mut code = 0;
    // SAFETY: process remains alive as a handle and code is writable.
    if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Some(code))
}

fn wait_for_signal(process: &OwnedHandle, cancel: Option<&Cancellation>) -> io::Result<bool> {
    loop {
        // Always probe once more after cancellation, so an observed exit remains real.
        let timeout = match cancel {
            Some(cancel) if cancel.check().is_err() => 0,
            Some(_) => PROCESS_POLL_MS,
            None => INFINITE,
        };
        if process_finished_in(process, timeout)? {
            return Ok(true);
        }
        if timeout == 0 {
            return Ok(false);
        }
    }
}

fn process_finished_in(process: &OwnedHandle, timeout: u32) -> io::Result<bool> {
    // SAFETY: process owns a live process handle with SYNCHRONIZE access.
    match unsafe { WaitForSingleObject(process.as_raw_handle(), timeout) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        WAIT_FAILED => Err(io::Error::last_os_error()),
        _ => Err(invalid("unexpected Windows process wait status")),
    }
}

pub(super) fn normalize_product_code(code: &str) -> io::Result<String> {
    let bytes = code.as_bytes();
    if bytes.len() != 38 || bytes[0] != b'{' || bytes[37] != b'}' {
        return Err(invalid("the MSI ProductCode must be a GUID in braces"));
    }
    for (index, byte) in bytes.iter().enumerate().take(37).skip(1) {
        let is_valid = if matches!(index, 9 | 14 | 19 | 24) {
            *byte == b'-'
        } else {
            byte.is_ascii_hexdigit()
        };
        if !is_valid {
            return Err(invalid("the MSI ProductCode must be a GUID in braces"));
        }
    }
    Ok(code.to_ascii_uppercase())
}

pub(super) fn verify_msi_context(product: &str, machine: bool) -> io::Result<()> {
    let mut selected = None;
    for context in MSI_CONTEXTS {
        let Some(installed) = msi_product_state(product, context)? else {
            continue;
        };
        // msiexec accepts the ProductCode, not a user SID/context pair.
        if selected.is_some() {
            return Err(invalid(
                "the MSI ProductCode is registered in multiple contexts; use Windows Settings",
            ));
        }
        selected = Some((context, installed));
    }
    match selected {
        Some((context, true)) if (context == MSIINSTALLCONTEXT_MACHINE) == machine => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "the MSI product is not installed in the requested scope",
        )),
    }
}

/// Verifies machine and both current-user registration contexts for the exact product.
pub(super) fn verify_msi_product_absent(product: &str) -> io::Result<bool> {
    for context in MSI_CONTEXTS {
        if msi_product_state(product, context)?.is_some() {
            return Ok(false);
        }
    }
    Ok(true)
}

fn msi_product_state(product: &str, context: MSIINSTALLCONTEXT) -> io::Result<Option<bool>> {
    let product = wide(OsStr::new(product));
    let mut state = [0u16; 2];
    let mut length = state.len() as u32;
    // SAFETY: product is NUL-terminated, the empty SID means current user, and
    // state and length point to writable buffers of the documented sizes.
    let status = unsafe {
        MsiGetProductInfoExW(
            product.as_ptr(),
            null(),
            context,
            INSTALLPROPERTY_PRODUCTSTATE,
            state.as_mut_ptr(),
            &mut length,
        )
    };
    match (status, state[0]) {
        (ERROR_UNKNOWN_PRODUCT, _) => Ok(None),
        (ERROR_SUCCESS, value) if value == u16::from(b'1') => Ok(Some(false)),
        (ERROR_SUCCESS, value) if value == u16::from(b'5') => Ok(Some(true)),
        (ERROR_SUCCESS, _) => Err(invalid(
            "Windows Installer did not return a recognized product state",
        )),
        (code, _) => Err(io::Error::from_raw_os_error(code as i32)),
    }
}

fn system_directory() -> io::Result<PathBuf> {
    let mut path = vec![0; MAX_WINDOWS_COMMAND_UNITS];
    // SAFETY: path contains the reported number of writable UTF-16 units.
    let written = unsafe { GetSystemDirectoryW(path.as_mut_ptr(), path.len() as u32) } as usize;
    if written == 0 {
        return Err(io::Error::last_os_error());
    }
    if written >= path.len() {
        return Err(invalid(
            "the Windows system directory exceeded the supported length",
        ));
    }
    String::from_utf16(&path[..written])
        .map(PathBuf::from)
        .map_err(|_| invalid("the Windows system directory returned invalid UTF-16"))
}

fn classify_msi(code: u32) -> OfficialOutcome {
    match code {
        ERROR_SUCCESS => OfficialOutcome::Completed,
        ERROR_SUCCESS_REBOOT_INITIATED | ERROR_SUCCESS_REBOOT_REQUIRED => {
            OfficialOutcome::NeedsRestart
        }
        ERROR_INSTALL_USEREXIT | ERROR_CANCELLED => OfficialOutcome::Cancelled,
        _ if confirmed_msi_failure(code) => OfficialOutcome::Failed(code),
        _ => OfficialOutcome::Unverified(code),
    }
}

fn confirmed_msi_failure(code: u32) -> bool {
    // MsiExec returns raw Win32 codes. Accept the documented terminal errors
    // and specific failed-launch codes without treating arbitrary DWORDs or
    // an HRESULT's low word as confirmation that the service ended the work.
    matches!(
        code,
        ERROR_ACCESS_DENIED
            | ERROR_ELEVATION_REQUIRED
            | ERROR_INVALID_DATA
            | ERROR_INVALID_PARAMETER
            | ERROR_CALL_NOT_IMPLEMENTED
            | ERROR_APPHELP_BLOCK
            | ERROR_INSTALL_FAILURE
            | ERROR_UNKNOWN_PRODUCT..=ERROR_INVALID_FIELD
            | ERROR_INSTALL_ALREADY_RUNNING..=ERROR_INSTALL_REMOTE_DISALLOWED
            | ERROR_PATCH_TARGET_NOT_FOUND..=ERROR_INSTALL_REJECTED
    )
}

/// Interprets results from the current MSI client and older authenticated helpers.
pub(super) fn unsettled_msi_execution(outcome: OfficialOutcome) -> Option<NativeExecution> {
    let (outcome, warning) = match outcome {
        OfficialOutcome::NeedsRestart => (
            outcome,
            "Windows Installer reported a restart. Changes remain blocked until Windows restarts.".into(),
        ),
        OfficialOutcome::Failed(ERROR_INSTALL_SUSPEND)
        | OfficialOutcome::Unverified(ERROR_INSTALL_SUSPEND) => (
            OfficialOutcome::Unverified(ERROR_INSTALL_SUSPEND),
            "Windows Installer suspended the operation (1604). Changes remain blocked. Restart Windows and let Windows Installer finish or roll back its work before continuing.".into(),
        ),
        OfficialOutcome::Completed
        | OfficialOutcome::Cancelled
        | OfficialOutcome::Unverified(ERROR_SUCCESS) => return None,
        OfficialOutcome::Failed(code) if confirmed_msi_failure(code) => return None,
        // Old helpers used Failed for any raw client exit they didn't recognize.
        OfficialOutcome::Unverified(code) | OfficialOutcome::Failed(code) => (
            OfficialOutcome::Unverified(code),
            format!("Windows Installer did not report a known completion status ({code:#010x}). Changes remain blocked until Windows restarts."),
        ),
    };
    Some(NativeExecution::finished(outcome).with_warning(warning))
}

fn classify_win32(code: u32, observed_end: bool) -> OfficialOutcome {
    match (code, observed_end) {
        // The caller still checks that the exact original registration is absent.
        (0, true) => OfficialOutcome::Completed,
        (0, false) => OfficialOutcome::Unverified(code),
        _ => OfficialOutcome::Failed(code),
    }
}

fn eligible_win32_failure(code: u32) -> bool {
    !matches!(
        code,
        ERROR_SUCCESS
            | ERROR_CANCELLED
            | ERROR_INSTALL_USEREXIT
            | ERROR_INSTALL_SUSPEND
            | ERROR_INSTALL_ALREADY_RUNNING
            | ERROR_SUCCESS_REBOOT_INITIATED
            | ERROR_SUCCESS_REBOOT_REQUIRED
            | ERROR_ACCESS_DENIED
            | ERROR_ELEVATION_REQUIRED
    )
}

fn wide(input: &OsStr) -> Vec<u16> {
    input.encode_wide().chain([0]).collect()
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quoted_executable_and_preserves_raw_arguments() {
        let parsed =
            split_command(r#""C:\Program Files\Example\uninstall.exe" /S /log="a b""#).unwrap();
        assert_eq!(
            parsed,
            (
                r"C:\Program Files\Example\uninstall.exe",
                r#"/S /log="a b""#
            )
        );
    }

    #[test]
    fn rejects_ambiguous_nonlocal_or_special_windows_paths() {
        for command in [
            r"C:\Program Files\Example\uninstall.exe /S",
            r"uninstall.exe /S",
            r"C:uninstall.exe /S",
            r"\\server\applications\uninstall.exe /S",
            r"C:\Apps\..\Other\uninstall.exe /S",
            r"C:\Apps\NUL.exe /S",
            r"C:\Apps\uninstall.exe:stream /S",
            r#""C:\Example\uninstall.exe"/S"#,
            "C:\\App\\uninstall.exe\n/S",
        ] {
            assert!(split_command(command).is_err(), "{command}");
        }
    }

    #[test]
    fn unrelated_service_paths_do_not_trigger_file_system_reads() -> io::Result<()> {
        let scope = LocalPath::parse(Path::new(r"C:\Example"))?;
        let (program, _) = split_command(r"C:\Example-Other\service.exe")?;
        assert!(registration_child(Path::new(program), &scope, "exe").is_none());
        Ok(())
    }

    #[test]
    fn display_icon_path_accepts_a_literal_path_and_optional_index() {
        let executable = r"C:\Users\Sam\Apps\Example Editor\editor.exe";
        assert_eq!(display_icon_path(executable), Some(Path::new(executable)));
        assert_eq!(
            display_icon_path(&format!(r#""{executable}",0"#)),
            Some(Path::new(executable))
        );
        for invalid in [
            r"%TEMP%\editor.exe,0",
            r"C:\Apps\..\editor.exe,0",
            r"C:\Apps\editor.exe,argument",
            r"C:\Apps\editor.exe\",
        ] {
            assert!(display_icon_path(invalid).is_none(), "{invalid}");
        }
    }

    #[test]
    #[ignore = "run on a disposable Windows VM with fixed NTFS storage"]
    fn missing_shortcut_target_requires_the_recorded_volume() -> io::Result<()> {
        let files = crate::files::WindowsFiles::new()?;
        let root = tempfile::tempdir_in(files.local_app_data())?;
        let former = root.path().join("Example Editor");
        let program = former.join("editor.exe");
        std::fs::create_dir(&former)?;
        let observed = FormerInstallation::capture(&former, root.path())?;
        std::fs::remove_dir(&former)?;
        let scope = RegisteredScope::after_uninstall(&former, root.path(), &observed)?;
        let directory = native::open(&LocalPath::parse(root.path())?, 0, FILE_SHARE_READ)?;
        let serial = native::volume_serial(directory.leaf())?;

        let matched = registered_shortcut_image(&program, &scope, serial)?;
        assert_eq!(
            matched.map(|reference| reference.evidence),
            Some(MatchKind::AppName)
        );
        assert!(registered_shortcut_image(&program, &scope, serial ^ 1)?.is_none());
        Ok(())
    }

    #[test]
    #[ignore = "run on a disposable Windows VM with fixed NTFS storage"]
    fn replaced_installation_is_rejected_even_when_the_address_is_unchanged() -> io::Result<()> {
        let files = crate::files::WindowsFiles::new()?;
        let root = tempfile::tempdir_in(files.local_app_data())?;
        let former = root.path().join("Example Editor");
        std::fs::create_dir(&former)?;
        let observed = FormerInstallation::capture(&former, root.path())?;
        std::fs::write(former.join("uninstall-marker"), b"test marker")?;
        observed.verify(&former)?;

        std::fs::rename(&former, root.path().join("original-directory"))?;
        std::fs::create_dir(&former)?;
        assert!(observed.verify(&former).is_err());
        assert!(RegisteredScope::after_uninstall(&former, root.path(), &observed).is_err());
        Ok(())
    }

    #[test]
    fn rejects_wrappers_before_inspecting_a_program_on_disk() {
        let result = prepare_win32_command(
            r"C:\Example\POWERSHELL.exe /x",
            true,
            Path::new(r"C:\Example"),
            None,
        );
        let Err(error) = result else {
            panic!("wrapper was accepted")
        };
        assert!(error.to_string().contains("system command wrapper"));
    }

    #[test]
    fn product_code_syntax_rejects_additional_arguments() {
        let code = "{12345678-1234-abcd-1234-123456789012}";
        assert_eq!(
            normalize_product_code(code).unwrap(),
            "{12345678-1234-ABCD-1234-123456789012}"
        );
        assert!(normalize_product_code(&format!("{code} /q")).is_err());
    }

    #[test]
    fn separates_native_msi_outcomes_and_unverified_win32_success() {
        assert_eq!(classify_msi(0), OfficialOutcome::Completed);
        assert_eq!(classify_msi(1602), OfficialOutcome::Cancelled);
        assert_eq!(classify_msi(1641), OfficialOutcome::NeedsRestart);
        assert_eq!(classify_msi(3010), OfficialOutcome::NeedsRestart);
        assert_eq!(classify_msi(1603), OfficialOutcome::Failed(1603));
        assert_eq!(classify_win32(0, false), OfficialOutcome::Unverified(0));
        assert_eq!(classify_win32(0, true), OfficialOutcome::Completed);
        assert_eq!(classify_win32(7, true), OfficialOutcome::Failed(7));
        assert_eq!(classify_win32(7, false), OfficialOutcome::Failed(7));
    }

    #[test]
    fn only_confirmed_msi_results_allow_the_pending_marker_to_clear() {
        for code in [
            ERROR_INSTALL_SUSPEND,
            259,         // STILL_ACTIVE is not an Installer result.
            1726,        // RPC_S_CALL_FAILED does not establish that the request failed to execute.
            0x8007_0005, // HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED).
            0xc000_0005, // STATUS_ACCESS_VIOLATION.
        ] {
            let unresolved = OfficialOutcome::Unverified(code);
            assert_eq!(classify_msi(code), unresolved);
            for reported in [unresolved, OfficialOutcome::Failed(code)] {
                assert_eq!(
                    unsettled_msi_execution(reported).map(|execution| execution.outcome),
                    Some(unresolved)
                );
            }
        }
        for code in [
            ERROR_SUCCESS_REBOOT_INITIATED,
            ERROR_SUCCESS_REBOOT_REQUIRED,
        ] {
            assert_eq!(
                unsettled_msi_execution(classify_msi(code)).map(|execution| execution.outcome),
                Some(OfficialOutcome::NeedsRestart)
            );
        }
        for code in [
            ERROR_SUCCESS,
            ERROR_INSTALL_USEREXIT,
            ERROR_INSTALL_FAILURE,
            ERROR_INSTALL_ALREADY_RUNNING,
            ERROR_ACCESS_DENIED,
            ERROR_ELEVATION_REQUIRED,
        ] {
            assert!(unsettled_msi_execution(classify_msi(code)).is_none());
        }
        assert!(unsettled_msi_execution(OfficialOutcome::Unverified(ERROR_SUCCESS)).is_none());
    }

    #[test]
    fn force_removal_accepts_failure_but_rejects_permission_and_interrupted_outcomes() {
        assert!(eligible_win32_failure(7));
        for code in [
            ERROR_SUCCESS,
            ERROR_ACCESS_DENIED,
            ERROR_ELEVATION_REQUIRED,
            ERROR_CANCELLED,
            ERROR_INSTALL_USEREXIT,
            ERROR_INSTALL_ALREADY_RUNNING,
            ERROR_INSTALL_SUSPEND,
            ERROR_SUCCESS_REBOOT_INITIATED,
            ERROR_SUCCESS_REBOOT_REQUIRED,
        ] {
            assert!(!eligible_win32_failure(code), "exit code {code}");
        }
    }

    #[test]
    fn cancelled_wait_checks_for_a_signal_before_returning() -> io::Result<()> {
        use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent};

        // SAFETY: optional security and name pointers are absent for this private event.
        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateEventW returned a new owned handle.
        let event = unsafe { OwnedHandle::from_raw_handle(event) };
        let cancel = Cancellation::default();
        cancel.cancel();
        assert!(!wait_for_signal(&event, Some(&cancel))?);
        // SAFETY: the private event remains live through the call.
        if unsafe { SetEvent(event.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        assert!(wait_for_signal(&event, Some(&cancel))?);
        Ok(())
    }
}
