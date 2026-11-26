use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uninstallany_core::MatchKind;
use windows_sys::Win32::Foundation::{
    ERROR_CANCELLED, ERROR_INSTALL_USEREXIT, ERROR_SUCCESS, ERROR_SUCCESS_REBOOT_INITIATED,
    ERROR_SUCCESS_REBOOT_REQUIRED, ERROR_UNKNOWN_PRODUCT, HANDLE, WAIT_OBJECT_0,
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
    QueryInformationJobObject,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
    GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION, STARTUPINFOEXW, STARTUPINFOW,
    UpdateProcThreadAttribute, WaitForSingleObject,
};
use windows_sys::Win32::System::WindowsProgramming::{SCS_32BIT_BINARY, SCS_64BIT_BINARY};

use super::files::native::{self, Identity, LocalPath, OpenPath, PathWalk};

const MAX_WINDOWS_COMMAND_UNITS: usize = 32_767;
const MAX_UNINSTALLER_BYTES: u64 = 512 * 1024 * 1024;
const HASH_BUFFER_BYTES: usize = 64 * 1024;
const DESCENDANT_POLL: Duration = Duration::from_millis(100);
const DESCENDANT_WAIT: Duration = Duration::from_secs(30);
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

/// Stable executable and ancestor identities plus a digest of the file contents.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
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

/// Validated official uninstall intent. Arguments are not exposed for editing or logging.
pub struct OfficialUninstall {
    program: PathBuf,
    arguments: String,
    is_quiet: bool,
    provider: Provider,
    identity: ExecutableIdentity,
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
    pub fn execute(self) -> io::Result<OfficialOutcome> {
        let pinned = pin_executable(&self.program)?;
        if pinned.identity()? != self.identity {
            return Err(invalid(
                "the official uninstaller or its containing directory changed; preview again",
            ));
        }

        if let Provider::Msi {
            product_code,
            machine,
        } = &self.provider
        {
            verify_msi_context(product_code, *machine)?;
        }
        let process = start_process(&self, &pinned);
        // Some uninstallers remove themselves after starting. Release the pins once
        // Windows has opened the exact executable and returned a process handle.
        drop(pinned);
        let process = match process {
            Ok(process) => process,
            Err(error) if error.raw_os_error() == Some(ERROR_CANCELLED as i32) => {
                return Ok(OfficialOutcome::Cancelled);
            }
            Err(error) => return Err(error),
        };
        let code = wait_for_exit(&process.root)?;

        let Provider::Msi { product_code, .. } = &self.provider else {
            let observed_end = code == 0 && process.job.as_ref().is_some_and(job_finished);
            return Ok(classify_win32(code, observed_end));
        };
        let outcome = classify_msi(code);
        if outcome == OfficialOutcome::Completed && !msi_product_absent(product_code) {
            return Ok(OfficialOutcome::Unverified(code));
        }
        Ok(outcome)
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
    let intent = |command, is_quiet| prepare_win32_command(command, is_quiet, directory);
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
    })
}

fn prepare_win32_command(
    command: &str,
    is_quiet: bool,
    directory: &Path,
) -> io::Result<OfficialUninstall> {
    let (program, arguments) = split_command(command)?;
    let program = PathBuf::from(program);
    let stem = program
        .file_stem()
        .and_then(OsStr::to_str)
        .ok_or_else(|| invalid("the uninstaller has no valid executable name"))?;
    if BLOCKED_EXECUTABLES
        .iter()
        .any(|name| stem.eq_ignore_ascii_case(name))
    {
        return Err(invalid(
            "the registered uninstall command uses a shell or a system command wrapper",
        ));
    }

    let pinned = pin_executable_in_directory(&program, directory)?;
    Ok(OfficialUninstall {
        program,
        arguments: arguments.to_owned(),
        is_quiet,
        provider: Provider::Win32 {
            quiet_rejected: false,
        },
        identity: pinned.identity()?,
    })
}

/// Directory scope for read-only references from Windows registrations.
pub(super) struct RegisteredScope {
    location: LocalPath,
    location_id: Option<Identity>,
    anchor_depth: usize,
    anchor_id: Identity,
    former_location: Option<PathBuf>,
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
            former_location: None,
        })
    }

    /// Allows missing paths below the former install location after verified uninstall.
    pub(super) fn after_uninstall(directory: &Path, trusted_root: &Path) -> io::Result<Self> {
        let location = LocalPath::parse(directory)?;
        let anchor = LocalPath::parse(trusted_root)?;
        let anchor_depth = anchor.depth();
        if anchor_depth == 0 || location.depth() <= anchor_depth || !location.starts_with(&anchor) {
            return Err(invalid(
                "the former installation is outside the trusted root",
            ));
        }
        let root = native::open(&anchor, 0, FILE_SHARE_READ | FILE_SHARE_WRITE)?;
        native::require_directory(root.leaf())?;
        root.verify_address_under(&anchor)?;
        let anchor_id = native::identity(root.leaf())?;
        let location_id = match native::walk(&location, 0, FILE_SHARE_READ | FILE_SHARE_WRITE)? {
            PathWalk::Present(directory) => {
                verify_registration_anchor(&directory, anchor_depth, &anchor_id)?;
                native::require_directory(directory.leaf())?;
                directory.verify_address_under(&location)?;
                Some(native::identity(directory.leaf())?)
            }
            PathWalk::Missing { parent, .. } => {
                verify_registration_anchor(&parent, anchor_depth, &anchor_id)?;
                parent.verify_address_under(&location)?;
                None
            }
        };
        Ok(Self {
            location,
            location_id,
            anchor_depth,
            anchor_id,
            former_location: Some(directory.to_path_buf()),
        })
    }

    fn verify_ancestors(&self, path: &OpenPath, requested: &LocalPath) -> io::Result<()> {
        verify_registration_anchor(path, self.anchor_depth, &self.anchor_id)?;
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

/// Attribution for a verified present file or an absent, read-only registration target.
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

/// Matches an existing executable only on the volume recorded by the Shell Link.
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
            if scope.former_location.is_none() {
                return Ok(None);
            }
            scope.verify_ancestors(&parent, &child)?;
            (MatchKind::AppName, scope.former_location.clone())
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

fn split_command(command: &str) -> io::Result<(&str, &str)> {
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

fn pin_executable(path: &Path) -> io::Result<PinnedExecutable> {
    let path = native::open(&LocalPath::parse(path)?, FILE_GENERIC_READ, FILE_SHARE_READ)?;
    let leaf = path.leaf();
    let metadata = native::metadata(leaf)?;
    if metadata.is_directory || metadata.is_reparse {
        return Err(invalid(
            "the uninstaller is not an ordinary executable file",
        ));
    }
    let native_name = final_name(leaf)?;
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
    let mut attributes = job.as_ref().map(JobAttributes::new).transpose()?;
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
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful call owns two new handles. Only the process handle
    // must outlive this function, so the primary-thread handle is closed here.
    let thread = unsafe { OwnedHandle::from_raw_handle(process.hThread) };
    drop(thread);
    // SAFETY: ownership of the valid process handle is transferred exactly once.
    let root = unsafe { OwnedHandle::from_raw_handle(process.hProcess) };
    Ok(OfficialProcess { root, job })
}

struct OfficialProcess {
    root: OwnedHandle,
    job: Option<OwnedHandle>,
}

fn create_tracking_job() -> io::Result<OwnedHandle> {
    // SAFETY: null inputs create an unnamed job with default security and limits.
    // There is no kill-on-close limit, so closing this observer never stops a job.
    let job = unsafe { CreateJobObjectW(null(), null()) };
    if job.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the API returned a new owned job handle on success.
    Ok(unsafe { OwnedHandle::from_raw_handle(job) })
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

fn job_finished(job: &OwnedHandle) -> bool {
    let start = Instant::now();
    loop {
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
            return false;
        }
        if info.ActiveProcesses == 0 {
            return true;
        }
        if start.elapsed() >= DESCENDANT_WAIT {
            return false;
        }
        // Closing the job leaves any externally managed or long-running child alone.
        thread::sleep(DESCENDANT_POLL);
    }
}

fn wait_for_exit(process: &OwnedHandle) -> io::Result<u32> {
    // SAFETY: process owns a live process handle allowed for waiting.
    if unsafe { WaitForSingleObject(process.as_raw_handle(), INFINITE) } != WAIT_OBJECT_0 {
        return Err(io::Error::last_os_error());
    }
    let mut code = 0;
    // SAFETY: process remains alive as a handle and code is writable.
    if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(code)
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

fn msi_product_absent(product: &str) -> bool {
    MSI_CONTEXTS
        .into_iter()
        .all(|context| matches!(msi_product_state(product, context), Ok(None)))
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
        _ => OfficialOutcome::Failed(code),
    }
}

fn classify_win32(code: u32, observed_end: bool) -> OfficialOutcome {
    match (code, observed_end) {
        // The caller still checks that the exact original registration is absent.
        (0, true) => OfficialOutcome::Completed,
        (0, false) => OfficialOutcome::Unverified(code),
        _ => OfficialOutcome::Failed(code),
    }
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
    fn rejects_wrappers_before_inspecting_a_program_on_disk() {
        let result = prepare_win32_command(
            r"C:\Example\POWERSHELL.exe /x",
            true,
            Path::new(r"C:\Example"),
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
    }
}
