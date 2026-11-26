//! Local image provenance and installation ACL checks for the privileged helper.

use std::{
    ffi::{OsString, c_void},
    io,
    mem::{offset_of, size_of},
    os::windows::{
        ffi::OsStringExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Path, PathBuf},
    ptr::null_mut,
};

use windows_sys::Win32::{
    Foundation::{GENERIC_ALL, GENERIC_WRITE, HANDLE, LocalFree},
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL_SIZE_INFORMATION, AclSizeInformation,
        Authorization::{ConvertStringSidToSidW, GetSecurityInfo, SE_FILE_OBJECT},
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, INHERIT_ONLY_ACE,
        IsValidAcl, IsValidSid, IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSID,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    },
    Storage::FileSystem::{
        DELETE, FILE_ADD_SUBDIRECTORY, FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
        READ_CONTROL, WRITE_DAC, WRITE_OWNER,
    },
    System::{
        Com::CoTaskMemFree,
        SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE},
        Threading::{GetCurrentProcess, QueryFullProcessImageNameW},
    },
    UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath},
};

#[cfg(feature = "privileged-helper")]
use windows_sys::Win32::{
    Security::{
        Authorization::ConvertSidToStringSidW, GetTokenInformation, SECURITY_MAX_SID_SIZE,
        TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenSessionId, TokenUser,
    },
    Storage::FileSystem::SYNCHRONIZE,
    System::Threading::{
        GetCurrentProcessId, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    },
};

use crate::files::native::{self, LocalPath, OpenPath};

const INSTALL_DIRECTORY: &str = "UninstallAny";
const GUI_NAME: &str = "UninstallAny.exe";
const HELPER_NAME: &str = "UninstallAnyHelper.exe";
const MAX_PATH_UNITS: u32 = 32_768;
const LOCAL_VERBATIM_PREFIX: [u16; 4] = [92, 92, 63, 92];
const SID_HEADER_BYTES: usize = 8;
// The Windows Modules Installer service owns protected Windows directories.
const TRUSTED_INSTALLER_SID: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const MUTATION_RIGHTS: u32 = GENERIC_ALL
    | GENERIC_WRITE
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_DELETE_CHILD
    | FILE_WRITE_ATTRIBUTES;

/// Holds the verified image and its ancestor handles without delete sharing.
pub(super) struct TrustedExecutable {
    path: PathBuf,
    expected: LocalPath,
    pinned: OpenPath,
}

impl TrustedExecutable {
    /// The fixed install path. Keep this pin alive across process launch and verification.
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// Checks the kernel-reported image of a process held by the caller.
    pub(super) fn verify_process(&self, process: &OwnedHandle) -> io::Result<()> {
        self.verify_image(process.as_raw_handle())
    }

    /// Checks that the current GUI or helper was started from its protected install.
    pub(super) fn verify_current_process(&self) -> io::Result<()> {
        // SAFETY: a current-process pseudohandle may be queried without being closed.
        self.verify_image(unsafe { GetCurrentProcess() })
    }

    fn verify_image(&self, process: HANDLE) -> io::Result<()> {
        let path = process_image(process)?;
        let path = LocalPath::parse(&path)?;
        if path.depth() != self.expected.depth() || !path.starts_with(&self.expected) {
            return Err(denied(
                "the process image is outside the trusted installation",
            ));
        }
        let image = native::open(&path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ)?;
        image.verify_address_under(&self.expected)?;
        native::regular(image.leaf())?;
        if native::identity(image.leaf())? != native::identity(self.pinned.leaf())? {
            return Err(denied(
                "the process image did not match the pinned executable",
            ));
        }
        Ok(())
    }
}

/// Verifies the fixed installed GUI address and holds it against replacement.
pub(super) fn pin_gui() -> io::Result<TrustedExecutable> {
    pin(GUI_NAME)
}

/// Verifies the fixed installed helper address and holds it against replacement.
pub(super) fn pin_helper() -> io::Result<TrustedExecutable> {
    pin(HELPER_NAME)
}

fn pin(name: &str) -> io::Result<TrustedExecutable> {
    let path = program_files()?.join(INSTALL_DIRECTORY).join(name);
    let expected = LocalPath::parse(&path)?;
    let pinned = native::open(
        &expected,
        READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ,
    )?;
    pinned.verify_address_under(&expected)?;
    native::regular(pinned.leaf())?;
    if path.ancestors().count() != pinned.handles().len() {
        return Err(denied("the installation ancestry has an unexpected layout"));
    }

    let installer = trusted_installer_sid()?;
    verify_acl(pinned.leaf(), installer.0, false)?;
    for (depth, ancestor) in path.ancestors().skip(1).enumerate() {
        let index = expected.depth() - 1 - depth;
        // The path walk's parent handles need traverse access. Take a second
        // guarded walk to obtain READ_CONTROL on each, and compare its identity.
        let address = LocalPath::parse(ancestor)?;
        let anchored = native::open(
            &address,
            READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )?;
        anchored.verify_address_under(&address)?;
        native::require_directory(anchored.leaf())?;
        if native::identity(anchored.leaf())? != native::identity(&pinned.handles()[index])? {
            return Err(denied(
                "an installation directory changed during verification",
            ));
        }
        verify_acl(anchored.leaf(), installer.0, index == 0)?;
    }
    Ok(TrustedExecutable {
        path,
        expected,
        pinned,
    })
}

/// Opens a live GUI caller candidate from the helper's interactive Windows session.
/// The caller image and the local channel's peer PID must be verified separately.
#[cfg(feature = "privileged-helper")]
pub(super) fn open_caller(pid: u32) -> io::Result<OwnedHandle> {
    // SAFETY: these calls require no pointers. The process handle is never inheritable.
    if pid == 0 || pid == unsafe { GetCurrentProcessId() } {
        return Err(denied("invalid helper caller process"));
    }
    // SAFETY: query and wait rights suffice to authenticate the process and its lifetime.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcess returned a newly owned process handle.
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    let caller = process_token(process.as_raw_handle())?;
    // SAFETY: the current process pseudohandle is valid for opening its token.
    let current = process_token(unsafe { GetCurrentProcess() })?;
    let session = token_u32(&caller, TokenSessionId)?;
    if session == 0 || session != token_u32(&current, TokenSessionId)? {
        return Err(denied(
            "the helper caller is outside the current interactive session",
        ));
    }
    // TokenElevation is a TOKEN_ELEVATION containing exactly one DWORD.
    if token_u32(&caller, TokenElevation)? != 0 {
        return Err(denied(
            "the helper caller must be running without elevation",
        ));
    }
    Ok(process)
}

/// Obtains the verified peer account for the helper's local channel ACL.
#[cfg(feature = "privileged-helper")]
pub(super) fn caller_sid(process: &OwnedHandle) -> io::Result<String> {
    const WORDS: usize =
        (size_of::<TOKEN_USER>() + SECURITY_MAX_SID_SIZE as usize).div_ceil(size_of::<usize>());
    const BYTES: u32 = (WORDS * size_of::<usize>()) as u32;
    const MAX_SID_TEXT_UNITS: usize = 192;
    let token = process_token(process.as_raw_handle())?;
    let mut buffer = [0_usize; WORDS];
    let mut returned = 0u32;
    // SAFETY: the initialized buffer has TOKEN_USER alignment and room for a maximum-size SID.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            BYTES,
            &mut returned,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let length = returned as usize;
    if length < size_of::<TOKEN_USER>() + SID_HEADER_BYTES || returned > BYTES {
        return Err(denied("Windows returned an invalid token user buffer"));
    }
    // SAFETY: the successful query initialized an aligned TOKEN_USER in this buffer.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let start = sid
        .addr()
        .checked_sub(buffer.as_ptr().addr())
        .filter(|&offset| (size_of::<TOKEN_USER>()..=length - SID_HEADER_BYTES).contains(&offset))
        .ok_or_else(|| denied("the process user SID is outside the token buffer"))?;
    // SAFETY: the complete SID header lies in the retained output buffer.
    let count = unsafe { *sid.cast::<u8>().add(1) };
    if SID_HEADER_BYTES + usize::from(count) * size_of::<u32>() > length - start {
        return Err(denied("the process user SID exceeds the token buffer"));
    }

    let mut text = null_mut();
    // SAFETY: the complete SID remains live while Windows validates and converts it.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _text = LocalAllocation(text.cast());
    if text.is_null() {
        return Err(denied("Windows returned no process user SID"));
    }
    // SAFETY: the API returns a terminated UTF-16 string owned by the guard.
    let length = (0..MAX_SID_TEXT_UNITS)
        .find(|&index| unsafe { *text.add(index) == 0 })
        .ok_or_else(|| denied("the process user SID text exceeds the supported length"))?;
    // SAFETY: only units preceding the terminator in the live allocation are read.
    let text = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
        .map_err(io::Error::other)?;
    if !text.strip_prefix("S-").is_some_and(|fields| {
        fields
            .split('-')
            .all(|field| !field.is_empty() && field.bytes().all(|byte| byte.is_ascii_digit()))
    }) {
        return Err(denied(
            "the process user SID cannot be used as a literal access entry",
        ));
    }
    Ok(text)
}

#[cfg(feature = "privileged-helper")]
fn process_token(process: HANDLE) -> io::Result<OwnedHandle> {
    let mut token = null_mut();
    // SAFETY: the process is live and token is a writable output pointer.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful OpenProcessToken returned a newly owned token.
    Ok(unsafe { OwnedHandle::from_raw_handle(token) })
}

#[cfg(feature = "privileged-helper")]
fn token_u32(
    token: &OwnedHandle,
    class: windows_sys::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> io::Result<u32> {
    let mut value = 0u32;
    let mut returned = 0;
    const BYTES: u32 = size_of::<u32>() as u32;
    const _: () = assert!(size_of::<TOKEN_ELEVATION>() == size_of::<u32>());
    // SAFETY: only DWORD-sized token classes are passed, and both output buffers are writable.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            (&mut value as *mut u32).cast(),
            BYTES,
            &mut returned,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if returned != BYTES {
        return Err(denied(
            "Windows returned an unexpected process token layout",
        ));
    }
    Ok(value)
}

fn process_image(process: HANDLE) -> io::Result<PathBuf> {
    let mut length = MAX_PATH_UNITS;
    let mut units = vec![0; MAX_PATH_UNITS as usize];
    // SAFETY: process may be queried. The output buffer has `length` UTF-16 units.
    if unsafe { QueryFullProcessImageNameW(process, 0, units.as_mut_ptr(), &mut length) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let path = units
        .get(..length as usize)
        .ok_or_else(|| denied("invalid process image length"))?;
    Ok(local_dos_path(path))
}

fn program_files() -> io::Result<PathBuf> {
    let mut path = null_mut();
    // SAFETY: reads the fixed folder ID and returns a terminated COM-allocated string.
    let result = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, 0, null_mut(), &mut path) };
    let allocation = KnownFolder(path.cast());
    if result < 0 || path.is_null() {
        return Err(io::Error::other(format!(
            "could not locate Program Files (HRESULT {result:#x})"
        )));
    }
    // SAFETY: the OS returned a NUL-terminated path that the allocation guard keeps alive.
    let length = (0..MAX_PATH_UNITS as usize)
        .find(|&index| unsafe { *path.add(index) == 0 })
        .ok_or_else(|| denied("Program Files path exceeds the Windows path limit"))?;
    let path = local_dos_path(unsafe { std::slice::from_raw_parts(path, length) });
    drop(allocation);
    if LocalPath::parse(&path)?.depth() == 0 {
        return Err(denied("Program Files cannot be a drive root"));
    }
    Ok(path)
}

fn local_dos_path(path: &[u16]) -> PathBuf {
    // The native guard still requires a DOS drive path after stripping this prefix.
    let path = path.strip_prefix(&LOCAL_VERBATIM_PREFIX).unwrap_or(path);
    PathBuf::from(OsString::from_wide(path))
}

fn verify_acl(handle: &OwnedHandle, installer: PSID, drive_root: bool) -> io::Result<()> {
    let (mut owner, mut acl, mut descriptor) = (null_mut(), null_mut(), null_mut());
    // SAFETY: the live handle has READ_CONTROL and each requested output is writable.
    let result = unsafe {
        GetSecurityInfo(
            handle.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut descriptor,
        )
    };
    let memory = LocalAllocation(descriptor);
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    // SAFETY: GetSecurityInfo returned a DACL owned by the retained descriptor.
    if memory.0.is_null()
        || acl.is_null()
        || unsafe { IsValidAcl(acl) } == 0
        || !trusted_sid(owner, installer)
    {
        return Err(denied(
            "the installation owner or access control is not trusted",
        ));
    }
    let mut info = ACL_SIZE_INFORMATION::default();
    // SAFETY: info is sized for this query, and acl outlives the call and returned entries.
    if unsafe {
        GetAclInformation(
            acl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // Default NTFS drive roots can let users create sibling directories. The
    // grant cannot modify or delete the existing Program Files ancestry.
    let mutation = if drive_root {
        MUTATION_RIGHTS & !FILE_ADD_SUBDIRECTORY
    } else {
        MUTATION_RIGHTS
    };
    for index in 0..info.AceCount {
        let mut entry = null_mut();
        // SAFETY: the index is bounded by the validated ACL's entry count.
        if unsafe { GetAce(acl, index, &mut entry) } == 0 {
            return Err(io::Error::last_os_error());
        }
        check_ace(entry, installer, mutation)?;
    }
    Ok(())
}

fn check_ace(entry: *mut c_void, installer: PSID, mutation: u32) -> io::Result<()> {
    // SAFETY: GetAce returned an entry from a validated, live ACL.
    let header = unsafe { &*entry.cast::<ACE_HEADER>() };
    if u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0
        || u32::from(header.AceType) == ACCESS_DENIED_ACE_TYPE
    {
        return Ok(());
    }
    if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
        return Err(denied(
            "the installation DACL has an unsupported access entry",
        ));
    }
    const SID_START: usize = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    let size = usize::from(header.AceSize);
    if size < SID_START + SID_HEADER_BYTES {
        return Err(denied("the installation DACL has a malformed access entry"));
    }
    // SAFETY: the ACE points to a complete fixed header and an embedded SID header.
    let (mask, sid) = unsafe {
        (
            (*entry.cast::<ACCESS_ALLOWED_ACE>()).Mask,
            entry.cast::<u8>().add(SID_START),
        )
    };
    // SAFETY: the SID's second byte is its sub-authority count, inside the checked header.
    let sid_size = SID_HEADER_BYTES + usize::from(unsafe { *sid.add(1) }) * size_of::<u32>();
    if size < SID_START + sid_size || (mask & mutation != 0 && !trusted_sid(sid.cast(), installer))
    {
        return Err(denied(
            "a non-administrator can modify or replace the installation",
        ));
    }
    Ok(())
}

fn trusted_installer_sid() -> io::Result<LocalAllocation> {
    let text: Vec<u16> = TRUSTED_INSTALLER_SID.encode_utf16().chain([0]).collect();
    let mut sid = null_mut();
    // SAFETY: text is NUL-terminated and sid is a writable LocalFree-allocated output.
    if unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut sid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(LocalAllocation(sid))
}

fn trusted_sid(sid: PSID, installer: PSID) -> bool {
    // SAFETY: caller guarantees a live SID buffer; only valid SIDs reach the comparisons.
    !sid.is_null()
        && unsafe {
            IsValidSid(sid) != 0
                && (EqualSid(sid, installer) != 0
                    || IsWellKnownSid(sid, WinLocalSystemSid) != 0
                    || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0)
        }
}

struct KnownFolder(*mut c_void);

impl Drop for KnownFolder {
    fn drop(&mut self) {
        // SAFETY: this pointer was allocated by SHGetKnownFolderPath.
        unsafe { CoTaskMemFree(self.0) };
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: the Windows API allocated this descriptor or SID for LocalFree.
        unsafe { LocalFree(self.0) };
    }
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
