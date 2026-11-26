use std::ffi::{OsStr, OsString, c_void};
use std::io;
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use serde::{Deserialize, Serialize};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_NO_RECALL,
    FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT,
    FileRenameInformation, NtCreateFile, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_FILES, ERROR_PATH_NOT_FOUND, HANDLE, INVALID_HANDLE_VALUE,
    OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, UNICODE_STRING,
};
use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_OFFLINE,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_BASIC_INFO, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_NO_RECALL,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_FULL_DIR_INFO, FILE_ID_INFO, FILE_INFO_BY_HANDLE_CLASS,
    FILE_LIST_DIRECTORY, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_STANDARD_INFO, FILE_TRAVERSE, FileAttributeTagInfo, FileBasicInfo,
    FileDispositionInfo, FileFullDirectoryInfo, FileFullDirectoryRestartInfo, FileIdInfo,
    FileStandardInfo, GetDriveTypeW, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
    GetVolumeInformationByHandleW, MAXIMUM_REPARSE_DATA_BUFFER_SIZE, OPEN_EXISTING, SYNCHRONIZE,
    SetFileInformationByHandle, VOLUME_NAME_DOS,
};
use windows_sys::Win32::System::IO::{DeviceIoControl, IO_STATUS_BLOCK};
use windows_sys::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT;
use windows_sys::Win32::System::SystemServices::{
    IO_REPARSE_TAG_MOUNT_POINT, IO_REPARSE_TAG_SYMLINK,
};
use windows_sys::Win32::System::WindowsProgramming::DRIVE_FIXED;

const SHARE_DIRECTORY: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;
const DIRECTORY_BUFFER_BYTES: usize = 64 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 16_384;
const MAX_COMPONENT_UNITS: usize = 255;
const MAX_PATH_UNITS: usize = 32_767;

#[derive(Clone)]
pub(crate) struct LocalPath {
    drive: u16,
    components: Vec<OsString>,
}

impl LocalPath {
    pub(crate) fn parse(path: &Path) -> io::Result<Self> {
        let units: Vec<u16> = path.as_os_str().encode_wide().collect();
        let (drive, tail) = match units.as_slice() {
            [drive, 58, 92 | 47, tail @ ..]
                if matches!(*drive, 65..=90 | 97..=122) && units.len() <= MAX_PATH_UNITS =>
            {
                (*drive & !32_u16, tail)
            }
            _ => return Err(invalid("expected an absolute local drive path")),
        };
        let mut components = Vec::new();
        let tail = match tail.last() {
            Some(47 | 92) => &tail[..tail.len() - 1],
            _ => tail,
        };
        if !tail.is_empty() {
            for part in tail.split(|unit| matches!(unit, 47 | 92)) {
                validate_component(part)?;
                components.push(OsString::from_wide(part));
            }
        }
        Ok(Self { drive, components })
    }

    pub(super) fn as_path(&self) -> PathBuf {
        let mut path = PathBuf::from(OsString::from_wide(&[self.drive, 58, 92]));
        path.extend(self.components.iter());
        path
    }

    pub(super) fn parent(&self) -> Option<Self> {
        let mut parent = self.clone();
        parent.components.pop()?;
        Some(parent)
    }

    pub(super) fn name(&self) -> Option<&OsStr> {
        self.components.last().map(OsString::as_os_str)
    }

    pub(super) fn child(&self, name: &OsStr) -> io::Result<Self> {
        validate_component(&wide(name))?;
        let mut child = self.clone();
        child.components.push(name.to_owned());
        Ok(child)
    }

    pub(crate) fn depth(&self) -> usize {
        self.components.len()
    }

    pub(super) fn first(&self) -> Option<&OsStr> {
        self.components.first().map(OsString::as_os_str)
    }

    pub(crate) fn starts_with(&self, prefix: &Self) -> bool {
        self.drive == prefix.drive
            && self.depth() >= prefix.depth()
            && self
                .components
                .iter()
                .zip(&prefix.components)
                .all(|(left, right)| equal_name(left, right))
    }

    pub(super) fn same(&self, other: &Self) -> bool {
        self.depth() == other.depth() && self.starts_with(other)
    }
}

fn validate_component(part: &[u16]) -> io::Result<()> {
    let invalid_char = part
        .iter()
        .any(|unit| matches!(unit, 0..=31 | 34 | 42 | 47 | 58 | 60 | 62 | 63 | 92 | 124));
    if part.is_empty()
        || part.len() > MAX_COMPONENT_UNITS
        || matches!(part.last(), Some(32 | 46))
        || invalid_char
        || reserved_name(part)
    {
        return Err(invalid(
            "ambiguous, reserved, or invalid file path component",
        ));
    }
    Ok(())
}

fn reserved_name(part: &[u16]) -> bool {
    let stem = part.split(|unit| *unit == 46).next().unwrap_or_default();
    let upper: Vec<u16> = stem
        .iter()
        .copied()
        .map(|unit| {
            if matches!(unit, 97..=122) {
                unit - 32
            } else {
                unit
            }
        })
        .collect();
    matches!(
        upper.as_slice(),
        [65, 85, 88]
            | [67, 79, 78]
            | [78, 85, 76]
            | [80, 82, 78]
            | [67, 79, 78, 73, 78, 36]
            | [67, 79, 78, 79, 85, 84, 36]
            | [67, 79, 77, 49..=57 | 178 | 179 | 185]
            | [76, 80, 84, 49..=57 | 178 | 179 | 185]
    )
}

pub(super) fn equal_name(left: &OsStr, right: &OsStr) -> bool {
    let (left, right) = (wide(left), wide(right));
    // SAFETY: Both buffers remain live and their explicit lengths are bounded by MAX_PATH_UNITS.
    unsafe {
        CompareStringOrdinal(
            left.as_ptr(),
            left.len() as i32,
            right.as_ptr(),
            right.len() as i32,
            1,
        ) == CSTR_EQUAL
    }
}

fn wide(name: &OsStr) -> Vec<u16> {
    name.encode_wide().collect()
}

pub(crate) fn open(path: &LocalPath, access: u32, share: u32) -> io::Result<OpenPath> {
    match walk(path, access, share)? {
        PathWalk::Present(path) => Ok(path),
        PathWalk::Missing { error, .. } => Err(error),
    }
}

/// Distinguishes a missing component from a failed guard or inaccessible object.
pub(crate) enum PathWalk {
    Present(OpenPath),
    Missing { parent: OpenPath, error: io::Error },
}

pub(crate) fn walk(path: &LocalPath, access: u32, share: u32) -> io::Result<PathWalk> {
    let root_access = if path.depth() == 0 {
        access
    } else {
        FILE_TRAVERSE
    };
    let root = open_root(path.drive, root_access)?;
    let volume = identity(&root)?.volume;
    let mut handles = vec![root];
    for (index, part) in path.components.iter().enumerate() {
        let parent = &handles[handles.len() - 1];
        require_directory(parent)?;
        let is_leaf = index + 1 == path.depth();
        let request = if is_leaf {
            OpenRequest::existing(access, share, 0)
        } else {
            // NtCreateFile limits the flags that can accompany FILE_DIRECTORY_FILE.
            // Keep the no-follow open and check this handle before using it as a parent.
            OpenRequest::existing(FILE_TRAVERSE, SHARE_DIRECTORY, 0)
        };
        let child = match open_child(parent, part, request) {
            Ok(child) => child,
            Err(error) if missing_component(&error) => {
                return Ok(PathWalk::Missing {
                    parent: OpenPath { handles },
                    error,
                });
            }
            Err(error) => return Err(error),
        };
        if identity(&child)?.volume != volume {
            return Err(denied("path crosses a volume boundary"));
        }
        handles.push(child);
    }
    Ok(PathWalk::Present(OpenPath { handles }))
}

fn missing_component(error: &io::Error) -> bool {
    // Access denied and more general volume/path probe errors never establish absence.
    error.raw_os_error().is_some_and(|code| {
        u32::try_from(code)
            .is_ok_and(|code| matches!(code, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND))
    })
}

pub(crate) fn volume_serial(handle: &OwnedHandle) -> io::Result<u32> {
    let mut serial = 0;
    // SAFETY: handle is live and serial is writable. All other optional outputs are null.
    let result = unsafe {
        GetVolumeInformationByHandleW(
            raw(handle),
            null_mut(),
            0,
            &mut serial,
            null_mut(),
            null_mut(),
            null_mut(),
            0,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(serial)
}

fn open_root(drive: u16, access: u32) -> io::Result<OwnedHandle> {
    let name = [drive, 58, 92, 0];
    // SAFETY: The path points to a NUL-terminated four-unit drive root.
    if unsafe { GetDriveTypeW(name.as_ptr()) } != DRIVE_FIXED {
        return Err(denied("the drive is not a fixed local volume"));
    }
    // SAFETY: The drive string is valid, and null optional parameters are documented.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            SHARE_DIRECTORY,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OPEN_NO_RECALL,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned a new handle which this function owns.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    require_directory(&handle)?;
    let final_path = canonical(&handle)?;
    if final_path.depth() != 0 || final_path.drive != drive {
        return Err(denied("the drive is an alias for another location"));
    }
    let mut file_system = [0_u16; 32];
    // SAFETY: The handle is a live volume root and the filesystem buffer is writable.
    let success = unsafe {
        GetVolumeInformationByHandleW(
            raw(&handle),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            null_mut(),
            file_system.as_mut_ptr(),
            file_system.len() as u32,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    if !file_system.starts_with(&[78, 84, 70, 83, 0]) {
        return Err(denied(
            "the filesystem is not verified for guarded access (NTFS)",
        ));
    }
    Ok(handle)
}

pub(crate) struct OpenPath {
    handles: Vec<OwnedHandle>,
}

impl OpenPath {
    pub(crate) fn leaf(&self) -> &OwnedHandle {
        &self.handles[self.handles.len() - 1]
    }

    pub(crate) fn handles(&self) -> &[OwnedHandle] {
        &self.handles
    }

    /// Checks the canonical address of the deepest component reached by the walk.
    pub(crate) fn verify_address_under(&self, requested: &LocalPath) -> io::Result<()> {
        let observed = canonical(self.leaf())?;
        // A short-name alias could otherwise hide a protected directory from a
        // check based on the spelling in the registry. The last held parent is
        // enough even when the remaining suffix does not exist.
        if observed.depth() != self.handles.len() - 1 || !requested.starts_with(&observed) {
            return Err(denied(
                "the native path differs from the registration address",
            ));
        }
        Ok(())
    }

    pub(super) fn parent_id(&self) -> io::Result<Option<Identity>> {
        if self.handles.len() < 2 {
            return Ok(None);
        }
        identity(&self.handles[self.handles.len() - 2]).map(Some)
    }
}

pub(super) struct OpenRequest {
    pub(super) access: u32,
    pub(super) share: u32,
    pub(super) disposition: u32,
    pub(super) options: u32,
    pub(super) security: *mut c_void,
}

impl OpenRequest {
    pub(super) fn existing(access: u32, share: u32, options: u32) -> Self {
        Self {
            access,
            share,
            disposition: FILE_OPEN,
            options,
            security: null_mut(),
        }
    }
}

pub(super) fn open_child(
    parent: &OwnedHandle,
    name: &OsStr,
    request: OpenRequest,
) -> io::Result<OwnedHandle> {
    let mut name = wide(name);
    validate_component(&name)?;
    let bytes = (name.len() * size_of::<u16>()) as u16;
    let name = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: raw(parent),
        ObjectName: &name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: request.security.cast(),
        SecurityQualityOfService: null(),
    };
    let mut handle = null_mut();
    let mut result = IO_STATUS_BLOCK::default();
    // SAFETY: Handles and buffers remain valid until the synchronous native call returns.
    // A single validated component is relative to the held parent and is opened no-follow.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            request.access | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &attributes,
            &mut result,
            null(),
            0,
            request.share,
            request.disposition,
            request.options
                | FILE_OPEN_REPARSE_POINT
                | FILE_OPEN_NO_RECALL
                | FILE_SYNCHRONOUS_IO_NONALERT,
            null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: The converter accepts any NTSTATUS.
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ));
    }
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::other("native file open returned no handle"));
    }
    // SAFETY: A successful native open yielded a newly owned kernel handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

pub(crate) fn require_directory(handle: &OwnedHandle) -> io::Result<()> {
    let info: FILE_ATTRIBUTE_TAG_INFO = information(handle, FileAttributeTagInfo)?;
    if info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(denied("an intermediate directory is a reparse point"));
    }
    if info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "expected a directory",
        ));
    }
    Ok(())
}

pub(crate) fn regular(handle: &OwnedHandle) -> io::Result<Metadata> {
    let metadata = metadata(handle)?;
    if metadata.is_directory || metadata.is_reparse || metadata.links != 1 {
        return Err(denied("expected an ordinary file with a single link"));
    }
    Ok(metadata)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Identity {
    pub(super) volume: u64,
    id: [u8; 16],
}

pub(crate) fn identity(handle: &OwnedHandle) -> io::Result<Identity> {
    let info: FILE_ID_INFO = information(handle, FileIdInfo)?;
    if info.FileId.Identifier == [0; 16] {
        return Err(denied("the filesystem did not provide a stable file ID"));
    }
    Ok(Identity {
        volume: info.VolumeSerialNumber,
        id: info.FileId.Identifier,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Metadata {
    pub(super) identity: Identity,
    pub(super) size: i64,
    pub(crate) is_directory: bool,
    pub(crate) is_reparse: bool,
    pub(super) tag: u32,
    pub(super) links: u32,
    created: i64,
    written: i64,
    changed: i64,
    attributes: u32,
}

impl Metadata {
    pub(super) fn is_single_local_file(&self) -> bool {
        // Data marked for recall must never be read by the offline scanner.
        self.attributes & (FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS) == 0
            && !self.is_directory
            && !self.is_reparse
            && self.links == 1
    }

    pub(super) fn same_moved_object(&self, original: &Self) -> bool {
        // NTFS can update the metadata change time on a successful rename.
        self.identity == original.identity
            && self.created == original.created
            && self.written == original.written
            && self.size == original.size
            && self.links == original.links
            && self.tag == original.tag
            && self.attributes == original.attributes
    }
}

pub(crate) fn metadata(handle: &OwnedHandle) -> io::Result<Metadata> {
    let tag: FILE_ATTRIBUTE_TAG_INFO = information(handle, FileAttributeTagInfo)?;
    let basics: FILE_BASIC_INFO = information(handle, FileBasicInfo)?;
    let standard: FILE_STANDARD_INFO = information(handle, FileStandardInfo)?;
    if standard.DeletePending {
        return Err(denied("the file is pending deletion"));
    }
    Ok(Metadata {
        identity: identity(handle)?,
        size: standard.EndOfFile,
        is_directory: standard.Directory,
        is_reparse: tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0,
        tag: tag.ReparseTag,
        links: standard.NumberOfLinks,
        created: basics.CreationTime,
        written: basics.LastWriteTime,
        changed: basics.ChangeTime,
        attributes: basics.FileAttributes,
    })
}

fn information<T: Default>(
    handle: &OwnedHandle,
    class: FILE_INFO_BY_HANDLE_CLASS,
) -> io::Result<T> {
    let mut buffer = T::default();
    // SAFETY: Private callers supply the Windows buffer type matching the queried class.
    let success = unsafe {
        GetFileInformationByHandleEx(
            raw(handle),
            class,
            (&mut buffer as *mut T).cast(),
            size_of::<T>() as u32,
        )
    };
    if success == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(buffer)
    }
}

pub(super) fn supported_link(handle: &OwnedHandle, tag: u32) -> io::Result<bool> {
    match tag {
        IO_REPARSE_TAG_SYMLINK => Ok(true),
        IO_REPARSE_TAG_MOUNT_POINT => {
            let mut buffer = [0_u8; MAXIMUM_REPARSE_DATA_BUFFER_SIZE as usize];
            let mut written = 0;
            // SAFETY: This reads the reparse metadata of the open handle without opening a target.
            // The output buffer and byte count are writable for a synchronous call.
            let success = unsafe {
                DeviceIoControl(
                    raw(handle),
                    FSCTL_GET_REPARSE_POINT,
                    null(),
                    0,
                    buffer.as_mut_ptr().cast(),
                    buffer.len() as u32,
                    &mut written,
                    null_mut(),
                )
            };
            if success == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(buffer
                .get(..written as usize)
                .and_then(junction_target)
                .is_some())
        }
        _ => Ok(false),
    }
}

fn junction_target(buffer: &[u8]) -> Option<LocalPath> {
    // The common header is eight bytes and the mount-point header is eight more.
    const HEADER_BYTES: usize = 8;
    const PATH_OFFSET: usize = 16;
    let tag = u32::from_le_bytes(buffer.get(..4)?.try_into().ok()?);
    if tag != IO_REPARSE_TAG_MOUNT_POINT {
        return None;
    }
    let data_length = usize::from(u16::from_le_bytes(buffer.get(4..6)?.try_into().ok()?));
    let offset = usize::from(u16::from_le_bytes(buffer.get(8..10)?.try_into().ok()?));
    let length = usize::from(u16::from_le_bytes(buffer.get(10..12)?.try_into().ok()?));
    if offset % 2 != 0
        || length % 2 != 0
        || PATH_OFFSET + offset + length > HEADER_BYTES + data_length
    {
        return None;
    }
    let name = buffer.get(PATH_OFFSET + offset..PATH_OFFSET + offset + length)?;
    let units: Vec<_> = name
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    // A normal local junction substitutes a DOS directory. A volume mount substitutes a GUID.
    let drive_path = units.strip_prefix(&[92, 63, 63, 92])?;
    let path = LocalPath::parse(Path::new(&OsString::from_wide(drive_path))).ok()?;
    (path.depth() > 0).then_some(path)
}

pub(super) fn canonical(handle: &OwnedHandle) -> io::Result<LocalPath> {
    let options = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    // SAFETY: A zero-size query returns the length needed for a live handle.
    let length = unsafe { GetFinalPathNameByHandleW(raw(handle), null_mut(), 0, options) };
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut path = vec![0_u16; length as usize];
    // SAFETY: The output buffer has the previously required length in UTF-16 units.
    let written =
        unsafe { GetFinalPathNameByHandleW(raw(handle), path.as_mut_ptr(), length, options) };
    if written == 0 {
        return Err(io::Error::last_os_error());
    }
    if written >= length {
        return Err(denied("the normalized file path changed during lookup"));
    }
    let path = &path[..written as usize];
    let Some(path) = path.strip_prefix(&[92, 92, 63, 92]) else {
        return Err(denied("the system returned an unsupported file namespace"));
    };
    LocalPath::parse(Path::new(&OsString::from_wide(path)))
}

pub(super) fn rename(
    source: &OwnedHandle,
    destination: &OwnedHandle,
    name: &OsStr,
) -> io::Result<()> {
    let name = wide(name);
    validate_component(&name)?;
    let name_length = size_of_val(name.as_slice());
    let info = FILE_RENAME_INFORMATION {
        RootDirectory: raw(destination),
        FileNameLength: u32::try_from(name_length)
            .expect("validated names contain at most 255 UTF-16 units"),
        ..FILE_RENAME_INFORMATION::default()
    };
    // The Win32 wrapper can reject handle-relative renames. The native
    // operation resolves the leaf relative to the already-checked handle.
    let name_offset = offset_of!(FILE_RENAME_INFORMATION, FileName);
    let byte_count = size_of::<FILE_RENAME_INFORMATION>() + name_length;
    let mut buffer = vec![0_usize; byte_count.div_ceil(size_of::<usize>())];
    let bytes = buffer.as_mut_ptr().cast::<u8>();
    let mut io_status = IO_STATUS_BLOCK::default();
    let length =
        u32::try_from(byte_count).expect("the rename header and validated name fit in u32");
    // SAFETY: The aligned buffer contains the header and name, and both handles
    // remain live for the synchronous call. Default leaves ReplaceIfExists false.
    let status = unsafe {
        bytes.cast::<FILE_RENAME_INFORMATION>().write(info);
        bytes
            .add(name_offset)
            .cast::<u16>()
            .copy_from_nonoverlapping(name.as_ptr(), name.len());
        NtSetInformationFile(
            raw(source),
            &mut io_status,
            bytes.cast(),
            length,
            FileRenameInformation,
        )
    };
    if status < 0 {
        // SAFETY: status is the result of the native rename operation.
        Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ))
    } else {
        Ok(())
    }
}

pub(super) const SCAN_DIRECTORY: u32 = FILE_LIST_DIRECTORY | FILE_TRAVERSE;
pub(super) const EXISTING_FILE: u32 = FILE_NON_DIRECTORY_FILE;
pub(super) const EXISTING_DIRECTORY: u32 = FILE_DIRECTORY_FILE;

pub(super) fn delete_checked_handle(handle: &OwnedHandle) -> io::Result<()> {
    let information = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: The buffer lives through the call and describes file disposition.
    // The caller supplies a DELETE handle opened on the checked, non-directory object.
    let success = unsafe {
        SetFileInformationByHandle(
            raw(handle),
            FileDispositionInfo,
            (&information as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if success == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) fn list(handle: &OwnedHandle, bounded: bool) -> io::Result<Vec<OsString>> {
    require_directory(handle)?;
    let mut buffer = vec![0_u64; DIRECTORY_BUFFER_BYTES / size_of::<u64>()];
    let mut class = FileFullDirectoryRestartInfo;
    let mut names = Vec::new();
    loop {
        // SAFETY: The buffer is writable and aligned for FILE_FULL_DIR_INFO records.
        let result = unsafe {
            GetFileInformationByHandleEx(
                raw(handle),
                class,
                buffer.as_mut_ptr().cast(),
                DIRECTORY_BUFFER_BYTES as u32,
            )
        };
        if result == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                return Ok(names);
            }
            return Err(error);
        }
        read_directory_page(&buffer, &mut names, bounded)?;
        class = FileFullDirectoryInfo;
    }
}

fn read_directory_page(buffer: &[u64], names: &mut Vec<OsString>, bounded: bool) -> io::Result<()> {
    let start = buffer.as_ptr().cast::<u8>();
    let end = std::mem::size_of_val(buffer);
    let name_offset = offset_of!(FILE_FULL_DIR_INFO, FileName);
    let mut offset = 0;
    loop {
        if end - offset < size_of::<FILE_FULL_DIR_INFO>() {
            return Err(invalid("incomplete Windows directory entry"));
        }
        // SAFETY: The checked buffer contains a complete header; unaligned reads are allowed.
        let entry = unsafe {
            start
                .add(offset)
                .cast::<FILE_FULL_DIR_INFO>()
                .read_unaligned()
        };
        let size = entry.FileNameLength as usize;
        if size == 0 || size % size_of::<u16>() != 0 || size > end - offset - name_offset {
            return Err(invalid("invalid Windows directory name length"));
        }
        // SAFETY: The name length is checked above and the header offset aligns the UTF-16 name.
        let name = unsafe {
            std::slice::from_raw_parts(start.add(offset + name_offset).cast::<u16>(), size / 2)
        };
        if let Ok(()) = validate_component(name) {
            if bounded && names.len() == MAX_DIRECTORY_ENTRIES {
                return Err(denied("directory exceeds the maximum scan entry count"));
            }
            names.push(OsString::from_wide(name));
        }
        let next = entry.NextEntryOffset as usize;
        if next == 0 {
            return Ok(());
        }
        if next < name_offset + size || next >= end - offset || next % size_of::<u64>() != 0 {
            return Err(invalid("invalid Windows directory entry offset"));
        }
        offset += next;
    }
}

pub(super) fn raw(handle: &OwnedHandle) -> HANDLE {
    handle.as_raw_handle()
}

pub(super) fn denied(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}

pub(super) fn invalid(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use uuid::Uuid;
    use windows_sys::Win32::Storage::FileSystem::DELETE;

    use super::*;

    #[test]
    fn junction_payload_distinguishes_local_directories_and_volume_mounts() {
        assert!(junction_target(&mount_point_payload(r"\??\C:\Example\Target")).is_some());
        assert!(junction_target(&mount_point_payload(r"\??\Volume{example}\")).is_none());
        assert!(junction_target(&mount_point_payload(r"\??\C:\")).is_none());
        assert!(junction_target(&mount_point_payload(r"\??\C:\Example\..\Windows")).is_none());
        assert!(junction_target(&[0; 16]).is_none());
    }

    fn mount_point_payload(target: &str) -> Vec<u8> {
        let name: Vec<_> = target.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let byte_count = name.len() as u16;
        let mut buffer = Vec::new();
        buffer.extend(IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
        buffer.extend((byte_count + 8).to_le_bytes());
        buffer.extend([0; 4]);
        buffer.extend(byte_count.to_le_bytes());
        buffer.extend([0; 4]);
        buffer.extend(name);
        buffer
    }

    #[test]
    fn native_rename_preserves_identity_and_fails_if_destination_exists() -> io::Result<()> {
        let scratch = Scratch::create()?;
        let source = scratch.0.join("source");
        let destination = scratch.0.join("destination");
        fs::create_dir(&source)?;
        fs::create_dir(&destination)?;
        let original = source.join("sample.txt");
        fs::write(&original, b"original test fixture")?;
        let occupied = destination.join("occupied.txt");
        fs::write(&occupied, b"existing test fixture")?;

        let source_path = LocalPath::parse(&original)?;
        open_root(source_path.drive, FILE_TRAVERSE).expect("open the fixture volume root");
        let source_file = open(&source_path, DELETE, FILE_SHARE_READ)
            .expect("open the fixture source through its guarded ancestors");
        let before = identity(source_file.leaf()).expect("read the original file identity");
        let destination_dir = open(
            &LocalPath::parse(&destination)?,
            FILE_TRAVERSE,
            SHARE_DIRECTORY,
        )
        .expect("open the fixture destination directory");
        assert_eq!(
            rename(
                source_file.leaf(),
                destination_dir.leaf(),
                OsStr::new("occupied.txt")
            )
            .expect_err("an occupied destination must reject the rename")
            .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&occupied)?, b"existing test fixture");
        assert_eq!(fs::read(&original)?, b"original test fixture");
        rename(
            source_file.leaf(),
            destination_dir.leaf(),
            OsStr::new("moved.txt"),
        )
        .expect("rename into the unoccupied destination");
        assert_eq!(identity(source_file.leaf())?, before);
        assert!(!original.try_exists()?);
        assert_eq!(
            fs::read(destination.join("moved.txt"))?,
            b"original test fixture"
        );
        Ok(())
    }

    struct Scratch(PathBuf);

    impl Scratch {
        fn create() -> io::Result<Self> {
            let path = std::env::temp_dir().join(format!("uninstallany-native-{}", Uuid::new_v4()));
            fs::create_dir(&path)?;
            Ok(Self(path))
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            for entry in [
                "source/sample.txt",
                "destination/occupied.txt",
                "destination/moved.txt",
            ] {
                let _ = fs::remove_file(self.0.join(entry));
            }
            for entry in ["source", "destination"] {
                let _ = fs::remove_dir(self.0.join(entry));
            }
            let _ = fs::remove_dir(&self.0);
        }
    }
}
