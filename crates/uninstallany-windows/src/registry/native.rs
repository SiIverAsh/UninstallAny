use std::io;
use std::mem::{size_of, size_of_val};
use std::ptr::{null, null_mut};

use uninstallany_core::{RegistryHive, RegistryTarget, RegistryView};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::System::Registry::{NtCreateKeyTransacted, NtOpenKeyTransactedEx};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA,
    ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, FILETIME, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, RtlNtStatusToDosError, UNICODE_STRING,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetTokenInformation, IsValidSecurityDescriptor, OBJECT_SECURITY_INFORMATION, TOKEN_QUERY,
    TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CommitTransaction, CreateTransaction, RollbackTransaction,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, KEY_WOW64_32KEY,
    KEY_WOW64_64KEY, REG_CREATED_NEW_KEY, REG_OPTION_NON_VOLATILE, REG_OPTION_OPEN_LINK,
    RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegGetKeySecurity, RegOpenCurrentUser,
    RegOpenKeyExW, RegQueryInfoKeyW, RegQueryValueExW,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::format::RawValue;

const MAX_KEY_NAME_WIDE: usize = 255;
const MAX_VALUE_NAME_WIDE: usize = 16_383;
const MAX_REGISTRY_VALUE_BYTES: u32 = 1_048_576;
const MAX_KEY_ENTRIES: u32 = 32_768;
const MAX_SECURITY_BYTES: u32 = 262_144;
const TRANSACTION_TIMEOUT_MS: u32 = 30_000;

pub(super) struct Key(pub HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: Key only owns fresh handles returned by successful opens.
        unsafe { RegCloseKey(self.0) };
    }
}

struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: Handle owns a live kernel handle returned by a successful call.
        unsafe { CloseHandle(self.0) };
    }
}

pub(super) struct Transaction {
    handle: Handle,
    committed: bool,
}

impl Transaction {
    pub fn new() -> io::Result<Self> {
        // SAFETY: Optional arguments are null, and the timeout is in milliseconds.
        let handle = unsafe {
            CreateTransaction(
                null_mut(),
                null_mut(),
                0,
                0,
                0,
                TRANSACTION_TIMEOUT_MS,
                null(),
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            handle: Handle(handle),
            committed: false,
        })
    }

    pub fn commit(mut self) -> io::Result<()> {
        // SAFETY: The transaction handle remains live until self is dropped.
        if unsafe { CommitTransaction(self.handle.0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        self.committed = true;
        Ok(())
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if !self.committed {
            // SAFETY: The transaction still owns the open handle. Rollback may
            // report that a conflicting writer has already aborted it.
            unsafe { RollbackTransaction(self.handle.0) };
        }
    }
}

pub(super) fn status(code: u32) -> io::Result<()> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}

pub(super) fn ntstatus(code: i32) -> io::Result<()> {
    if code >= 0 {
        Ok(())
    } else {
        // SAFETY: RtlNtStatusToDosError accepts any NTSTATUS value.
        status(unsafe { RtlNtStatusToDosError(code) })
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(super) fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

pub(super) fn path_components(path: &str) -> io::Result<impl Iterator<Item = &str>> {
    let is_valid = path.split('\\').all(|part| {
        !part.is_empty()
            && part != "."
            && part != ".."
            && !part.contains('/')
            && !part.chars().any(char::is_control)
            && !part.eq_ignore_ascii_case("Wow6432Node")
            && !part.eq_ignore_ascii_case("WowAA32Node")
            && part.encode_utf16().count() <= MAX_KEY_NAME_WIDE
    });
    if !is_valid {
        return Err(invalid("invalid or aliased registry key component"));
    }
    Ok(path.split('\\'))
}

pub(super) fn view_flags(view: RegistryView) -> u32 {
    match view {
        RegistryView::Native => 0,
        RegistryView::Registry32 => KEY_WOW64_32KEY,
        RegistryView::Registry64 => KEY_WOW64_64KEY,
    }
}

pub(super) fn open(
    target: &RegistryTarget,
    access: u32,
    transaction: Option<&Transaction>,
) -> io::Result<Key> {
    let mut parts = path_components(&target.key)?.peekable();
    let view = view_flags(target.view);
    let inspect = KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS;
    let mut current = match target.hive {
        RegistryHive::CurrentUser => {
            let mut user = null_mut();
            // SAFETY: The out pointer is valid. RegOpenCurrentUser returns an
            // owned HKEY scoped to the current process user in this backend.
            status(unsafe { RegOpenCurrentUser(inspect, &mut user) })?;
            Some(Key(user))
        }
        RegistryHive::LocalMachine => None,
    };
    while let Some(part) = parts.next() {
        let base = current.as_ref().map_or(HKEY_LOCAL_MACHINE, |key| key.0);
        let rights = if parts.peek().is_some() {
            inspect
        } else {
            access | KEY_QUERY_VALUE
        };
        let key = open_child(base, part, rights | view, transaction)?;
        if query(&key, "SymbolicLinkValue")?.is_some() {
            return Err(invalid(
                "registry symbolic link is outside the supported scope",
            ));
        }
        current = Some(key);
    }
    current.ok_or_else(|| invalid("registry hive root is outside the supported scope"))
}

fn open_child(
    parent: HKEY,
    part: &str,
    access: u32,
    transaction: Option<&Transaction>,
) -> io::Result<Key> {
    let mut part = wide(part);
    let mut opened = null_mut();
    if let Some(transaction) = transaction {
        let name = unicode(&mut part);
        let attributes = attributes(parent, &name);
        // SAFETY: Both structures and buffers remain valid through the call.
        // The native API supports no-follow in a transaction. Win32's
        // RegOpenKeyTransactedW has a reserved options parameter.
        ntstatus(unsafe {
            NtOpenKeyTransactedEx(
                &mut opened,
                access,
                &attributes,
                REG_OPTION_OPEN_LINK,
                transaction.handle.0,
            )
        })?;
    } else {
        // SAFETY: part is NUL-terminated and opened is a valid out pointer.
        status(unsafe {
            RegOpenKeyExW(
                parent,
                part.as_ptr(),
                REG_OPTION_OPEN_LINK,
                access,
                &mut opened,
            )
        })?;
    }
    Ok(Key(opened))
}

fn unicode(words: &mut [u16]) -> UNICODE_STRING {
    // All key/class callers are capped at MAX_KEY_NAME_WIDE plus the NUL.
    let length = size_of_val(words) as u16;
    UNICODE_STRING {
        Length: length - size_of::<u16>() as u16,
        MaximumLength: length,
        Buffer: words.as_mut_ptr(),
    }
}

fn attributes(parent: HKEY, name: &UNICODE_STRING) -> OBJECT_ATTRIBUTES {
    OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent,
        ObjectName: name,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: null(),
        SecurityQualityOfService: null(),
    }
}

pub(super) fn create_leaf(
    parent: &Key,
    path: &str,
    access: u32,
    metadata: (&[u16], &[u8]),
    transaction: &Transaction,
) -> io::Result<Key> {
    let (class, descriptor) = metadata;
    let descriptor = validate_descriptor(descriptor)?;
    if class.len() > MAX_KEY_NAME_WIDE || class.contains(&0) {
        return Err(invalid("invalid backup registry class"));
    }
    let mut path = wide(path);
    let name = unicode(&mut path);
    let mut class: Vec<u16> = class.iter().copied().chain(std::iter::once(0)).collect();
    let class = unicode(&mut class);
    let mut attributes = attributes(parent.0, &name);
    attributes.SecurityDescriptor = descriptor.as_ptr().cast();
    let mut opened = null_mut();
    let mut disposition = 0;
    // SAFETY: All referenced buffers and kernel handles remain live for this
    // call, and the security descriptor has been validated as self-relative.
    ntstatus(unsafe {
        NtCreateKeyTransacted(
            &mut opened,
            access,
            &attributes,
            0,
            &class,
            REG_OPTION_NON_VOLATILE,
            transaction.handle.0,
            &mut disposition,
        )
    })?;
    let key = Key(opened);
    if disposition != REG_CREATED_NEW_KEY {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "registry restore target exists",
        ));
    }
    Ok(key)
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct KeyInfo {
    pub class: Vec<u16>,
    pub subkeys: u32,
    pub modified: u64,
}

pub(super) fn key_info(key: &Key) -> io::Result<KeyInfo> {
    let mut class = [0; MAX_KEY_NAME_WIDE + 1];
    let mut class_size = class.len() as u32;
    let mut subkeys = 0;
    let mut modified = FILETIME::default();
    // SAFETY: The output arguments are valid for the requested sizes.
    status(unsafe {
        RegQueryInfoKeyW(
            key.0,
            class.as_mut_ptr(),
            &mut class_size,
            null(),
            &mut subkeys,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut modified,
        )
    })?;
    Ok(KeyInfo {
        class: class[..class_size as usize].to_vec(),
        subkeys,
        modified: u64::from(modified.dwHighDateTime) << 32 | u64::from(modified.dwLowDateTime),
    })
}

pub(super) fn subkeys(key: &Key) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    let mut name = [0; MAX_KEY_NAME_WIDE + 1];
    for index in 0..MAX_KEY_ENTRIES {
        let mut name_size = name.len() as u32;
        // SAFETY: The wide buffer length matches the input capacity. All
        // optional outputs are null and reserved is null.
        let code = unsafe {
            RegEnumKeyExW(
                key.0,
                index,
                name.as_mut_ptr(),
                &mut name_size,
                null(),
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        if code == ERROR_NO_MORE_ITEMS {
            return Ok(names);
        }
        status(code)?;
        names.push(String::from_utf16(&name[..name_size as usize]).map_err(io::Error::other)?);
    }
    Err(invalid("too many registry subkeys to verify"))
}

pub(super) fn value_names(key: &Key) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    let mut name = vec![0; MAX_VALUE_NAME_WIDE + 1];
    for index in 0..MAX_KEY_ENTRIES {
        let mut name_size = name.len() as u32;
        // SAFETY: The wide buffer length matches the input capacity. The
        // remaining outputs are optional and not requested.
        let code = unsafe {
            RegEnumValueW(
                key.0,
                index,
                name.as_mut_ptr(),
                &mut name_size,
                null(),
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        if code == ERROR_NO_MORE_ITEMS {
            return Ok(names);
        }
        status(code)?;
        names.push(String::from_utf16(&name[..name_size as usize]).map_err(io::Error::other)?);
    }
    Err(invalid("too many registry values to verify"))
}

pub(super) fn query(key: &Key, name: &str) -> io::Result<Option<RawValue>> {
    let name = wide(name);
    let mut kind = 0;
    let mut size = 0;
    // SAFETY: The NUL-terminated name and output pointers are valid. Null data
    // requests only the type and required buffer size.
    let code = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            null(),
            &mut kind,
            null_mut(),
            &mut size,
        )
    };
    if code == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    status(code)?;
    if size > MAX_REGISTRY_VALUE_BYTES {
        return Err(invalid("registry value exceeds the supported backup limit"));
    }
    let mut data = vec![0; size as usize];
    // SAFETY: data has size writable bytes. For empty values no bytes are
    // written. A concurrent resize is reported as a conflict by the caller.
    let code = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            null(),
            &mut kind,
            data.as_mut_ptr(),
            &mut size,
        )
    };
    if code == ERROR_MORE_DATA {
        return Err(invalid("registry value changed size while being read"));
    }
    status(code)?;
    data.truncate(size as usize);
    Ok(Some(RawValue { kind, data }))
}

pub(super) fn security(key: &Key, information: OBJECT_SECURITY_INFORMATION) -> io::Result<Vec<u8>> {
    let mut size = 0;
    // SAFETY: The null output buffer asks for the required size.
    let code = unsafe { RegGetKeySecurity(key.0, information, null_mut(), &mut size) };
    if code != ERROR_INSUFFICIENT_BUFFER {
        status(code)?;
    }
    if size == 0 || size > MAX_SECURITY_BYTES {
        return Err(invalid("registry security descriptor has unsupported size"));
    }
    let mut buffer = vec![0_u32; (size as usize).div_ceil(size_of::<u32>())];
    // SAFETY: buffer is aligned and contains at least size writable bytes.
    status(unsafe {
        RegGetKeySecurity(key.0, information, buffer.as_mut_ptr().cast(), &mut size)
    })?;
    let bytes: Vec<u8> = buffer
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .take(size as usize)
        .collect();
    validate_descriptor(&bytes)?;
    Ok(bytes)
}

fn validate_descriptor(bytes: &[u8]) -> io::Result<Vec<u32>> {
    const HEADER: usize = 20;
    if bytes.len() < HEADER || bytes.len() > MAX_SECURITY_BYTES as usize || bytes[3] & 0x80 == 0 {
        return Err(invalid(
            "registry security descriptor is not bounded and self-relative",
        ));
    }
    for (index, word) in bytes[4..HEADER].chunks_exact(4).enumerate() {
        let offset = u32::from_le_bytes([word[0], word[1], word[2], word[3]]) as usize;
        if offset == 0 {
            continue;
        }
        if offset % 4 != 0 || offset < HEADER || offset > bytes.len() - 8 {
            return Err(invalid(
                "registry security descriptor offset is out of bounds",
            ));
        }
        let size = if index < 2 {
            8 + 4 * usize::from(bytes[offset + 1])
        } else {
            usize::from(u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]))
        };
        if size < 8 || size > bytes.len() - offset {
            return Err(invalid(
                "registry security descriptor component is out of bounds",
            ));
        }
    }
    let mut words = vec![0_u32; bytes.len().div_ceil(4)];
    for (word, chunk) in words.iter_mut().zip(bytes.chunks(4)) {
        let mut pad = [0; 4];
        pad[..chunk.len()].copy_from_slice(chunk);
        *word = u32::from_le_bytes(pad);
    }
    // SAFETY: The self-relative header and all referenced SID/ACL ranges have
    // backing storage in the aligned words buffer.
    if unsafe { IsValidSecurityDescriptor(words.as_ptr().cast_mut().cast()) } == 0 {
        return Err(invalid("Windows rejected the backup security descriptor"));
    }
    Ok(words)
}

pub(super) fn user_sid() -> io::Result<String> {
    let mut token = null_mut();
    // SAFETY: GetCurrentProcess supplies a pseudo-handle. token is a valid out pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Handle(token);
    let mut size = 0;
    // SAFETY: The null buffer is a size query; size points to writable storage.
    unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut size) };
    if (size as usize) < size_of::<TOKEN_USER>() || size > 4_096 {
        return Err(invalid("Windows did not return a bounded process user SID"));
    }
    let mut buffer = vec![0_usize; (size as usize).div_ceil(size_of::<usize>())];
    // SAFETY: The token is open and the aligned buffer has capacity for size bytes.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut text = null_mut();
    // SAFETY: The successful TokenUser query wrote a TOKEN_USER in the buffer
    // followed by the SID that its User.Sid points to.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // SAFETY: sid is from the live token buffer and text is an out pointer.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: ConvertSidToStringSidW returns a NUL-terminated LocalAlloc string.
    let result = unsafe {
        let length = (0..).take_while(|index| *text.add(*index) != 0).count();
        let result = String::from_utf16(std::slice::from_raw_parts(text, length));
        LocalFree(text.cast());
        result
    };
    result.map_err(io::Error::other)
}
