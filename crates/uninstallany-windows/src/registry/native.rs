use std::ffi::c_void;
use std::io;
use std::mem::{offset_of, size_of, size_of_val};
use std::ptr::{null, null_mut};

use uninstallany_core::{RegistryHive, RegistryTarget, RegistryView};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::System::Registry::{
    NtCreateKey, NtCreateKeyTransacted, NtOpenKeyEx, NtOpenKeyTransactedEx,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA,
    ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, FILETIME, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, RtlNtStatusToDosError, STATUS_OBJECT_NAME_NOT_FOUND,
    UNICODE_STRING,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_REGISTRY_KEY,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL_SIZE_INFORMATION, AclSizeInformation,
    DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, GetSecurityDescriptorControl,
    GetTokenInformation, IsValidSecurityDescriptor, OBJECT_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSID, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CommitTransaction, CreateTransaction, READ_CONTROL, RollbackTransaction,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_ALL_ACCESS, KEY_CREATE_SUB_KEY,
    KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
    REG_CREATED_NEW_KEY, REG_OPTION_NON_VOLATILE, REG_OPTION_OPEN_LINK, REG_OPTION_VOLATILE,
    RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegGetKeySecurity, RegOpenKeyExW, RegQueryInfoKeyW,
    RegQueryValueExW,
};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::format::RawValue;

const MAX_KEY_NAME_WIDE: usize = 255;
const MAX_VALUE_NAME_WIDE: usize = 16_383;
const MAX_REGISTRY_VALUE_BYTES: u32 = 1_048_576;
const MAX_KEY_ENTRIES: u32 = 32_768;
const MAX_SECURITY_BYTES: u32 = 262_144;
const TRANSACTION_TIMEOUT_MS: u32 = 30_000;
const RECOVERY_KEY: &str = "UninstallAny.RegistryRecovery";
const RECOVERY_KEY_READ: u32 = READ_CONTROL | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS;
const LOCAL_SYSTEM_SID: &str = "S-1-5-18";

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

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: This owns only memory returned by APIs specifying LocalFree.
        unsafe { LocalFree(self.0) };
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
        RegistryHive::CurrentUser => Some(open_user_hive(&user_sid()?)?),
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

pub(super) fn open_launch_parent(access: u32) -> io::Result<Key> {
    let inspect = KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS;
    // HKCU Software is shared between WOW64 views. Open the SID explicitly
    // because RegOpenCurrentUser can use the default hive if it is unloaded.
    let user = open_child(HKEY_USERS, &user_sid()?, inspect, None)?;
    if query(&user, "SymbolicLinkValue")?.is_some() {
        return Err(invalid("the current user hive is a registry alias"));
    }
    let software = open_relative_leaf(&user, "Software", access | inspect)?
        .ok_or_else(|| invalid("the current user Software key is missing"))?;
    if query(&software, "SymbolicLinkValue")?.is_some() {
        return Err(invalid("the current user Software key is a registry alias"));
    }
    Ok(software)
}

pub(super) fn open_relative_leaf(parent: &Key, leaf: &str, access: u32) -> io::Result<Option<Key>> {
    let mut words = leaf_name(leaf)?;
    let name = unicode(&mut words);
    let attributes = attributes(parent.0, &name);
    open_native_key(&attributes, access, None)
}

fn open_native_key(
    attributes: &OBJECT_ATTRIBUTES,
    access: u32,
    transaction: Option<&Transaction>,
) -> io::Result<Option<Key>> {
    let mut opened = null_mut();
    // SAFETY: The validated name, optional handles and output remain live.
    // Open the link itself if this address names a registry symbolic link.
    let status = unsafe {
        match transaction {
            Some(transaction) => NtOpenKeyTransactedEx(
                &mut opened,
                access,
                attributes,
                REG_OPTION_OPEN_LINK,
                transaction.handle.0,
            ),
            None => NtOpenKeyEx(&mut opened, access, attributes, REG_OPTION_OPEN_LINK),
        }
    };
    if status == STATUS_OBJECT_NAME_NOT_FOUND {
        return Ok(None);
    }
    ntstatus(status)?;
    Ok(Some(Key(opened)))
}

/// Opens the private receipt key for lookup, or for writing in the given transaction.
pub(super) fn open_recovery_key(transaction: Option<&Transaction>) -> io::Result<Option<Key>> {
    let user = user_sid()?;
    let parent = open_recovery_parent(&user, 0)?;
    let mut words = leaf_name(RECOVERY_KEY)?;
    let name = unicode(&mut words);
    let attributes = attributes(parent.0, &name);
    let access = RECOVERY_KEY_READ | transaction.map_or(0, |_| KEY_SET_VALUE);
    let Some(key) = open_native_key(&attributes, access, transaction)? else {
        return Ok(None);
    };
    verify_recovery_key(&key, &user)?;
    Ok(Some(key))
}

/// Ensures a protected receipt key exists before starting an approved target transaction.
pub(super) fn ensure_recovery_key() -> io::Result<()> {
    let user = user_sid()?;
    let parent = open_recovery_parent(&user, KEY_CREATE_SUB_KEY)?;
    let sddl = wide(&format!("O:{user}D:P(A;;KA;;;{user})(A;;KA;;;SY)"));
    let mut descriptor = null_mut();
    // SAFETY: The SDDL input is terminated and the descriptor out pointer is writable.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let descriptor = LocalAllocation(descriptor);
    let mut words = leaf_name(RECOVERY_KEY)?;
    let name = unicode(&mut words);
    let mut attributes = attributes(parent.0, &name);
    attributes.SecurityDescriptor = descriptor.0.cast();
    let mut opened = null_mut();
    // SAFETY: The parent and all buffers stay live through the relative create.
    // Windows applies creation options only to a newly created key. An existing
    // key must pass the same validation and is never reconfigured here.
    ntstatus(unsafe {
        NtCreateKey(
            &mut opened,
            RECOVERY_KEY_READ,
            &attributes,
            0,
            null(),
            REG_OPTION_NON_VOLATILE,
            null_mut(),
        )
    })?;
    verify_recovery_key(&Key(opened), &user)
}

fn open_user_hive(user: &str) -> io::Result<Key> {
    let inspect = KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS;
    // This is the supplied process SID in the kernel HKU namespace. A missing
    // hive is an error and cannot fall back to the default profile.
    let mut words = wide(&format!(r"\Registry\User\{user}"));
    let name = unicode(&mut words);
    let attributes = attributes(null_mut(), &name);
    let user = open_native_key(&attributes, inspect, None)?
        .ok_or_else(|| invalid("the process user registry hive is missing"))?;
    if query(&user, "SymbolicLinkValue")?.is_some() {
        return Err(invalid("the process user registry hive is an alias"));
    }
    Ok(user)
}

fn open_recovery_parent(user: &str, access: u32) -> io::Result<Key> {
    let inspect = KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS;
    let user = open_user_hive(user)?;
    let software = open_relative_leaf(&user, "Software", access | inspect)?
        .ok_or_else(|| invalid("the process user Software key is missing"))?;
    if query(&software, "SymbolicLinkValue")?.is_some() {
        return Err(invalid("the registry recovery parent is an alias"));
    }
    Ok(software)
}

fn verify_recovery_key(key: &Key, user: &str) -> io::Result<()> {
    let info = key_info(key)?;
    if info.subkeys != 0 || !info.class.is_empty() || query(key, "SymbolicLinkValue")?.is_some() {
        return Err(invalid("the registry recovery key is not a plain leaf"));
    }
    let (mut owner, mut acl, mut descriptor) = (null_mut(), null_mut(), null_mut());
    // SAFETY: The opened key remains live and the requested outputs are writable.
    let result = unsafe {
        GetSecurityInfo(
            key.0,
            SE_REGISTRY_KEY,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut descriptor,
        )
    };
    status(result)?;
    let descriptor = LocalAllocation(descriptor);
    if owner.is_null() || acl.is_null() || descriptor.0.is_null() || sid_string(owner)? != user {
        return Err(invalid(
            "the registry recovery key has an unexpected owner or ACL",
        ));
    }
    let (mut control, mut revision) = (0, 0);
    // SAFETY: The Windows-owned descriptor remains live and outputs are writable.
    if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if control & SE_DACL_PROTECTED == 0 {
        return Err(invalid("the registry recovery key inherits permissions"));
    }
    let mut expected = [Some(user), Some(LOCAL_SYSTEM_SID)];
    let mut info = ACL_SIZE_INFORMATION::default();
    // SAFETY: The ACL is owned by the descriptor and the output matches the class.
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
    if info.AceCount != expected.len() as u32 {
        return Err(invalid("the registry recovery key has an unexpected ACL"));
    }
    for index in 0..info.AceCount {
        let mut entry = null_mut();
        // SAFETY: The index is bounded by the ACL information and the output is writable.
        if unsafe { GetAce(acl, index, &mut entry) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: An ACE returned by Windows starts with a live ACE_HEADER.
        let header = unsafe { &*entry.cast::<ACE_HEADER>() };
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
            || header.AceFlags != 0
            || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(invalid("the registry recovery key has an unexpected ACE"));
        }
        // SAFETY: We checked the ACE kind and size before reading its allowed fields.
        let mask = unsafe { (*entry.cast::<ACCESS_ALLOWED_ACE>()).Mask };
        if mask != KEY_ALL_ACCESS {
            return Err(invalid(
                "the registry recovery key has unexpected access rights",
            ));
        }
        // SAFETY: SidStart marks the contained SID of the validated allow ACE.
        let sid = unsafe {
            entry
                .cast::<u8>()
                .add(offset_of!(ACCESS_ALLOWED_ACE, SidStart))
                .cast()
        };
        let principal = sid_string(sid)?;
        let Some(expected) = expected
            .iter_mut()
            .find(|candidate| **candidate == Some(principal.as_str()))
        else {
            return Err(invalid(
                "the registry recovery key grants unexpected access",
            ));
        };
        *expected = None;
    }
    Ok(())
}

pub(super) fn create_volatile_leaf(parent: &Key, leaf: &str, access: u32) -> io::Result<Key> {
    let mut words = leaf_name(leaf)?;
    let name = unicode(&mut words);
    let attributes = attributes(parent.0, &name);
    let mut opened = null_mut();
    let mut disposition = 0;
    // SAFETY: The single-component name and output pointers remain live.
    // The relative parent is already open and OBJ_DONT_REPARSE rejects links.
    ntstatus(unsafe {
        NtCreateKey(
            &mut opened,
            access,
            &attributes,
            0,
            null(),
            REG_OPTION_VOLATILE,
            &mut disposition,
        )
    })?;
    let key = Key(opened);
    if disposition != REG_CREATED_NEW_KEY {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "a Windows uninstall launch marker already exists",
        ));
    }
    Ok(key)
}

fn leaf_name(leaf: &str) -> io::Result<Vec<u16>> {
    if path_components(leaf)?.count() != 1 {
        return Err(invalid("expected a single relative registry key component"));
    }
    Ok(wide(leaf))
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
    pub values: u32,
    pub modified: u64,
}

pub(super) fn key_info(key: &Key) -> io::Result<KeyInfo> {
    let mut class = [0; MAX_KEY_NAME_WIDE + 1];
    let mut class_size = class.len() as u32;
    let mut subkeys = 0;
    let mut values = 0;
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
            &mut values,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut modified,
        )
    })?;
    Ok(KeyInfo {
        class: class[..class_size as usize].to_vec(),
        subkeys,
        values,
        modified: u64::from(modified.dwHighDateTime) << 32 | u64::from(modified.dwLowDateTime),
    })
}

pub(super) fn subkeys(key: &Key) -> io::Result<Vec<String>> {
    // One of the existing enumeration calls is reserved to detect the end.
    subkeys_with_limit(key, MAX_KEY_ENTRIES - 1)
}

/// Reads every child name up to the given count, rejecting incomplete results.
pub(super) fn subkeys_with_limit(key: &Key, limit: u32) -> io::Result<Vec<String>> {
    let limit = limit.min(MAX_KEY_ENTRIES - 1);
    let mut names = Vec::new();
    let mut name = [0; MAX_KEY_NAME_WIDE + 1];
    for index in 0..=limit {
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
        if index == limit {
            break;
        }
        names.push(String::from_utf16(&name[..name_size as usize]).map_err(io::Error::other)?);
    }
    Err(invalid("too many registry subkeys to verify"))
}

pub(super) fn value_names(key: &Key) -> io::Result<Vec<String>> {
    value_names_with_limit(key, MAX_KEY_ENTRIES - 1)
}

/// Reads every value name up to the given count, rejecting incomplete results.
pub(super) fn value_names_with_limit(key: &Key, limit: u32) -> io::Result<Vec<String>> {
    let limit = limit.min(MAX_KEY_ENTRIES - 1);
    let mut names = Vec::new();
    let mut name = vec![0; MAX_VALUE_NAME_WIDE + 1];
    for index in 0..=limit {
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
        if index == limit {
            break;
        }
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
    // SAFETY: The successful TokenUser query wrote a TOKEN_USER in the buffer
    // followed by the SID that its User.Sid points to.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    sid_string(sid)
}

fn sid_string(sid: PSID) -> io::Result<String> {
    let mut text = null_mut();
    // SAFETY: The SID belongs to a live Windows response and text is writable.
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
