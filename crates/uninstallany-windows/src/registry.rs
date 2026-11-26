mod format;
mod native;

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uninstallany_core::{
    Access, Cancellation, Inspection, RegistryHive, RegistryTarget, RegistryView,
    is_protected_registry_target,
};
use windows_sys::Wdk::System::Registry::NtDeleteKey;
use windows_sys::Win32::Security::{
    BACKUP_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{DELETE, READ_CONTROL};
use windows_sys::Win32::System::Registry::{
    KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_EXPAND_SZ,
    REG_SZ, RegDeleteValueW, RegSetValueExW,
};
use windows_sys::Win32::System::SystemInformation::{
    GetNativeSystemInfo, PROCESSOR_ARCHITECTURE_AMD64, PROCESSOR_ARCHITECTURE_ARM64, SYSTEM_INFO,
};
use windows_sys::Win32::System::SystemServices::ACCESS_SYSTEM_SECURITY;

use self::format::RawValue;
use self::native::{Key, Transaction};
use super::files::native::LocalPath;
use super::uninstall::{ExecutableIdentity, pin_startup_executable};

pub(crate) const UNINSTALL_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
pub(crate) const STARTUP_KEYS: [&str; 2] = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
];
const SNAPSHOT_VERSION: u8 = 1;
const MAX_BACKUP_DATA_BYTES: usize = 4 * 1024 * 1024;
const MAX_SNAPSHOT_BYTES: usize = MAX_BACKUP_DATA_BYTES * 4 + 1024 * 1024;
const MAX_STARTUP_COMMAND_UNITS: usize = 260;
const READ_VALUES: u32 = KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS;
const READ_SECURITY: u32 = READ_CONTROL | ACCESS_SYSTEM_SECURITY;
const VALUE_PARENT_SECURITY: u32 =
    OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;

#[derive(Debug)]
pub(crate) struct InstalledEntry {
    pub address: RegistryTarget,
    pub display_name: String,
    pub display_version: Option<String>,
    pub publisher: Option<String>,
    pub install_location: Option<String>,
    pub uninstall_string: Option<String>,
    pub quiet_uninstall_string: Option<String>,
    pub estimated_size_kib: Option<u32>,
    pub install_date: Option<String>,
    pub windows_installer: bool,
    pub system_component: bool,
    pub no_remove: bool,
}

#[derive(Debug, Default)]
pub(crate) struct Inventory {
    pub entries: Vec<InstalledEntry>,
    pub warnings: Vec<String>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

pub(crate) fn machine_views() -> &'static [RegistryView] {
    let mut info = SYSTEM_INFO::default();
    // SAFETY: info is a live, writable SYSTEM_INFO output. The architecture
    // comes from the documented native-architecture union field.
    let architecture = unsafe {
        GetNativeSystemInfo(&mut info);
        info.Anonymous.Anonymous.wProcessorArchitecture
    };
    if matches!(
        architecture,
        PROCESSOR_ARCHITECTURE_AMD64 | PROCESSOR_ARCHITECTURE_ARM64
    ) {
        &[RegistryView::Registry64, RegistryView::Registry32]
    } else {
        &[RegistryView::Native]
    }
}

pub(crate) fn current_user_sid() -> io::Result<String> {
    native::user_sid()
}

pub(crate) fn enumerate_uninstall(cancel: &Cancellation) -> uninstallany_core::Result<Inventory> {
    let mut inventory = Inventory::default();
    // HKCU's Uninstall tree is shared by the WOW views on Windows 10 and 11.
    // It is read once to preserve one stable identity for a per-user entry.
    let sources = [(RegistryHive::CurrentUser, RegistryView::Native)]
        .into_iter()
        .chain(
            machine_views()
                .iter()
                .copied()
                .map(|view| (RegistryHive::LocalMachine, view)),
        );
    for (hive, view) in sources {
        cancel.check()?;
        let parent = RegistryTarget {
            hive,
            view,
            key: UNINSTALL_KEY.to_string(),
            value: None,
        };
        let names = match subkeys(&parent) {
            Ok(names) => names,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                inventory
                    .warnings
                    .push(format!("Read {hive:?}/{view:?}/{UNINSTALL_KEY}: {error}"));
                continue;
            }
        };
        for name in names {
            cancel.check()?;
            let entry = RegistryTarget {
                key: format!("{UNINSTALL_KEY}\\{name}"),
                ..parent.clone()
            };
            match installed_entry(&entry) {
                Ok(Some(entry)) => inventory.entries.push(entry),
                Ok(None) => {}
                Err(error) => inventory
                    .warnings
                    .push(format!("Read {hive:?}/{view:?}/{}: {error}", entry.key)),
            }
        }
    }
    inventory
        .entries
        .sort_by(|left, right| left.display_name.cmp(&right.display_name));
    Ok(inventory)
}

pub(crate) fn uninstall_key_present(target: &RegistryTarget) -> io::Result<bool> {
    if target.value.is_some() || !is_uninstall_leaf(&target.key) {
        return Err(invalid(
            "registry address is outside the Uninstall inventory",
        ));
    }
    match native::open(target, KEY_QUERY_VALUE, None) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

pub(super) fn installed_entry(target: &RegistryTarget) -> io::Result<Option<InstalledEntry>> {
    if target.value.is_some() || !is_uninstall_leaf(&target.key) {
        return Err(invalid(
            "registry address is outside the Uninstall inventory",
        ));
    }
    let key = match native::open(target, KEY_QUERY_VALUE, None) {
        Ok(key) => key,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let Some(display_name) = query_string(&key, "DisplayName")? else {
        return Ok(None);
    };
    Ok(Some(InstalledEntry {
        address: target.clone(),
        display_name,
        display_version: query_string(&key, "DisplayVersion")?,
        publisher: query_string(&key, "Publisher")?,
        install_location: query_string(&key, "InstallLocation")?,
        uninstall_string: query_string(&key, "UninstallString")?,
        quiet_uninstall_string: query_string(&key, "QuietUninstallString")?,
        estimated_size_kib: query_dword(&key, "EstimatedSize")?,
        install_date: query_string(&key, "InstallDate")?,
        windows_installer: query_dword(&key, "WindowsInstaller")? == Some(1),
        system_component: query_dword(&key, "SystemComponent")? == Some(1),
        no_remove: native::query(&key, "NoRemove")?.is_some_and(|value| value.dword() != Some(0)),
    }))
}

fn query_string(key: &Key, name: &str) -> io::Result<Option<String>> {
    Ok(native::query(key, name)?.and_then(|value| raw_string(&value)))
}

fn raw_string(value: &RawValue) -> Option<String> {
    if !matches!(value.kind, REG_SZ | REG_EXPAND_SZ) {
        return None;
    }
    value.string().filter(|text| !text.trim().is_empty())
}

fn query_dword(key: &Key, name: &str) -> io::Result<Option<u32>> {
    Ok(native::query(key, name)?.and_then(|value| value.dword()))
}

pub(crate) fn subkeys(target: &RegistryTarget) -> io::Result<Vec<String>> {
    let key = native::open(target, READ_VALUES, None)?;
    native::subkeys(&key)
}

pub(crate) fn value_names(target: &RegistryTarget) -> io::Result<Vec<String>> {
    let key = native::open(target, READ_VALUES, None)?;
    native::value_names(&key)
}

pub(crate) fn string_value(target: &RegistryTarget) -> io::Result<Option<String>> {
    let name = target
        .value
        .as_deref()
        .ok_or_else(|| invalid("expected a registry value name"))?;
    if !format::valid_value_name(name) {
        return Err(invalid("invalid registry value name"));
    }
    let key = native::open(target, KEY_QUERY_VALUE, None)?;
    query_string(&key, name)
}

/// The direct executable and exact native snapshot fingerprint observed together.
pub(crate) struct StartupValue {
    pub(crate) executable: PathBuf,
    pub(crate) fingerprint: String,
}

/// Reads a startup value eligible for further attribution to an application.
pub(crate) fn startup_value(target: &RegistryTarget) -> io::Result<Option<StartupValue>> {
    let Some(WriteScope::StartupValue) = write_scope(target) else {
        return Ok(None);
    };
    let scope = WriteScope::StartupValue;
    let key = native::open(target, snapshot_read_access(scope), None)?;
    let snapshot = match read_snapshot(&key, target, scope) {
        Ok(snapshot) => snapshot,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return Ok(None),
        Err(error) => return Err(error),
    };
    Ok(Some(StartupValue {
        executable: startup_snapshot_program(&snapshot)?,
        fingerprint: fingerprint(&snapshot)?,
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriteScope {
    AppValue,
    StartupValue,
    AppLeaf,
    UninstallLeaf,
}

impl WriteScope {
    fn single_value(self) -> bool {
        matches!(self, Self::AppValue | Self::StartupValue)
    }
}

fn write_scope(target: &RegistryTarget) -> Option<WriteScope> {
    let parts: Vec<_> = native::path_components(&target.key).ok()?.collect();
    if target.hive != RegistryHive::CurrentUser
        || target.view != RegistryView::Native
        || is_protected_registry_target(target)
    {
        return None;
    }
    if STARTUP_KEYS
        .iter()
        .any(|key| target.key.eq_ignore_ascii_case(key))
    {
        // This excludes the default value and RunOnce execution prefix options.
        return target
            .value
            .as_deref()
            .filter(|name| app_segment(name))
            .map(|_| WriteScope::StartupValue);
    }
    if is_uninstall_leaf(&target.key) && target.value.is_none() && app_segment(parts.last()?) {
        return Some(WriteScope::UninstallLeaf);
    }
    let [software, vendor, product] = parts.as_slice() else {
        return None;
    };
    if !software.eq_ignore_ascii_case("Software") || !app_segment(vendor) || !app_segment(product) {
        return None;
    }
    match target.value.as_deref() {
        None => Some(WriteScope::AppLeaf),
        Some(name) if format::valid_value_name(name) => Some(WriteScope::AppValue),
        Some(_) => None,
    }
}

fn startup_program(value: &RawValue) -> Option<PathBuf> {
    let command = format::exact_string(value)?;
    if command.encode_utf16().count() > MAX_STARTUP_COMMAND_UNITS || command.contains('%') {
        return None;
    }
    let program = if let Some(quoted) = command.strip_prefix('"') {
        quoted.strip_suffix('"')?
    } else {
        // An unquoted command with whitespace could launch a different executable.
        if command.chars().any(char::is_whitespace) {
            return None;
        }
        &command
    };
    let path = Path::new(program);
    if program.ends_with(['\\', '/'])
        || !path
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
    {
        return None;
    }
    LocalPath::parse(path).ok()?;
    Some(path.to_path_buf())
}

fn is_uninstall_leaf(key: &str) -> bool {
    key.rsplit_once('\\').is_some_and(|(parent, leaf)| {
        parent.eq_ignore_ascii_case(UNINSTALL_KEY) && !leaf.is_empty()
    })
}

fn app_segment(segment: &str) -> bool {
    const RESERVED: &[&str] = &[
        "app",
        "application",
        "applications",
        "classes",
        "clients",
        "common",
        "data",
        "default",
        "driver",
        "drivers",
        "installer",
        "microsoft",
        "policies",
        "program",
        "programs",
        "settings",
        "shared",
        "system",
        "uninstall",
        "update",
        "updater",
        "updates",
        "windows",
        "wow6432node",
        "wowaa32node",
    ];
    let normalized = segment.trim().to_ascii_lowercase();
    segment.trim() == segment
        && normalized.bytes().filter(u8::is_ascii_alphanumeric).count() >= 3
        && normalized
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_. {}()".contains(&byte))
        && !RESERVED.contains(&normalized.as_str())
        && !normalized.starts_with("microsoft")
        && !normalized.starts_with("windows")
}

fn third_party_uninstall(values: &BTreeMap<String, RawValue>) -> bool {
    let get = |name: &str| {
        values
            .iter()
            .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value))
    };
    let Some(publisher) = get("Publisher").and_then(raw_string) else {
        return false;
    };
    if !app_segment(publisher.trim()) || get("DisplayName").and_then(raw_string).is_none() {
        return false;
    }
    ["SystemComponent", "WindowsInstaller", "NoRemove"]
        .into_iter()
        .all(|name| get(name).is_none_or(|value| value.dword() == Some(0)))
        && get("ParentKeyName").is_none()
        && get("ReleaseType").is_none()
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct Snapshot {
    version: u8,
    target: RegistryTarget,
    user_sid: String,
    modified: Option<u64>,
    class: Vec<u16>,
    security: Vec<u8>,
    values: BTreeMap<String, RawValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    startup_executable: Option<ExecutableIdentity>,
}

fn startup_snapshot_program(snapshot: &Snapshot) -> io::Result<PathBuf> {
    snapshot
        .values
        .values()
        .next()
        .and_then(startup_program)
        .ok_or_else(|| invalid("startup snapshot has no direct executable"))
}

fn fingerprint(snapshot: &Snapshot) -> io::Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(snapshot).map_err(io::Error::other)?)
    ))
}

fn read_values(key: &Key) -> io::Result<BTreeMap<String, RawValue>> {
    let mut values = BTreeMap::new();
    let mut size = 0;
    for name in native::value_names(key)? {
        let Some(value) = native::query(key, &name)? else {
            return Err(invalid("registry data changed during the snapshot"));
        };
        if !value.can_export() || !format::valid_value_name(&name) {
            return Err(invalid(
                "registry target holds a value that cannot be backed up exactly",
            ));
        }
        size += name.len() + value.data.len();
        if size > MAX_BACKUP_DATA_BYTES || values.insert(name, value).is_some() {
            return Err(invalid(
                "registry snapshot is too large or was changed during reading",
            ));
        }
    }
    Ok(values)
}

fn read_snapshot(key: &Key, target: &RegistryTarget, scope: WriteScope) -> io::Result<Snapshot> {
    let info = native::key_info(key)?;
    let (security, values) = if scope.single_value() {
        let name = target
            .value
            .as_deref()
            .ok_or_else(|| invalid("expected an exact value name"))?;
        let value = read_exact_value(key, name)?;
        if scope == WriteScope::StartupValue && startup_program(&value).is_none() {
            return Err(denied("startup value does not name one literal executable"));
        }
        (
            native::security(key, VALUE_PARENT_SECURITY)?,
            BTreeMap::from([(name.to_string(), value)]),
        )
    } else {
        if info.subkeys != 0 {
            return Err(denied(
                "registry key contains subkeys; recursive deletion is prohibited",
            ));
        }
        let values = read_values(key)?;
        if scope == WriteScope::UninstallLeaf && !third_party_uninstall(&values) {
            return Err(denied(
                "uninstall record is managed, system-owned, or lacks third-party evidence",
            ));
        }
        (native::security(key, BACKUP_SECURITY_INFORMATION)?, values)
    };
    if native::key_info(key)? != info {
        return Err(invalid("registry key changed during the snapshot"));
    }
    Ok(Snapshot {
        version: SNAPSHOT_VERSION,
        target: target.clone(),
        user_sid: native::user_sid()?,
        // A change to a sibling value is not a change to the selected value.
        // The key timestamp is still checked around each individual read.
        modified: (!scope.single_value()).then_some(info.modified),
        class: info.class,
        security,
        values,
        startup_executable: None,
    })
}

fn read_exact_value(key: &Key, name: &str) -> io::Result<RawValue> {
    if !native::value_names(key)?
        .iter()
        .any(|candidate| candidate == name)
    {
        return Err(invalid("registry value missing or renamed"));
    }
    let value = native::query(key, name)?.ok_or_else(|| invalid("registry value disappeared"))?;
    if !value.can_export() {
        return Err(invalid("registry value cannot be backed up exactly"));
    }
    Ok(value)
}

fn snapshot_read_access(scope: WriteScope) -> u32 {
    if scope.single_value() {
        READ_VALUES | READ_CONTROL
    } else {
        READ_VALUES | READ_SECURITY
    }
}

pub(crate) fn inspect(target: &RegistryTarget) -> io::Result<Inspection> {
    let Some(scope) = write_scope(target) else {
        return readonly_inspection(
            target,
            "registry object is outside the writable current-user scope",
        );
    };
    let snapshot = native::open(target, snapshot_read_access(scope), None)
        .and_then(|key| read_snapshot(&key, target, scope));
    match snapshot {
        Ok(snapshot) => Ok(Inspection {
            fingerprint: fingerprint(&snapshot)?,
            access: Access::Allowed,
        }),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => readonly_inspection(
            target,
            &format!("exact registry backup or write scope unavailable: {error}"),
        ),
        Err(error) => Err(error),
    }
}

fn readonly_inspection(target: &RegistryTarget, reason: &str) -> io::Result<Inspection> {
    let key = native::open(target, READ_VALUES, None)?;
    let info = native::key_info(&key)?;
    let value = if let Some(name) = target.value.as_deref() {
        if !format::valid_value_name(name) {
            return Err(invalid("invalid registry value name"));
        }
        let Some(value) = native::query(&key, name)? else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "registry value is no longer present",
            ));
        };
        Some(value)
    } else {
        None
    };
    let encoding = serde_json::to_vec(&(target, info.modified, value)).map_err(io::Error::other)?;
    Ok(Inspection {
        fingerprint: format!("{:x}", Sha256::digest(encoding)),
        access: Access::ReadOnly(reason.to_string()),
    })
}

pub(crate) fn remove(
    target: &RegistryTarget,
    expected: &str,
    backup: impl FnOnce(&[u8], &[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let scope =
        write_scope(target).ok_or_else(|| denied("registry target is outside the write policy"))?;
    let transaction = Transaction::new()?;
    let change_access = if scope.single_value() {
        KEY_SET_VALUE
    } else {
        DELETE
    };
    let access = snapshot_read_access(scope);
    let key = native::open(target, access | change_access, Some(&transaction))?;
    let mut snapshot = read_snapshot(&key, target, scope)?;
    if fingerprint(&snapshot)? != expected {
        return Err(invalid("registry target changed since dry-run"));
    }
    let _pinned_startup = if scope == WriteScope::StartupValue {
        // The registry bytes are already bound to confirmation. Preserve the
        // current image identity in the private backup for safe replay.
        let (pinned, identity) = pin_startup_executable(&startup_snapshot_program(&snapshot)?)?;
        snapshot.startup_executable = Some(identity);
        Some(pinned)
    } else {
        None
    };
    let reg = format::export(
        "HKEY_CURRENT_USER",
        "shared current user",
        &target.key,
        &snapshot.values,
    )?;
    let encoded = serde_json::to_vec(&snapshot).map_err(io::Error::other)?;
    backup(&reg, &encoded)?;

    if let Some(name) = target.value.as_deref() {
        let name = native::wide(name);
        // SAFETY: name is NUL-terminated and key is a verified transacted
        // handle to this exact registry key.
        native::status(unsafe { RegDeleteValueW(key.0, name.as_ptr()) })?;
    } else {
        // SAFETY: NtDeleteKey acts on the anchored, transacted, no-follow
        // handle and refuses an object with subkeys.
        native::ntstatus(unsafe { NtDeleteKey(key.0) })?;
    }
    // TxR exposes committed state to independent readers. Check it after
    // staging the exact write to detect changes between backup and staging.
    // A later conflicting write must abort the transaction before commit.
    let committed_key = native::open(target, access, None)?;
    if fingerprint(&read_snapshot(&committed_key, target, scope)?)? != expected {
        return Err(invalid(
            "a concurrent registry change invalidated the backup",
        ));
    }
    transaction.commit()
}

pub(crate) fn restore(target: &RegistryTarget, bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(invalid("registry backup exceeds the supported size"));
    }
    let scope =
        write_scope(target).ok_or_else(|| denied("backup target is outside the write policy"))?;
    let snapshot: Snapshot = serde_json::from_slice(bytes).map_err(io::Error::other)?;
    validate_snapshot(target, scope, &snapshot)?;
    let _pinned_startup = if let Some(expected) = &snapshot.startup_executable {
        // Hold the verified file without write or delete sharing through commit.
        let (pinned, current) = pin_startup_executable(&startup_snapshot_program(&snapshot)?)?;
        if &current != expected {
            return Err(invalid("startup executable changed since the backup"));
        }
        Some(pinned)
    } else {
        None
    };
    let transaction = Transaction::new()?;
    if scope.single_value() {
        restore_value(&snapshot, &transaction)?;
    } else {
        restore_leaf(&snapshot, &transaction)?;
    }
    transaction.commit()
}

fn validate_snapshot(
    target: &RegistryTarget,
    scope: WriteScope,
    snapshot: &Snapshot,
) -> io::Result<()> {
    if snapshot.version != SNAPSHOT_VERSION
        || snapshot.target != *target
        || snapshot.user_sid != native::user_sid()?
    {
        return Err(invalid(
            "registry backup does not belong to this exact target and Windows user",
        ));
    }
    if snapshot.startup_executable.is_some() != (scope == WriteScope::StartupValue) {
        return Err(invalid(
            "startup executable identity does not match the backup scope",
        ));
    }
    if snapshot
        .values
        .iter()
        .any(|(name, value)| !format::valid_value_name(name) || !value.can_export())
    {
        return Err(invalid("registry backup contains an unsupported value"));
    }
    match scope {
        WriteScope::AppValue | WriteScope::StartupValue => {
            let selected = target
                .value
                .as_ref()
                .and_then(|name| snapshot.values.get(name));
            if snapshot.values.len() != 1 || selected.is_none() {
                return Err(invalid(
                    "registry backup has values outside the exact approved target",
                ));
            }
            if scope == WriteScope::StartupValue && selected.and_then(startup_program).is_none() {
                return Err(invalid(
                    "startup backup does not name one literal executable",
                ));
            }
        }
        WriteScope::UninstallLeaf if !third_party_uninstall(&snapshot.values) => {
            return Err(denied(
                "backup is not a removable third-party uninstall record",
            ));
        }
        WriteScope::AppLeaf | WriteScope::UninstallLeaf => {}
    }
    Ok(())
}

fn restore_value(snapshot: &Snapshot, transaction: &Transaction) -> io::Result<()> {
    let target = &snapshot.target;
    let name = target
        .value
        .as_deref()
        .ok_or_else(|| invalid("expected an exact value name"))?;
    let access = snapshot_read_access(WriteScope::AppValue);
    let key = native::open(target, access | KEY_SET_VALUE, Some(transaction))?;
    check_value_destination(&key, name, snapshot)?;
    set_values(&key, &snapshot.values)?;
    let committed_key = native::open(target, access, None)?;
    check_value_destination(&committed_key, name, snapshot)
}

fn check_value_destination(key: &Key, name: &str, snapshot: &Snapshot) -> io::Result<()> {
    let info = native::key_info(key)?;
    if native::query(key, name)?.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "registry value restore conflict",
        ));
    }
    if info.class != snapshot.class
        || native::security(key, VALUE_PARENT_SECURITY)? != snapshot.security
    {
        return Err(invalid("registry parent class or permissions changed"));
    }
    if native::key_info(key)? != info {
        return Err(invalid("registry parent changed during restore checks"));
    }
    Ok(())
}

fn restore_leaf(snapshot: &Snapshot, transaction: &Transaction) -> io::Result<()> {
    let target = &snapshot.target;
    let (parent, leaf) = target
        .key
        .rsplit_once('\\')
        .ok_or_else(|| invalid("missing registry parent"))?;
    let parent = RegistryTarget {
        key: parent.to_string(),
        ..target.clone()
    };
    let parent = native::open(&parent, READ_VALUES | KEY_CREATE_SUB_KEY, Some(transaction))?;
    let security = &snapshot.security;
    let key = native::create_leaf(
        &parent,
        leaf,
        READ_VALUES | READ_SECURITY | KEY_SET_VALUE,
        (&snapshot.class, security),
        transaction,
    )?;
    if native::key_info(&key)?.class != snapshot.class
        || native::security(&key, BACKUP_SECURITY_INFORMATION)? != *security
    {
        return Err(invalid(
            "registry class or security could not be restored exactly",
        ));
    }
    set_values(&key, &snapshot.values)?;
    match native::open(target, READ_VALUES, None) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "registry key restore conflict",
        )),
    }
}

fn set_values(key: &Key, values: &BTreeMap<String, RawValue>) -> io::Result<()> {
    for (name, value) in values {
        let name = native::wide(name);
        let size = u32::try_from(value.data.len()).map_err(io::Error::other)?;
        // SAFETY: The validated name is NUL-terminated and the data buffer is
        // valid for size bytes. The caller owns the live, writable key handle.
        native::status(unsafe {
            RegSetValueExW(
                key.0,
                name.as_ptr(),
                0,
                value.kind,
                value.data.as_ptr(),
                size,
            )
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_string_fixture(text: &str) -> RawValue {
        RawValue {
            kind: REG_SZ,
            data: text
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect(),
        }
    }

    fn user_target(key: &str, value: Option<&str>) -> RegistryTarget {
        RegistryTarget {
            hive: RegistryHive::CurrentUser,
            view: RegistryView::Native,
            key: key.to_string(),
            value: value.map(str::to_string),
        }
    }

    #[test]
    fn write_scope_excludes_system_aliases_and_shared_vendor_keys() {
        for path in [
            r"SYSTEM\CurrentControlSet",
            r"Software\Microsoft\Office",
            r"Software\Classes\Acme",
            r"Software\Acme\Common",
            r"Software\Acme\..",
            r"Software\Wow6432Node\Acme",
            r"Software\Acme",
        ] {
            assert_eq!(
                write_scope(&user_target(path, Some("Enabled"))),
                None,
                "{path}"
            );
        }
        let target = user_target(r"Software\Northstar\Nebula", Some("Enabled"));
        assert_eq!(write_scope(&target), Some(WriteScope::AppValue));
        assert_eq!(
            write_scope(&RegistryTarget {
                hive: RegistryHive::LocalMachine,
                ..target.clone()
            }),
            None
        );
        assert_eq!(
            write_scope(&RegistryTarget {
                view: RegistryView::Registry32,
                ..target
            }),
            None
        );
    }

    #[test]
    fn only_exact_uninstall_leaf_is_considered_for_force_removal() {
        let leaf = format!("{UNINSTALL_KEY}\\Northstar Nebula");
        assert_eq!(
            write_scope(&user_target(&leaf, None)),
            Some(WriteScope::UninstallLeaf)
        );
        assert_eq!(write_scope(&user_target(&leaf, Some("DisplayName"))), None);
        assert_eq!(write_scope(&user_target(UNINSTALL_KEY, None)), None);
        assert_eq!(
            write_scope(&user_target(&format!("{leaf}\\Sub"), None)),
            None
        );
    }

    #[test]
    fn uninstall_evidence_rejects_system_and_managed_records() {
        let mut values = BTreeMap::from([
            ("DISPLAYNAME".to_string(), raw_string_fixture("Nebula")),
            ("publisher".to_string(), raw_string_fixture("Northstar")),
        ]);
        assert!(third_party_uninstall(&values));
        values.insert(
            "SystemComponent".to_string(),
            RawValue {
                kind: windows_sys::Win32::System::Registry::REG_DWORD,
                data: 1_u32.to_le_bytes().to_vec(),
            },
        );
        assert!(!third_party_uninstall(&values));
        values.remove("SystemComponent");
        values.insert(
            "publisher".to_string(),
            raw_string_fixture("Microsoft Corporation"),
        );
        assert!(!third_party_uninstall(&values));
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "writes a random HKCU fixture; run under a standard user in a disposable Windows VM"]
    fn disposable_vm_registry_value_round_trip() -> io::Result<()> {
        if std::env::var("UNINSTALLANY_DISPOSABLE_WINDOWS_VM").as_deref() != Ok("1") {
            return Err(denied(
                "set UNINSTALLANY_DISPOSABLE_WINDOWS_VM=1 only inside the disposable VM",
            ));
        }
        let fixture = format!("UninstallAny Test {}", uuid::Uuid::new_v4());
        let software = native::open(
            &user_target("Software", None),
            READ_VALUES | KEY_CREATE_SUB_KEY,
            None,
        )?;
        let root = FixtureKey::create(software.0, &fixture)?;
        let app = FixtureKey::create(root.0.0, "RoundTrip")?;
        let path = format!(r"Software\{fixture}\RoundTrip");
        let target = user_target(&path, Some("Selected"));
        let sibling = user_target(&path, Some("Sibling"));
        set_values(
            &app.0,
            &BTreeMap::from([
                ("Selected".to_string(), raw_string_fixture("original")),
                ("Sibling".to_string(), raw_string_fixture("unselected")),
            ]),
        )?;

        let initial = inspect(&target)?;
        assert_eq!(initial.access, Access::Allowed);
        let intentionally_failed = remove(&target, &initial.fingerprint, |_, _| {
            assert_eq!(string_value(&target)?.as_deref(), Some("original"));
            Err(io::Error::other("fixture backup intentionally failed"))
        });
        assert!(intentionally_failed.is_err());
        assert_eq!(string_value(&target)?.as_deref(), Some("original"));

        let mut backup = Vec::new();
        remove(&target, &initial.fingerprint, |reg, snapshot| {
            assert_eq!(string_value(&target)?.as_deref(), Some("original"));
            assert!(reg.starts_with(&0xfeff_u16.to_le_bytes()));
            backup.extend_from_slice(snapshot);
            Ok(())
        })?;
        assert_eq!(string_value(&target)?, None);
        assert_eq!(string_value(&sibling)?.as_deref(), Some("unselected"));
        let other_view = RegistryTarget {
            view: RegistryView::Registry32,
            ..target.clone()
        };
        assert!(restore(&other_view, &backup).is_err());
        assert!(restore(&sibling, &backup).is_err());
        assert_eq!(string_value(&target)?, None);
        restore(&target, &backup)?;
        assert_eq!(string_value(&target)?.as_deref(), Some("original"));

        let fresh = inspect(&target)?;
        remove(&target, &fresh.fingerprint, |_, _| Ok(()))?;
        set_values(
            &app.0,
            &BTreeMap::from([("Selected".to_string(), raw_string_fixture("replacement"))]),
        )?;
        assert_eq!(
            restore(&target, &backup).err().map(|error| error.kind()),
            Some(io::ErrorKind::AlreadyExists)
        );
        assert_eq!(string_value(&target)?.as_deref(), Some("replacement"));
        assert_eq!(string_value(&sibling)?.as_deref(), Some("unselected"));
        Ok(())
    }

    #[cfg(windows)]
    struct FixtureKey(Key);

    #[cfg(windows)]
    impl FixtureKey {
        fn create(
            parent: windows_sys::Win32::System::Registry::HKEY,
            name: &str,
        ) -> io::Result<Self> {
            use std::ptr::{null, null_mut};
            use windows_sys::Win32::System::Registry::{
                REG_CREATED_NEW_KEY, REG_OPTION_NON_VOLATILE, RegCreateKeyExW,
            };

            let name = native::wide(name);
            let mut key = null_mut();
            let mut disposition = 0;
            // SAFETY: All pointers are valid for this call and name is scoped
            // to the fresh random fixture under the disposable VM's HKCU.
            native::status(unsafe {
                RegCreateKeyExW(
                    parent,
                    name.as_ptr(),
                    0,
                    null(),
                    REG_OPTION_NON_VOLATILE,
                    READ_VALUES | KEY_CREATE_SUB_KEY | KEY_SET_VALUE | DELETE,
                    null(),
                    &mut key,
                    &mut disposition,
                )
            })?;
            let key = Key(key);
            if disposition != REG_CREATED_NEW_KEY {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "disposable VM registry fixture already exists",
                ));
            }
            Ok(Self(key))
        }
    }

    #[cfg(windows)]
    impl Drop for FixtureKey {
        fn drop(&mut self) {
            // SAFETY: This guard owns only the newly allocated fixture
            // handle. Delete by handle to keep cleanup bound to that identity.
            let status = unsafe { NtDeleteKey(self.0.0) };
            if let Err(error) = native::ntstatus(status) {
                eprintln!(
                    "disposable registry fixture cleanup requires VM snapshot revert: {error}"
                );
            }
        }
    }
}
