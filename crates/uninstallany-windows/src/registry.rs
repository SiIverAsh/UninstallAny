mod format;
mod native;
mod recovery;

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uninstallany_core::{
    Access, Cancellation, Inspection, RegistryChangeReceipt, RegistryHive, RegistryTarget,
    RegistryView, is_current_user_app_path_default_target, is_protected_registry_target,
};
use uuid::Uuid;
use windows_sys::Wdk::System::Registry::NtDeleteKey;
use windows_sys::Win32::Security::{
    BACKUP_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{DELETE, READ_CONTROL};
use windows_sys::Win32::System::Registry::{
    KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_BINARY,
    REG_EXPAND_SZ, REG_SZ, RegDeleteValueW, RegSetValueExW,
};
use windows_sys::Win32::System::SystemInformation::{
    GetNativeSystemInfo, PROCESSOR_ARCHITECTURE_AMD64, PROCESSOR_ARCHITECTURE_ARM64, SYSTEM_INFO,
};
use windows_sys::Win32::System::SystemServices::ACCESS_SYSTEM_SECURITY;

use self::format::RawValue;
use self::native::{Key, Transaction};
use super::files::native::{LocalPath, equal_name};
use super::uninstall::{
    ExecutableIdentity, PinnedExecutable, RegisteredScope, is_system_command_wrapper,
    pin_startup_executable, split_command,
};

pub(crate) const UNINSTALL_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
pub(crate) const STARTUP_KEYS: [&str; 2] = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
];
pub(super) const MAX_NESTED_SETTINGS_DEPTH: usize = 3;
pub(super) const MAX_NESTED_SETTINGS_VALUES: u32 = 512;
const SNAPSHOT_VERSION: u8 = 1;
const MAX_BACKUP_DATA_BYTES: usize = 4 * 1024 * 1024;
const MAX_SNAPSHOT_BYTES: usize = MAX_BACKUP_DATA_BYTES * 4 + 1024 * 1024;
const MAX_STARTUP_COMMAND_UNITS: usize = 260;
const READ_VALUES: u32 = KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS;
const READ_SECURITY: u32 = READ_CONTROL | ACCESS_SYSTEM_SECURITY;
const VALUE_PARENT_SECURITY: u32 =
    OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
// Keep the original marker location and Win32 phase bytes. Older builds
// reject the new phase bytes and therefore cannot bypass a live system wait.
const NATIVE_LAUNCH_KEY: &str = "UninstallAny.PendingWin32Launch";
const NATIVE_LAUNCH_VALUE: &str = "Launch";

#[derive(Clone, Debug)]
pub(crate) struct InstalledEntry {
    pub address: RegistryTarget,
    pub display_name: String,
    pub display_version: Option<String>,
    pub publisher: Option<String>,
    pub install_location: Option<String>,
    pub install_location_absent: bool,
    pub display_icon: Option<String>,
    pub uninstall_string: Option<String>,
    pub quiet_uninstall_string: Option<String>,
    pub estimated_size_kib: Option<u32>,
    pub install_date: Option<String>,
    pub windows_installer: bool,
    pub system_component: bool,
    pub no_remove: bool,
}

impl InstalledEntry {
    pub(super) fn same_uninstall_registration(&self, current: &Self) -> bool {
        self.address == current.address
            && self.display_name == current.display_name
            && self.display_version == current.display_version
            && self.publisher == current.publisher
            && self.install_location == current.install_location
            && self.install_location_absent == current.install_location_absent
            && self.display_icon == current.display_icon
            && self.uninstall_string == current.uninstall_string
            && self.quiet_uninstall_string == current.quiet_uninstall_string
            && self.windows_installer == current.windows_installer
            && self.system_component == current.system_component
            && self.no_remove == current.no_remove
    }
}

#[derive(Debug, Default)]
pub(crate) struct Inventory {
    pub entries: Vec<InstalledEntry>,
    pub warnings: Vec<String>,
    pub(super) path_claims: Vec<InstallPathClaims>,
}

#[derive(Debug)]
pub(super) struct InstallPathClaims {
    pub address: RegistryTarget,
    pub directory: Option<String>,
    pub icon: Option<String>,
    pub uninstall: Option<String>,
    pub quiet_uninstall: Option<String>,
}

#[derive(Clone, Copy)]
enum InventoryScope {
    Display,
    Ownership,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SystemUninstaller {
    DirectMsi,
    ElevatedMsi,
    Msix,
}

impl SystemUninstaller {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::DirectMsi => "Windows Installer",
            Self::ElevatedMsi => "the elevated Windows Installer",
            Self::Msix => "Windows Package Manager",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NativeLaunch {
    Win32 {
        id: Uuid,
        committed: bool,
    },
    System {
        id: Uuid,
        uninstaller: SystemUninstaller,
    },
}

impl NativeLaunch {
    fn payload(self) -> [u8; 17] {
        let (phase, id) = match self {
            Self::Win32 { id, committed } => (u8::from(committed), id),
            Self::System { id, uninstaller } => {
                let phase = match uninstaller {
                    SystemUninstaller::DirectMsi => 2,
                    SystemUninstaller::ElevatedMsi => 3,
                    SystemUninstaller::Msix => 4,
                };
                (phase, id)
            }
        };
        let mut payload = [0; 17];
        payload[0] = phase;
        payload[1..].copy_from_slice(id.as_bytes());
        payload
    }

    fn from_payload(payload: &[u8]) -> Option<Self> {
        let (&phase, bytes) = payload.split_first()?;
        let id = Uuid::from_slice(bytes).ok().filter(|id| !id.is_nil())?;
        match phase {
            0 | 1 => Some(Self::Win32 {
                id,
                committed: phase == 1,
            }),
            2 => Some(Self::System {
                id,
                uninstaller: SystemUninstaller::DirectMsi,
            }),
            3 => Some(Self::System {
                id,
                uninstaller: SystemUninstaller::ElevatedMsi,
            }),
            4 => Some(Self::System {
                id,
                uninstaller: SystemUninstaller::Msix,
            }),
            _ => None,
        }
    }
}

/// Pending system work remains recorded until the caller receives terminal proof.
/// Dropping this token after an error deliberately does not remove the marker.
pub(super) struct SystemUninstallWait(NativeLaunch);

impl SystemUninstallWait {
    /// Reserves a dispatch under the current user's already-held mutation lock.
    pub(super) fn begin(uninstaller: SystemUninstaller) -> io::Result<Self> {
        let launch = NativeLaunch::System {
            id: Uuid::new_v4(),
            uninstaller,
        };
        begin_native_launch(launch)?;
        Ok(Self(launch))
    }

    /// Releases the reservation only for a proven non-dispatch or terminal result.
    pub(super) fn finish(self) -> io::Result<()> {
        clear_native_launch(|observed| observed == self.0)
    }
}

/// Reads the exact pending action in the current user's loaded registry hive.
pub(super) fn pending_native_launch() -> io::Result<Option<NativeLaunch>> {
    open_native_launch(0)?
        .map(|key| read_native_launch(&key))
        .transpose()
}

/// Reports a Win32 marker without treating other providers as a reopenable Job.
pub(super) fn pending_win32_launch() -> io::Result<Option<(Uuid, bool)>> {
    Ok(match pending_native_launch()? {
        Some(NativeLaunch::Win32 { id, committed }) => Some((id, committed)),
        _ => None,
    })
}

/// Records intent before launch. Writers hold the shared mutation lock.
pub(super) fn begin_win32_launch(id: Uuid) -> io::Result<()> {
    if id.is_nil() {
        return Err(invalid("a Win32 uninstall launch must have a non-nil ID"));
    }
    begin_native_launch(NativeLaunch::Win32 {
        id,
        committed: false,
    })
}

/// Records successful process creation against the same launch intent.
pub(super) fn commit_win32_launch(id: Uuid) -> io::Result<()> {
    let key = open_native_launch(KEY_SET_VALUE)?
        .ok_or_else(|| invalid("the Win32 uninstall launch intent is missing"))?;
    let NativeLaunch::Win32 {
        id: current,
        committed,
    } = read_native_launch(&key)?
    else {
        return Err(invalid(
            "the uninstall launch belongs to a different provider",
        ));
    };
    if current != id {
        return Err(invalid("the Win32 uninstall launch marker ID changed"));
    }
    if committed {
        return Ok(());
    }
    write_native_launch(
        &key,
        NativeLaunch::Win32 {
            id,
            committed: true,
        },
    )
}

/// Clears only the matching launch marker while holding the mutation lock.
pub(super) fn clear_win32_launch(id: Uuid) -> io::Result<()> {
    clear_native_launch(
        |launch| matches!(launch, NativeLaunch::Win32 { id: current, .. } if current == id),
    )
}

fn begin_native_launch(launch: NativeLaunch) -> io::Result<()> {
    let parent = native::open_launch_parent(KEY_CREATE_SUB_KEY)?;
    let key = native::create_volatile_leaf(&parent, NATIVE_LAUNCH_KEY, KEY_SET_VALUE)?;
    // Leave an incomplete key in place on failure so later writes fail closed.
    write_native_launch(&key, launch)
}

fn clear_native_launch(matches_launch: impl FnOnce(NativeLaunch) -> bool) -> io::Result<()> {
    let Some(key) = open_native_launch(DELETE)? else {
        return Ok(());
    };
    if !matches_launch(read_native_launch(&key)?) {
        return Err(invalid("the uninstall launch marker identity changed"));
    }
    // SAFETY: The handle is the verified, matching, flat marker key. The
    // native API deletes only this key and refuses keys with child keys.
    native::ntstatus(unsafe { NtDeleteKey(key.0) })
}

fn open_native_launch(access: u32) -> io::Result<Option<Key>> {
    let parent = native::open_launch_parent(0)?;
    native::open_relative_leaf(&parent, NATIVE_LAUNCH_KEY, access | READ_VALUES)
}

fn read_native_launch(key: &Key) -> io::Result<NativeLaunch> {
    let malformed = || invalid("the pending Windows uninstall launch marker is malformed");
    let info = native::key_info(key)?;
    if info.subkeys != 0 || info.values != 1 || !info.class.is_empty() {
        return Err(malformed());
    }
    let value = native::query(key, NATIVE_LAUNCH_VALUE)?.ok_or_else(malformed)?;
    if value.kind != REG_BINARY || native::key_info(key)? != info {
        return Err(malformed());
    }
    NativeLaunch::from_payload(&value.data).ok_or_else(malformed)
}

fn write_native_launch(key: &Key, launch: NativeLaunch) -> io::Result<()> {
    let name = native::wide(NATIVE_LAUNCH_VALUE);
    let payload = launch.payload();
    // SAFETY: The writable marker handle, terminated name and complete
    // fixed-size value remain live throughout the registry call.
    native::status(unsafe {
        RegSetValueExW(
            key.0,
            name.as_ptr(),
            0,
            REG_BINARY,
            payload.as_ptr(),
            payload.len() as u32,
        )
    })
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
    read_inventory(cancel, InventoryScope::Display)
}

/// Reads path evidence from every uninstall key, including entries hidden from the list.
pub(super) fn inventory_for_ownership(
    cancel: &Cancellation,
) -> uninstallany_core::Result<Inventory> {
    read_inventory(cancel, InventoryScope::Ownership)
}

fn read_inventory(
    cancel: &Cancellation,
    scope: InventoryScope,
) -> uninstallany_core::Result<Inventory> {
    let mut inventory = Inventory::default();
    for (hive, view) in uninstall_sources() {
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
            let claims = match scope {
                InventoryScope::Display => None,
                InventoryScope::Ownership => Some(&mut inventory.path_claims),
            };
            match read_uninstall_entry(&entry, claims) {
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

fn uninstall_sources() -> impl Iterator<Item = (RegistryHive, RegistryView)> {
    // HKCU's Uninstall tree is shared by the WOW views on Windows 10 and 11.
    // Use one stable identity for each per-user entry.
    [(RegistryHive::CurrentUser, RegistryView::Native)]
        .into_iter()
        .chain(
            machine_views()
                .iter()
                .copied()
                .map(|view| (RegistryHive::LocalMachine, view)),
        )
}

pub(super) fn lookup_uninstall_entry(
    target: &RegistryTarget,
    cancel: &Cancellation,
) -> uninstallany_core::Result<Option<InstalledEntry>> {
    cancel.check()?;
    let Some((parent, leaf)) = target.key.rsplit_once('\\') else {
        return Ok(None);
    };
    if target.value.is_some()
        || parent != UNINSTALL_KEY
        || !uninstall_sources().any(|source| source == (target.hive, target.view))
    {
        return Ok(None);
    }
    let parent = RegistryTarget {
        key: UNINSTALL_KEY.into(),
        ..target.clone()
    };
    // Windows opens keys without regard to case. Match the catalog's spelling
    // before passing this address to its exact identity and ownership checks.
    let names = match subkeys(&parent) {
        Ok(names) => names,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    cancel.check()?;
    if !names.iter().any(|name| name == leaf) {
        return Ok(None);
    }
    let entry = installed_entry(target)?;
    cancel.check()?;
    Ok(entry)
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
    read_uninstall_entry(target, None)
}

/// A plain third-party uninstall record and its literal executable paths.
pub(super) struct ForceRegistration {
    pub(super) binding: String,
    pub(super) programs: [Option<PathBuf>; 2],
}

/// Reads the same raw record for force-removal review and revalidation.
pub(super) fn force_registration(
    target: &RegistryTarget,
    expected: Option<&InstalledEntry>,
) -> io::Result<Option<ForceRegistration>> {
    if target.value.is_some() || !is_uninstall_leaf(&target.key) {
        return Ok(None);
    }
    let key = native::open(target, READ_VALUES | READ_CONTROL, None)?;
    let info = native::key_info(&key)?;
    let values = read_values(&key)?;
    let security = native::security(&key, VALUE_PARENT_SECURITY)?;
    if native::key_info(&key)? != info {
        return Err(invalid("the uninstall record changed during inspection"));
    }
    if !third_party_uninstall(&values) {
        return Ok(None);
    }
    let Some(programs) = force_programs(&values) else {
        return Ok(None);
    };
    if expected.is_some_and(|entry| !force_registration_matches(&values, entry)) {
        return Ok(None);
    }
    let payload = serde_json::to_vec(&(
        target,
        info.modified,
        info.class,
        info.subkeys,
        security,
        &values,
    ))
    .map_err(io::Error::other)?;
    Ok(Some(ForceRegistration {
        binding: format!("{:x}", Sha256::digest(payload)),
        programs,
    }))
}

fn force_programs(values: &BTreeMap<String, RawValue>) -> Option<[Option<PathBuf>; 2]> {
    let mut programs = [None, None];
    for (name, program) in ["QuietUninstallString", "UninstallString"]
        .into_iter()
        .zip(&mut programs)
    {
        if let Some(value) = named_value(values, name) {
            let literal = format::exact_string(value)?;
            let (path, _) = split_command(&literal).ok()?;
            let path = Path::new(path);
            if is_system_command_wrapper(path) {
                return None;
            }
            *program = Some(path.to_path_buf());
        }
    }
    Some(programs)
}

fn force_registration_matches(values: &BTreeMap<String, RawValue>, entry: &InstalledEntry) -> bool {
    let string = |name| named_value(values, name).and_then(raw_string);
    let location = named_value(values, "InstallLocation");
    string("DisplayName").as_deref() == Some(entry.display_name.as_str())
        && string("DisplayVersion") == entry.display_version
        && string("Publisher") == entry.publisher
        && location.and_then(raw_string) == entry.install_location
        && location.is_none() == entry.install_location_absent
        && string("QuietUninstallString") == entry.quiet_uninstall_string
        && string("UninstallString") == entry.uninstall_string
        && (!entry.install_location_absent
            || named_value(values, "DisplayIcon").and_then(format::exact_string)
                == entry.display_icon)
}

fn read_uninstall_entry(
    target: &RegistryTarget,
    claims: Option<&mut Vec<InstallPathClaims>>,
) -> io::Result<Option<InstalledEntry>> {
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
    let display_name = query_string(&key, "DisplayName")?;
    if display_name.is_none() && claims.is_none() {
        return Ok(None);
    }
    let location = native::query(&key, "InstallLocation")?;
    let install_location = location.as_ref().and_then(raw_string);
    let windows_installer =
        display_name.is_some() && query_dword(&key, "WindowsInstaller")? == Some(1);
    let may_infer_directory =
        location.is_none() && target.hive == RegistryHive::CurrentUser && !windows_installer;
    let icon = if claims.is_some() || may_infer_directory {
        native::query(&key, "DisplayIcon")?
    } else {
        None
    };
    let uninstall_string = query_string(&key, "UninstallString")?;
    let quiet_uninstall_string = query_string(&key, "QuietUninstallString")?;
    if let Some(claims) = claims {
        let referenced_icon = icon.as_ref().and_then(raw_string);
        if install_location.is_some()
            || referenced_icon.is_some()
            || uninstall_string.is_some()
            || quiet_uninstall_string.is_some()
        {
            claims.push(InstallPathClaims {
                address: target.clone(),
                directory: install_location.clone(),
                icon: referenced_icon,
                uninstall: uninstall_string.clone(),
                quiet_uninstall: quiet_uninstall_string.clone(),
            });
        }
    }
    let Some(display_name) = display_name else {
        return Ok(None);
    };
    let display_icon = if may_infer_directory {
        icon.as_ref().and_then(format::exact_string)
    } else {
        None
    };
    Ok(Some(InstalledEntry {
        address: target.clone(),
        display_name,
        display_version: query_string(&key, "DisplayVersion")?,
        publisher: query_string(&key, "Publisher")?,
        install_location,
        install_location_absent: location.is_none(),
        display_icon,
        uninstall_string,
        quiet_uninstall_string,
        estimated_size_kib: query_dword(&key, "EstimatedSize")?,
        install_date: query_string(&key, "InstallDate")?,
        windows_installer,
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

/// Reads only bounded entries from a verified current-user application settings key.
pub(super) fn bounded_app_settings_entries(
    target: &RegistryTarget,
    subkey_limit: Option<u32>,
    value_limit: Option<u32>,
) -> io::Result<(Vec<String>, Vec<String>)> {
    let parts: Vec<_> = native::path_components(&target.key)?.collect();
    if target.value.is_some()
        || !is_writable_current_user_address(target)
        || app_settings_depth(&parts).is_none()
    {
        return Err(denied(
            "registry key is outside the application settings scope",
        ));
    }
    let key = native::open(target, READ_VALUES, None)?;
    let before = native::key_info(&key)?;
    let subkeys = subkey_limit
        .map(|limit| native::subkeys_with_limit(&key, limit))
        .transpose()?
        .unwrap_or_default();
    let values = value_limit
        .map(|limit| native::value_names_with_limit(&key, limit))
        .transpose()?
        .unwrap_or_default();
    if native::key_info(&key)? != before {
        return Err(invalid(
            "the application settings key changed during enumeration",
        ));
    }
    Ok((subkeys, values))
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

/// The exact native registration and executable observed together.
pub(super) struct ExecutableValue {
    pub(super) executable: PathBuf,
    pub(super) fingerprint: String,
}

/// Reads a value and binds its executable only after confirming installation ownership.
pub(super) fn executable_value(
    target: &RegistryTarget,
    registration: &RegisteredScope,
) -> io::Result<Option<ExecutableValue>> {
    let Some(scope) = write_scope(target).filter(|scope| scope.requires_executable()) else {
        return Ok(None);
    };
    if scope == WriteScope::AppPathDefault && !registration.is_former_installation() {
        return Ok(None);
    }
    let key = native::open(target, snapshot_read_access(scope), None)?;
    let mut snapshot = match read_snapshot(&key, target, scope) {
        Ok(snapshot) => snapshot,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return Ok(None),
        Err(error) => return Err(error),
    };
    let executable = snapshot_program(&snapshot, scope)?;
    let Some(identity) = registration.executable_identity(&executable)? else {
        return Ok(None);
    };
    snapshot.executable = Some(identity);
    Ok(Some(ExecutableValue {
        executable,
        fingerprint: fingerprint(&snapshot)?,
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriteScope {
    AppValue,
    NestedAppValue,
    StartupValue,
    AppPathDefault,
    AppLeaf,
    UninstallLeaf,
}

impl WriteScope {
    fn single_value(self) -> bool {
        matches!(
            self,
            Self::AppValue | Self::NestedAppValue | Self::StartupValue | Self::AppPathDefault
        )
    }

    fn requires_executable(self) -> bool {
        matches!(self, Self::StartupValue | Self::AppPathDefault)
    }
}

fn write_scope(target: &RegistryTarget) -> Option<WriteScope> {
    let parts: Vec<_> = native::path_components(&target.key).ok()?.collect();
    if !is_writable_current_user_address(target) {
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
    if is_current_user_app_path_default_target(target) {
        return Some(WriteScope::AppPathDefault);
    }
    if is_uninstall_leaf(&target.key) && target.value.is_none() && app_segment(parts.last()?) {
        return Some(WriteScope::UninstallLeaf);
    }
    match (app_settings_depth(&parts)?, target.value.as_deref()) {
        (0, None) => Some(WriteScope::AppLeaf),
        (0, Some(name)) if format::valid_value_name(name) => Some(WriteScope::AppValue),
        (_, Some(name)) if is_named_app_setting(name) => Some(WriteScope::NestedAppValue),
        _ => None,
    }
}

/// Tests descendant key scope independently of the selected value.
pub(super) fn is_nested_app_settings_key(target: &RegistryTarget) -> bool {
    is_writable_current_user_address(target)
        && native::path_components(&target.key).is_ok_and(|parts| {
            app_settings_depth(&parts.collect::<Vec<_>>()).is_some_and(|depth| depth != 0)
        })
}

fn is_writable_current_user_address(target: &RegistryTarget) -> bool {
    target.hive == RegistryHive::CurrentUser
        && target.view == RegistryView::Native
        && !is_protected_registry_target(target)
}

fn app_settings_depth(parts: &[&str]) -> Option<usize> {
    let [software, vendor, product, descendants @ ..] = parts else {
        return None;
    };
    let in_scope = software.eq_ignore_ascii_case("Software")
        && app_segment(vendor)
        && app_segment(product)
        && descendants.len() <= MAX_NESTED_SETTINGS_DEPTH
        && descendants.iter().all(|part| private_settings_subkey(part));
    in_scope.then_some(descendants.len())
}

fn private_settings_subkey(name: &str) -> bool {
    // A precise app root does not establish ownership of nested shared or
    // system-registration containers. Ordinary settings names remain eligible.
    const PROTECTED: &[&str] = &[
        "app paths",
        "autoload",
        "autorun",
        "clients",
        "common",
        "dependencies",
        "drivers",
        "installer",
        "licensing",
        "run",
        "runonce",
        "services",
        "shared",
        "system",
        "uninstall",
        "updates",
    ];
    !name.contains(['[', ']'])
        && !PROTECTED
            .iter()
            .any(|blocked| name.eq_ignore_ascii_case(blocked))
}

pub(super) fn is_named_app_setting(name: &str) -> bool {
    !name.trim().is_empty() && format::valid_value_name(name)
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

fn app_path_program(target: &RegistryTarget, value: &RawValue) -> Option<PathBuf> {
    let (_, key_name) = target.key.rsplit_once('\\')?;
    let original = format::exact_string(value)?;
    let program = match original.strip_prefix('"') {
        Some(quoted) => quoted.strip_suffix('"')?,
        None => original.as_str(),
    };
    let path = Path::new(program);
    if program.ends_with(['\\', '/'])
        || program.contains(['%', '"'])
        || !path
            .file_name()
            .is_some_and(|name| equal_name(name, OsStr::new(key_name)))
        || is_system_command_wrapper(path)
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

fn named_value<'a>(values: &'a BTreeMap<String, RawValue>, name: &str) -> Option<&'a RawValue> {
    values
        .iter()
        .find_map(|(key, value)| equal_name(OsStr::new(key), OsStr::new(name)).then_some(value))
}

fn third_party_uninstall(values: &BTreeMap<String, RawValue>) -> bool {
    let get = |name| named_value(values, name);
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
    #[serde(
        default,
        rename = "startup_executable",
        skip_serializing_if = "Option::is_none"
    )]
    executable: Option<ExecutableIdentity>,
}

fn snapshot_program(snapshot: &Snapshot, scope: WriteScope) -> io::Result<PathBuf> {
    snapshot
        .values
        .values()
        .next()
        .and_then(|value| match scope {
            WriteScope::StartupValue => startup_program(value),
            WriteScope::AppPathDefault => app_path_program(&snapshot.target, value),
            _ => None,
        })
        .ok_or_else(|| invalid("registry backup has no direct executable"))
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
        if scope == WriteScope::AppPathDefault {
            if info.subkeys != 0 || info.values != 1 {
                return Err(denied("App Paths contains another value or a subkey"));
            }
            require_no_machine_app_path(target)?;
        }
        let value = read_exact_value(key, name, scope)?;
        if scope == WriteScope::StartupValue && startup_program(&value).is_none() {
            return Err(denied("startup value does not name one literal executable"));
        }
        if scope == WriteScope::AppPathDefault && app_path_program(target, &value).is_none() {
            return Err(denied(
                "App Paths default does not name its exact literal executable",
            ));
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
        modified: (!scope.single_value() || scope == WriteScope::AppPathDefault)
            .then_some(info.modified),
        class: info.class,
        security,
        values,
        executable: None,
    })
}

fn require_no_machine_app_path(target: &RegistryTarget) -> io::Result<()> {
    let machine = RegistryTarget {
        hive: RegistryHive::LocalMachine,
        ..target.clone()
    };
    match native::open(&machine, KEY_QUERY_VALUE, None) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(denied(
            "a machine-wide App Paths registration uses this executable name",
        )),
    }
}

fn pin_snapshot_executable(
    snapshot: &mut Snapshot,
    scope: WriteScope,
) -> io::Result<Option<PinnedExecutable>> {
    if !scope.requires_executable() {
        return Ok(None);
    }
    let (image, identity) = pin_startup_executable(&snapshot_program(snapshot, scope)?)?;
    snapshot.executable = Some(identity);
    Ok(Some(image))
}

fn read_exact_value(key: &Key, name: &str, scope: WriteScope) -> io::Result<RawValue> {
    let names = if scope == WriteScope::NestedAppValue {
        native::value_names_with_limit(key, MAX_NESTED_SETTINGS_VALUES)?
    } else {
        native::value_names(key)?
    };
    if !names.iter().any(|candidate| candidate == name) {
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
    let snapshot = native::open(target, snapshot_read_access(scope), None).and_then(|key| {
        let mut snapshot = read_snapshot(&key, target, scope)?;
        pin_snapshot_executable(&mut snapshot, scope)?;
        Ok(snapshot)
    });
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
    operation_id: Option<Uuid>,
    backup: impl FnOnce(&[u8], &[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let scope =
        write_scope(target).ok_or_else(|| denied("registry target is outside the write policy"))?;
    if operation_id.is_some() {
        native::ensure_recovery_key()?;
    }
    let transaction = Transaction::new()?;
    let change_access = if scope.single_value() {
        KEY_SET_VALUE
    } else {
        DELETE
    };
    let access = snapshot_read_access(scope);
    let key = native::open(target, access | change_access, Some(&transaction))?;
    let mut snapshot = read_snapshot(&key, target, scope)?;
    // A confirmed Run entry or App Paths default must still resolve to the
    // approved executable. Hold the exact image through backup and commit.
    let _pinned_executable = pin_snapshot_executable(&mut snapshot, scope)?;
    if fingerprint(&snapshot)? != expected {
        return Err(invalid("registry target changed since dry-run"));
    }
    let reg = format::export(
        "HKEY_CURRENT_USER",
        "shared current user",
        &target.key,
        &snapshot.values,
    )?;
    let encoded = serde_json::to_vec(&snapshot).map_err(io::Error::other)?;
    backup(&reg, &encoded)?;
    let receipt = operation_id
        .map(|id| recovery::Receipt::bind(id, target, &encoded))
        .transpose()?;
    if let Some(receipt) = &receipt {
        receipt.stage(&transaction, RegistryChangeReceipt::Applied)?;
    }

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
    let mut committed = read_snapshot(&committed_key, target, scope)?;
    // The original handle still pins the image while we compare committed bytes.
    committed.executable = snapshot.executable;
    if fingerprint(&committed)? != expected {
        return Err(invalid(
            "a concurrent registry change invalidated the backup",
        ));
    }
    match receipt {
        Some(receipt) => receipt.commit(transaction, RegistryChangeReceipt::Applied),
        None => transaction.commit(),
    }
}

pub(crate) fn restore(
    target: &RegistryTarget,
    bytes: &[u8],
    operation_id: Option<Uuid>,
) -> io::Result<()> {
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(invalid("registry backup exceeds the supported size"));
    }
    let scope =
        write_scope(target).ok_or_else(|| denied("backup target is outside the write policy"))?;
    let snapshot: Snapshot = serde_json::from_slice(bytes).map_err(io::Error::other)?;
    validate_snapshot(target, scope, &snapshot)?;
    let _pinned_executable = if let Some(expected) = &snapshot.executable {
        // Hold the verified file without write or delete sharing through commit.
        let (pinned, current) = pin_startup_executable(&snapshot_program(&snapshot, scope)?)?;
        if &current != expected {
            return Err(invalid("registered executable changed since the backup"));
        }
        Some(pinned)
    } else {
        None
    };
    let receipt = operation_id
        .map(|id| recovery::Receipt::bind(id, target, bytes))
        .transpose()?;
    if receipt.is_some() {
        native::ensure_recovery_key()?;
    }
    let transaction = Transaction::new()?;
    if let Some(receipt) = &receipt {
        receipt.stage(&transaction, RegistryChangeReceipt::Restored)?;
    }
    if scope.single_value() {
        restore_value(&snapshot, scope, &transaction)?;
    } else {
        restore_leaf(&snapshot, &transaction)?;
    }
    match receipt {
        Some(receipt) => receipt.commit(transaction, RegistryChangeReceipt::Restored),
        None => transaction.commit(),
    }
}

pub(crate) fn change_receipt(
    target: &RegistryTarget,
    bytes: &[u8],
    operation_id: Uuid,
) -> io::Result<Option<RegistryChangeReceipt>> {
    if bytes.len() > MAX_SNAPSHOT_BYTES || write_scope(target).is_none() {
        return Err(invalid(
            "registry receipt falls outside the supported backup scope",
        ));
    }
    recovery::Receipt::bind(operation_id, target, bytes)?.read()
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
    if snapshot.executable.is_some() != scope.requires_executable() {
        return Err(invalid(
            "registered executable identity does not match the backup scope",
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
        WriteScope::AppValue
        | WriteScope::NestedAppValue
        | WriteScope::StartupValue
        | WriteScope::AppPathDefault => {
            let selected = target
                .value
                .as_ref()
                .and_then(|name| snapshot.values.get(name));
            if snapshot.values.len() != 1 || selected.is_none() {
                return Err(invalid(
                    "registry backup has values outside the exact approved target",
                ));
            }
            if scope.requires_executable() {
                snapshot_program(snapshot, scope)?;
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

fn restore_value(
    snapshot: &Snapshot,
    scope: WriteScope,
    transaction: &Transaction,
) -> io::Result<()> {
    let target = &snapshot.target;
    let name = target
        .value
        .as_deref()
        .ok_or_else(|| invalid("expected an exact value name"))?;
    let access = snapshot_read_access(scope);
    let key = native::open(target, access | KEY_SET_VALUE, Some(transaction))?;
    check_value_destination(&key, name, snapshot, scope)?;
    set_values(&key, &snapshot.values)?;
    let committed_key = native::open(target, access, None)?;
    check_value_destination(&committed_key, name, snapshot, scope)
}

fn check_value_destination(
    key: &Key,
    name: &str,
    snapshot: &Snapshot,
    scope: WriteScope,
) -> io::Result<()> {
    let info = native::key_info(key)?;
    if scope == WriteScope::AppPathDefault {
        if info.subkeys != 0 || info.values != 0 {
            return Err(denied("the original App Paths key is no longer empty"));
        }
        require_no_machine_app_path(&snapshot.target)?;
    }
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
    fn system_wait_records_cannot_be_reopened_as_win32_jobs() {
        let id = Uuid::new_v4();
        for (phase, uninstaller) in [
            (2, SystemUninstaller::DirectMsi),
            (3, SystemUninstaller::ElevatedMsi),
            (4, SystemUninstaller::Msix),
        ] {
            let launch = NativeLaunch::System { id, uninstaller };
            let payload = launch.payload();
            assert_eq!(payload[0], phase);
            assert_eq!(NativeLaunch::from_payload(&payload), Some(launch));
        }
        for committed in [false, true] {
            let launch = NativeLaunch::Win32 { id, committed };
            let payload = launch.payload();
            assert_eq!(payload[0], u8::from(committed));
            assert_eq!(NativeLaunch::from_payload(&payload), Some(launch));
        }
        let mut invalid = NativeLaunch::Win32 {
            id,
            committed: false,
        }
        .payload();
        invalid[0] = 5;
        assert_eq!(NativeLaunch::from_payload(&invalid), None);
    }

    #[test]
    fn app_path_default_requires_the_exact_image_name_and_a_literal_path() {
        let target = user_target(
            r"Software\Microsoft\Windows\CurrentVersion\App Paths\Example Editor.exe",
            Some(""),
        );
        let literal = r"C:\Program Files\Example Editor\example editor.exe";
        assert_eq!(write_scope(&target), Some(WriteScope::AppPathDefault));
        assert_eq!(
            app_path_program(&target, &raw_string_fixture(literal)),
            Some(PathBuf::from(literal))
        );
        for changed in [
            r"C:\Program Files\Example Editor\other.exe",
            r#""C:\Program Files\Example Editor\Example Editor.exe" /quiet"#,
            r"%LOCALAPPDATA%\Example Editor\Example Editor.exe",
            r"C:\Program Files\..\Example Editor.exe",
        ] {
            assert!(
                app_path_program(&target, &raw_string_fixture(changed)).is_none(),
                "{changed}"
            );
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
    fn nested_settings_scope_accepts_only_named_values_in_private_current_user_descendants() {
        let root = r"Software\Northstar\Nebula";
        let settings = format!(r"{root}\Settings\Preferences\Current");
        let value = user_target(&settings, Some("Enabled"));
        assert!(is_nested_app_settings_key(&user_target(&settings, None)));
        assert_eq!(write_scope(&value), Some(WriteScope::NestedAppValue));
        for name in [None, Some(""), Some(" "), Some("\nEnabled")] {
            assert!(write_scope(&user_target(&settings, name)).is_none());
        }
        for suffix in [
            r"Common\Settings",
            r"Settings\Shared\Profiles",
            r"Settings\Policies",
            r"Settings\Wow6432Node",
            r"Settings\[Other App]",
            r"Settings\Preferences\Current\Extra",
        ] {
            assert!(
                write_scope(&user_target(&format!(r"{root}\{suffix}"), Some("Enabled"))).is_none()
            );
        }
        assert!(
            write_scope(&RegistryTarget {
                hive: RegistryHive::LocalMachine,
                ..value.clone()
            })
            .is_none()
        );
        assert!(
            write_scope(&RegistryTarget {
                view: RegistryView::Registry32,
                ..value
            })
            .is_none()
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
    fn force_commands_distinguish_absence_from_invalid_alternatives() {
        let mut values = BTreeMap::new();
        assert_eq!(force_programs(&values), Some([None, None]));
        let program = r"C:\Apps\Editor\remove.exe";
        values.insert("UninstallString".into(), raw_string_fixture(program));
        assert_eq!(force_programs(&values), Some([None, Some(program.into())]));
        for invalid_command in ["", r"remove.exe", r"C:\Windows\System32\cmd.exe /c exit"] {
            values.insert(
                "QUIETUNINSTALLSTRING".into(),
                raw_string_fixture(invalid_command),
            );
            assert!(force_programs(&values).is_none(), "{invalid_command}");
        }
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
        let intentionally_failed = remove(&target, &initial.fingerprint, None, |_, _| {
            assert_eq!(string_value(&target)?.as_deref(), Some("original"));
            Err(io::Error::other("fixture backup intentionally failed"))
        });
        assert!(intentionally_failed.is_err());
        assert_eq!(string_value(&target)?.as_deref(), Some("original"));

        let mut backup = Vec::new();
        remove(&target, &initial.fingerprint, None, |reg, snapshot| {
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
        assert!(restore(&other_view, &backup, None).is_err());
        assert!(restore(&sibling, &backup, None).is_err());
        assert_eq!(string_value(&target)?, None);
        restore(&target, &backup, None)?;
        assert_eq!(string_value(&target)?.as_deref(), Some("original"));

        let fresh = inspect(&target)?;
        remove(&target, &fresh.fingerprint, None, |_, _| Ok(()))?;
        set_values(
            &app.0,
            &BTreeMap::from([("Selected".to_string(), raw_string_fixture("replacement"))]),
        )?;
        assert_eq!(
            restore(&target, &backup, None)
                .err()
                .map(|error| error.kind()),
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
