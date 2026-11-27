use std::{
    io,
    marker::PhantomData,
    ptr::{NonNull, null_mut},
    rc::Rc,
    slice, thread,
    time::Duration,
};

use uninstallany_core::Cancellation;
use windows::ApplicationModel::Core::AppListEntry;
use windows::ApplicationModel::{Package, PackageSignatureKind};
use windows::Management::Deployment::PackageManager;
use windows::Win32::System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize};
use windows::core::{HRESULT, HSTRING};
use windows_future::AsyncStatus;
use windows_sys::Win32::{
    Foundation::{E_UNEXPECTED, ERROR_CANCELLED, ERROR_INSTALL_USEREXIT, ERROR_SUCCESS},
    Globalization::{CSTR_EQUAL, CompareStringOrdinal},
    Storage::Packaging::Appx::{
        APPLICATION_USER_MODEL_ID_MAX_LENGTH, PACKAGE_FAMILY_NAME_MAX_LENGTH,
        PACKAGE_RELATIVE_APPLICATION_ID_MAX_LENGTH, PackageFamilyNameFromFullName,
    },
    System::Com::CoTaskMemFree,
    UI::Shell::{
        Common::ITEMIDLIST, FOLDERID_AppsFolder, ILGetSize, ILIsParent, SHGetKnownFolderIDList,
        SHGetNameFromIDList, SHParseDisplayName, SIGDN_PARENTRELATIVEPARSING,
    },
};

use super::registry::{SystemUninstallWait, SystemUninstaller};
use super::uninstall::OfficialOutcome;

const WINDOWS_PUBLISHERS: &[&str] = &["8wekyb3d8bbwe", "cw5n1h2txyewy"];
const E_ABORT: HRESULT = HRESULT(0x8000_4004u32 as i32);
const MAX_SHORTCUT_ENTRIES: usize = 128;
const MAX_SHORTCUT_PIDL_BYTES: u32 = 4096;
const DEPLOYMENT_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Shell evidence captured for a launchable entry in the approved package.
pub(super) struct PackageShortcutTarget {
    pub(super) aumid: String,
    pub(super) pidl: Vec<u8>,
}

/// A registered AppX/MSIX package found in the current user's inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MsixPackage {
    /// Exact identity used by the deployment API, including version and architecture.
    pub full_name: String,
    /// Package identity across versions.
    pub family_name: String,
    /// Canonical package name from Windows.
    pub name: String,
    /// Localized display name when available, otherwise the canonical name.
    pub display_name: String,
    /// Localized publisher when available, otherwise the package identity publisher.
    pub publisher: String,
    /// Major, minor, build and revision reported by Windows.
    pub version: String,
    /// Whether metadata allows continuing to a native uninstall preflight.
    pub removable: bool,
}

/// The current user's package inventory, with per-package metadata failures.
#[derive(Debug)]
pub struct MsixInventory {
    /// Packages for which Windows returned an exact identity.
    pub packages: Vec<MsixPackage>,
    /// Diagnostics that did not prevent the remainder of the inventory from being read.
    pub warnings: Vec<String>,
}

/// Preflight for removing the current user's registration of one package.
pub struct MsixUninstall {
    package: MsixPackage,
}

impl MsixUninstall {
    /// Returns the confirmed PackageFullName without exposing arguments or user SIDs.
    pub fn summary(&self) -> String {
        format!(
            "Windows Package Manager {} (current user)",
            self.package.full_name
        )
    }

    /// Removes the current user's package registration and verifies its absence.
    pub(super) fn execute_with_cancel(
        self,
        cancel: &Cancellation,
        warnings: &mut Vec<String>,
        observe: impl FnOnce(
            &[PackageShortcutTarget],
            &mut Vec<String>,
        ) -> uninstallany_core::Result<()>,
    ) -> uninstallany_core::Result<OfficialOutcome> {
        if cancel.check().is_err() {
            return Ok(OfficialOutcome::Cancelled);
        }
        let _apartment = Mta::enter()?;
        let manager = PackageManager::new().map_err(windows_error)?;
        let (package, entries) = find_removable(&manager, &self.package.full_name)?;
        if package != self.package {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the Windows package metadata changed; preview again",
            )
            .into());
        }

        let name = HSTRING::from(package.full_name.as_str());
        let targets = shortcut_targets(&package.family_name, entries, warnings, cancel)?;
        cancel.check()?;
        observe(&targets, warnings)?;
        if cancel.check().is_err() {
            return Ok(OfficialOutcome::Cancelled);
        }
        // This overload defaults to the process user. Do not use all-users or
        // deprovision APIs here, even for a package sharing staged payloads.
        let wait = SystemUninstallWait::begin(SystemUninstaller::Msix)?;
        if cancel.check().is_err() {
            finish_uninstall_wait(wait, warnings);
            return Ok(OfficialOutcome::Cancelled);
        }
        let operation = match manager.RemovePackageAsync(&name) {
            Ok(operation) => operation,
            Err(error) => {
                // A remote call can fail at the caller after the service has
                // accepted the request. Leave the marker in place.
                warnings.push(format!(
                    "Windows did not confirm the MSIX uninstall request ({}). Windows changes remain blocked.",
                    error.code()
                ));
                return Ok(OfficialOutcome::Unverified(error.code().0 as u32));
            }
        };
        // A local wait failure does not establish that deployment stopped.
        // After dispatch, keep watching the same operation regardless of UI
        // cancellation; the core can still skip the residual scan.
        let status = loop {
            match operation.Status() {
                Ok(AsyncStatus::Started) => thread::sleep(DEPLOYMENT_POLL_INTERVAL),
                Ok(
                    status @ (AsyncStatus::Completed | AsyncStatus::Error | AsyncStatus::Canceled),
                ) => {
                    break status;
                }
                Ok(_) => {
                    warnings.push(
                        "Windows returned an unknown MSIX uninstall state. Windows changes remain blocked."
                            .into(),
                    );
                    return Ok(OfficialOutcome::Unverified(E_UNEXPECTED as u32));
                }
                Err(error) => {
                    warnings.push(format!(
                        "Could not verify the MSIX uninstall state ({}). Windows changes remain blocked.",
                        error.code()
                    ));
                    return Ok(OfficialOutcome::Unverified(error.code().0 as u32));
                }
            }
        };
        finish_uninstall_wait(wait, warnings);
        if status == AsyncStatus::Canceled {
            return Ok(OfficialOutcome::Cancelled);
        }

        let result_code = operation
            .GetResults()
            .and_then(|result| result.ExtendedErrorCode());
        let code = if status == AsyncStatus::Error {
            // The deployment result can provide a more specific error. If
            // unavailable, the same operation can still report its HRESULT.
            match result_code {
                Ok(code) if code.is_err() => Ok(code),
                _ => operation.ErrorCode(),
            }
        } else {
            result_code
        };
        let code = match code {
            Ok(code) => code,
            Err(error) => {
                warnings.push(format!(
                    "The MSIX uninstall ended, but its result could not be read ({}).",
                    error.code()
                ));
                return Ok(OfficialOutcome::Unverified(error.code().0 as u32));
            }
        };
        if status == AsyncStatus::Error && code.is_ok() {
            warnings.push("Windows reported an MSIX uninstall error without an error code.".into());
            return Ok(OfficialOutcome::Unverified(E_UNEXPECTED as u32));
        }
        if code.is_err() {
            return Ok(classify_hresult(code));
        }
        let verification = Cancellation::default();
        if matches!(
            current_user_contains(&manager, &package.full_name, &verification),
            Ok(false)
        ) {
            return Ok(OfficialOutcome::Completed);
        }
        Ok(OfficialOutcome::Unverified(code.0 as u32))
    }
}

fn finish_uninstall_wait(wait: SystemUninstallWait, warnings: &mut Vec<String>) {
    if let Err(error) = wait.finish() {
        warnings.push(format!(
            "Could not clear the MSIX uninstall wait marker: {error}"
        ));
    }
}

/// Enumerates current-user packages and collects recoverable metadata errors.
pub fn inventory_current_user(cancel: &Cancellation) -> uninstallany_core::Result<MsixInventory> {
    cancel.check()?;
    let _apartment = Mta::enter()?;
    let manager = PackageManager::new().map_err(windows_error)?;
    let iterable = manager
        .FindPackagesByUserSecurityId(&HSTRING::new())
        .map_err(windows_error)?;
    let iter = iterable.First().map_err(windows_error)?;
    let mut inventory = MsixInventory {
        packages: Vec::new(),
        warnings: Vec::new(),
    };
    while iter.HasCurrent().map_err(windows_error)? {
        cancel.check()?;
        match iter
            .Current()
            .and_then(|package| read_package(&package, &mut inventory.warnings))
        {
            Ok(package) => inventory.packages.push(package),
            Err(error) => inventory.warnings.push(format!(
                "could not read metadata for one Windows package: {}",
                error.code()
            )),
        }
        if let Err(error) = iter.MoveNext() {
            inventory.warnings.push(format!(
                "Windows stopped package enumeration early: {}",
                error.code()
            ));
            break;
        }
    }
    Ok(inventory)
}

/// Reads inventory metadata for one exact current-user package identity.
pub(super) fn lookup_current_user(
    full_name: &str,
    cancel: &Cancellation,
) -> uninstallany_core::Result<Option<MsixPackage>> {
    cancel.check()?;
    let name = checked_full_name(full_name)?;
    let _apartment = Mta::enter()?;
    let manager = PackageManager::new().map_err(windows_error)?;
    let direct = manager.FindPackageByUserSecurityIdPackageFullName(&HSTRING::new(), &name);
    cancel.check()?;
    let package = match direct {
        Ok(package) => package,
        Err(error) => {
            // The direct API has no documented absent-package error contract.
            let present = current_user_contains(&manager, full_name, cancel)?;
            cancel.check()?;
            return if present {
                Err(windows_error(error).into())
            } else {
                Ok(None)
            };
        }
    };
    // Inventory reports safety diagnostics. The single record carries the read-only flag.
    let info = read_package(&package, &mut Vec::new()).map_err(windows_error)?;
    cancel.check()?;
    if !info.full_name.eq_ignore_ascii_case(full_name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned a different package identity",
        )
        .into());
    }
    Ok((info.full_name == full_name).then_some(info))
}

/// Validates a healthy third-party app before exposing its uninstall intent.
pub fn prepare_current_user(full_name: &str) -> io::Result<MsixUninstall> {
    let _apartment = Mta::enter()?;
    let manager = PackageManager::new().map_err(windows_error)?;
    let (package, _) = find_removable(&manager, full_name)?;
    Ok(MsixUninstall { package })
}

/// Checks the exact registration independently of display metadata and capabilities.
pub(super) fn current_package_present(
    full_name: &str,
    cancel: &Cancellation,
) -> uninstallany_core::Result<bool> {
    cancel.check()?;
    let _apartment = Mta::enter()?;
    let manager = PackageManager::new().map_err(windows_error)?;
    current_user_contains(&manager, full_name, cancel)
}

/// Checks for any version of this package family registered to the process user.
pub(super) fn current_family_present(
    full_name: &str,
    cancel: &Cancellation,
) -> uninstallany_core::Result<bool> {
    cancel.check()?;
    let family_name = package_family_name(full_name)?;
    let _apartment = Mta::enter()?;
    let manager = PackageManager::new().map_err(windows_error)?;
    let packages = manager
        .FindPackagesByUserSecurityIdPackageFamilyName(&HSTRING::new(), &family_name)
        .map_err(windows_error)?;
    let present = packages
        .First()
        .and_then(|packages| packages.HasCurrent())
        .map_err(windows_error)?;
    cancel.check()?;
    Ok(present)
}

/// Derives the stable Windows family identity from a full package name.
pub(super) fn package_family_name(full_name: &str) -> io::Result<HSTRING> {
    let name = checked_full_name(full_name)?;
    let mut length = PACKAGE_FAMILY_NAME_MAX_LENGTH + 1;
    let mut family = [0; PACKAGE_FAMILY_NAME_MAX_LENGTH as usize + 1];
    // SAFETY: name is NUL-terminated and the length describes the writable UTF-16 buffer.
    let status =
        unsafe { PackageFamilyNameFromFullName(name.as_ptr(), &mut length, family.as_mut_ptr()) };
    if status != ERROR_SUCCESS {
        return Err(io::Error::other(format!(
            "Windows could not resolve the package family ({status})"
        )));
    }
    let name = family
        .get(..length as usize)
        .and_then(|output| output.strip_suffix(&[0]))
        .filter(|output| !output.is_empty() && !output.contains(&0))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows returned a malformed package family name",
            )
        })?;
    Ok(HSTRING::from_wide(name))
}

fn read_package(
    package: &Package,
    warnings: &mut Vec<String>,
) -> windows::core::Result<MsixPackage> {
    let identity = package.Id()?;
    let name = identity.Name()?.to_string_lossy();
    let full_name = identity.FullName()?.to_string_lossy();
    let family_name = identity.FamilyName()?.to_string_lossy();
    let version = identity.Version()?;
    let display_name = match package.DisplayName() {
        Ok(display_name) if !display_name.is_empty() => display_name.to_string_lossy(),
        _ => name.clone(),
    };
    let publisher = match package.PublisherDisplayName() {
        Ok(publisher) if !publisher.is_empty() => publisher.to_string_lossy(),
        _ => identity.Publisher()?.to_string_lossy(),
    };
    let removable = match is_removable(package, &name, &identity.PublisherId()?.to_string_lossy()) {
        Ok(removable) => removable,
        Err(error) => {
            warnings.push(format!("package {full_name} is read-only because its safety properties could not be evaluated: {}", error.code()));
            false
        }
    };
    Ok(MsixPackage {
        full_name,
        family_name,
        name,
        display_name,
        publisher,
        version: format!(
            "{}.{}.{}.{}",
            version.Major, version.Minor, version.Build, version.Revision
        ),
        removable,
    })
}

fn is_removable(package: &Package, name: &str, publisher_id: &str) -> windows::core::Result<bool> {
    if is_windows_package(name, publisher_id) {
        return Ok(false);
    }
    let signature = package.SignatureKind()?;
    if !matches!(
        signature,
        PackageSignatureKind::Developer
            | PackageSignatureKind::Enterprise
            | PackageSignatureKind::Store
    ) {
        return Ok(false);
    }
    Ok(!package.IsFramework()?
        && !package.IsResourcePackage()?
        && !package.IsBundle()?
        && !package.IsOptional()?
        && !package.IsDevelopmentMode()?
        && package.Status()?.VerifyIsOK()?)
}

fn is_windows_package(name: &str, publisher_id: &str) -> bool {
    let lowercase_name = name.to_ascii_lowercase();
    lowercase_name.starts_with("microsoft.")
        || lowercase_name.starts_with("windows.")
        || WINDOWS_PUBLISHERS
            .iter()
            .any(|id| publisher_id.eq_ignore_ascii_case(id))
}

fn checked_full_name(full_name: &str) -> io::Result<HSTRING> {
    if full_name.is_empty() || full_name.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected an exact Windows package full name",
        ));
    }
    Ok(HSTRING::from(full_name))
}

fn find_removable(
    manager: &PackageManager,
    full_name: &str,
) -> io::Result<(
    MsixPackage,
    impl ExactSizeIterator<Item = windows::core::Result<AppListEntry>>,
)> {
    let name = checked_full_name(full_name)?;
    let package = manager
        .FindPackageByUserSecurityIdPackageFullName(&HSTRING::new(), &name)
        .map_err(windows_error)?;
    let mut warnings = Vec::new();
    let info = read_package(&package, &mut warnings).map_err(windows_error)?;
    if info.full_name != full_name || !info.removable {
        let reason = warnings.pop().unwrap_or_else(|| {
            format!(
                "the Windows package {full_name} is protected or lacks verified uninstall support"
            )
        });
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, reason));
    }
    // Resource packages and non-launchable dependencies lack an app-list entry.
    let entries = package
        .GetAppListEntriesAsync()
        .map_err(windows_error)?
        .join()
        .map_err(windows_error)?;
    let count = entries.Size().map_err(windows_error)?;
    if count == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the Windows package has no launchable application entry",
        ));
    }
    Ok((info, (0..count).map(move |index| entries.GetAt(index))))
}

fn current_user_contains(
    manager: &PackageManager,
    full_name: &str,
    cancel: &Cancellation,
) -> uninstallany_core::Result<bool> {
    cancel.check()?;
    let family = package_family_name(full_name)?;
    let name = HSTRING::from(full_name);
    let packages = manager
        .FindPackagesByUserSecurityIdPackageFamilyName(&HSTRING::new(), &family)
        .map_err(windows_error)?;
    let iter = packages.First().map_err(windows_error)?;
    loop {
        cancel.check()?;
        if !iter.HasCurrent().map_err(windows_error)? {
            return Ok(false);
        }
        let full_name = iter
            .Current()
            .and_then(|package| package.Id())
            .and_then(|identity| identity.FullName())
            .map_err(windows_error)?;
        if same_package_name(&full_name, &name)? {
            return Ok(true);
        }
        iter.MoveNext().map_err(windows_error)?;
    }
}

fn same_package_name(first: &HSTRING, second: &HSTRING) -> io::Result<bool> {
    let first_len = i32::try_from(first.len()).map_err(io::Error::other)?;
    let second_len = i32::try_from(second.len()).map_err(io::Error::other)?;
    // SAFETY: both UTF-16 buffers stay live for the call and lengths fit i32.
    let result =
        unsafe { CompareStringOrdinal(first.as_ptr(), first_len, second.as_ptr(), second_len, 1) };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(result == CSTR_EQUAL)
}

fn shortcut_targets(
    family: &str,
    entries: impl ExactSizeIterator<Item = windows::core::Result<AppListEntry>>,
    warnings: &mut Vec<String>,
    cancel: &Cancellation,
) -> uninstallany_core::Result<Vec<PackageShortcutTarget>> {
    cancel.check()?;
    let folder = match apps_folder() {
        Ok(folder) => folder,
        Err(error) => {
            warnings.push(format!(
                "could not verify the Windows AppsFolder for shortcut discovery: {error}"
            ));
            return Ok(Vec::new());
        }
    };
    let mut targets: Vec<PackageShortcutTarget> = Vec::new();
    let mut unavailable = entries.len() > MAX_SHORTCUT_ENTRIES;
    for entry in entries.take(MAX_SHORTCUT_ENTRIES) {
        cancel.check()?;
        let id = entry.and_then(|entry| entry.AppUserModelId());
        let Ok(id) = id else {
            unavailable = true;
            continue;
        };
        let aumid = id.to_string_lossy();
        if !valid_aumid(family, &aumid) {
            unavailable = true;
            continue;
        }
        if targets.iter().any(|target| target.aumid == aumid) {
            continue;
        }
        match apps_folder_target(&folder, &aumid) {
            Ok(pidl) => targets.push(PackageShortcutTarget { aumid, pidl }),
            Err(_) => unavailable = true,
        }
    }
    if unavailable {
        warnings.push(
            "some Windows package shortcuts could not be verified and will be left untouched"
                .into(),
        );
    }
    Ok(targets)
}

fn valid_aumid(family: &str, aumid: &str) -> bool {
    if aumid.len() > APPLICATION_USER_MODEL_ID_MAX_LENGTH as usize {
        return false;
    }
    let Some((actual_family, application)) = aumid.split_once('!') else {
        return false;
    };
    !actual_family.is_empty()
        && actual_family == family
        && actual_family
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        && application.len() < PACKAGE_RELATIVE_APPLICATION_ID_MAX_LENGTH as usize
        && application.split('.').all(|field| {
            field
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
                && field.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
}

fn apps_folder() -> io::Result<ShellAllocation<ITEMIDLIST>> {
    let mut folder = null_mut();
    // SAFETY: a valid known-folder GUID and writable result pointer are supplied.
    // No impersonation token is passed, so this uses the current user.
    let result =
        unsafe { SHGetKnownFolderIDList(&FOLDERID_AppsFolder, 0, null_mut(), &mut folder) };
    ShellAllocation::from_result(result, folder)
}

fn apps_folder_target(folder: &ShellAllocation<ITEMIDLIST>, aumid: &str) -> io::Result<Vec<u8>> {
    let name = HSTRING::from(format!("shell:AppsFolder\\{aumid}"));
    let mut item = null_mut();
    // SAFETY: name is a terminated UTF-16 string built from a validated WinRT
    // identity. Neither user-supplied paths nor shortcut bytes reach the Shell.
    let result = unsafe { SHParseDisplayName(name.as_ptr(), null_mut(), &mut item, 0, null_mut()) };
    let item = ShellAllocation::from_result(result, item)?;
    // SAFETY: only the trusted, allocated PIDL returned by the Shell is sized.
    let size = unsafe { ILGetSize(item.0.as_ptr()) };
    if !(4..=MAX_SHORTCUT_PIDL_BYTES).contains(&size) {
        return Err(io::Error::other("invalid AppsFolder item size"));
    }
    // SAFETY: both pointers are live Shell PIDLs; true requires an immediate child.
    if unsafe { ILIsParent(folder.0.as_ptr(), item.0.as_ptr(), 1) } == 0 {
        return Err(io::Error::other("the Shell item is outside AppsFolder"));
    }
    let mut parsing_name = null_mut();
    // SAFETY: item is a live Shell PIDL and parsing_name is a writable output pointer.
    let result = unsafe {
        SHGetNameFromIDList(
            item.0.as_ptr(),
            SIGDN_PARENTRELATIVEPARSING,
            &mut parsing_name,
        )
    };
    let parsing_name = ShellAllocation::from_result(result, parsing_name)?;
    // SAFETY: the Shell returned a NUL-terminated UTF-16 string. The ASCII
    // expected identity has no NUL, so a shorter string stops at its terminator.
    let name_matches = unsafe {
        aumid
            .bytes()
            .enumerate()
            .all(|(index, byte)| *parsing_name.0.as_ptr().add(index) == u16::from(byte))
            && *parsing_name.0.as_ptr().add(aumid.len()) == 0
    };
    if !name_matches {
        return Err(io::Error::other(
            "the Shell item does not identify the approved application",
        ));
    }
    // SAFETY: the trusted Shell PIDL is readable for its bounded, API-reported size.
    Ok(unsafe { slice::from_raw_parts(item.0.as_ptr().cast::<u8>(), size as usize) }.to_vec())
}

struct ShellAllocation<T>(NonNull<T>);

impl<T> ShellAllocation<T> {
    fn from_result(result: i32, pointer: *mut T) -> io::Result<Self> {
        if result < 0 {
            return Err(io::Error::other(format!(
                "Windows Shell returned {}",
                HRESULT(result)
            )));
        }
        NonNull::new(pointer)
            .map(Self)
            .ok_or_else(|| io::Error::other("Windows Shell returned no item"))
    }
}

impl<T> Drop for ShellAllocation<T> {
    fn drop(&mut self) {
        // SAFETY: this uniquely owns a Shell result allocated by the COM task allocator.
        unsafe { CoTaskMemFree(self.0.as_ptr().cast()) };
    }
}

fn windows_error(error: windows::core::Error) -> io::Error {
    // Only format the HRESULT, not a deployment message that could contain paths.
    io::Error::other(format!("Windows Package Manager returned {}", error.code()))
}

fn classify_hresult(code: HRESULT) -> OfficialOutcome {
    if code == E_ABORT
        || code == HRESULT::from_win32(ERROR_CANCELLED)
        || code == HRESULT::from_win32(ERROR_INSTALL_USEREXIT)
    {
        return OfficialOutcome::Cancelled;
    }
    OfficialOutcome::Failed(code.0 as u32)
}

struct Mta(PhantomData<Rc<()>>);

impl Mta {
    fn enter() -> io::Result<Self> {
        // SAFETY: WinRT initialization is paired by Drop on the same worker thread.
        // Blocking async WinRT operations need an MTA worker, never the GUI STA.
        unsafe { RoInitialize(RO_INIT_MULTITHREADED) }.map_err(windows_error)?;
        Ok(Self(PhantomData))
    }
}

impl Drop for Mta {
    fn drop(&mut self) {
        // SAFETY: enter incremented the WinRT initialization count on this thread.
        unsafe { RoUninitialize() };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_package_inventory_stops_before_initializing_winrt() {
        let cancel = Cancellation::default();
        cancel.cancel();
        assert!(matches!(
            inventory_current_user(&cancel),
            Err(uninstallany_core::Error::Cancelled)
        ));
    }

    #[test]
    fn cleanup_family_identity_is_independent_of_version_and_architecture() -> io::Result<()> {
        let before = package_family_name("Example.Editor_1.0.0.0_x64__8wekyb3d8bbwe")?;
        let after = package_family_name("Example.Editor_2.0.0.0_arm64__8wekyb3d8bbwe")?;
        assert_eq!(before.to_string_lossy(), "Example.Editor_8wekyb3d8bbwe");
        assert_eq!(before, after);
        Ok(())
    }

    #[test]
    fn package_presence_ignores_case_and_retains_full_identity() -> io::Result<()> {
        let expected = HSTRING::from("Example.Editor_1.0.0.0_x64__8wekyb3d8bbwe");
        let case_variant = HSTRING::from("example.editor_1.0.0.0_X64__8WEKYB3D8BBWE");
        let different_version = HSTRING::from("Example.Editor_2.0.0.0_x64__8wekyb3d8bbwe");
        assert!(same_package_name(&expected, &case_variant)?);
        assert!(!same_package_name(&expected, &different_version)?);
        Ok(())
    }

    #[test]
    fn shell_input_requires_a_single_exact_family_and_manifest_application_id() {
        let family = "Example.Editor_8wekyb3d8bbwe";
        assert!(valid_aumid(family, &format!("{family}!Editor.Main2")));
        for suffix in [
            "",
            "!Extra",
            "../App",
            "Editor\\File",
            "Editor..File",
            "1Editor",
        ] {
            assert!(!valid_aumid(family, &format!("{family}!{suffix}")));
        }
        assert!(!valid_aumid(family, "Example.Other_8wekyb3d8bbwe!Editor"));
    }

    #[test]
    fn protects_windows_packages_even_when_a_display_name_is_unrelated() {
        assert!(is_windows_package("Example.Name", "8WEKYB3D8BBWE"));
        assert!(is_windows_package("Microsoft.Edge", "OtherPublisher"));
        assert!(is_windows_package(
            "windows.immersivecontrolpanel",
            "OtherPublisher"
        ));
        assert!(!is_windows_package("Example.Editor", "OtherPublisher"));
    }

    #[test]
    fn distinguishes_package_cancellation_from_native_failure() {
        assert_eq!(classify_hresult(E_ABORT), OfficialOutcome::Cancelled);
        assert_eq!(
            classify_hresult(HRESULT::from_win32(ERROR_CANCELLED)),
            OfficialOutcome::Cancelled
        );
        assert_eq!(
            classify_hresult(HRESULT::from_win32(5)),
            OfficialOutcome::Failed(0x8007_0005)
        );
    }
}
