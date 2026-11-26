use std::io;
use std::marker::PhantomData;
use std::rc::Rc;

use uninstallany_core::Cancellation;
use windows::ApplicationModel::{Package, PackageSignatureKind};
use windows::Management::Deployment::PackageManager;
use windows::Win32::System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize};
use windows::core::{HRESULT, HSTRING};
use windows_sys::Win32::Foundation::{ERROR_CANCELLED, ERROR_INSTALL_USEREXIT};

use super::uninstall::OfficialOutcome;

const WINDOWS_PUBLISHERS: &[&str] = &["8wekyb3d8bbwe", "cw5n1h2txyewy"];
const E_ABORT: HRESULT = HRESULT(0x8000_4004u32 as i32);

/// A registered AppX/MSIX package found in the current user's inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MsixPackage {
    /// Exact identity used by the deployment API, including version and architecture.
    pub full_name: String,
    /// Package identity across versions, used only as discovery evidence.
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
    pub fn execute(self) -> io::Result<OfficialOutcome> {
        let _apartment = Mta::enter()?;
        let manager = PackageManager::new().map_err(windows_error)?;
        let package = find_removable(&manager, &self.package.full_name)?;
        if package != self.package {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the Windows package metadata changed; preview again",
            ));
        }

        let name = HSTRING::from(package.full_name.as_str());
        // This overload defaults to the process user. Do not use all-users or
        // deprovision APIs here, even for a package sharing staged payloads.
        let operation = match manager.RemovePackageAsync(&name) {
            Ok(operation) => operation,
            Err(error) => return Ok(classify_hresult(error.code())),
        };
        let result = match operation.join() {
            Ok(result) => result,
            Err(error) => return Ok(classify_hresult(error.code())),
        };
        let code = result.ExtendedErrorCode().map_err(windows_error)?;
        if code.is_err() {
            return Ok(classify_hresult(code));
        }
        if matches!(current_user_contains(&manager, &name), Ok(false)) {
            return Ok(OfficialOutcome::Completed);
        }
        Ok(OfficialOutcome::Unverified(code.0 as u32))
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

/// Validates a healthy third-party app before exposing its uninstall intent.
pub fn prepare_current_user(full_name: &str) -> io::Result<MsixUninstall> {
    let _apartment = Mta::enter()?;
    let manager = PackageManager::new().map_err(windows_error)?;
    Ok(MsixUninstall {
        package: find_removable(&manager, full_name)?,
    })
}

/// Checks the exact registration independently of display metadata and capabilities.
pub(super) fn current_package_present(full_name: &str) -> io::Result<bool> {
    let _apartment = Mta::enter()?;
    let manager = PackageManager::new().map_err(windows_error)?;
    current_user_contains(&manager, &HSTRING::from(full_name)).map_err(windows_error)
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

fn find_removable(manager: &PackageManager, full_name: &str) -> io::Result<MsixPackage> {
    if full_name.is_empty() || full_name.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected an exact Windows package full name",
        ));
    }
    let name = HSTRING::from(full_name);
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
    if entries.Size().map_err(windows_error)? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the Windows package has no launchable application entry",
        ));
    }
    Ok(info)
}

fn current_user_contains(manager: &PackageManager, name: &HSTRING) -> windows::core::Result<bool> {
    let packages = manager.FindPackagesByUserSecurityId(&HSTRING::new())?;
    let iter = packages.First()?;
    while iter.HasCurrent()? {
        if iter.Current()?.Id()?.FullName()? == *name {
            return Ok(true);
        }
        iter.MoveNext()?;
    }
    Ok(false)
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
