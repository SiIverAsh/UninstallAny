//! Machine MSI removal request verified independently in both processes.

use std::{io, ptr::null};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(feature = "privileged-helper")]
use uninstallany_core::RegistryTarget;
use uninstallany_core::{RegistryHive, RegistryView};
use windows_sys::Win32::{
    Foundation::ERROR_SUCCESS,
    System::ApplicationInstallationAndServicing::{
        INSTALLPROPERTY_INSTALLEDPRODUCTNAME, INSTALLPROPERTY_PACKAGECODE,
        INSTALLPROPERTY_PUBLISHER, INSTALLPROPERTY_VERSIONSTRING, MSIINSTALLCONTEXT_MACHINE,
        MsiGetProductInfoExW,
    },
};
use windows_sys::core::PCWSTR;

#[cfg(feature = "privileged-helper")]
use super::uninstall::OfficialOutcome;
use super::{
    platform::is_protected_entry,
    registry::{self, InstalledEntry},
    uninstall,
};

const MSI_PROPERTY_BUFFER_UNITS: usize = 1_024;
#[cfg(feature = "privileged-helper")]
const CONFIRMATION_NAME_CHARS: usize = 160;

/// A single machine MSI operation. Paths and command lines cannot enter via IPC.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MachineMsiRequest {
    product_code: String,
    view: RegistryView,
    quiet: bool,
    fingerprint: [u8; 32],
}

impl MachineMsiRequest {
    /// Captures the reviewed HKLM record and the installed MSI package identity.
    pub(super) fn preflight(entry: &InstalledEntry) -> io::Result<Self> {
        let product_code = product_code(entry)?;
        if !entry.windows_installer || entry.no_remove || is_protected_entry(entry) {
            return Err(rejected("this MSI registration is protected"));
        }
        // This rejects a same-code per-user product in the token doing the check.
        // The elevated process must repeat it because UAC can use another account.
        uninstall::verify_msi_context(&product_code, true)?;
        let installer = InstalledPackage::read(&product_code)?;
        if entry.display_name != installer.product_name
            || entry.publisher.as_deref() != Some(installer.publisher.as_str())
        {
            return Err(rejected(
                "the machine uninstall record disagrees with Windows Installer",
            ));
        }
        let fingerprint = registration_fingerprint(entry, &installer)?;
        Ok(Self {
            product_code,
            view: entry.address.view,
            quiet: entry.quiet_uninstall_string.is_some(),
            fingerprint,
        })
    }

    /// Builds the elevated confirmation from a fresh local machine registration.
    #[cfg(feature = "privileged-helper")]
    pub(super) fn confirmation_text(&self, chinese: bool) -> io::Result<String> {
        let entry = self.revalidate()?;
        let display_name: String = entry
            .display_name
            .chars()
            .filter(|character| {
                !character.is_control()
                    && !matches!(
                        *character,
                        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}'
                            | '\u{2066}'..='\u{206F}' | '\u{2028}' | '\u{2029}'
                    )
            })
            .take(CONFIRMATION_NAME_CHARS)
            .collect();
        if display_name.trim().is_empty() {
            return Err(rejected(
                "the MSI registration has no displayable product name",
            ));
        }
        let question = if chinese {
            "为此电脑上的所有用户卸载以下 Windows Installer 产品？"
        } else {
            "Remove this Windows Installer product for all users?"
        };
        Ok(format!(
            "{question}\n\n{}\n{}",
            display_name.trim(),
            self.product_code
        ))
    }

    /// Executes only after the authenticated caller and elevated prompt approve this request.
    #[cfg(feature = "privileged-helper")]
    pub(super) fn execute(self) -> io::Result<OfficialOutcome> {
        let target = self.address()?;
        let command = uninstall::prepare_msi(&self.product_code, true, self.quiet)?;
        self.revalidate()?;
        let outcome = command.execute()?;
        if outcome == OfficialOutcome::Completed
            && !matches!(registry::uninstall_key_present(&target), Ok(false))
        {
            return Ok(OfficialOutcome::Unverified(ERROR_SUCCESS));
        }
        Ok(outcome)
    }

    #[cfg(feature = "privileged-helper")]
    fn address(&self) -> io::Result<RegistryTarget> {
        if uninstall::normalize_product_code(&self.product_code)? != self.product_code
            || !registry::machine_views().contains(&self.view)
        {
            return Err(rejected("invalid machine MSI identity or registry view"));
        }
        Ok(RegistryTarget {
            hive: RegistryHive::LocalMachine,
            view: self.view,
            key: format!("{}\\{}", registry::UNINSTALL_KEY, self.product_code),
            value: None,
        })
    }

    #[cfg(feature = "privileged-helper")]
    fn revalidate(&self) -> io::Result<InstalledEntry> {
        let target = self.address()?;
        let entry = registry::installed_entry(&target)?
            .ok_or_else(|| rejected("the approved machine MSI registration no longer exists"))?;
        if &Self::preflight(&entry)? != self {
            return Err(rejected(
                "the machine MSI registration changed after preview",
            ));
        }
        Ok(entry)
    }
}

fn product_code(entry: &InstalledEntry) -> io::Result<String> {
    let (branch, leaf) = entry
        .address
        .key
        .rsplit_once('\\')
        .ok_or_else(|| rejected("expected a machine MSI uninstall registration"))?;
    if entry.address.hive != RegistryHive::LocalMachine
        || entry.address.value.is_some()
        || !registry::machine_views().contains(&entry.address.view)
        || !branch.eq_ignore_ascii_case(registry::UNINSTALL_KEY)
    {
        return Err(rejected("expected a machine MSI uninstall registration"));
    }
    uninstall::normalize_product_code(leaf)
}

#[derive(Serialize)]
struct InstalledPackage {
    package_code: String,
    product_name: String,
    publisher: String,
    version: String,
}

impl InstalledPackage {
    fn read(product_code: &str) -> io::Result<Self> {
        let product: Vec<_> = product_code.encode_utf16().chain([0]).collect();
        let package_code = machine_property(&product, INSTALLPROPERTY_PACKAGECODE)?;
        let product_name = machine_property(&product, INSTALLPROPERTY_INSTALLEDPRODUCTNAME)?;
        let publisher = machine_property(&product, INSTALLPROPERTY_PUBLISHER)?;
        let version = machine_property(&product, INSTALLPROPERTY_VERSIONSTRING)?;
        if product_name.trim().is_empty()
            || publisher.trim().is_empty()
            || version.trim().is_empty()
            || publisher
                .split(|character: char| !character.is_alphanumeric())
                .any(|part| part.eq_ignore_ascii_case("microsoft"))
        {
            return Err(rejected(
                "the machine MSI has protected or incomplete publisher metadata",
            ));
        }
        Ok(Self {
            package_code: uninstall::normalize_product_code(&package_code)?,
            product_name,
            publisher,
            version,
        })
    }
}

fn machine_property(product: &[u16], property: PCWSTR) -> io::Result<String> {
    let mut output = [0u16; MSI_PROPERTY_BUFFER_UNITS];
    let mut length = u32::try_from(output.len()).map_err(io::Error::other)?;
    // SAFETY: product is NUL-terminated, property is a constant property name,
    // and output plus its length parameter are writable for the stated capacity.
    let status = unsafe {
        MsiGetProductInfoExW(
            product.as_ptr(),
            null(),
            MSIINSTALLCONTEXT_MACHINE,
            property,
            output.as_mut_ptr(),
            &mut length,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(status).map_err(io::Error::other)?,
        ));
    }
    let length = usize::try_from(length).map_err(io::Error::other)?;
    if output.get(length) != Some(&0) || output[..length].contains(&0) {
        return Err(rejected(
            "Windows Installer returned malformed product metadata",
        ));
    }
    String::from_utf16(&output[..length]).map_err(io::Error::other)
}

fn registration_fingerprint(
    entry: &InstalledEntry,
    installer: &InstalledPackage,
) -> io::Result<[u8; 32]> {
    // Bind display and install metadata without transporting potentially private strings.
    let reviewed = serde_json::to_vec(&(
        &entry.display_name,
        &entry.display_version,
        &entry.publisher,
        &entry.install_location,
        &entry.install_date,
        &entry.uninstall_string,
        &entry.quiet_uninstall_string,
        installer,
    ))
    .map_err(io::Error::other)?;
    Ok(Sha256::digest(reviewed).into())
}

fn rejected(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
