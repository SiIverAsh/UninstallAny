use std::{
    ffi::OsStr,
    io,
    os::unix::ffi::OsStrExt,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use uninstallany_core::{
    Access, AppId, AppRecord, Cancellation, Category, Error, MatchKind, Proposal, Result, Risk,
    Scan, Target,
};
use uninstallany_unix::UnixFiles;

use crate::plist;

pub(super) const MANAGER: &str = "macos-bundle";
pub(super) const APPLICATIONS: &str = "/Applications";
const MAX_PLIST_BYTES: usize = 2 * 1024 * 1024;
const MAX_DISCOVERY_ENTRIES: usize = 4_096;
const MAX_BACKGROUND_ITEMS: usize = 128;

#[derive(Debug)]
pub(super) struct Bundle {
    pub(super) identifier: String,
    pub(super) name: String,
    pub(super) version: Option<String>,
    pub(super) path: PathBuf,
}

impl Bundle {
    pub(super) fn is_system(&self) -> bool {
        let identifier = self.identifier.to_ascii_lowercase();
        self.path.starts_with("/System")
            || identifier == "com.apple"
            || identifier.starts_with("com.apple.")
    }

    pub(super) fn record(&self) -> AppRecord {
        let path_hash = app_id_path_hash(&self.path);
        AppRecord {
            id: AppId::Package {
                manager: MANAGER.into(),
                id: format!("{}:{path_hash}", self.identifier),
            },
            name: self.name.clone(),
            publisher: None,
            version: self.version.clone(),
            install_location: Some(self.path.clone()),
            // Bundle directory metadata describes the directory entry.
            // Installed size and date need separate evidence.
            size_bytes: None,
            install_date: None,
            system_component: self.is_system(),
            official_uninstall_available: false,
        }
    }
}

pub(super) fn discover(
    files: &UnixFiles,
    roots: &[PathBuf],
    cancel: &Cancellation,
    warnings: &mut Vec<String>,
) -> Result<Vec<Bundle>> {
    let mut result = Vec::new();
    let mut remaining = MAX_DISCOVERY_ENTRIES;
    for root in roots {
        inspect_root(files, root, &mut result, &mut remaining, cancel, warnings)?;
        if remaining == 0 {
            warnings.push("application bundle enumeration reached its entry limit".into());
            break;
        }
    }
    Ok(result)
}

fn inspect_root(
    files: &UnixFiles,
    root: &Path,
    result: &mut Vec<Bundle>,
    remaining: &mut usize,
    cancel: &Cancellation,
    warnings: &mut Vec<String>,
) -> Result<()> {
    for item in list(files, root, warnings)? {
        cancel.check()?;
        if !inspect_entry(files, &item, result, remaining, warnings) {
            break;
        }
        if is_app(&item) {
            continue;
        }
        // Applications in product-suite or Utilities directories are common.
        // Never traverse into the contents of a discovered app.
        for child in list(files, &item, warnings)? {
            cancel.check()?;
            if !inspect_entry(files, &child, result, remaining, warnings) {
                return Ok(());
            }
        }
    }
    Ok(())
}

fn inspect_entry(
    files: &UnixFiles,
    item: &Path,
    result: &mut Vec<Bundle>,
    remaining: &mut usize,
    warnings: &mut Vec<String>,
) -> bool {
    if *remaining == 0 {
        return false;
    }
    *remaining -= 1;
    if is_app(item) {
        match read(files, item) {
            Ok(bundle) => result.push(bundle),
            Err(error)
                if error.kind() == io::ErrorKind::NotADirectory && is_known_system_alias(item) => {}
            Err(error) => {
                warnings.push(format!("could not read bundle {}: {error}", item.display()))
            }
        }
    }
    true
}

fn is_known_system_alias(path: &Path) -> bool {
    if path.parent() != Some(Path::new(APPLICATIONS)) {
        return false;
    }
    // Recent macOS releases expose first-party apps through root-owned
    // links. Inspect the link text without opening its destination.
    if !std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_symlink() && meta.uid() == 0) {
        return false;
    }
    let Some(name) = path.file_name() else {
        return false;
    };
    std::fs::read_link(path).is_ok_and(|destination| {
        [
            "../System/Applications",
            "../System/Cryptexes/App/System/Applications",
            "/System/Applications",
            "/System/Cryptexes/App/System/Applications",
        ]
        .into_iter()
        .any(|root| destination == Path::new(root).join(name))
    })
}

fn list(files: &UnixFiles, path: &Path, warnings: &mut Vec<String>) -> io::Result<Vec<PathBuf>> {
    match files.list(path) {
        Ok(children) => Ok(children),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(Vec::new())
        }
        Err(error) => {
            warnings.push(format!("could not enumerate {}: {error}", path.display()));
            Ok(Vec::new())
        }
    }
}

pub(super) fn is_app(path: &Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("app"))
}

pub(super) fn identifier_from_app_id(id: &str) -> Option<&str> {
    let (identifier, _) = id.split_once(':')?;
    valid_identifier(identifier).then_some(identifier)
}

/// Matches a normalized AppKit bundle path to the catalogued path hash.
pub(super) fn app_id_matches_path(id: &str, path_without_root: &Path) -> bool {
    let Some((_, expected_hash)) = id.split_once(':') else {
        return false;
    };
    let absolute = Path::new("/").join(path_without_root);
    app_id_path_hash(&absolute) == expected_hash
}

fn app_id_path_hash(path: &Path) -> String {
    format!("{:x}", Sha256::digest(path.as_os_str().as_bytes()))
}

/// Verifies absence at a catalogued path without following links.
pub(super) fn original_bundle_absent(
    files: &UnixFiles,
    original: &Path,
    application_roots: &[PathBuf],
) -> io::Result<bool> {
    match files.local_entry_absent(original) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let Some(suite) = original.parent().filter(|suite| {
                suite
                    .parent()
                    .is_some_and(|root| application_roots.iter().any(|path| path.as_path() == root))
            }) else {
                return Err(error);
            };
            // Uninstallers can remove a whole suite directory. Prove that
            // directory itself is absent from the still-present Applications root.
            files.local_entry_absent(suite)
        }
        result => result,
    }
}

/// Recognizes a literal direct selection under the system Applications root.
pub(super) fn is_selected_system_application(path: &Path) -> Result<bool> {
    if path.parent() != Some(Path::new(APPLICATIONS)) || !is_app(path) {
        return Ok(false);
    }
    let is_literal = path
        .file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| {
            path.as_os_str() == Path::new(APPLICATIONS).join(name).as_os_str()
                && !name.starts_with('.')
                && !name.chars().any(char::is_control)
        });
    if !is_literal {
        return Err(Error::Rejected(
            "Choose the exact path of one application directly in /Applications.".into(),
        ));
    }
    Ok(true)
}

/// Reports service declarations embedded in the selected bundle.
///
/// The bundle shows what can be registered, even when launchd has no loaded job.
/// A declaration is kept with the bundle to preserve its code-signing seal.
pub(super) fn scan_background_items(
    files: &UnixFiles,
    path: &Path,
    scan: &mut Scan,
    cancel: &Cancellation,
) -> Result<bool> {
    let mut requires_vendor_action = false;
    let mut remaining = MAX_BACKGROUND_ITEMS;
    for (directory, extension, category) in [
        ("LoginItems", "app", Category::Startup),
        ("LaunchAgents", "plist", Category::Startup),
        ("LaunchDaemons", "plist", Category::Service),
    ] {
        cancel.check()?;
        let directory = path.join("Contents/Library").join(directory);
        let children = match files.list(&directory) {
            Ok(children) => children,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                requires_vendor_action = true;
                scan.warnings.push(format!(
                    "could not inspect embedded background items in {}: {error}",
                    directory.display()
                ));
                continue;
            }
        };
        for item in children {
            cancel.check()?;
            if !item
                .extension()
                .is_some_and(|value| value.eq_ignore_ascii_case(extension))
            {
                continue;
            }
            requires_vendor_action = true;
            if remaining == 0 {
                scan.warnings
                    .push("embedded background item discovery reached its limit".into());
                return Ok(true);
            }
            remaining -= 1;
            scan.proposals.push(Proposal {
                target: Target::File(item),
                category,
                evidence: MatchKind::ExactIdentity,
                reason: "background item packaged inside the selected application".into(),
                risk: Risk::High,
                access: Access::ReadOnly(
                    "registration is managed by the application; use its vendor uninstaller".into(),
                ),
            });
        }
    }
    Ok(requires_vendor_action)
}

pub(super) fn read(files: &UnixFiles, path: &Path) -> io::Result<Bundle> {
    let bytes = files.read_regular(&path.join("Contents/Info.plist"), MAX_PLIST_BYTES)?;
    let dictionary = plist::dictionary(&bytes)?;
    let identifier = plist::string(&dictionary, "CFBundleIdentifier")
        .filter(|id| valid_identifier(id))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing or invalid bundle identifier",
            )
        })?;
    let version = plist::string(&dictionary, "CFBundleShortVersionString")
        .or_else(|| plist::string(&dictionary, "CFBundleVersion"));
    let name = plist::string(&dictionary, "CFBundleDisplayName")
        .or_else(|| plist::string(&dictionary, "CFBundleName"))
        .unwrap_or_else(|| {
            path.file_stem()
                .unwrap_or(OsStr::new(&identifier))
                .to_string_lossy()
                .into_owned()
        });
    Ok(Bundle {
        identifier,
        name,
        version,
        path: path.to_path_buf(),
    })
}

pub(super) fn valid_identifier(id: &str) -> bool {
    id.len() <= 255
        && id.contains('.')
        && id.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_ids_cannot_be_paths_or_incomplete_components() {
        for invalid in [
            ".com.arm",
            "com.vendor..app",
            "../app",
            "com.vendor/../../app",
            "org:app",
            "generic",
        ] {
            assert!(!valid_identifier(invalid), "{invalid}");
        }
        assert!(valid_identifier("com.Example.App-Beta"));
        assert!(valid_identifier("com.apple.Image_Capture"));
    }
}
