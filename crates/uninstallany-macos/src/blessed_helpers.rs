//! Read-only discovery of legacy privileged helpers declared by an application.

use std::{fs, io, os::unix::fs::MetadataExt, path::Path};

use core_foundation::{
    array::CFArray,
    base::{CFType, TCFType},
    dictionary::CFDictionary,
    string::CFString,
};
use uninstallany_core::{
    Access, Cancellation, Category, MatchKind, Proposal, Result, Risk, Scan, Target,
};
use uninstallany_unix::UnixFiles;

use crate::{bundle, plist};

pub(super) const HELPER_ROOT: &str = "/Library/PrivilegedHelperTools";
const DAEMON_ROOT: &str = "/Library/LaunchDaemons";
const MAX_INFO_BYTES: usize = 2 * 1024 * 1024;
const MAX_DAEMON_BYTES: usize = 256 * 1024;
const MAX_DECLARATIONS: usize = 64;
const MAX_LABEL_BYTES: usize = 249;
const ROOT_UID: u32 = 0;
const SHARED_WRITE_BITS: u32 = 0o022;
const EXECUTABLE_BITS: u32 = 0o111;

/// Reports installed legacy helper references and whether manual app isolation can proceed.
///
/// An exact plist declaration is attribution evidence only. It does not
/// authorize changes to a system service or its executable.
pub(super) fn scan(
    files: &UnixFiles,
    bundle_path: &Path,
    scan: &mut Scan,
    cancel: &Cancellation,
) -> Result<bool> {
    cancel.check()?;
    let info_path = bundle_path.join("Contents/Info.plist");
    let info = match files
        .read_regular(&info_path, MAX_INFO_BYTES)
        .and_then(|bytes| plist::dictionary(&bytes))
    {
        Ok(info) => info,
        Err(error) => {
            scan.warnings.push(format!(
                "could not read legacy privileged helper declarations in {}: {error}",
                info_path.display()
            ));
            return Ok(true);
        }
    };
    let Some(declarations) = property(&info, "SMPrivilegedExecutables") else {
        return Ok(false);
    };
    let Some(declarations) = declarations.downcast_into::<CFDictionary>() else {
        scan.warnings
            .push("legacy privileged helper declarations must be a dictionary".into());
        return Ok(true);
    };
    if declarations.len() > MAX_DECLARATIONS {
        scan.warnings
            .push("legacy privileged helper declarations exceed the discovery limit".into());
        return Ok(true);
    }

    let (labels, requirements) = declarations.get_keys_and_values();
    let mut blocked = false;
    let mut valid_labels = Vec::with_capacity(labels.len());
    for (label, requirement) in labels.into_iter().zip(requirements) {
        cancel.check()?;
        // SAFETY: The dictionary retains these values while their dynamic
        // types are checked and the strings are copied.
        let (label, requirement) = unsafe {
            (
                CFType::wrap_under_get_rule(label),
                CFType::wrap_under_get_rule(requirement),
            )
        };
        let label = label
            .downcast_into::<CFString>()
            .map(|label| label.to_string());
        let requirement = requirement.downcast_into::<CFString>();
        if let Some(label) = label.filter(|label| valid_label(label)) {
            if requirement.is_some_and(|requirement| !requirement.to_string().trim().is_empty()) {
                valid_labels.push(label);
                continue;
            }
        }
        blocked = true;
        scan.warnings.push(
            "a legacy privileged helper declaration has an invalid label or requirement".into(),
        );
    }

    valid_labels.sort_unstable();
    for label in valid_labels {
        cancel.check()?;
        let executable = Path::new(HELPER_ROOT).join(&label);
        let daemon = Path::new(DAEMON_ROOT).join(format!("{label}.plist"));
        blocked |= report(
            scan,
            &executable,
            guarded_file(files, &executable, true),
            "installed executable at the exact location declared for a legacy privileged helper",
        );
        blocked |= report(
            scan,
            &daemon,
            matching_daemon(files, &daemon, &label, &executable),
            "system launch daemon names the declared legacy label and its exact executable path",
        );
    }
    Ok(blocked)
}

fn valid_label(label: &str) -> bool {
    if label.len() > MAX_LABEL_BYTES || !bundle::valid_identifier(label) {
        return false;
    }
    let lower = label.to_ascii_lowercase();
    lower != "com.apple" && !lower.starts_with("com.apple.")
}

fn guarded_file(files: &UnixFiles, path: &Path, executable: bool) -> io::Result<bool> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing service directory"))?;
    match files.require_trusted_local_directory(parent) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    }
    match files.probe_discovery_target(path) {
        Ok(Some(target)) if target.category == Category::File => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
        _ => {
            return Err(io::Error::other(
                "the declared entry is not a guarded regular file",
            ));
        }
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.uid() != ROOT_UID
        || metadata.mode() & SHARED_WRITE_BITS != 0
        || executable && metadata.mode() & EXECUTABLE_BITS == 0
    {
        return Err(io::Error::other(
            "the declared entry has unexpected ownership, type or mode",
        ));
    }
    Ok(true)
}

fn matching_daemon(
    files: &UnixFiles,
    path: &Path,
    label: &str,
    executable: &Path,
) -> io::Result<bool> {
    if !guarded_file(files, path, false)? {
        return Ok(false);
    }
    let daemon = files
        .read_regular(path, MAX_DAEMON_BYTES)
        .and_then(|bytes| plist::dictionary(&bytes))?;
    if plist::string(&daemon, "Label").as_deref() != Some(label)
        || daemon_program(&daemon).as_deref() != executable.to_str()
    {
        return Err(io::Error::other(
            "the daemon label or executable differs from the declaration",
        ));
    }
    Ok(true)
}

fn daemon_program(dictionary: &CFDictionary) -> Option<String> {
    if ["BundleProgram", "RootDirectory", "EnableGlobbing"]
        .into_iter()
        .any(|key| property(dictionary, key).is_some())
    {
        return None;
    }
    if let Some(program) = property(dictionary, "Program") {
        return Some(program.downcast_into::<CFString>()?.to_string());
    }
    let arguments = property(dictionary, "ProgramArguments")?.downcast_into::<CFArray>()?;
    let first = arguments.get(0)?;
    // SAFETY: The array retains this value until its dynamic type is checked.
    let value = unsafe { CFType::wrap_under_get_rule(*first) };
    Some(value.downcast_into::<CFString>()?.to_string())
}

fn property(dictionary: &CFDictionary, key: &str) -> Option<CFType> {
    let key = CFString::new(key);
    let value = dictionary.find(key.as_CFTypeRef())?;
    // SAFETY: The immutable property list retains the borrowed object.
    Some(unsafe { CFType::wrap_under_get_rule(*value) })
}

fn report(scan: &mut Scan, path: &Path, status: io::Result<bool>, reason: &str) -> bool {
    match status {
        Ok(false) => false,
        Ok(true) => {
            scan.proposals.push(Proposal {
                target: Target::File(path.to_path_buf()),
                category: Category::Service,
                evidence: MatchKind::RuleHint,
                reason: reason.into(),
                risk: Risk::High,
                access: Access::ReadOnly(
                    "use the vendor's procedure to remove the system-wide privileged helper".into(),
                ),
            });
            true
        }
        Err(error) => {
            scan.warnings.push(format!(
                "could not verify the legacy privileged helper entry at {}: {error}",
                path.display()
            ));
            true
        }
    }
}
