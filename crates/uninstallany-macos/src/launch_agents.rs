use std::{
    collections::HashMap,
    io,
    path::{Component, Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use core_foundation::{
    array::CFArray,
    base::{CFType, TCFType},
    dictionary::CFDictionary,
    string::CFString,
};
use sha2::{Digest, Sha256};
use uninstallany_core::{
    Access, Cancellation, Category, MatchKind, Proposal, Result, Risk, Target,
};
use uninstallany_unix::UnixFiles;

use crate::{bundle, plist};

const MAX_PLIST_BYTES: usize = 256 * 1024;
const MAX_ASSOCIATED_BUNDLE_IDENTIFIERS: isize = 64;
const MAX_CAPTURE_ENTRIES: usize = 4_096;
const MAX_CAPTURED_AGENTS: usize = 16;
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(1);
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const QUERY_POLL_INTERVAL: Duration = Duration::from_millis(15);
const DISPLAY_OBSERVATION_PREFIX: &str = "display-sha256:";
// Verified in the native launchctl service-not-found exit path. Other
// failures (including a missing domain) do not establish absence.
const SERVICE_NOT_FOUND: i32 = 113;

pub(super) struct AgentCandidate {
    pub(super) proposal: Proposal,
    pub(super) fingerprint: Option<String>,
}

pub(super) struct AgentScope<'a> {
    pub(super) home: &'a Path,
    pub(super) install_location: Option<&'a Path>,
    pub(super) bundle_id: Option<&'a str>,
    pub(super) write_denial: Option<&'a str>,
    /// An empty post-uninstall map still requires prior evidence for writes.
    pub(super) pre_uninstall_files: Option<&'a HashMap<PathBuf, String>>,
}

/// Captures directly attributed user agents before the reviewed bundle moves.
pub(super) fn capture_before_uninstall(
    files: &UnixFiles,
    home: &Path,
    bundle_path: &Path,
    identifier: &str,
    cancel: &Cancellation,
) -> Result<HashMap<PathBuf, String>> {
    cancel.check()?;
    let deadline = Instant::now() + CAPTURE_TIMEOUT;
    let root = user_launch_agents(home);
    let entries = match files.list(&root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            cancel.check()?;
            return Ok(HashMap::new());
        }
        Err(error) => return Err(capture_error(&root, error).into()),
    };
    if entries.len() > MAX_CAPTURE_ENTRIES {
        return Err(capture_error(&root, "directory entry limit reached").into());
    }

    let app_identity = files
        .local_directory_identity(bundle_path)
        .map_err(|error| capture_error(bundle_path, error))?;
    let current =
        bundle::read(files, bundle_path).map_err(|error| capture_error(bundle_path, error))?;
    if current.identifier != identifier {
        return Err(capture_error(bundle_path, "application identifier changed").into());
    }

    let mut evidence = HashMap::new();
    for path in entries {
        cancel.check()?;
        if Instant::now() >= deadline {
            return Err(capture_error(&root, "ownership check timed out").into());
        }
        let Some(observation) = capture_agent(files, &path, bundle_path, identifier)
            .map_err(|error| capture_error(&path, error))?
        else {
            continue;
        };
        if evidence.len() == MAX_CAPTURED_AGENTS {
            return Err(capture_error(&root, "matching LaunchAgent limit reached").into());
        }
        evidence.insert(path, observation);
    }

    if files
        .local_directory_identity(bundle_path)
        .map_err(|error| capture_error(bundle_path, error))?
        != app_identity
    {
        return Err(capture_error(bundle_path, "application directory changed").into());
    }
    cancel.check()?;
    if Instant::now() >= deadline {
        return Err(capture_error(&root, "ownership check timed out").into());
    }
    Ok(evidence)
}

fn capture_agent(
    files: &UnixFiles,
    path: &Path,
    bundle_path: &Path,
    identifier: &str,
) -> io::Result<Option<String>> {
    let Some(stem) = plist_stem(path) else {
        return Ok(None);
    };
    let named_for_app = valid_label(stem) && in_writable_namespace(stem, identifier);
    let decoded = files.read_regular(path, MAX_PLIST_BYTES).and_then(|bytes| {
        let dictionary = plist::dictionary(&bytes)?;
        Ok((bytes, dictionary))
    });
    let (bytes, dictionary) = match decoded {
        Ok(decoded) => decoded,
        Err(error) if named_for_app && error.kind() != io::ErrorKind::NotFound => {
            return Err(error);
        }
        // An unrelated unreadable plist does not establish a program reference.
        Err(_) => return Ok(None),
    };
    let Some(program) = program_in_bundle(bundle_path, &dictionary) else {
        return Ok(None);
    };
    if !has_macho_header(files, &program)? {
        return Ok(None);
    }
    let eligible_name = named_for_app
        && plist::string(&dictionary, "Label").as_deref() == Some(stem)
        && legacy_association(&dictionary, Some(identifier))
            .write_denial()
            .is_none();
    if eligible_name {
        match files.read_observed_regular(path, MAX_PLIST_BYTES) {
            Ok((observed, inspection)) if inspection.access == Access::Allowed => {
                verify_observed_bytes(&bytes, &observed)?;
                return Ok(Some(inspection.fingerprint));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {}
            Err(error) => return Err(error),
        }
    }
    // A direct program reference can block an app move without granting
    // permission to move the plist. Only the private fingerprint can do that.
    let (observed, _) = files.read_trusted_local_file(path, MAX_PLIST_BYTES)?;
    verify_observed_bytes(&bytes, &observed)?;
    Ok(Some(display_observation(&observed)))
}

fn verify_observed_bytes(expected: &[u8], current: &[u8]) -> io::Result<()> {
    if expected == current {
        Ok(())
    } else {
        Err(denied("launchd property list changed during capture"))
    }
}

fn display_observation(bytes: &[u8]) -> String {
    format!("{DISPLAY_OBSERVATION_PREFIX}{:x}", Sha256::digest(bytes))
}

fn read_captured_agent(
    files: &UnixFiles,
    path: &Path,
    expected: &str,
) -> io::Result<(Vec<u8>, Option<String>)> {
    if expected.starts_with(DISPLAY_OBSERVATION_PREFIX) {
        let (bytes, _) = files.read_trusted_local_file(path, MAX_PLIST_BYTES)?;
        if display_observation(&bytes) != expected {
            return Err(denied("launchd property list changed after capture"));
        }
        return Ok((bytes, None));
    }
    let (bytes, inspection) = files.read_observed_regular(path, MAX_PLIST_BYTES)?;
    if inspection.access != Access::Allowed || inspection.fingerprint != expected {
        return Err(denied("launchd property list changed after capture"));
    }
    Ok((bytes, Some(inspection.fingerprint)))
}

fn capture_error(path: &Path, error: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("could not capture {}: {error}", path.display()))
}

/// Discovers service attribution while keeping loaded and system jobs read-only.
pub(super) fn inspect_candidate(
    files: &UnixFiles,
    path: &Path,
    scope: &AgentScope<'_>,
    cancel: &Cancellation,
) -> Result<Option<AgentCandidate>> {
    cancel.check()?;
    let Some(stem) = plist_stem(path) else {
        return Ok(None);
    };
    let captured = scope
        .pre_uninstall_files
        .and_then(|observations| observations.get(path));
    if in_namespace(stem, "com.apple") && captured.is_none() {
        return Ok(None);
    }
    let valid_filename = valid_label(stem);
    let filename_matches = valid_filename
        && scope
            .bundle_id
            .is_some_and(|identifier| in_namespace(stem, identifier));
    let user_agent = in_user_launch_agents(scope.home, path);
    let captured_observation =
        captured.and_then(|expected| read_captured_agent(files, path, expected).ok());
    let captured_matches = captured_observation.is_some();
    let observed = captured_observation.or_else(|| {
        if !user_agent
            || !valid_filename
            || scope.write_denial.is_some()
            || scope.pre_uninstall_files.is_some()
        {
            return None;
        }
        let (bytes, inspection) = files.read_observed_regular(path, MAX_PLIST_BYTES).ok()?;
        let fingerprint = (inspection.access == Access::Allowed).then_some(inspection.fingerprint);
        Some((bytes, fingerprint))
    });
    let (bytes, fingerprint) = match observed {
        Some((bytes, fingerprint)) => (Ok(bytes), fingerprint),
        None => (files.read_regular(path, MAX_PLIST_BYTES), None),
    };
    let dictionary = match bytes.and_then(|bytes| plist::dictionary(&bytes)) {
        Ok(dictionary) => dictionary,
        Err(error) if filename_matches => {
            return Ok(Some(candidate(
                path,
                MatchKind::AppName,
                "filename matches the selected app's bundle identifier",
                Access::ReadOnly(format!("cannot verify the launchd property list: {error}")),
                None,
            )));
        }
        Err(_) => return Ok(None),
    };
    let label = plist::string(&dictionary, "Label").filter(|label| valid_label(label));
    let label_matches = label
        .as_deref()
        .zip(scope.bundle_id)
        .is_some_and(|(label, identifier)| in_namespace(label, identifier));
    let writable_label = label
        .as_deref()
        .zip(scope.bundle_id)
        .is_some_and(|(label, identifier)| in_writable_namespace(label, identifier));
    let application = scope.install_location.zip(scope.bundle_id);
    let program_owned = application.is_some_and(|(bundle_path, identifier)| {
        let Some(program) = program_in_bundle(bundle_path, &dictionary) else {
            return false;
        };
        match scope.pre_uninstall_files {
            // The program is gone after official uninstall. Only the
            // same observed plist can inherit its previous attribution.
            Some(_) => captured_matches,
            None => {
                bundle::read(files, bundle_path)
                    .is_ok_and(|current| current.identifier == identifier)
                    && has_macho_header(files, &program).is_ok_and(|matches| matches)
            }
        }
    });
    let association = legacy_association(&dictionary, scope.bundle_id);
    let (evidence, reason) = if program_owned {
        let reason = if scope.pre_uninstall_files.is_some() {
            "unchanged launchd property list points into the application reviewed before uninstall"
        } else {
            "launchd program points into the selected application bundle"
        };
        (MatchKind::ExactIdentity, reason)
    } else if label_matches {
        (
            MatchKind::ExactIdentity,
            "launchd label matches the selected app's bundle identifier",
        )
    } else if matches!(
        association,
        LegacyAssociation::Exclusive | LegacyAssociation::Shared
    ) {
        (
            MatchKind::RuleHint,
            "legacy launchd declaration lists the selected app's exact bundle identifier",
        )
    } else if filename_matches {
        (
            MatchKind::AppName,
            "filename matches the selected app's bundle identifier",
        )
    } else {
        return Ok(None);
    };

    let access = if !user_agent {
        Access::ReadOnly("system-wide launchd records require separate authorization".into())
    } else if let Some(reason) = association.write_denial() {
        Access::ReadOnly(reason.into())
    } else if !program_owned {
        let reason = if scope.pre_uninstall_files.is_some() {
            scope.write_denial.unwrap_or(
                "cleanup requires the same verified LaunchAgent observed before uninstall",
            )
        } else {
            "the launchd program could not be attributed to this app"
        };
        Access::ReadOnly(reason.into())
    } else if !writable_label {
        Access::ReadOnly("this label is outside the app's bundle identifier namespace".into())
    } else if !valid_filename || label.as_deref() != Some(stem) {
        Access::ReadOnly("the filename must exactly match the verified launchd label".into())
    } else if let Some(reason) = scope.write_denial {
        Access::ReadOnly(reason.into())
    } else if fingerprint.is_none() {
        Access::ReadOnly("the property list could not be bound to the quarantine preview".into())
    } else {
        let state = require_label_inactive(stem, cancel);
        cancel.check()?;
        match state {
            Ok(()) => Access::Allowed,
            Err(error) => Access::ReadOnly(error.to_string()),
        }
    };
    let fingerprint = fingerprint.filter(|_| access == Access::Allowed);
    Ok(Some(candidate(path, evidence, reason, access, fingerprint)))
}

/// Checks the actual label of a directly attributed job before moving its bundle.
pub(super) fn require_attributed_inactive(
    files: &UnixFiles,
    path: &Path,
    expected: &str,
    cancel: &Cancellation,
) -> io::Result<()> {
    let (bytes, _) = read_captured_agent(files, path, expected)?;
    let dictionary = plist::dictionary(&bytes)?;
    let label = plist::string(&dictionary, "Label")
        .filter(|label| valid_label(label))
        .ok_or_else(|| denied("could not verify the attributed launchd label"))?;
    require_label_inactive(&label, cancel)
}

/// Rechecks the content identity and launchd state immediately before quarantine.
pub(super) fn require_inactive(
    files: &UnixFiles,
    home: &Path,
    path: &Path,
    expected: &str,
    cancel: &Cancellation,
) -> io::Result<()> {
    let stem = user_label(home, path)?;
    let (bytes, inspection) = files.read_observed_regular(path, MAX_PLIST_BYTES)?;
    if inspection.access != Access::Allowed || inspection.fingerprint != expected {
        return Err(denied("launchd property list changed after review"));
    }
    let dictionary = plist::dictionary(&bytes)?;
    if plist::string(&dictionary, "Label").as_deref() != Some(stem) {
        return Err(denied("the filename no longer matches the launchd label"));
    }
    require_label_inactive(stem, cancel)
}

/// Rechecks the previously verified filename before restoring its quarantined file.
pub(super) fn require_inactive_at_restore(home: &Path, path: &Path) -> io::Result<()> {
    require_label_inactive(user_label(home, path)?, &Cancellation::default())
}

fn candidate(
    path: &Path,
    evidence: MatchKind,
    reason: &str,
    access: Access,
    fingerprint: Option<String>,
) -> AgentCandidate {
    let is_daemon = path
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|name| name == "LaunchDaemons");
    AgentCandidate {
        proposal: Proposal {
            target: Target::File(path.to_owned()),
            category: if is_daemon {
                Category::Service
            } else {
                Category::Startup
            },
            evidence,
            reason: reason.into(),
            risk: Risk::High,
            access,
        },
        fingerprint,
    }
}

fn in_user_launch_agents(home: &Path, path: &Path) -> bool {
    path.parent() == Some(user_launch_agents(home).as_path())
}

fn user_launch_agents(home: &Path) -> PathBuf {
    home.join("Library/LaunchAgents")
}

fn user_label<'a>(home: &Path, path: &'a Path) -> io::Result<&'a str> {
    if !in_user_launch_agents(home, path) {
        return Err(denied(
            "only the current user's LaunchAgents can be changed",
        ));
    }
    filename_label(path).ok_or_else(|| denied("invalid or protected launchd label"))
}

fn filename_label(path: &Path) -> Option<&str> {
    plist_stem(path).filter(|label| valid_label(label))
}

fn plist_stem(path: &Path) -> Option<&str> {
    path.file_name()?.to_str()?.strip_suffix(".plist")
}

fn valid_label(label: &str) -> bool {
    label.len() <= 249
        && label.contains('.')
        && !in_namespace(label, "com.apple")
        && label.split('.').all(|part| {
            part.as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
}

fn in_namespace(label: &str, identifier: &str) -> bool {
    if identifier.is_empty() {
        return false;
    }
    let Some(prefix) = label.get(..identifier.len()) else {
        return false;
    };
    prefix.eq_ignore_ascii_case(identifier)
        && (label.len() == identifier.len()
            || label.as_bytes().get(identifier.len()) == Some(&b'.'))
}

fn in_writable_namespace(label: &str, identifier: &str) -> bool {
    label == identifier
        || label
            .strip_prefix(identifier)
            .is_some_and(|suffix| suffix.starts_with('.'))
}

fn program_in_bundle(bundle: &Path, dictionary: &CFDictionary) -> Option<PathBuf> {
    if !bundle::is_app(bundle) || !is_literal_absolute(bundle) {
        return None;
    }
    let program = PathBuf::from(launch_program(dictionary)?);
    if !is_literal_absolute(&program) {
        return None;
    }
    let relative = program.strip_prefix(bundle.join("Contents")).ok()?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|part| bundle::is_app(Path::new(part.as_os_str())))
    {
        return None;
    }
    Some(program)
}

fn has_macho_header(files: &UnixFiles, program: &Path) -> io::Result<bool> {
    match files.read_prefix(program, 4) {
        Ok(header) => Ok(matches!(
            header.as_slice(),
            [0xfe, 0xed, 0xfa, 0xce | 0xcf]
                | [0xce | 0xcf, 0xfa, 0xed, 0xfe]
                | [0xca, 0xfe, 0xba, 0xbe | 0xbf]
                | [0xbe | 0xbf, 0xba, 0xfe, 0xca]
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn is_literal_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        && path
            .as_os_str()
            .as_encoded_bytes()
            .split(|byte| *byte == b'/')
            .all(|part| part != b"." && !part.contains(&0))
}

fn launch_program(dictionary: &CFDictionary) -> Option<String> {
    // These options can resolve a different executable than the literal path.
    if ["BundleProgram", "RootDirectory", "EnableGlobbing"]
        .iter()
        .any(|key| plist_value(dictionary, key).is_some())
    {
        return None;
    }
    if let Some(program) = plist_value(dictionary, "Program") {
        return Some(program.downcast_into::<CFString>()?.to_string());
    }
    let arguments = plist_value(dictionary, "ProgramArguments")?.downcast_into::<CFArray>()?;
    let first = arguments.get(0)?;
    // SAFETY: The typed property list array retains its elements. This adds a
    // retain while the borrowed value remains valid, before testing its type.
    let first = unsafe { CFType::wrap_under_get_rule(*first) };
    Some(first.downcast_into::<CFString>()?.to_string())
}

#[derive(Clone, Copy)]
enum LegacyAssociation {
    Undeclared,
    Exclusive,
    Shared,
    Different,
    Malformed,
}

impl LegacyAssociation {
    fn write_denial(self) -> Option<&'static str> {
        match self {
            Self::Undeclared | Self::Exclusive => None,
            Self::Shared => Some("the legacy launchd plist lists multiple bundle associations"),
            Self::Different => Some("the legacy launchd plist lists a different bundle"),
            Self::Malformed => Some("the legacy launchd bundle association is malformed"),
        }
    }
}

fn legacy_association(dictionary: &CFDictionary, selected: Option<&str>) -> LegacyAssociation {
    let Some(value) = plist_value(dictionary, "AssociatedBundleIdentifiers") else {
        return LegacyAssociation::Undeclared;
    };
    if let Some(identifier) = value.downcast::<CFString>() {
        let identifier = identifier.to_string();
        return if !bundle::valid_identifier(&identifier) {
            LegacyAssociation::Malformed
        } else if Some(identifier.as_str()) == selected {
            LegacyAssociation::Exclusive
        } else {
            LegacyAssociation::Different
        };
    }
    let Some(identifiers) = value.downcast_into::<CFArray>() else {
        return LegacyAssociation::Malformed;
    };
    let count = identifiers.len();
    if !(1..=MAX_ASSOCIATED_BUNDLE_IDENTIFIERS).contains(&count) {
        return LegacyAssociation::Malformed;
    }
    let mut matches_selected = false;
    for entry in &identifiers {
        // SAFETY: The property-list array retains its elements while they
        // are borrowed, and the dynamic type is checked before use.
        let value = unsafe { CFType::wrap_under_get_rule(*entry) };
        let Some(identifier) = value.downcast_into::<CFString>() else {
            return LegacyAssociation::Malformed;
        };
        let identifier = identifier.to_string();
        if !bundle::valid_identifier(&identifier) {
            return LegacyAssociation::Malformed;
        }
        matches_selected |= Some(identifier.as_str()) == selected;
    }
    match (matches_selected, count) {
        (false, _) => LegacyAssociation::Different,
        (true, 1) => LegacyAssociation::Exclusive,
        (true, _) => LegacyAssociation::Shared,
    }
}

fn plist_value(dictionary: &CFDictionary, key: &str) -> Option<CFType> {
    let key = CFString::new(key);
    let value = dictionary.find(key.as_CFTypeRef())?;
    // SAFETY: The property list dictionary retains the value while this call
    // adds its own retain.
    Some(unsafe { CFType::wrap_under_get_rule(*value) })
}

fn require_label_inactive(label: &str, cancel: &Cancellation) -> io::Result<()> {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: Darwin's geteuid takes no arguments and returns a uid_t (u32).
    let uid = unsafe { geteuid() };
    if uid == 0 {
        return Err(denied(
            "launchd state must be checked by the current non-root user",
        ));
    }
    for namespace in ["gui", "user"] {
        let domain = format!("{namespace}/{uid}");
        if !print_status(&domain, cancel)?.success() {
            return Err(denied(format!(
                "could not verify the launchd domain {domain}"
            )));
        }
        let service = format!("{domain}/{label}");
        let status = print_status(&service, cancel)?;
        match status.code() {
            Some(SERVICE_NOT_FOUND) => {}
            _ if status.success() => {
                return Err(denied("launchd still has a registration for this label"));
            }
            _ => {
                return Err(denied(format!(
                    "could not verify launchd service absence: {status}"
                )));
            }
        }
    }
    Ok(())
}

fn print_status(target: &str, cancel: &Cancellation) -> io::Result<ExitStatus> {
    cancel.check().map_err(io::Error::other)?;
    let mut child = Command::new("/bin/launchctl")
        .args(["print", target])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let started = Instant::now();
    let result = loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(error) => break Err(error),
        }
        if cancel.check().is_err() {
            break Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "launchd query was cancelled",
            ));
        }
        if started.elapsed() >= QUERY_TIMEOUT {
            break Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "launchd query timed out",
            ));
        }
        thread::sleep(QUERY_POLL_INTERVAL);
    };
    // This only terminates the query process started above, never the service.
    let _ = child.kill();
    let _ = child.wait();
    result
}

fn denied(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.into())
}
