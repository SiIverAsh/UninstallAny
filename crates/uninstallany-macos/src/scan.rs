use std::{
    collections::HashMap,
    ffi::OsStr,
    io,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use uninstallany_core::{
    Access, AppRecord, Cancellation, Category, Inspection, MatchKind, Proposal, Result, Risk, Scan,
    ScanMode, Target, match_name,
};
use uninstallany_unix::UnixFiles;
use uuid::Uuid;

use crate::{bundle, launch_agents, plist};

const MAX_ENTRIES_PER_AREA: usize = 4_096;
const MAX_CANDIDATES: usize = 2_048;
const MAX_DESCENT_DEPTH: u8 = 4;
const MAX_LAUNCH_PLIST_BYTES: usize = 262_144;
const MAX_DIAGNOSTIC_REPORTS: usize = 256;
const MAX_DIAGNOSTIC_HEADER_BYTES: usize = 8 * 1_024;
const DIAGNOSTIC_REPORTS_DIRECTORY: &str = "Library/Logs/DiagnosticReports";
const HTTP_STORAGE_DIRECTORY: &str = "Library/HTTPStorages";
const WEBKIT_DIRECTORY: &str = "Library/WebKit";
const WEBSITE_DATA_DIRECTORY: &str = "WebsiteData";
const CANDIDATE_LIMIT_WARNING: &str = "macOS scan reached its candidate limit";
const SYSTEM_LIBRARY_WRITE_DENIAL: &str =
    "system-wide Library entries need separate confirmed ownership and authorization";

#[derive(Clone, Copy, Eq, PartialEq)]
enum Area {
    Support,
    Cache,
    Preferences,
    Logs,
    Containers,
    SharedContainers,
    SavedState,
    LaunchAgents,
    LaunchDaemons,
}

const USER_AREAS: [Area; 8] = [
    Area::Support,
    Area::Cache,
    Area::Preferences,
    Area::Logs,
    Area::Containers,
    Area::SharedContainers,
    Area::SavedState,
    Area::LaunchAgents,
];
const MACHINE_AREAS: [Area; 9] = [
    Area::Support,
    Area::Cache,
    Area::Preferences,
    Area::Logs,
    Area::Containers,
    Area::SharedContainers,
    Area::SavedState,
    Area::LaunchAgents,
    Area::LaunchDaemons,
];

impl Area {
    fn name(self) -> &'static str {
        match self {
            Self::Support => "Application Support",
            Self::Cache => "Caches",
            Self::Preferences => "Preferences",
            Self::Logs => "Logs",
            Self::Containers => "Containers",
            Self::SharedContainers => "Group Containers",
            Self::SavedState => "Saved Application State",
            Self::LaunchAgents => "LaunchAgents",
            Self::LaunchDaemons => "LaunchDaemons",
        }
    }

    fn is_launch(self) -> bool {
        matches!(self, Self::LaunchAgents | Self::LaunchDaemons)
    }

    fn list_descendants(self) -> bool {
        matches!(self, Self::Support | Self::Cache | Self::Logs)
    }

    fn directory_preferred(self) -> bool {
        matches!(
            self,
            Self::Containers | Self::SharedContainers | Self::SavedState
        )
    }
}

pub(super) fn scan_roots(home: &Path) -> Vec<PathBuf> {
    USER_AREAS
        .into_iter()
        .map(|area| home.join("Library").join(area.name()))
        .chain([WEBKIT_DIRECTORY, HTTP_STORAGE_DIRECTORY].map(|area| home.join(area)))
        .chain(
            MACHINE_AREAS
                .into_iter()
                .map(|area| Path::new("/Library").join(area.name())),
        )
        .collect()
}

/// Checks whether a system path is inside a configured Library scan area.
pub(super) fn is_system_library_residual_path(path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix("/Library") else {
        return false;
    };
    let mut components = relative.components();
    let Some(area) = components.next() else {
        return false;
    };
    components.next().is_some()
        && MACHINE_AREAS
            .iter()
            .any(|candidate| area.as_os_str() == candidate.name())
}

pub(super) fn application(
    files: &UnixFiles,
    search: &Search<'_>,
    cancel: &Cancellation,
) -> Result<Scan> {
    let mut scan = Scan::default();
    let mut sandbox_support_root = None;
    for (library, areas, system) in [
        (search.home.join("Library"), USER_AREAS.as_slice(), false),
        (PathBuf::from("/Library"), MACHINE_AREAS.as_slice(), true),
    ] {
        for area in areas {
            if let Some(root) =
                scan_area(files, &mut scan, &library, (*area, system), search, cancel)?
            {
                sandbox_support_root = Some(root);
            }
            if scan.proposals.len() == MAX_CANDIDATES {
                scan.warnings.push(CANDIDATE_LIMIT_WARNING.into());
                return Ok(scan);
            }
        }
    }
    // Support data can contain thousands of files. Preserve the preview
    // budget for the existing areas before walking this optional subtree.
    if let Some((root, identifier)) = sandbox_support_root.zip(search.identifier) {
        scan_sandbox_application_support(
            files,
            &mut scan,
            root,
            (identifier, search.mode),
            cancel,
        )?;
    }
    if scan.proposals.len() < MAX_CANDIDATES {
        scan_webkit_website_data(files, &mut scan, search, cancel)?;
    }
    if scan.proposals.len() < MAX_CANDIDATES {
        scan_diagnostic_reports(files, &mut scan, search, cancel)?;
    }
    if scan.proposals.len() == MAX_CANDIDATES {
        scan.warnings.push(CANDIDATE_LIMIT_WARNING.into());
    }
    Ok(scan)
}

fn scan_diagnostic_reports(
    files: &UnixFiles,
    scan: &mut Scan,
    search: &Search<'_>,
    cancel: &Cancellation,
) -> Result<()> {
    let Some(identifier) = search.identifier.filter(|id| {
        let lower = id.to_ascii_lowercase();
        bundle::valid_identifier(id) && lower != "com.apple" && !lower.starts_with("com.apple.")
    }) else {
        return Ok(());
    };
    cancel.check()?;
    let root = search.home.join(DIAGNOSTIC_REPORTS_DIRECTORY);
    let Some(children) = read_children(files, &root, scan) else {
        return Ok(());
    };
    let mut reports = children
        .into_iter()
        .filter(|path| path.extension() == Some(OsStr::new("ips")));
    let mut unavailable = 0;
    let mut first_probe_failure = None;
    for path in reports.by_ref().take(MAX_DIAGNOSTIC_REPORTS) {
        cancel.check()?;
        if scan.proposals.len() >= MAX_CANDIDATES {
            break;
        }
        match files.probe_discovery_target(&path) {
            Ok(Some(target)) if target.category == Category::File => {}
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                unavailable += 1;
                first_probe_failure.get_or_insert(error);
                continue;
            }
        }
        match files.read_prefix(&path, MAX_DIAGNOSTIC_HEADER_BYTES) {
            Ok(bytes) if diagnostic_header_matches(&bytes, identifier) => {}
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                unavailable += 1;
                first_probe_failure.get_or_insert(error);
                continue;
            }
        }

        let (access, fingerprint) = if let Some(reason) = search.write_denial {
            (Access::ReadOnly(reason.into()), None)
        } else {
            match files.read_macos_observed_regular_prefix(&path, MAX_DIAGNOSTIC_HEADER_BYTES) {
                Ok((bytes, inspection)) if diagnostic_header_matches(&bytes, identifier) => {
                    (inspection.access, Some(inspection.fingerprint))
                }
                Ok(_) => continue,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => (Access::ReadOnly(error.to_string()), None),
            }
        };
        let proposal = Proposal {
            target: Target::File(path),
            category: Category::File,
            evidence: MatchKind::ExactIdentity,
            reason: "the crash report header identifies the exact application Bundle ID".into(),
            risk: Risk::High,
            access,
        };
        match fingerprint {
            Some(fingerprint) => scan.push_observed(proposal, fingerprint),
            None => scan.proposals.push(proposal),
        }
    }
    if reports.next().is_some() {
        scan.warnings
            .push("DiagnosticReports reached the crash-report inspection limit".into());
    }
    if let Some(error) = first_probe_failure {
        scan.warnings.push(format!(
            "Could not inspect {unavailable} files in DiagnosticReports: {error}"
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
struct DiagnosticHeader<'a> {
    #[serde(rename = "bundleID")]
    bundle_id: &'a str,
    bug_type: &'a str,
}

fn diagnostic_header_matches(prefix: &[u8], identifier: &str) -> bool {
    let Some(first_line_end) = prefix.iter().position(|byte| *byte == b'\n') else {
        return false;
    };
    serde_json::from_slice::<DiagnosticHeader<'_>>(&prefix[..first_line_end])
        .is_ok_and(|header| header.bundle_id == identifier && header.bug_type == "309")
}

fn scan_webkit_website_data(
    files: &UnixFiles,
    scan: &mut Scan,
    search: &Search<'_>,
    cancel: &Cancellation,
) -> Result<()> {
    let Some(identifier) = search.identifier else {
        return Ok(());
    };
    cancel.check()?;
    let root = search.home.join(WEBKIT_DIRECTORY);
    let path = root.join(identifier).join(WEBSITE_DATA_DIRECTORY);
    if files.macos_webkit_website_data_bundle_id(&path) != Some(identifier) {
        return Ok(());
    }
    if !has_literal_path(
        files,
        scan,
        &root,
        &[identifier, WEBSITE_DATA_DIRECTORY],
        cancel,
    )? {
        return Ok(());
    }
    scan_webkit_store(files, scan, path, search.write_denial, cancel)
}

fn has_literal_path(
    files: &UnixFiles,
    scan: &mut Scan,
    root: &Path,
    components: &[&str],
    cancel: &Cancellation,
) -> Result<bool> {
    // A case-folding lookup can succeed for a differently spelled directory.
    let mut parent = root.to_path_buf();
    for component in components {
        cancel.check()?;
        let child = parent.join(component);
        if !read_children(files, &parent, scan).is_some_and(|paths| {
            paths
                .iter()
                .any(|entry| entry.as_os_str() == child.as_os_str())
        }) {
            return Ok(false);
        }
        parent = child;
    }
    Ok(true)
}

fn scan_webkit_store(
    files: &UnixFiles,
    scan: &mut Scan,
    path: PathBuf,
    write_denial: Option<&str>,
    cancel: &Cancellation,
) -> Result<()> {
    cancel.check()?;
    match files.probe_discovery_target(&path) {
        Ok(Some(target)) if target.category == Category::Directory => {}
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            scan.warnings
                .push(format!("could not inspect {}: {error}", path.display()));
            return Ok(());
        }
    }
    let (access, fingerprint) = if let Some(reason) = write_denial {
        (Access::ReadOnly(reason.into()), None)
    } else {
        match files.inspect_macos_webkit_website_data(&path) {
            Ok(Inspection {
                fingerprint,
                access,
            }) => (access, Some(fingerprint)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => (Access::ReadOnly(error.to_string()), None),
        }
    };
    cancel.check()?;
    let proposal = Proposal {
        target: Target::File(path),
        category: Category::Directory,
        evidence: MatchKind::ExactIdentity,
        reason: "exact Bundle ID match for local WebKit website data".into(),
        risk: Risk::High,
        access,
    };
    match fingerprint {
        Some(fingerprint) => scan.push_observed(proposal, fingerprint),
        None => scan.proposals.push(proposal),
    }
    Ok(())
}

/// Reviews the exact per-app HTTP store after the app's absence is verified.
pub(super) fn http_storage_after_uninstall(
    files: &UnixFiles,
    scan: &mut Scan,
    search: &Search<'_>,
    cancel: &Cancellation,
) -> Result<()> {
    if scan.proposals.len() >= MAX_CANDIDATES {
        return Ok(());
    }
    let Some(identifier) = search.identifier else {
        return Ok(());
    };
    cancel.check()?;
    let root = search.home.join(HTTP_STORAGE_DIRECTORY);
    let path = root.join(identifier);
    if files.macos_http_storage_bundle_id(&path) != Some(identifier) {
        return Ok(());
    }
    // Use the directory entry's literal spelling on case-folding volumes.
    if !read_children(files, &root, scan).is_some_and(|entries| {
        entries
            .iter()
            .any(|entry| entry.as_os_str() == path.as_os_str())
    }) {
        return Ok(());
    }
    cancel.check()?;
    match files.probe_discovery_target(&path) {
        Ok(Some(target)) if target.category == Category::Directory => {}
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            scan.warnings
                .push(format!("could not inspect {}: {error}", path.display()));
            return Ok(());
        }
    }
    let (access, fingerprint) = if let Some(reason) = search.write_denial {
        (Access::ReadOnly(reason.into()), None)
    } else {
        match files.inspect_macos_http_storage(&path) {
            Ok(Inspection {
                fingerprint,
                access,
            }) => (access, Some(fingerprint)),
            Err(error) => (Access::ReadOnly(error.to_string()), None),
        }
    };
    cancel.check()?;
    let proposal = Proposal {
        target: Target::File(path),
        category: Category::Directory,
        evidence: MatchKind::ExactIdentity,
        reason: "exact Bundle ID match for local HTTP storage".into(),
        risk: Risk::High,
        access,
    };
    match fingerprint {
        Some(fingerprint) => scan.push_observed(proposal, fingerprint),
        None => scan.proposals.push(proposal),
    }
    if scan.proposals.len() == MAX_CANDIDATES {
        scan.warnings.push(CANDIDATE_LIMIT_WARNING.into());
    }
    Ok(())
}

/// Finds still-present shared container names from pre-uninstall declarations.
pub(super) fn declared_groups(
    files: &UnixFiles,
    home: &Path,
    identifiers: &[String],
    cancel: &Cancellation,
) -> Result<Scan> {
    let mut scan = Scan::default();
    for library in [home.join("Library"), PathBuf::from("/Library")] {
        cancel.check()?;
        let root = library.join(Area::SharedContainers.name());
        let children = read_children(files, &root, &mut scan).unwrap_or_default();
        if children.len() > MAX_ENTRIES_PER_AREA {
            scan.warnings.push(format!(
                "{} reached its directory entry limit",
                root.display()
            ));
        }
        for path in children.into_iter().take(MAX_ENTRIES_PER_AREA) {
            cancel.check()?;
            if path
                .file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| identifiers.iter().any(|id| id == name))
            {
                scan.proposals.push(app_group_proposal(path));
            }
        }
    }
    Ok(scan)
}

pub(super) const OWNERSHIP_UNCERTAIN: &str =
    "another app instance or an unavailable inventory source may share this data";
pub(super) const APPLICATION_RUNNING: &str =
    "quit the application before cleaning up its leftovers";

pub(super) struct Search<'a> {
    pub(super) home: &'a Path,
    pub(super) app: &'a AppRecord,
    pub(super) mode: ScanMode,
    pub(super) identifier: Option<&'a str>,
    pub(super) group_identifiers: &'a [String],
    pub(super) write_denial: Option<&'static str>,
    pub(super) name_attribution_uncertain: bool,
    pub(super) pre_uninstall_files: Option<&'a HashMap<PathBuf, String>>,
}

fn scan_area(
    files: &UnixFiles,
    scan: &mut Scan,
    library: &Path,
    (area, system): (Area, bool),
    search: &Search<'_>,
    cancel: &Cancellation,
) -> Result<Option<PathBuf>> {
    let root = library.join(area.name());
    let mut sandbox_support_root = None;
    let children = read_children(files, &root, scan).unwrap_or_default();
    if children.len() > MAX_ENTRIES_PER_AREA {
        scan.warnings.push(format!(
            "{} reached its directory entry limit",
            root.display()
        ));
    }
    let agent_scope = launch_agents::AgentScope {
        home: search.home,
        install_location: search.app.install_location.as_deref(),
        bundle_id: search.identifier,
        write_denial: search.write_denial,
        pre_uninstall_files: search.pre_uninstall_files,
    };
    for path in children.into_iter().take(MAX_ENTRIES_PER_AREA) {
        cancel.check()?;
        if scan.proposals.len() >= MAX_CANDIDATES {
            break;
        }
        let launch_candidate = if area.is_launch() {
            launch_agents::inspect_candidate(files, &path, &agent_scope, cancel)?
        } else {
            None
        };
        if let Some(candidate) = launch_candidate {
            match candidate.fingerprint {
                Some(fingerprint) => scan.push_observed(candidate.proposal, fingerprint),
                None => scan.proposals.push(candidate.proposal),
            }
            continue;
        }
        let Some(name) = path.file_name().and_then(OsStr::to_str) else {
            continue;
        };
        if area == Area::SharedContainers && search.group_identifiers.iter().any(|id| id == name) {
            scan.proposals.push(app_group_proposal(path));
            continue;
        }
        let Some(evidence) = evidence(area, name, search) else {
            continue;
        };
        let literal_identity = search.identifier.filter(|identifier| {
            (match area {
                Area::Preferences => name.strip_suffix(".plist"),
                Area::SavedState => name.strip_suffix(".savedState"),
                _ => Some(name),
            }) == Some(*identifier)
        });
        let access = if system {
            Access::ReadOnly(SYSTEM_LIBRARY_WRITE_DENIAL.into())
        } else if area == Area::SharedContainers {
            Access::ReadOnly("App Group containers can be shared by several applications".into())
        } else if area.is_launch() {
            Access::ReadOnly(
                "unloading and reconstructing this launchd registration is not enabled".into(),
            )
        } else if evidence == MatchKind::FuzzyName {
            Access::ReadOnly("a fuzzy name match is insufficient for cleanup".into())
        } else if evidence == MatchKind::ExactIdentity && literal_identity.is_none() {
            // Differently spelled entries can be distinct on case-sensitive APFS.
            Access::ReadOnly(
                "the entry does not exactly match the recorded bundle identifier".into(),
            )
        } else if let Some(reason) = search.write_denial {
            Access::ReadOnly(reason.into())
        } else if evidence == MatchKind::AppName && search.name_attribution_uncertain {
            Access::ReadOnly("another application may use the same residual name".into())
        } else {
            Access::Allowed
        };
        let safe_descendants = access == Access::Allowed
            && literal_identity.is_some()
            && (area.list_descendants() || area == Area::SavedState);
        let sandbox_identifier =
            literal_identity.filter(|_| area == Area::Containers && access == Access::Allowed);
        let contents = if area.list_descendants() || area == Area::SavedState {
            read_children(files, &path, scan)
        } else {
            None
        };
        let mut directory_reason = None;
        if safe_descendants
            && contents.is_some()
            && matches!(area, Area::Cache | Area::Logs | Area::SavedState)
        {
            let inspected = if area == Area::SavedState {
                files.inspect_macos_saved_state_directory(&path)
            } else {
                files.inspect_macos_cache_directory(&path)
            };
            match inspected {
                Ok(Inspection {
                    fingerprint,
                    access: Access::Allowed,
                }) => {
                    scan.push_observed(
                        Proposal {
                            target: Target::File(path),
                            category: Category::Directory,
                            evidence,
                            reason: if area == Area::SavedState {
                                "exact Bundle ID match for a private directory containing saved window and session state".into()
                            } else {
                                format!(
                                    "bundle identifier matched a verified private {} directory",
                                    area.name()
                                )
                            },
                            risk: Risk::High,
                            access: Access::Allowed,
                        },
                        fingerprint,
                    );
                    // Keep the directory and its descendants out of the same plan.
                    continue;
                }
                Ok(Inspection {
                    access: Access::ReadOnly(reason),
                    ..
                }) => directory_reason = Some(reason),
                Err(error) => directory_reason = Some(error.to_string()),
            }
        }
        let category = if area == Area::LaunchDaemons {
            Category::Service
        } else if area.is_launch() {
            Category::Startup
        } else if contents.is_some() || area.directory_preferred() {
            Category::Directory
        } else {
            Category::File
        };
        let reason = describe_match(files, area, &path, search.identifier, evidence);
        let contents_retained = category == Category::Directory && access == Access::Allowed;
        scan.proposals.push(Proposal {
            target: Target::File(path),
            category,
            evidence,
            reason,
            risk: if matches!(area, Area::Cache | Area::Preferences | Area::Logs) {
                Risk::Normal
            } else {
                Risk::High
            },
            access: if contents_retained {
                Access::ReadOnly(directory_reason.unwrap_or_else(|| {
                    if safe_descendants || sandbox_identifier.is_some() {
                        "directory retained with eligible individual entries shown separately"
                            .into()
                    } else {
                        "directory retained because exclusive ownership was not established".into()
                    }
                }))
            } else {
                access
            },
        });
        if let Some(identifier) = sandbox_identifier {
            sandbox_support_root = scan_sandbox(
                files,
                scan,
                (&root.join(identifier), identifier),
                search.mode,
                cancel,
            )?;
        } else if safe_descendants {
            if let Some(children) = contents {
                scan_children(files, scan, children, area != Area::Cache, cancel)?;
            }
        }
    }
    if let (Area::Preferences, Some(identifier)) = (area, search.identifier) {
        let write_denial = system
            .then_some(SYSTEM_LIBRARY_WRITE_DENIAL)
            .or(search.write_denial);
        scan_by_host_preferences(files, scan, &root, (identifier, write_denial), cancel)?;
    }
    Ok(sandbox_support_root)
}

fn scan_by_host_preferences(
    files: &UnixFiles,
    scan: &mut Scan,
    preferences: &Path,
    (identifier, write_denial): (&str, Option<&str>),
    cancel: &Cancellation,
) -> Result<()> {
    cancel.check()?;
    if scan.proposals.len() >= MAX_CANDIDATES {
        return Ok(());
    }
    let root = preferences.join("ByHost");
    let children = read_children(files, &root, scan).unwrap_or_default();
    if children.len() > MAX_ENTRIES_PER_AREA {
        scan.warnings.push(format!(
            "{} reached its directory entry limit",
            root.display()
        ));
    }
    for path in children.into_iter().take(MAX_ENTRIES_PER_AREA) {
        cancel.check()?;
        if scan.proposals.len() >= MAX_CANDIDATES {
            break;
        }
        let matched = path
            .file_name()
            .and_then(OsStr::to_str)
            .and_then(|name| name.strip_suffix(".plist"))
            .and_then(|stem| stem.rsplit_once('.'))
            .is_some_and(|(bundle, host)| {
                bundle == identifier
                    && Uuid::parse_str(host)
                        .is_ok_and(|id| host.eq_ignore_ascii_case(&id.hyphenated().to_string()))
            });
        if !matched {
            continue;
        }
        match files.probe_discovery_target(&path) {
            Ok(Some(target)) if target.category == Category::File => {}
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                scan.warnings
                    .push(format!("could not inspect {}: {error}", path.display()));
                continue;
            }
        }
        let (access, fingerprint) = if let Some(reason) = write_denial {
            (Access::ReadOnly(reason.into()), None)
        } else {
            match files.inspect_macos_regular_file(&path) {
                Ok(Inspection {
                    access,
                    fingerprint,
                }) => (access, Some(fingerprint)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    if error.kind() != io::ErrorKind::PermissionDenied {
                        scan.warnings
                            .push(format!("could not inspect {}: {error}", path.display()));
                    }
                    (Access::ReadOnly(error.to_string()), None)
                }
            }
        };
        let proposal = Proposal {
            target: Target::File(path),
            category: Category::File,
            evidence: MatchKind::ExactIdentity,
            reason: "exact Bundle ID match for a host-specific preferences plist".into(),
            risk: Risk::High,
            access,
        };
        match fingerprint {
            Some(fingerprint) => scan.push_observed(proposal, fingerprint),
            None => scan.proposals.push(proposal),
        }
    }
    Ok(())
}

fn app_group_proposal(path: PathBuf) -> Proposal {
    // Listing the parent yields the name without opening the protected
    // container. Other members can still depend on the shared files.
    Proposal {
        target: Target::File(path),
        category: Category::Directory,
        evidence: MatchKind::ExactIdentity,
        reason: "entry name matches the app's signed App Group declaration".into(),
        risk: Risk::High,
        access: Access::ReadOnly("App Groups may have other members".into()),
    }
}

fn evidence(area: Area, leaf: &str, search: &Search<'_>) -> Option<MatchKind> {
    let normalized = leaf.to_ascii_lowercase();
    let candidate = match area {
        Area::Preferences | Area::LaunchAgents | Area::LaunchDaemons => {
            normalized.strip_suffix(".plist")?
        }
        Area::SavedState => normalized.strip_suffix(".savedstate")?,
        _ => normalized.as_str(),
    };
    if let Some(identifier) = search.identifier {
        let exact = candidate.eq_ignore_ascii_case(identifier);
        if area == Area::SharedContainers {
            let suffix = candidate
                .strip_suffix(identifier.to_ascii_lowercase().as_str())
                .is_some_and(|prefix| prefix.ends_with('.'));
            return (exact || suffix).then_some(MatchKind::FuzzyName);
        }
        if exact {
            return Some(MatchKind::ExactIdentity);
        }
    }
    if area == Area::SharedContainers || area.is_launch() || area == Area::Containers {
        return None;
    }
    match_name(&search.app.name, None, candidate, None)
}

fn describe_match(
    files: &UnixFiles,
    area: Area,
    path: &Path,
    identifier: Option<&str>,
    evidence: MatchKind,
) -> String {
    if area == Area::SharedContainers {
        return "entry name resembles the app's Bundle ID".into();
    }
    if area.is_launch() {
        let label = files
            .read_regular(path, MAX_LAUNCH_PLIST_BYTES)
            .ok()
            .and_then(|bytes| plist::dictionary(&bytes).ok())
            .and_then(|plist| plist::string(&plist, "Label"));
        if identifier
            .zip(label.as_deref())
            .is_some_and(|(expected, label)| label.eq_ignore_ascii_case(expected))
        {
            return "launchd label and filename match the app bundle identifier".into();
        }
    }
    if evidence == MatchKind::ExactIdentity {
        format!("bundle identifier matched the {} entry", area.name())
    } else {
        format!("application name matched the {} entry", area.name())
    }
}

fn read_children(files: &UnixFiles, path: &Path, scan: &mut Scan) -> Option<Vec<PathBuf>> {
    match files.list(path) {
        Ok(children) => Some(children),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            None
        }
        Err(error) => {
            scan.warnings
                .push(format!("could not scan {}: {error}", path.display()));
            None
        }
    }
}

fn scan_sandbox(
    files: &UnixFiles,
    scan: &mut Scan,
    (container, identifier): (&Path, &str),
    mode: ScanMode,
    cancel: &Cancellation,
) -> Result<Option<PathBuf>> {
    if scan.proposals.len() >= MAX_CANDIDATES {
        return Ok(None);
    }
    // Sandbox homes can contain links to the user's folders. Start only
    // from fixed Library subpaths and let native discovery reject links.
    let library = container.join("Data/Library");
    if mode == ScanMode::AfterOfficialUninstall {
        let path = library.join("WebKit").join(WEBSITE_DATA_DIRECTORY);
        if files.macos_webkit_website_data_bundle_id(&path) == Some(identifier)
            && has_literal_path(
                files,
                scan,
                container,
                &["Data", "Library", "WebKit", WEBSITE_DATA_DIRECTORY],
                cancel,
            )?
        {
            scan_webkit_store(files, scan, path, None, cancel)?;
        }
    }
    if scan.proposals.len() >= MAX_CANDIDATES {
        return Ok(None);
    }
    let preferences = library.join(Area::Preferences.name());
    cancel.check()?;
    scan_sandbox_file(files, scan, preferences.join(format!("{identifier}.plist")));
    scan_by_host_preferences(files, scan, &preferences, (identifier, None), cancel)?;
    for root in [
        library.join(Area::Cache.name()),
        library.join(Area::Logs.name()),
        library
            .join(Area::SavedState.name())
            .join(format!("{identifier}.savedState")),
    ] {
        cancel.check()?;
        if scan.proposals.len() >= MAX_CANDIDATES {
            break;
        }
        if let Some(children) = read_children(files, &root, scan) {
            scan_descendants(files, scan, children, DescendantScope::Sandbox, cancel)?;
        }
    }
    Ok(Some(library.join(Area::Support.name())))
}

fn scan_sandbox_application_support(
    files: &UnixFiles,
    scan: &mut Scan,
    root: PathBuf,
    (identifier, mode): (&str, ScanMode),
    cancel: &Cancellation,
) -> Result<()> {
    cancel.check()?;
    if scan.proposals.len() >= MAX_CANDIDATES {
        return Ok(());
    }
    let Some(children) = read_children(files, &root, scan) else {
        return Ok(());
    };
    scan.proposals.push(Proposal {
        target: Target::File(root),
        category: Category::Directory,
        evidence: MatchKind::ExactIdentity,
        reason: "Application Support in the exact app sandbox container".into(),
        risk: Risk::High,
        access: Access::ReadOnly("cleanup requires a dedicated Bundle ID directory".into()),
    });
    if scan.proposals.len() >= MAX_CANDIDATES {
        return Ok(());
    }
    // Use the listed spelling. Joining the identifier directly could find
    // a differently spelled name on a case-insensitive filesystem.
    let Some(dedicated) = children
        .into_iter()
        .find(|path| path.file_name() == Some(OsStr::new(identifier)))
    else {
        return Ok(());
    };
    cancel.check()?;
    match files.require_trusted_local_directory(&dedicated) {
        Ok(()) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(());
        }
        Err(error) => {
            scan.warnings.push(format!(
                "could not verify private app data at {}: {error}",
                dedicated.display(),
            ));
            return Ok(());
        }
    }
    if mode == ScanMode::AfterOfficialUninstall {
        let reason = match files.inspect_macos_sandbox_application_support(&dedicated) {
            Ok(Inspection {
                access: Access::Allowed,
                fingerprint,
            }) => {
                scan.push_observed(
                    Proposal {
                        target: Target::File(dedicated),
                        category: Category::Directory,
                        evidence: MatchKind::ExactIdentity,
                        reason: "dedicated sandbox Application Support matches the exact Bundle ID and may contain user data".into(),
                        risk: Risk::High,
                        access: Access::Allowed,
                    },
                    fingerprint,
                );
                // Back up this tree as a unit so related files stay together.
                return Ok(());
            }
            Ok(Inspection {
                access: Access::ReadOnly(reason),
                ..
            }) => reason,
            Err(error) => error.to_string(),
        };
        scan.warnings.push(format!(
            "Could not review {} as one directory: {reason}",
            dedicated.display(),
        ));
    }
    let Some(children) = read_children(files, &dedicated, scan) else {
        return Ok(());
    };
    scan_descendants(files, scan, children, DescendantScope::Sandbox, cancel)
}

fn scan_sandbox_file(files: &UnixFiles, scan: &mut Scan, path: PathBuf) {
    match files.probe_discovery_target(&path) {
        Ok(Some(target)) if target.category == Category::File => {}
        Ok(_) => return,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            return;
        }
        Err(error) => {
            scan.warnings
                .push(format!("could not inspect {}: {error}", path.display()));
            return;
        }
    }
    let inspected = files.inspect_macos_regular_file(&path);
    let (access, fingerprint) = match inspected {
        Ok(Inspection {
            access: Access::Allowed,
            fingerprint,
        }) => (Access::Allowed, Some(fingerprint)),
        Ok(Inspection { access, .. }) => (access, None),
        Err(error) => (Access::ReadOnly(error.to_string()), None),
    };
    let proposal = Proposal {
        target: Target::File(path),
        category: Category::File,
        evidence: MatchKind::ExactIdentity,
        reason: "file in a bounded Library scope of the verified app sandbox".into(),
        risk: Risk::High,
        access,
    };
    match fingerprint {
        Some(fingerprint) => scan.push_observed(proposal, fingerprint),
        None => scan.proposals.push(proposal),
    }
}

pub(super) fn scan_children(
    files: &UnixFiles,
    scan: &mut Scan,
    initial: Vec<PathBuf>,
    user_data_possible: bool,
    cancel: &Cancellation,
) -> Result<()> {
    let scope = if user_data_possible {
        DescendantScope::UserData
    } else {
        DescendantScope::Cache
    };
    scan_descendants(files, scan, initial, scope, cancel)
}

#[derive(Clone, Copy)]
enum DescendantScope {
    UserData,
    Cache,
    Sandbox,
}

fn scan_descendants(
    files: &UnixFiles,
    scan: &mut Scan,
    initial: Vec<PathBuf>,
    scope: DescendantScope,
    cancel: &Cancellation,
) -> Result<()> {
    let mut has_unvisited_entries = initial.len() > MAX_CANDIDATES;
    let mut pending: Vec<_> = initial
        .into_iter()
        .take(MAX_CANDIDATES)
        .map(|path| (path, 0))
        .collect();
    for _ in 0..MAX_CANDIDATES {
        let Some((path, depth)) = pending.pop() else {
            break;
        };
        cancel.check()?;
        if scan.proposals.len() >= MAX_CANDIDATES {
            has_unvisited_entries = true;
            break;
        }
        if bundle::is_app(&path) {
            // A nested bundle may own other data. Leave it intact unless the
            // caller selects and verifies that specific application.
            scan.proposals.push(Proposal {
                target: Target::File(path),
                category: Category::Directory,
                evidence: MatchKind::AppName,
                reason: "independent application bundle within the selected directory".into(),
                risk: Risk::High,
                access: Access::ReadOnly(
                    "select and verify the bundle directly for its own cleanup preview".into(),
                ),
            });
            continue;
        }
        let descendants = read_children(files, &path, scan);
        if let Some(children) = descendants {
            let remaining = if depth < MAX_DESCENT_DEPTH {
                MAX_CANDIDATES.saturating_sub(scan.proposals.len() + pending.len() + 1)
            } else {
                0
            };
            has_unvisited_entries |= children.len() > remaining;
            pending.extend(
                children
                    .into_iter()
                    .take(remaining)
                    .map(|child| (child, depth + 1)),
            );
            scan.proposals.push(Proposal {
                target: Target::File(path),
                category: Category::Directory,
                evidence: MatchKind::AppName,
                reason: "directory within the selected application scope".into(),
                risk: Risk::High,
                access: Access::ReadOnly("nested directories are preserved".into()),
            });
        } else if matches!(scope, DescendantScope::Sandbox) {
            scan_sandbox_file(files, scan, path);
        } else {
            scan.proposals.push(Proposal {
                target: Target::File(path),
                category: Category::File,
                evidence: MatchKind::AppName,
                reason: "individual entry from a verified application-specific directory".into(),
                risk: if matches!(scope, DescendantScope::Cache) {
                    Risk::Normal
                } else {
                    Risk::High
                },
                access: Access::Allowed,
            });
        }
    }
    if has_unvisited_entries || !pending.is_empty() {
        scan.warnings
            .push("macOS scan reached its descendant depth or entry limit".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uninstallany_core::AppId;

    #[test]
    fn crash_report_requires_a_complete_header_with_exact_identity_and_type() {
        let app = "com.example.editor";
        let report = b"{\"bug_type\":\"309\",\"bundleID\":\"com.example.editor\"}\n{\"incident\":\"example\"}";
        assert!(diagnostic_header_matches(report, app));
        assert!(!diagnostic_header_matches(report, "com.example.Editor"));
        assert!(!diagnostic_header_matches(report, "com.example"));
        assert!(!diagnostic_header_matches(
            br#"{"bug_type":"309","bundleID":"com.example.editor"}"#,
            app
        ));
        assert!(!diagnostic_header_matches(
            b"{\"bug_type\":\"288\",\"bundleID\":\"com.example.editor\"}\n",
            app
        ));
        assert!(!diagnostic_header_matches(
            b"{\"bug_type\":\"309\",\"bundleID\":\"other\",\"bundleID\":\"com.example.editor\"}\n",
            app
        ));
    }

    #[test]
    fn app_group_matches_require_a_component_boundary() {
        let app = AppRecord {
            id: AppId::Package {
                manager: "fixture".into(),
                id: "editor".into(),
            },
            name: "Example Editor".into(),
            publisher: None,
            version: None,
            install_location: None,
            size_bytes: None,
            install_date: None,
            system_component: false,
            official_uninstall_available: false,
        };
        let search = Search {
            home: Path::new("/Users/user"),
            app: &app,
            mode: ScanMode::Leftovers,
            identifier: Some("com.example.editor"),
            group_identifiers: &[],
            write_denial: None,
            name_attribution_uncertain: false,
            pre_uninstall_files: None,
        };
        assert_eq!(
            evidence(Area::SharedContainers, "TEAM.com.example.editor", &search),
            Some(MatchKind::FuzzyName)
        );
        assert_eq!(
            evidence(Area::SharedContainers, "TEAMcom.example.editor", &search),
            None
        );
        assert_eq!(
            evidence(Area::Preferences, "COM.EXAMPLE.EDITOR.plist", &search),
            Some(MatchKind::ExactIdentity)
        );
    }
}
