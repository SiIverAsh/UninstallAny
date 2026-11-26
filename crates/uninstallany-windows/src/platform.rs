use std::{
    ffi::OsStr,
    io,
    mem::size_of,
    os::windows::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
    ptr::null_mut,
    sync::Arc,
};

use uninstallany_core::{
    Access, AppId, AppRecord, Artifact, Cancellation, Category, Engine, Error, FileStore,
    Inspection, Inventory, Journal, MatchKind, OfficialIntent, OfficialOutcome, PlatformBackend,
    Proposal, RegistryBackupWriter, RegistryHive, RegistryStore, RegistryTarget, Result, Risk,
    RuleRoot, RuleTarget, Scan, ScanMode, Target, is_protected_registry_target, match_name,
};
use uuid::Uuid;
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_ACCESS_DENIED, ERROR_ELEVATION_REQUIRED, HANDLE},
    Globalization::{CSTR_EQUAL, CompareStringOrdinal},
    Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

use crate::{
    files::{FileDisposition, FileSnapshot, WindowsFiles},
    firewall, helper, highrisk, msix, registrations, registry, shortcuts, tasks, uninstall,
};

const MAX_CANDIDATES: usize = 5_000;
const MAX_DEPTH: u8 = 8;
const APP_PATHS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\App Paths";
const FORCE_REASON: &str =
    "registered third-party application; adding this item only removes its listing";
const ARP_INCOMPLETE: &str =
    "another application may own this object because its installation records could not be read";
const RISKY_EXTENSIONS: &[&str] = &[
    "csv", "db", "doc", "docx", "jpeg", "jpg", "md", "mp3", "mp4", "odp", "ods", "odt", "pdf",
    "png", "pptx", "sqlite", "txt", "wav", "xlsx",
];

/// Opens the Windows engine under a standard user token.
///
/// The returned value exposes only the core confirmation workflow.
pub fn open() -> io::Result<Engine<impl PlatformBackend, impl Journal>> {
    if elevated()? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "run UninstallAny without elevation",
        ));
    }
    let files = Arc::new(WindowsFiles::new()?);
    let platform = Backend {
        files: Arc::clone(&files),
    };
    Ok(Engine::new(platform, State { files }))
}

#[derive(Clone)]
struct Backend {
    files: Arc<WindowsFiles>,
}

struct State {
    files: Arc<WindowsFiles>,
}

enum NativeCommand {
    Desktop {
        native: uninstall::OfficialUninstall,
        elevation: Option<helper::PreparedMsi>,
    },
    Package(msix::MsixUninstall),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScanPurpose {
    Preview,
    Recheck,
}

impl PlatformBackend for Backend {
    type Official = NativeCommand;

    fn rule_root(&self, root: RuleRoot) -> Option<PathBuf> {
        match root {
            RuleRoot::WindowsRoamingAppData => self.files.roaming_app_data(),
            RuleRoot::WindowsLocalAppData => Some(self.files.local_app_data()),
            _ => None,
        }
    }

    fn probe_rule_target(&self, path: &Path) -> io::Result<Option<RuleTarget>> {
        let snapshot = self.files.inspect(path)?;
        let category = match snapshot.disposition {
            FileDisposition::Regular => Category::File,
            FileDisposition::Directory => Category::Directory,
            FileDisposition::Protected | FileDisposition::Link => return Ok(None),
        };
        Ok(Some(RuleTarget {
            path: snapshot.path,
            category,
        }))
    }

    fn inventory(&self, cancel: &Cancellation) -> Result<Inventory> {
        let arp = registry::enumerate_uninstall(cancel)?;
        let mut result = Inventory {
            applications: arp.entries.iter().map(desktop_record).collect(),
            warnings: arp.warnings,
        };
        cancel.check()?;
        match msix::inventory_current_user(cancel) {
            Ok(packaged) => {
                result
                    .applications
                    .extend(packaged.packages.into_iter().map(package_record));
                result.warnings.extend(packaged.warnings);
            }
            Err(Error::Cancelled) => return Err(Error::Cancelled),
            Err(error) => result
                .warnings
                .push(format!("current-user MSIX inventory: {error}")),
        }
        cancel.check()?;
        Ok(result)
    }

    fn scan(&self, app: &AppRecord, mode: ScanMode, cancel: &Cancellation) -> Result<Scan> {
        self.scan_application(app, mode, ScanPurpose::Preview, cancel)
    }

    fn scan_for_cleanup_recheck(
        &self,
        app: &AppRecord,
        mode: ScanMode,
        cancel: &Cancellation,
    ) -> Result<Scan> {
        // Only discovery sources with no writable targets can be skipped here.
        self.scan_application(app, mode, ScanPurpose::Recheck, cancel)
    }

    fn scan_portable(&self, directory: &Path, cancel: &Cancellation) -> Result<Scan> {
        let root = self.files.inspect(directory)?;
        if root.disposition != FileDisposition::Directory
            || self
                .files
                .roots()
                .iter()
                .any(|known| same_path(known, &root.path))
        {
            return Err(Error::Rejected(
                "choose an individual portable application directory".into(),
            ));
        }
        let arp = registry::enumerate_uninstall(cancel)?;
        if !arp.warnings.is_empty()
            || arp.entries.iter().any(|entry| {
                entry
                    .install_location
                    .as_deref()
                    .map(Path::new)
                    .is_some_and(|path| self.install_paths_overlap(path, &root.path))
            })
        {
            return Err(Error::Rejected(
                "could not exclude installed applications in the chosen directory".into(),
            ));
        }
        let mut scan = Scan::default();
        self.scan_tree(
            &mut scan,
            &root.path,
            MatchKind::AppName,
            "inside the explicitly selected portable directory",
            cancel,
        )?;
        Ok(scan)
    }

    fn prepare_official(&self, app: &AppRecord) -> Result<(OfficialIntent, Self::Official)> {
        let mut notice = "The system or publisher uninstaller makes its own changes. Review any native prompts. Residual restore covers UninstallAny cleanup.".to_string();
        let (command, method, quiet) = match &app.id {
            AppId::WindowsRegistry(address) => {
                let arp = registry::enumerate_uninstall(&Cancellation::default())?;
                let Some(registered) = arp
                    .entries
                    .iter()
                    .find(|entry| &entry.address == address && entry.display_name == app.name)
                else {
                    return Err(Error::Rejected(
                        "registered application changed or is protected".into(),
                    ));
                };
                if is_protected_entry(registered) || registered.no_remove {
                    return Err(Error::Rejected(
                        "the registry reports a protected application or system component".into(),
                    ));
                }
                let mut elevation = None;
                let native = if registered.windows_installer {
                    let code = address
                        .key
                        .rsplit('\\')
                        .next()
                        .ok_or_else(|| Error::Rejected("missing MSI ProductCode".into()))?;
                    let machine = address.hive == RegistryHive::LocalMachine;
                    let native = uninstall::prepare_msi(
                        code,
                        machine,
                        registered.quiet_uninstall_string.is_some(),
                    )?;
                    if machine {
                        match helper::PreparedMsi::prepare(registered) {
                            Ok(prepared) => {
                                notice.push_str(" If this machine-wide MSI uninstall explicitly needs administrator access, the installed helper will show the exact product and ask for confirmation.");
                                elevation = Some(prepared);
                            }
                            Err(error) => {
                                notice.push_str(&format!(" The standalone MSI helper is unavailable ({error}). Windows Settings can handle any required elevation."));
                            }
                        }
                    }
                    native
                } else {
                    let approved = self.exclusive_install_scope(app, &arp);
                    uninstall::prepare_win32(
                        registered.quiet_uninstall_string.as_deref(),
                        registered.uninstall_string.as_deref(),
                        approved.as_deref(),
                    )?
                };
                let method = native.summary();
                let quiet = native.is_quiet();
                (NativeCommand::Desktop { native, elevation }, method, quiet)
            }
            AppId::WindowsPackage(full_name) => {
                let native = msix::prepare_current_user(full_name)?;
                let method = native.summary();
                (NativeCommand::Package(native), method, false)
            }
            AppId::Package { .. } => {
                return Err(Error::Rejected(
                    "application is not managed by Windows".into(),
                ));
            }
        };
        let intent = OfficialIntent {
            application: app.name.clone(),
            method,
            quiet,
            notice,
        };
        Ok((intent, command))
    }

    fn run_official(&self, command: Self::Official) -> Result<OfficialOutcome> {
        let outcome = match command {
            NativeCommand::Desktop { native, elevation } => run_desktop(native, elevation)?,
            NativeCommand::Package(command) => command.execute()?,
        };
        Ok(match outcome {
            uninstall::OfficialOutcome::Completed => OfficialOutcome::Completed,
            uninstall::OfficialOutcome::NeedsRestart => OfficialOutcome::NeedsRestart,
            uninstall::OfficialOutcome::Cancelled => OfficialOutcome::Cancelled,
            uninstall::OfficialOutcome::Failed(code) => OfficialOutcome::Failed(code),
            uninstall::OfficialOutcome::Unverified(code) => OfficialOutcome::Unverified(code),
        })
    }

    fn official_uninstall_absent(&self, id: &AppId, cancel: &Cancellation) -> Result<bool> {
        cancel.check()?;
        match id {
            AppId::WindowsRegistry(target) => Ok(!registry::uninstall_key_present(target)?),
            AppId::WindowsPackage(full_name) => Ok(!msix::current_package_present(full_name)?),
            AppId::Package { .. } => Ok(false),
        }
    }
}

fn run_desktop(
    native: uninstall::OfficialUninstall,
    elevation: Option<helper::PreparedMsi>,
) -> io::Result<uninstall::OfficialOutcome> {
    let result = native.execute();
    let launch_needs_elevation = result
        .as_ref()
        .is_err_and(|error| error.raw_os_error() == Some(ERROR_ELEVATION_REQUIRED as i32));
    let msi_needs_elevation = elevation.is_some()
        && matches!(result.as_ref(), Ok(uninstall::OfficialOutcome::Failed(code)) if matches!(*code, ERROR_ACCESS_DENIED | ERROR_ELEVATION_REQUIRED));
    if !launch_needs_elevation && !msi_needs_elevation {
        return result;
    }
    if let Some(prepared) = elevation {
        return prepared.execute();
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "the official uninstaller requires administrator access. Use Windows Settings for the native prompt",
    ))
}

fn discover_system_registrations(
    scope: &uninstall::RegisteredScope,
    scan: &mut Scan,
    cancel: &Cancellation,
) -> Result<()> {
    type Discovery = fn(&uninstall::RegisteredScope, &Cancellation) -> Result<Scan>;
    let sources: [(&str, Discovery); 4] = [
        ("Service Control Manager", highrisk::discover_services),
        ("Task Scheduler", tasks::discover_tasks),
        ("Windows Firewall", firewall::discover_rules),
        (
            "Windows class registrations",
            registrations::discover_registrations,
        ),
    ];
    for (source, discover) in sources {
        cancel.check()?;
        let remaining = MAX_CANDIDATES.saturating_sub(scan.proposals.len());
        if remaining == 0 {
            scan.warnings.push(format!(
                "the {MAX_CANDIDATES} candidate limit was reached before {source} discovery"
            ));
            break;
        }
        match discover(scope, cancel) {
            Ok(found) => {
                scan.warnings.extend(found.warnings);
                if found.proposals.len() > remaining {
                    scan.warnings.push(format!(
                        "the {MAX_CANDIDATES} candidate limit truncated {source} discovery"
                    ));
                }
                scan.proposals
                    .extend(found.proposals.into_iter().take(remaining));
            }
            Err(Error::Cancelled) => return Err(Error::Cancelled),
            Err(error) => scan.warnings.push(format!("{source} inventory: {error}")),
        }
    }
    Ok(())
}

impl Backend {
    fn scan_application(
        &self,
        app: &AppRecord,
        mode: ScanMode,
        purpose: ScanPurpose,
        cancel: &Cancellation,
    ) -> Result<Scan> {
        let arp = registry::enumerate_uninstall(cancel)?;
        if let AppId::WindowsRegistry(address) = &app.id {
            if let Some(current) = arp.entries.iter().find(|entry| &entry.address == address) {
                if mode == ScanMode::AfterOfficialUninstall {
                    return Err(Error::Rejected("application is present again".into()));
                }
                if is_protected_entry(current) {
                    return Ok(Scan::new(
                        Vec::new(),
                        vec![
                            "the inventory source identifies a protected application or system component"
                                .into(),
                        ],
                    ));
                }
            }
        }
        let claimed = self.exclusive_install_claim(app, &arp);
        let directory = claimed.and_then(|(path, _)| self.inspect_install_directory(path));
        let mut scan = Scan::new(Vec::new(), arp.warnings.clone());
        let scope = match (mode, claimed, directory.as_deref()) {
            (ScanMode::AfterOfficialUninstall, Some((path, root)), _) => {
                Some(uninstall::RegisteredScope::after_uninstall(path, root))
            }
            (_, _, Some(path)) => Some(uninstall::RegisteredScope::existing(path)),
            _ => None,
        };
        let scope = match scope.transpose() {
            Ok(scope) => scope,
            Err(error) => {
                scan.warnings.push(format!(
                    "could not verify the installation location for registration discovery: {error}"
                ));
                None
            }
        };
        if let Some(path) = &directory {
            self.scan_tree(
                &mut scan,
                path,
                MatchKind::ExactIdentity,
                "verified application installation directory",
                cancel,
            )?;
        }
        self.scan_named_files(app, &mut scan, &arp, scope.as_ref(), cancel)?;
        match &app.id {
            AppId::WindowsRegistry(address) => {
                self.scan_registry(app, &arp, &mut scan, cancel)?;
                if let Some(scope) = &scope {
                    scan_startup_registrations(scope, &mut scan, purpose, cancel)?;
                }
                if mode == ScanMode::ForceRemoval {
                    scan.proposals.extend(force_registration(&arp, address));
                }
            }
            AppId::WindowsPackage(_) => scan.warnings.push(
                "Windows manages package files and application data; its package directory is protected".into()
            ),
            AppId::Package { .. } => {}
        }
        if let (ScanPurpose::Preview, Some(scope)) = (purpose, scope.as_ref()) {
            discover_system_registrations(scope, &mut scan, cancel)?;
        }
        Ok(scan)
    }

    fn exclusive_install_scope(
        &self,
        app: &AppRecord,
        arp: &registry::Inventory,
    ) -> Option<PathBuf> {
        let (path, _) = self.exclusive_install_claim(app, arp)?;
        self.inspect_install_directory(path)
    }

    fn exclusive_install_claim<'a>(
        &'a self,
        app: &'a AppRecord,
        arp: &registry::Inventory,
    ) -> Option<(&'a Path, &'a Path)> {
        let path = app.install_location.as_deref()?;
        if !arp.warnings.is_empty()
            || !self.files.allows_registration_location(path)
            || arp.entries.iter().any(|other| {
                AppId::WindowsRegistry(other.address.clone()) != app.id
                    && other
                        .install_location
                        .as_deref()
                        .map(Path::new)
                        .is_some_and(|other| self.install_paths_overlap(other, path))
            })
        {
            return None;
        }
        let leaf = path.file_name()?.to_str()?;
        match_name(&app.name, None, leaf, None).filter(|kind| *kind == MatchKind::AppName)?;
        let root = self
            .files
            .roots()
            .iter()
            .filter(|root| below(path, root))
            .max_by_key(|root| root.components().count())?;
        Some((path, root))
    }

    fn inspect_install_directory(&self, path: &Path) -> Option<PathBuf> {
        let item = self.files.inspect(path).ok()?;
        // Ownership was checked against the registered path. An alias must not
        // let the tree scan jump to a canonical directory with different owners.
        (item.disposition == FileDisposition::Directory && same_path(path, &item.path))
            .then_some(item.path)
    }

    fn install_paths_overlap(&self, observed: &Path, expected: &Path) -> bool {
        paths_overlap(observed, expected)
            || self
                .files
                .inspect(observed)
                .is_ok_and(|snapshot| paths_overlap(&snapshot.path, expected))
    }

    fn scan_tree(
        &self,
        scan: &mut Scan,
        directory: &Path,
        evidence: MatchKind,
        reason: &str,
        cancel: &Cancellation,
    ) -> Result<()> {
        let mut pending = vec![(directory.to_path_buf(), 0)];
        while let Some((path, depth)) = pending.pop() {
            cancel.check()?;
            if scan.proposals.len() >= MAX_CANDIDATES {
                scan.warnings
                    .push(format!("scan reached the {MAX_CANDIDATES} candidate limit"));
                break;
            }
            let inspected = match self.files.inspect(&path) {
                Ok(item) => item,
                Err(error) => {
                    scan.warnings.push(format!("{}: {error}", path.display()));
                    continue;
                }
            };
            let is_directory = inspected.disposition == FileDisposition::Directory;
            let category = if is_directory {
                Category::Directory
            } else {
                category_for_path(&path)
            };
            let access = if category == Category::Shortcut {
                Access::ReadOnly("shortcut destination has not been verified".into())
            } else {
                file_access(inspected.disposition)
            };
            if is_directory && depth < MAX_DEPTH {
                match self.files.children(&path) {
                    Ok(children) => pending.extend(
                        children
                            .into_iter()
                            .rev()
                            .take(MAX_CANDIDATES)
                            .map(|child| (child, depth + 1)),
                    ),
                    Err(error) => scan.warnings.push(format!("{}: {error}", path.display())),
                }
            } else if is_directory {
                scan.warnings
                    .push(format!("depth limit reached at {}", path.display()));
            }
            scan.proposals.push(Proposal {
                target: Target::File(path.clone()),
                category,
                // The installed directory identifies its root. Its children may
                // still contain unrelated or user-created files.
                evidence: if depth > 0 && evidence == MatchKind::ExactIdentity {
                    MatchKind::AppName
                } else {
                    evidence
                },
                reason: reason.into(),
                risk: file_risk(&path, category),
                access,
            });
        }
        Ok(())
    }

    fn scan_named_files(
        &self,
        app: &AppRecord,
        scan: &mut Scan,
        inventory: &registry::Inventory,
        scope: Option<&uninstall::RegisteredScope>,
        cancel: &Cancellation,
    ) -> Result<()> {
        for root in self.files.roots() {
            cancel.check()?;
            let children = match self.files.children(root) {
                Ok(children) => children,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    scan.warnings.push(format!("{}: {error}", root.display()));
                    continue;
                }
            };
            for child in children.into_iter().take(MAX_CANDIDATES) {
                cancel.check()?;
                if scan.proposals.len() >= MAX_CANDIDATES {
                    return Ok(());
                }
                if let Some(evidence) = path_name_match(app, &child, false) {
                    self.add_named_path(
                        scan,
                        app,
                        inventory,
                        (child.clone(), evidence),
                        scope,
                        cancel,
                    )?;
                }
                if app.publisher.as_deref().is_some_and(|name| {
                    child
                        .file_name()
                        .and_then(OsStr::to_str)
                        .is_some_and(|leaf| {
                            match_name(name, None, leaf, None) == Some(MatchKind::AppName)
                        })
                }) {
                    match self.files.children(&child) {
                        Ok(nested) => {
                            for leaf in nested.into_iter().take(MAX_CANDIDATES) {
                                cancel.check()?;
                                if scan.proposals.len() >= MAX_CANDIDATES {
                                    return Ok(());
                                }
                                if let Some(evidence) = path_name_match(app, &leaf, true) {
                                    self.add_named_path(
                                        scan,
                                        app,
                                        inventory,
                                        (leaf, evidence),
                                        scope,
                                        cancel,
                                    )?;
                                }
                            }
                        }
                        Err(error) => scan.warnings.push(format!("{}: {error}", child.display())),
                    }
                }
            }
        }
        Ok(())
    }

    fn add_named_path(
        &self,
        scan: &mut Scan,
        app: &AppRecord,
        inventory: &registry::Inventory,
        (path, evidence): (PathBuf, MatchKind),
        scope: Option<&uninstall::RegisteredScope>,
        cancel: &Cancellation,
    ) -> Result<()> {
        let is_shared = || {
            inventory.entries.iter().any(|other| {
                AppId::WindowsRegistry(other.address.clone()) != app.id
                    && (other
                        .install_location
                        .as_deref()
                        .map(Path::new)
                        .is_some_and(|claimed| self.install_paths_overlap(claimed, &path))
                        || path
                            .file_stem()
                            .and_then(OsStr::to_str)
                            .is_some_and(|name| {
                                match_name(&other.display_name, None, name, None)
                                    == Some(MatchKind::AppName)
                            }))
            })
        };
        let restriction = if !inventory.warnings.is_empty() {
            Some(ARP_INCOMPLETE)
        } else if is_shared() {
            Some("another application may own this object")
        } else {
            None
        };
        let category = category_for_path(&path);
        if let (None, Category::Shortcut, Some(scope)) = (restriction, category, scope) {
            match self.inspect_shortcut(&path, scope) {
                Ok(Some((proposal, fingerprint))) => {
                    scan.push_observed(proposal, fingerprint);
                    return Ok(());
                }
                Ok(None) => {}
                Err(error) => scan.warnings.push(format!("{}: {error}", path.display())),
            }
        }
        let restriction = restriction.or_else(|| {
            (evidence == MatchKind::FuzzyName)
                .then_some("fuzzy name alone does not authorize cleanup")
        });
        if let Some(reason) = restriction {
            scan.proposals.push(Proposal {
                category,
                target: Target::File(path),
                evidence,
                reason: "application-like name".into(),
                risk: Risk::High,
                access: Access::ReadOnly(reason.into()),
            });
        } else if evidence == MatchKind::PublisherAndApp
            && self
                .files
                .inspect(&path)
                .is_ok_and(|snapshot| snapshot.disposition == FileDisposition::Directory)
        {
            self.scan_tree(
                scan,
                &path,
                evidence,
                "strict application directory under a matched publisher",
                cancel,
            )?;
        } else {
            cancel.check()?;
            let access = if category == Category::Shortcut {
                Access::ReadOnly("shortcut destination has not been verified".into())
            } else {
                Access::Allowed
            };
            scan.proposals.push(Proposal {
                risk: file_risk(&path, category),
                target: Target::File(path),
                category,
                evidence,
                reason: "strict name match within a bounded scan root".into(),
                access,
            });
        }
        Ok(())
    }

    fn inspect_shortcut(
        &self,
        path: &Path,
        scope: &uninstall::RegisteredScope,
    ) -> io::Result<Option<(Proposal, String)>> {
        if !path
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|ext| ext.eq_ignore_ascii_case("lnk"))
        {
            return Ok(None);
        }
        let (snapshot, bytes) = self.files.read_shortcut(path)?;
        let Some(target) = shortcuts::target(&bytes)? else {
            return Ok(None);
        };
        let reference = if target.direct {
            uninstall::registered_shortcut_image(&target.path, scope, target.volume_serial)?
        } else {
            uninstall::registered_image(&target.path, scope)?
        };
        let Some(reference) = reference else {
            return Ok(None);
        };
        let access = if !target.direct {
            Access::ReadOnly("the shortcut carries alternate target data".into())
        } else if reference.evidence != MatchKind::ExactIdentity {
            Access::ReadOnly("the shortcut target is no longer present".into())
        } else if !self.files.is_user_shortcut(&snapshot.path)
            || snapshot.disposition != FileDisposition::Regular
        {
            Access::ReadOnly("this shortcut is outside the writable current-user scope".into())
        } else {
            Access::Allowed
        };
        let fingerprint = serde_json::to_string(&snapshot).map_err(io::Error::other)?;
        Ok(Some((
            Proposal {
                category: Category::Shortcut,
                target: Target::File(snapshot.path),
                evidence: reference.evidence,
                reason: reference.reason(&format!(
                    "shortcut points to {} in the verified installation directory",
                    reference.path.display()
                )),
                risk: Risk::High,
                access,
            },
            fingerprint,
        )))
    }

    fn scan_registry(
        &self,
        app: &AppRecord,
        inventory: &registry::Inventory,
        scan: &mut Scan,
        cancel: &Cancellation,
    ) -> Result<()> {
        let settings_access = if registry_settings_are_shared(app, inventory) {
            Access::ReadOnly(
                "the registry branch could also belong to another installed application".into(),
            )
        } else {
            Access::Allowed
        };
        use uninstallany_core::RegistryView;
        for (hive, view) in std::iter::once((RegistryHive::CurrentUser, RegistryView::Native))
            .chain(
                registry::machine_views()
                    .iter()
                    .copied()
                    .map(|view| (RegistryHive::LocalMachine, view)),
            )
        {
            cancel.check()?;
            if let Some(publisher) = app
                .publisher
                .as_deref()
                .filter(|name| is_registry_component(name))
            {
                if is_registry_component(&app.name)
                    && match_name(&app.name, Some(publisher), &app.name, Some(publisher))
                        == Some(MatchKind::PublisherAndApp)
                {
                    let target = RegistryTarget {
                        hive,
                        view,
                        key: format!(r"Software\{publisher}\{}", app.name),
                        value: None,
                    };
                    add_owned_registry_values(scan, target, &settings_access);
                }
            }
        }
        Ok(())
    }
}

impl FileStore for Backend {
    fn inspect_file(&self, path: &Path) -> io::Result<Inspection> {
        let snapshot = if path
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|ext| ext.eq_ignore_ascii_case("lnk"))
            && self.files.is_user_shortcut(path)
        {
            self.files.read_shortcut(path)?.0
        } else {
            self.files.inspect(path)?
        };
        let mut access = file_access(snapshot.disposition);
        if access == Access::Allowed {
            if let Err(error) = self
                .files
                .quarantine_slot(&snapshot, &Uuid::nil().to_string())
            {
                access = Access::ReadOnly(error.to_string());
            }
        }
        Ok(Inspection {
            fingerprint: serde_json::to_string(&snapshot).map_err(io::Error::other)?,
            access,
        })
    }

    fn file_backup_path(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<PathBuf> {
        self.files
            .quarantine_slot(&decode_snapshot(path, expected)?, &slot.to_string())
    }

    fn quarantine_file(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<()> {
        self.files
            .quarantine(&decode_snapshot(path, expected)?, &slot.to_string())
    }

    fn file_is_quarantined(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<bool> {
        self.files
            .quarantined(&decode_snapshot(path, expected)?, &slot.to_string())
    }

    fn restore_file(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<()> {
        self.files
            .restore(&decode_snapshot(path, expected)?, &slot.to_string())
    }

    fn can_purge_quarantined(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<bool> {
        self.files
            .can_purge(&decode_snapshot(path, expected)?, &slot.to_string())
    }

    fn purge_quarantined(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<()> {
        self.files
            .purge(&decode_snapshot(path, expected)?, &slot.to_string())
    }
}

impl RegistryStore for Backend {
    fn inspect_registry(&self, target: &RegistryTarget) -> io::Result<Inspection> {
        registry::inspect(target)
    }

    fn remove_registry(
        &self,
        target: &RegistryTarget,
        expected: &str,
        write: &mut RegistryBackupWriter<'_>,
    ) -> io::Result<()> {
        registry::remove(target, expected, write)
    }

    fn restore_registry(&self, target: &RegistryTarget, snapshot: &[u8]) -> io::Result<()> {
        registry::restore(target, snapshot)
    }
}

impl Journal for State {
    fn create(&self, id: Uuid, artifact: Artifact, bytes: &[u8]) -> io::Result<()> {
        self.files.create_artifact(&artifact.file_name(id), bytes)
    }

    fn read(&self, id: Uuid, artifact: Artifact) -> io::Result<Option<Vec<u8>>> {
        match self.files.read_artifact(&artifact.file_name(id)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn list(&self, artifact: Artifact) -> io::Result<Vec<Uuid>> {
        Ok(self
            .files
            .artifact_names()?
            .iter()
            .filter_map(|name| artifact.id(name))
            .collect())
    }

    fn location(&self, id: Uuid, artifact: Artifact) -> PathBuf {
        self.files.artifact_path(&artifact.file_name(id))
    }

    fn check_export_path(&self, path: &Path) -> io::Result<()> {
        WindowsFiles::check_report_path(path)
    }
}

fn desktop_record(entry: &registry::InstalledEntry) -> AppRecord {
    AppRecord {
        id: AppId::WindowsRegistry(entry.address.clone()),
        name: entry.display_name.clone(),
        publisher: entry.publisher.clone(),
        version: entry.display_version.clone(),
        install_location: entry.install_location.as_deref().map(PathBuf::from),
        size_bytes: entry.estimated_size_kib.map(|size| u64::from(size) * 1024),
        install_date: entry.install_date.clone(),
        system_component: entry.system_component,
        official_uninstall_available: !is_protected_entry(entry)
            && !entry.no_remove
            && (entry.windows_installer
                || entry.uninstall_string.is_some()
                || entry.quiet_uninstall_string.is_some()),
    }
}

fn package_record(package: msix::MsixPackage) -> AppRecord {
    AppRecord {
        id: AppId::WindowsPackage(package.full_name),
        name: package.display_name,
        publisher: Some(package.publisher),
        version: Some(package.version),
        install_location: None,
        size_bytes: None,
        install_date: None,
        system_component: !package.removable,
        official_uninstall_available: package.removable,
    }
}

pub(super) fn is_protected_entry(entry: &registry::InstalledEntry) -> bool {
    entry.system_component
        || entry.publisher.as_deref().is_some_and(|publisher| {
            publisher
                .split(|character: char| !character.is_alphanumeric())
                .any(|part| part.eq_ignore_ascii_case("microsoft"))
        })
        || is_protected_registry_target(&entry.address)
}

fn force_registration(
    inventory: &registry::Inventory,
    address: &RegistryTarget,
) -> Option<Proposal> {
    let entry = inventory
        .entries
        .iter()
        .find(|entry| &entry.address == address)?;
    if is_protected_entry(entry) || entry.no_remove {
        return None;
    }
    Some(Proposal {
        target: Target::Registry(address.clone()),
        category: Category::Registry,
        evidence: MatchKind::ExactIdentity,
        reason: FORCE_REASON.into(),
        risk: Risk::High,
        access: if inventory.warnings.is_empty() {
            Access::Allowed
        } else {
            Access::ReadOnly(ARP_INCOMPLETE.into())
        },
    })
}

fn category_for_path(path: &Path) -> Category {
    match path.extension().and_then(OsStr::to_str) {
        Some(extension)
            if extension.eq_ignore_ascii_case("lnk") || extension.eq_ignore_ascii_case("url") =>
        {
            Category::Shortcut
        }
        _ => Category::File,
    }
}

fn file_risk(path: &Path, category: Category) -> Risk {
    if category == Category::Shortcut
        || path
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|extension| {
                RISKY_EXTENSIONS
                    .iter()
                    .any(|risky| extension.eq_ignore_ascii_case(risky))
            })
    {
        return Risk::High;
    }
    Risk::Normal
}

fn file_access(disposition: FileDisposition) -> Access {
    match disposition {
        FileDisposition::Regular | FileDisposition::Link => Access::Allowed,
        FileDisposition::Directory => {
            Access::ReadOnly("directory retained; assessed children are listed separately".into())
        }
        FileDisposition::Protected => {
            Access::ReadOnly("protected or unsupported filesystem object".into())
        }
    }
}

fn decode_snapshot(path: &Path, serialized: &str) -> io::Result<FileSnapshot> {
    let snapshot: FileSnapshot = serde_json::from_str(serialized).map_err(io::Error::other)?;
    if same_path(&snapshot.path, path) {
        return Ok(snapshot);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "backup path differs from the approved object",
    ))
}

fn path_name_match(app: &AppRecord, path: &Path, publisher_match: bool) -> Option<MatchKind> {
    let name = if category_for_path(path) == Category::Shortcut {
        path.file_stem()?
    } else {
        path.file_name()?
    };
    let publisher = publisher_match
        .then_some(app.publisher.as_deref())
        .flatten();
    match_name(
        &app.name,
        app.publisher.as_deref(),
        name.to_str()?,
        publisher,
    )
}

fn windows_eq(first: &OsStr, second: &OsStr) -> bool {
    let left: Vec<_> = first.encode_wide().collect();
    let right: Vec<_> = second.encode_wide().collect();
    let (Ok(left_len), Ok(right_len)) = (i32::try_from(left.len()), i32::try_from(right.len()))
    else {
        return false;
    };
    // SAFETY: Windows reads the two buffers for the supplied exact lengths.
    unsafe {
        CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, 1) == CSTR_EQUAL
    }
}

fn below(path: &Path, root: &Path) -> bool {
    let mut path_components = path.components();
    for part in root.components() {
        if !path_components
            .next()
            .is_some_and(|other| windows_eq(part.as_os_str(), other.as_os_str()))
        {
            return false;
        }
    }
    matches!(path_components.next(), Some(Component::Normal(_)))
}

fn same_path(left: &Path, right: &Path) -> bool {
    left.components().count() == right.components().count()
        && left
            .components()
            .zip(right.components())
            .all(|(a, b)| windows_eq(a.as_os_str(), b.as_os_str()))
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    same_path(left, right) || below(left, right) || below(right, left)
}

fn is_registry_component(name: &str) -> bool {
    !name.is_empty()
        && name == name.trim()
        && !matches!(name, "." | "..")
        && !name.contains(['\\', '\0'])
}

fn registry_settings_are_shared(app: &AppRecord, inventory: &registry::Inventory) -> bool {
    !inventory.warnings.is_empty()
        || inventory.entries.iter().any(|entry| {
            app.id != AppId::WindowsRegistry(entry.address.clone())
                && windows_eq(OsStr::new(&entry.display_name), OsStr::new(&app.name))
                && entry
                    .publisher
                    .as_deref()
                    .zip(app.publisher.as_deref())
                    .is_none_or(|(left, right)| windows_eq(OsStr::new(left), OsStr::new(right)))
        })
}

fn add_owned_registry_values(scan: &mut Scan, key: RegistryTarget, access: &Access) {
    let names = match registry::value_names(&key) {
        Ok(names) => names,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return,
        Err(error) => {
            scan.warnings.push(format!("{}: {error}", key.key));
            return;
        }
    };
    let remaining = MAX_CANDIDATES.saturating_sub(scan.proposals.len());
    scan.proposals.extend(
        std::iter::once(None)
            .chain(names.into_iter().map(Some))
            .take(remaining)
            .map(|value| Proposal {
                target: Target::Registry(RegistryTarget {
                    value,
                    ..key.clone()
                }),
                category: Category::Registry,
                evidence: MatchKind::PublisherAndApp,
                reason: "exact publisher and app names in the registry key".into(),
                risk: Risk::Normal,
                access: access.clone(),
            }),
    );
}

fn scan_startup_registrations(
    scope: &uninstall::RegisteredScope,
    scan: &mut Scan,
    purpose: ScanPurpose,
    cancel: &Cancellation,
) -> Result<()> {
    use uninstallany_core::RegistryView;
    let current_user = (RegistryHive::CurrentUser, RegistryView::Native);
    add_startup_values(scan, current_user, scope, purpose, cancel)?;
    if purpose == ScanPurpose::Recheck {
        return Ok(());
    }
    add_application_paths(scan, current_user.0, current_user.1, scope, cancel)?;
    for &view in registry::machine_views() {
        cancel.check()?;
        if scan.proposals.len() >= MAX_CANDIDATES {
            break;
        }
        add_application_paths(scan, RegistryHive::LocalMachine, view, scope, cancel)?;
        add_startup_values(
            scan,
            (RegistryHive::LocalMachine, view),
            scope,
            purpose,
            cancel,
        )?;
    }
    Ok(())
}

fn add_application_paths(
    scan: &mut Scan,
    hive: RegistryHive,
    view: uninstallany_core::RegistryView,
    scope: &uninstall::RegisteredScope,
    cancel: &Cancellation,
) -> Result<()> {
    let parent = RegistryTarget {
        hive,
        view,
        key: APP_PATHS_KEY.into(),
        value: None,
    };
    for name in registry_list(scan, &parent, registry::subkeys) {
        cancel.check()?;
        let key = format!("{APP_PATHS_KEY}\\{name}");
        let executable = RegistryTarget {
            key: key.clone(),
            value: Some(String::new()),
            ..parent.clone()
        };
        if let Some(reference) = registration_match(scan, &executable, |text| {
            let path = text
                .strip_prefix('"')
                .and_then(|quoted| quoted.strip_suffix('"'))
                .unwrap_or(text);
            uninstall::registered_image(Path::new(path), scope)
        }) {
            let target = RegistryTarget {
                key,
                ..parent.clone()
            };
            scan.proposals.push(Proposal {
                target: Target::Registry(target),
                category: Category::Registry,
                evidence: reference.evidence,
                reason: reference
                    .reason("App Paths executable is within the verified installation directory"),
                risk: Risk::High,
                access: Access::ReadOnly(
                    "App Paths is outside the supported registry write scope".into(),
                ),
            });
        }
    }
    Ok(())
}

fn add_startup_values(
    scan: &mut Scan,
    (hive, view): (RegistryHive, uninstallany_core::RegistryView),
    scope: &uninstall::RegisteredScope,
    purpose: ScanPurpose,
    cancel: &Cancellation,
) -> Result<()> {
    for key in registry::STARTUP_KEYS {
        let parent = RegistryTarget {
            hive,
            view,
            key: key.into(),
            value: None,
        };
        for name in registry_list(scan, &parent, registry::value_names) {
            cancel.check()?;
            let target = RegistryTarget {
                value: Some(name),
                ..parent.clone()
            };
            match inspect_startup_value(&target, scope) {
                Ok(Some((proposal, fingerprint))) => {
                    scan.push_observed(proposal, fingerprint);
                    continue;
                }
                Ok(None) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => scan.warnings.push(format!("{}: {error}", target.key)),
            }
            if purpose == ScanPurpose::Recheck {
                continue;
            }
            if let Some(reference) =
                registration_match(scan, &target, |text| uninstall::service_image(text, scope))
            {
                scan.proposals.push(Proposal {
                    target: Target::Registry(target),
                    category: Category::Startup,
                    evidence: reference.evidence,
                    reason: reference
                        .reason("startup executable is within the verified installation directory"),
                    risk: Risk::High,
                    access: Access::ReadOnly(
                        "startup value is outside the verified direct current-user write scope"
                            .into(),
                    ),
                });
            }
        }
    }
    Ok(())
}

fn inspect_startup_value(
    target: &RegistryTarget,
    scope: &uninstall::RegisteredScope,
) -> io::Result<Option<(Proposal, String)>> {
    let Some(value) = registry::startup_value(target)? else {
        return Ok(None);
    };
    let Some(reference) = uninstall::registered_image(&value.executable, scope)? else {
        return Ok(None);
    };
    if reference.evidence != MatchKind::ExactIdentity {
        return Ok(None);
    }
    Ok(Some((
        Proposal {
            target: Target::Registry(target.clone()),
            category: Category::Startup,
            evidence: reference.evidence,
            reason: format!(
                "current-user startup value directly launches {} in the verified installation directory",
                reference.path.display()
            ),
            risk: Risk::High,
            access: Access::Allowed,
        },
        value.fingerprint,
    )))
}

fn registry_list(
    scan: &mut Scan,
    key: &RegistryTarget,
    read: impl FnOnce(&RegistryTarget) -> io::Result<Vec<String>>,
) -> Vec<String> {
    match read(key) {
        Ok(mut names) => {
            names.truncate(MAX_CANDIDATES.saturating_sub(scan.proposals.len()));
            names
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => {
            scan.warnings.push(format!("{}: {error}", key.key));
            Vec::new()
        }
    }
}

fn registration_match(
    scan: &mut Scan,
    address: &RegistryTarget,
    verify: impl FnOnce(&str) -> io::Result<Option<uninstall::RegisteredReference>>,
) -> Option<uninstall::RegisteredReference> {
    let verified = registry::string_value(address)
        .and_then(|text| text.as_deref().map(verify).transpose().map(Option::flatten));
    match verified {
        Ok(reference) => reference,
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => {
            scan.warnings.push(format!("{}: {error}", address.key));
            None
        }
    }
}

pub(super) fn elevated() -> io::Result<bool> {
    let mut token: HANDLE = null_mut();
    // SAFETY: The out pointer denotes a writable handle. The token is closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut elevation = TOKEN_ELEVATION::default();
    let mut length = 0;
    // SAFETY: TokenElevation writes a TOKEN_ELEVATION into the given output buffer.
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut length,
        )
    };
    let error = (result == 0).then(io::Error::last_os_error);
    // SAFETY: This token handle was returned by OpenProcessToken above.
    unsafe { CloseHandle(token) };
    match error {
        Some(error) => Err(error),
        None => Ok(elevation.TokenIsElevated != 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uninstallany_core::RegistryView;

    fn entry(key: &str, name: &str, publisher: Option<&str>) -> registry::InstalledEntry {
        registry::InstalledEntry {
            address: RegistryTarget {
                hive: RegistryHive::CurrentUser,
                view: RegistryView::Native,
                key: format!(r"Software\Microsoft\Windows\CurrentVersion\Uninstall\{key}"),
                value: None,
            },
            display_name: name.into(),
            display_version: None,
            publisher: publisher.map(str::to_owned),
            install_location: None,
            uninstall_string: None,
            quiet_uninstall_string: None,
            estimated_size_kib: None,
            install_date: None,
            windows_installer: false,
            system_component: false,
            no_remove: false,
        }
    }

    #[test]
    fn another_registration_for_the_same_registry_branch_blocks_cleanup() {
        let original = entry("version-one", "Example Editor", Some("Example Publisher"));
        let app = desktop_record(&original);
        let mut inventory = registry::Inventory {
            entries: vec![
                original,
                entry(
                    "different-publisher",
                    "EXAMPLE EDITOR",
                    Some("Other Publisher"),
                ),
                entry(
                    "different-editor",
                    "Other Editor",
                    Some("EXAMPLE PUBLISHER"),
                ),
            ],
            warnings: Vec::new(),
        };
        assert!(!registry_settings_are_shared(&app, &inventory));
        inventory.entries.push(entry(
            "version-two",
            "EXAMPLE EDITOR",
            Some("example publisher"),
        ));
        assert!(registry_settings_are_shared(&app, &inventory));
        inventory.entries.pop();
        inventory
            .entries
            .push(entry("unknown-publisher", "example editor", None));
        assert!(registry_settings_are_shared(&app, &inventory));
        inventory.entries.pop();
        inventory
            .warnings
            .push("Could not read one registry view".into());
        assert!(registry_settings_are_shared(&app, &inventory));
    }

    #[test]
    fn force_removal_requires_complete_inventory_and_an_unprotected_entry() {
        let original = entry("editor", "Example Editor", Some("Example Publisher"));
        let address = original.address.clone();
        let mut inventory = registry::Inventory {
            entries: vec![original],
            warnings: Vec::new(),
        };
        assert!(matches!(
            force_registration(&inventory, &address),
            Some(Proposal {
                access: Access::Allowed,
                ..
            })
        ));

        inventory
            .warnings
            .push("could not read an alternate registry view".into());
        assert!(matches!(
            force_registration(&inventory, &address),
            Some(Proposal {
                access: Access::ReadOnly(_),
                ..
            })
        ));

        inventory.warnings.clear();
        inventory.entries[0].system_component = true;
        assert!(is_protected_entry(&inventory.entries[0]));
        assert!(force_registration(&inventory, &address).is_none());
    }
}
