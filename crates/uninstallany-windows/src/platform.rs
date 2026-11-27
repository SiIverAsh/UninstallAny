use std::{
    collections::{HashMap, HashSet},
    ffi::OsStr,
    io,
    mem::size_of,
    num::NonZeroU16,
    os::windows::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
    ptr::null_mut,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use uninstallany_core::{
    Access, AppId, AppRecord, ApplicationUninstall, Artifact, Cancellation, Category, Engine,
    Error, FileStore, Inspection, Inventory, Journal, MatchKind, OfficialExecution, OfficialIntent,
    OfficialOutcome, PlatformBackend, PostUninstallCheck, PostUninstallScan, Proposal,
    RegistryBackupWriter, RegistryChangeReceipt, RegistryHive, RegistryStore, RegistryTarget,
    RegistryView, Result, Risk, RuleRoot, RuleTarget, Scan, ScanMode, Target,
    is_protected_registry_target, match_name,
};
use uuid::Uuid;
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_ACCESS_DENIED, ERROR_ELEVATION_REQUIRED, HANDLE},
    Globalization::{CSTR_EQUAL, CompareStringOrdinal},
    Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

use crate::{
    files::{
        FileDisposition, FileSnapshot, WindowsFiles,
        native::{OpenPath, canonical_claim_path},
    },
    firewall, helper, highrisk, msix, registrations, registry, shortcuts, tasks, uninstall,
};

/// ProductCode of the Windows machine MSI distributed by UninstallAny.
pub(crate) const OWN_MSI_PRODUCT_CODE: &str = "{B82A69F2-4229-4428-ADF3-001FBCFB2C16}";

const MAX_CANDIDATES: usize = 5_000;
const MAX_DEPTH: u8 = 8;
const APP_DATA_ENTRY_LIMIT: usize = 512;
const APP_DATA_DEPTH: u8 = 3;
const NESTED_SETTINGS_SUBKEY_LIMIT: u32 = 128;
const START_MENU_DEPTH: u8 = 2;
const SHORTCUT_EXECUTABLE_BYTE_BUDGET: u64 = 256 * 1024 * 1024;
const FAILED_UNINSTALL_AGE: Duration = Duration::from_secs(15 * 60);
const APP_PATHS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\App Paths";
const PACKAGE_NAME_HINT: &str =
    "a display-name match does not establish ownership for an MSIX package";
const FUZZY_NAME_HINT: &str = "fuzzy name alone does not authorize cleanup";
const MISSING_SHORTCUT_NAME_HINT: &str =
    "a missing shortcut target also requires a strict name match";
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
        failed_uninstalls: Arc::new(Mutex::new(HashMap::new())),
    };
    Ok(Engine::new(platform, State { files }))
}

#[derive(Clone)]
struct Backend {
    files: Arc<WindowsFiles>,
    failed_uninstalls: Arc<Mutex<HashMap<RegistryTarget, FailedUninstall>>>,
}

struct FailedUninstall {
    binding: String,
    action: uninstall::OfficialUninstall,
    directory: PathBuf,
    recorded: Instant,
    audited: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ObservedPackageShortcut {
    aumid: String,
    fingerprint: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedDesktopShortcut {
    fingerprint: String,
    executable: uninstall::ExecutableIdentity,
}

struct VerifiedDesktopShortcut {
    snapshot: FileSnapshot,
    executable: PathBuf,
    target_parent: OpenPath,
}

struct State {
    files: Arc<WindowsFiles>,
}

enum NativeCommand {
    Desktop(Box<DesktopUninstall>),
    Package(msix::MsixUninstall),
}

struct DesktopUninstall {
    native: uninstall::OfficialUninstall,
    elevation: Option<helper::PreparedMsi>,
    registration: registry::InstalledEntry,
    win32_directory: Option<PathBuf>,
}

struct InferredWin32Scope<'a> {
    command: &'a str,
    icon: &'a Path,
    directory: PathBuf,
}

struct InstallationOwnership<'a> {
    inventory: &'a registry::Inventory,
    paths: Vec<RegisteredPath<'a>>,
}

struct RegisteredPath<'a> {
    owner: &'a RegistryTarget,
    reported: PathBuf,
    canonical: Option<PathBuf>,
    parsed: bool,
}

impl<'a> InstallationOwnership<'a> {
    fn read(inventory: &'a registry::Inventory, cancel: &Cancellation) -> Result<Self> {
        let mut paths = Vec::new();
        let mut known_paths = HashMap::new();
        for registration in &inventory.path_claims {
            cancel.check()?;
            let possible_paths = [
                registration
                    .directory
                    .as_deref()
                    .map(|text| (text, Some(Path::new(text)))),
                registration
                    .icon
                    .as_deref()
                    .map(|text| (text, uninstall::display_icon_path(text))),
                registration.uninstall.as_deref().map(uninstall_path_claim),
                registration
                    .quiet_uninstall
                    .as_deref()
                    .map(uninstall_path_claim),
            ];
            for (text, parsed) in possible_paths.into_iter().flatten() {
                let reported =
                    parsed.unwrap_or_else(|| Path::new(text.trim_start_matches([' ', '\t', '"'])));
                if !reported.is_absolute() {
                    continue;
                }
                let canonical = if parsed.is_some() {
                    known_paths
                        .entry(reported.to_path_buf())
                        .or_insert_with(|| canonical_claim_path(reported).ok())
                        .clone()
                } else {
                    None
                };
                paths.push(RegisteredPath {
                    owner: &registration.address,
                    reported: reported.to_path_buf(),
                    canonical,
                    parsed: parsed.is_some(),
                });
            }
        }
        cancel.check()?;
        Ok(Self { inventory, paths })
    }

    fn another_owns(&self, selected: Option<&RegistryTarget>, path: &Path) -> bool {
        self.paths.iter().any(|claim| {
            selected != Some(claim.owner)
                && if claim.parsed {
                    paths_overlap(&claim.reported, path)
                        || claim
                            .canonical
                            .as_deref()
                            .is_some_and(|canonical| paths_overlap(canonical, path))
                } else {
                    // An ambiguous argument or icon suffix is only a veto when the
                    // registered text starts inside the candidate's directory.
                    below(&claim.reported, path)
                }
        })
    }

    fn another_matches_file_stem(&self, selected: Option<&RegistryTarget>, path: &Path) -> bool {
        let Some(name) = path.file_stem().and_then(OsStr::to_str) else {
            return false;
        };
        self.inventory.entries.iter().any(|other| {
            selected != Some(&other.address)
                && match_name(&other.display_name, None, name, None) == Some(MatchKind::AppName)
        })
    }

    fn app_data_directory_is_exclusive(&self, app: &AppRecord, directory: &Path) -> bool {
        let selected = registry_application(&app.id);
        let matches_app =
            |name| match_name(&app.name, None, name, None) == Some(MatchKind::AppName);
        self.inventory.warnings.is_empty()
            && matches_app(&app.name)
            && !app.publisher.as_deref().is_some_and(matches_app)
            // A registered install tree has its own evidence and scan path.
            // This fallback is limited to separate data folders.
            && !self.another_owns(None, directory)
            && !self.inventory.entries.iter().any(|entry| {
                selected != Some(&entry.address)
                    && (matches_app(&entry.display_name)
                        || entry.publisher.as_deref().is_some_and(matches_app))
            })
    }
}

fn uninstall_path_claim(text: &str) -> (&str, Option<&Path>) {
    (
        text,
        uninstall::split_command(text)
            .ok()
            .map(|(program, _)| Path::new(program)),
    )
}

fn registry_application(id: &AppId) -> Option<&RegistryTarget> {
    match id {
        AppId::WindowsRegistry(target) => Some(target),
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScanPurpose {
    Preview,
    Recheck,
}

enum StartupShortcutSource<'a> {
    Observed(&'a HashMap<PathBuf, String>),
    ForceRemoval(&'a RegistryTarget),
}

impl PlatformBackend for Backend {
    type Official = NativeCommand;

    fn begin_mutation(&self, cancel: &Cancellation) -> Result<impl Sized> {
        cancel.check()?;
        let lock = self.files.lock_mutations()?;
        if let Some(id) = self.finished_uninstall_marker()? {
            registry::clear_win32_launch(id)?;
        }
        *uninstall::local_pending_uninstall()? = None;
        cancel.check()?;
        Ok(lock)
    }

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

    fn lookup_application(&self, id: &AppId, cancel: &Cancellation) -> Result<Option<AppRecord>> {
        match id {
            AppId::WindowsRegistry(target) => Ok(registry::lookup_uninstall_entry(target, cancel)?
                .as_ref()
                .map(desktop_record)),
            AppId::WindowsPackage(full_name) => {
                Ok(msix::lookup_current_user(full_name, cancel)?.map(package_record))
            }
            AppId::Package { .. } => Ok(None),
        }
    }

    fn scan(&self, app: &AppRecord, mode: ScanMode, cancel: &Cancellation) -> Result<Scan> {
        self.scan_application(app, mode, ScanPurpose::Preview, None, cancel)
    }

    fn scan_for_cleanup_recheck(
        &self,
        app: &AppRecord,
        mode: ScanMode,
        cancel: &Cancellation,
    ) -> Result<Scan> {
        // Only discovery sources with no writable targets can be skipped here.
        self.scan_application(app, mode, ScanPurpose::Recheck, None, cancel)
    }

    fn scan_after_official_uninstall(
        &self,
        app: &AppRecord,
        observed_files: &HashMap<PathBuf, String>,
        phase: PostUninstallScan,
        cancel: &Cancellation,
    ) -> Result<Scan> {
        let purpose = match phase {
            PostUninstallScan::Preview => ScanPurpose::Preview,
            PostUninstallScan::Recheck => ScanPurpose::Recheck,
        };
        self.scan_application(
            app,
            ScanMode::AfterOfficialUninstall,
            purpose,
            Some(observed_files),
            cancel,
        )
    }

    fn scan_portable(&self, directory: &Path, cancel: &Cancellation) -> Result<Scan> {
        self.require_uninstall_idle()?;
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
        let arp = registry::inventory_for_ownership(cancel)?;
        let ownership = InstallationOwnership::read(&arp, cancel)?;
        if !arp.warnings.is_empty() || ownership.another_owns(None, &root.path) {
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

    fn check_force_removal_binding(
        &self,
        app: &AppId,
        binding: &str,
        cancel: &Cancellation,
    ) -> Result<()> {
        cancel.check()?;
        self.require_uninstall_idle()?;
        let address = registry_application(app)
            .ok_or_else(|| Error::Rejected("force removal requires a Win32 registration".into()))?;
        let current = registry::force_registration(address, None)?;
        if !current.is_some_and(|record| record.binding == binding) {
            return Err(Error::Rejected(
                "the uninstall registration changed; review force removal again".into(),
            ));
        }
        cancel.check()
    }

    fn check_force_removal_file(
        &self,
        app: &AppId,
        binding: &str,
        path: &Path,
        cancel: &Cancellation,
    ) -> Result<()> {
        if !self.files.is_startup_shortcut(path) {
            return self.check_force_removal_binding(app, binding, cancel);
        }

        cancel.check()?;
        self.require_uninstall_idle()?;
        let address = registry_application(app)
            .ok_or_else(|| Error::Rejected("force removal requires a Win32 registration".into()))?;
        let changed = || {
            Error::Rejected(
                "the Startup shortcut's force-removal eligibility changed; preview again".into(),
            )
        };
        let arp = registry::inventory_for_ownership(cancel)?;
        let ownership = InstallationOwnership::read(&arp, cancel)?;
        let entry = arp
            .entries
            .iter()
            .find(|entry| &entry.address == address)
            .ok_or_else(changed)?;
        let app = desktop_record(entry);
        let directory = self
            .exclusive_install_scope(&app, &ownership)
            .ok_or_else(changed)?;
        // The executable was bound inside this directory by the scan. The
        // file move still pins the exact link and executable from the preview.
        if ownership.another_owns(None, path)
            || self.force_removal_binding(&app, &ownership, Some(&directory), cancel)? != binding
        {
            return Err(changed());
        }
        cancel.check()
    }

    fn check_registry_cleanup_application(
        &self,
        app: &AppId,
        mode: ScanMode,
        target: &RegistryTarget,
        cancel: &Cancellation,
    ) -> Result<()> {
        if !registry::is_nested_app_settings_key(target) {
            return Ok(());
        }
        self.require_uninstall_idle()?;
        let changed = || {
            Error::Rejected(
                "the nested registry settings could belong to another application; preview again"
                    .into(),
            )
        };
        let address = registry_application(app).ok_or_else(changed)?;
        let mut parts = target.key.split('\\').skip(1);
        let publisher = parts.next().ok_or_else(changed)?;
        let application = parts.next().ok_or_else(changed)?;
        let inventory = registry::inventory_for_ownership(cancel)?;
        if !inventory.warnings.is_empty() {
            return Err(changed());
        }
        let original = inventory
            .entries
            .iter()
            .find(|entry| &entry.address == address);
        let eligible = match mode {
            ScanMode::AfterOfficialUninstall => !registry::uninstall_key_present(address)?,
            ScanMode::ForceRemoval => original.is_some_and(|entry| {
                !is_protected_entry(entry)
                    && !entry.no_remove
                    && !entry.windows_installer
                    && windows_eq(OsStr::new(&entry.display_name), OsStr::new(application))
                    && entry
                        .publisher
                        .as_deref()
                        .is_some_and(|name| windows_eq(OsStr::new(name), OsStr::new(publisher)))
            }),
            ScanMode::Leftovers => false,
        };
        let competing = competing_settings_apps(app, publisher, &inventory);
        if !eligible
            || std::iter::once(application)
                .chain(parts)
                .any(|name| settings_app_conflict(name, &competing))
        {
            return Err(changed());
        }
        cancel.check()
    }

    fn prepare_official(&self, app: &AppRecord) -> Result<(OfficialIntent, Self::Official)> {
        self.prepare_native_uninstall(app, &Cancellation::default())
    }

    fn prepare_application_uninstall(
        &self,
        app: &AppRecord,
        _retention_days: NonZeroU16,
        cancel: &Cancellation,
    ) -> Result<(OfficialIntent, ApplicationUninstall<Self::Official>)> {
        let (intent, command) = self.prepare_native_uninstall(app, cancel)?;
        Ok((intent, ApplicationUninstall::Official(command)))
    }

    fn run_official(&self, command: Self::Official) -> Result<OfficialOutcome> {
        self.run_official_with_cancel(command, &Cancellation::default())
            .map(|execution| execution.outcome)
    }

    fn run_official_with_cancel(
        &self,
        command: Self::Official,
        cancel: &Cancellation,
    ) -> Result<OfficialExecution> {
        cancel.check()?;
        self.require_uninstall_idle()?;
        let mut warnings = Vec::new();
        let (execution, mut observed_files, post_uninstall_check) = match command {
            NativeCommand::Desktop(command) => {
                let address = &command.registration.address;
                self.failed_uninstalls
                    .lock()
                    .map_err(|_| io::Error::other("could not reset the last uninstall result"))?
                    .remove(address);
                let force_record = if command.win32_directory.is_some() {
                    match registry::force_registration(address, Some(&command.registration)) {
                        Ok(record) => record,
                        Err(error) => {
                            warnings.push(format!(
                                "could not record the uninstall registration for possible force removal: {error}"
                            ));
                            None
                        }
                    }
                } else {
                    None
                };
                let observed = self.verify_desktop_uninstall(&command, &mut warnings, cancel)?;
                cancel.check()?;
                let msi_product = command.native.msi_product_code().map(str::to_owned);
                let mut execution = run_desktop(command.native, command.elevation, cancel)?;
                let check = if execution.outcome == uninstall::OfficialOutcome::Completed {
                    msi_product.map(msi_post_uninstall_check)
                } else {
                    None
                };
                if let (Some(action), Some(record), Some(directory)) = (
                    execution.terminal_win32_failure.take(),
                    force_record,
                    command.win32_directory,
                ) {
                    let mut failures = self.failed_uninstalls.lock().map_err(|_| {
                        io::Error::other("could not record the Windows uninstall failure")
                    })?;
                    failures.retain(|_, failure| failure.recorded.elapsed() < FAILED_UNINSTALL_AGE);
                    failures.insert(
                        command.registration.address,
                        FailedUninstall {
                            binding: record.binding,
                            action,
                            directory,
                            recorded: Instant::now(),
                            audited: false,
                        },
                    );
                }
                (execution, observed, check)
            }
            NativeCommand::Package(command) => {
                let mut observed = HashMap::new();
                let outcome =
                    command.execute_with_cancel(cancel, &mut warnings, |targets, warnings| {
                        observed = self.observe_package_shortcuts(targets, warnings, cancel)?;
                        Ok(())
                    })?;
                (
                    uninstall::NativeExecution::finished(outcome),
                    observed,
                    None,
                )
            }
        };
        if let Some(pending) = execution.detached {
            *uninstall::local_pending_uninstall()? = Some(pending.process);
            observed_files.clear();
            warnings.push(pending.warning);
        }
        warnings.extend(execution.warnings);
        let outcome = match execution.outcome {
            uninstall::OfficialOutcome::Completed => OfficialOutcome::Completed,
            uninstall::OfficialOutcome::NeedsRestart => OfficialOutcome::NeedsRestart,
            uninstall::OfficialOutcome::Cancelled => OfficialOutcome::Cancelled,
            uninstall::OfficialOutcome::Failed(code) => OfficialOutcome::Failed(code),
            uninstall::OfficialOutcome::Unverified(code) => OfficialOutcome::Unverified(code),
        };
        Ok(OfficialExecution {
            outcome,
            warnings,
            read_only_residuals: Vec::new(),
            observed_files,
            post_uninstall_check,
        })
    }

    fn verify_finished_official_after_cancel(&self) -> bool {
        true
    }

    fn record_audited_official_outcome(&self, app: &AppRecord, outcome: &OfficialOutcome) {
        if !matches!(outcome, OfficialOutcome::Failed(_)) {
            return;
        }
        let AppId::WindowsRegistry(address) = &app.id else {
            return;
        };
        let Ok(mut failures) = self.failed_uninstalls.lock() else {
            return;
        };
        if let Some(failure) = failures.get_mut(address) {
            failure.audited = true;
        }
    }

    fn official_uninstall_absent(&self, id: &AppId, cancel: &Cancellation) -> Result<bool> {
        cancel.check()?;
        match id {
            AppId::WindowsRegistry(target) => Ok(!registry::uninstall_key_present(target)?),
            AppId::WindowsPackage(full_name) => {
                Ok(!msix::current_package_present(full_name, cancel)?)
            }
            AppId::Package { .. } => Ok(false),
        }
    }

    fn check_cleanup_after_uninstall(&self, app: &AppRecord, cancel: &Cancellation) -> Result<()> {
        cancel.check()?;
        let registered = match &app.id {
            AppId::WindowsRegistry(target) => registry::uninstall_key_present(target)?,
            AppId::WindowsPackage(full_name) => msix::current_family_present(full_name, cancel)?,
            AppId::Package { .. } => {
                return Err(Error::Rejected(
                    "application is not managed by Windows".into(),
                ));
            }
        };
        cancel.check()?;
        if registered {
            return Err(Error::Rejected(
                "a Windows installation for this application is present; leftover cleanup is unavailable".into(),
            ));
        }
        Ok(())
    }

    fn check_cleanup_observations(
        &self,
        app: &AppRecord,
        observed_files: &HashMap<PathBuf, String>,
        cancel: &Cancellation,
    ) -> Result<()> {
        cancel.check()?;
        if let Some(directory) = app.install_location.as_deref() {
            if let Some(proof) = former_installation(app, observed_files)? {
                proof.verify(directory).map_err(|error| {
                    Error::Rejected(format!("the original Windows installation could not be reverified for cleanup: {error}"))
                })?;
            }
        }
        cancel.check()
    }

    fn pin_post_uninstall_file(
        &self,
        app: &AppRecord,
        path: &Path,
        observed_files: &HashMap<PathBuf, String>,
        cancel: &Cancellation,
    ) -> Result<impl Sized> {
        cancel.check()?;
        self.require_uninstall_idle()?;
        let changed = || {
            Error::Rejected(
                "the original shortcut or its missing target could not be reverified".into(),
            )
        };
        let selected = registry_application(&app.id).ok_or_else(changed)?;
        let arp = registry::inventory_for_ownership(cancel)?;
        let ownership = InstallationOwnership::read(&arp, cancel)?;
        let (directory, root) = self
            .exclusive_install_claim(app, &ownership)
            .ok_or_else(changed)?;
        let proof = former_installation(app, observed_files)?.ok_or_else(changed)?;
        let scope = uninstall::RegisteredScope::after_uninstall(directory, root, &proof)?;
        let evidence = serde_json::from_str(observed_files.get(path).ok_or_else(changed)?)?;
        let shortcut = self
            .verify_observed_desktop_shortcut(path, &evidence, &scope, &ownership, selected)?
            .ok_or_else(changed)?;
        if registry::uninstall_key_present(selected)? {
            return Err(changed());
        }
        cancel.check()?;
        Ok(shortcut.target_parent)
    }
}

fn former_installation(
    app: &AppRecord,
    observed_files: &HashMap<PathBuf, String>,
) -> Result<Option<uninstall::FormerInstallation>> {
    app.install_location
        .as_ref()
        .and_then(|path| observed_files.get(path))
        .map(|proof| serde_json::from_str(proof).map_err(Error::from))
        .transpose()
}

fn msi_post_uninstall_check(product_code: String) -> PostUninstallCheck {
    Box::new(move |cancel| {
        cancel.check()?;
        // An elevated helper can use a different account. Check the MSI
        // contexts visible to the desktop that will be cleaning up.
        if !uninstall::verify_msi_product_absent(&product_code)? {
            return Err(Error::Rejected(format!(
                "Windows Installer still registers product {product_code}; leftover cleanup is unavailable"
            )));
        }
        cancel.check()
    })
}

fn run_desktop(
    native: uninstall::OfficialUninstall,
    elevation: Option<helper::PreparedMsi>,
    cancel: &Cancellation,
) -> Result<uninstall::NativeExecution> {
    let result = native.execute_with_cancel(cancel);
    let launch_needs_elevation = result
        .as_ref()
        .is_err_and(|error| error.raw_os_error() == Some(ERROR_ELEVATION_REQUIRED as i32));
    let msi_needs_elevation = elevation.is_some()
        && result.as_ref().is_ok_and(|execution| {
            matches!(
                execution.outcome,
                uninstall::OfficialOutcome::Failed(ERROR_ACCESS_DENIED | ERROR_ELEVATION_REQUIRED)
            )
        });
    if !launch_needs_elevation && !msi_needs_elevation {
        return Ok(result?);
    }
    if cancel.check().is_err() {
        // Preserve the result of a completed first attempt. Only the retry was cancelled.
        return result.map_err(|_| Error::Cancelled);
    }
    if let Some(prepared) = elevation {
        // An observed error could still leave a marker if it could not be
        // cleared. Do not send another provider request in that state.
        if registry::pending_native_launch()?.is_some() {
            return Ok(result?);
        }
        return Ok(prepared.execute(cancel)?);
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "the official uninstaller requires administrator access. Use Windows Settings for the native prompt",
    )
    .into())
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
    fn require_uninstall_idle(&self) -> io::Result<()> {
        self.finished_uninstall_marker().map(|_| ())
    }

    // A preview can observe completion without changing the shared marker.
    // Only the write guard is allowed to clear it and release the local handle.
    fn finished_uninstall_marker(&self) -> io::Result<Option<Uuid>> {
        let marker = match registry::pending_native_launch()? {
            Some(registry::NativeLaunch::Win32 { id, committed }) => Some((id, committed)),
            Some(registry::NativeLaunch::System { uninstaller, .. }) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "The outcome from {} could not be verified. Restart Windows before making changes.",
                        uninstaller.name()
                    ),
                ));
            }
            None => None,
        };
        let pending = uninstall::local_pending_uninstall()?;
        if let Some(process) = pending.as_ref() {
            if !process.is_finished()? {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "the previous Windows uninstaller is still running",
                ));
            }
            if let Some((id, _)) = marker {
                if process.job_id() == Some(id) {
                    return Ok(Some(id));
                }
            }
        }
        if let Some((id, committed)) = marker {
            uninstall::require_finished_win32_job(id, committed)?;
            return Ok(Some(id));
        }
        Ok(None)
    }

    fn prepare_native_uninstall(
        &self,
        app: &AppRecord,
        cancel: &Cancellation,
    ) -> Result<(OfficialIntent, NativeCommand)> {
        cancel.check()?;
        self.require_uninstall_idle()?;
        let mut notice = "The system or publisher uninstaller makes its own changes. Review any native prompts. Residual restore covers UninstallAny cleanup.".to_string();
        let (command, method, quiet) = match &app.id {
            AppId::WindowsRegistry(address) => {
                let arp = registry::inventory_for_ownership(cancel)?;
                let Some(registered) = arp.entries.iter().find(|entry| &entry.address == address)
                else {
                    return Err(Error::Rejected(
                        "registered application changed or is protected".into(),
                    ));
                };
                let current = desktop_record(registered);
                if current.name != app.name
                    || current.version != app.version
                    || current.publisher != app.publisher
                    || current.install_location != app.install_location
                {
                    return Err(Error::Rejected(
                        "application registration changed while preparing the preview".into(),
                    ));
                }
                if is_protected_entry(registered) || registered.no_remove {
                    return Err(Error::Rejected(
                        "the registry reports a protected application or system component".into(),
                    ));
                }
                let mut elevation = None;
                let mut win32_directory = None;
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
                } else if registered.install_location_absent {
                    let ownership = InstallationOwnership::read(&arp, cancel)?;
                    let scope = self.inferred_win32_scope(registered, &ownership)?;
                    let native = uninstall::prepare_inferred_win32(
                        scope.command,
                        scope.icon,
                        &scope.directory,
                    )?;
                    notice.push_str(" Windows did not register an installation directory. The application icon and uninstaller were verified in the same current-user program folder. That folder is used to authorize this launch only.");
                    win32_directory = Some(scope.directory);
                    native
                } else {
                    let ownership = InstallationOwnership::read(&arp, cancel)?;
                    win32_directory = self.exclusive_install_scope(&current, &ownership);
                    uninstall::prepare_win32(
                        registered.quiet_uninstall_string.as_deref(),
                        registered.uninstall_string.as_deref(),
                        win32_directory.as_deref(),
                    )?
                };
                let method = native.summary();
                let quiet = native.is_quiet();
                let command = NativeCommand::Desktop(Box::new(DesktopUninstall {
                    native,
                    elevation,
                    registration: registered.clone(),
                    win32_directory,
                }));
                (command, method, quiet)
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
        cancel.check()?;
        Ok((intent, command))
    }

    fn inferred_win32_scope<'a>(
        &self,
        entry: &'a registry::InstalledEntry,
        ownership: &InstallationOwnership<'_>,
    ) -> Result<InferredWin32Scope<'a>> {
        let unavailable = || {
            Error::Rejected(
                "the registration has no verified current-user uninstall directory".into(),
            )
        };
        if entry.address.hive != RegistryHive::CurrentUser
            || !ownership.inventory.warnings.is_empty()
        {
            return Err(unavailable());
        }
        let command = entry.uninstall_string.as_deref().ok_or_else(unavailable)?;
        let (program, arguments) = uninstall::split_command(command)?;
        let icon = entry
            .display_icon
            .as_deref()
            .and_then(uninstall::display_icon_path)
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
            })
            .ok_or_else(unavailable)?;
        let directory = Path::new(program).parent().ok_or_else(unavailable)?;
        let name = directory
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(unavailable)?;
        let has_specific_scope = arguments.is_empty()
            && icon
                .parent()
                .is_some_and(|parent| same_path(parent, directory))
            && match_name(&entry.display_name, None, name, None) == Some(MatchKind::AppName);
        if !has_specific_scope {
            return Err(unavailable());
        }
        let directory = self
            .files
            .inferred_user_program_directory(directory)
            .and_then(|directory| self.inspect_install_directory(&directory))
            .ok_or_else(unavailable)?;

        let shares_name = ownership.inventory.entries.iter().any(|other| {
            other.address != entry.address
                && match_name(&entry.display_name, None, &other.display_name, None)
                    == Some(MatchKind::AppName)
        });
        if shares_name || ownership.another_owns(Some(&entry.address), &directory) {
            return Err(Error::Rejected(
                "another uninstall registration may own this application directory".into(),
            ));
        }
        Ok(InferredWin32Scope {
            command,
            icon,
            directory,
        })
    }

    fn verify_desktop_uninstall(
        &self,
        command: &DesktopUninstall,
        warnings: &mut Vec<String>,
        cancel: &Cancellation,
    ) -> Result<HashMap<PathBuf, String>> {
        let app = desktop_record(&command.registration);
        let mut observed_files = HashMap::new();
        let data_directories = self.files.app_data_directories(&app.name);
        if command.win32_directory.is_some()
            || app.install_location.is_some()
            || !data_directories.is_empty()
        {
            let arp = registry::inventory_for_ownership(cancel)?;
            let ownership = InstallationOwnership::read(&arp, cancel)?;
            if let Some(approved_directory) = &command.win32_directory {
                let exclusive = if command.registration.install_location_absent {
                    Some(
                        self.inferred_win32_scope(&command.registration, &ownership)?
                            .directory,
                    )
                } else {
                    self.exclusive_install_scope(&app, &ownership)
                };
                if !exclusive.is_some_and(|current| same_path(&current, approved_directory)) {
                    return Err(Error::Rejected(
                        "could not reverify the exclusive uninstall directory; preview again"
                            .into(),
                    ));
                }
            }
            // Inferred launch paths are deliberately absent from AppRecord.
            if let Some((path, root)) = self.exclusive_install_claim(&app, &ownership) {
                match uninstall::FormerInstallation::capture(path, root) {
                    Ok(proof) => {
                        observed_files.insert(path.to_path_buf(), serde_json::to_string(&proof)?);
                        // Link ownership must use the same installation identity
                        // captured here, even if the directory changes during discovery.
                        match uninstall::RegisteredScope::after_uninstall(path, root, &proof) {
                            Ok(scope) => {
                                self.capture_startup_shortcuts(
                                    &scope,
                                    &mut observed_files,
                                    warnings,
                                    cancel,
                                )?;
                                self.capture_desktop_shortcuts(
                                    &scope,
                                    &ownership,
                                    &command.registration.address,
                                    &mut observed_files,
                                    warnings,
                                    cancel,
                                )?;
                            }
                            Err(error) => warnings.push(format!(
                                "could not verify the installation for shortcut discovery: {error}"
                            )),
                        }
                    }
                    Err(error) => warnings.push(format!(
                        "could not record the installation directory before uninstall: {error}"
                    )),
                }
            }
            for directory in data_directories {
                if ownership.app_data_directory_is_exclusive(&app, &directory) {
                    self.capture_app_data_files(&directory, &mut observed_files, warnings, cancel)?;
                }
            }
        }
        // Re-read the selected record after the ownership scan. Executable
        // identity alone cannot tell whether the registered arguments changed.
        let current = registry::lookup_uninstall_entry(&command.registration.address, cancel)?;
        if !current
            .is_some_and(|current| command.registration.same_uninstall_registration(&current))
        {
            return Err(Error::Rejected(
                "the registered uninstall action changed; preview again".into(),
            ));
        }
        Ok(observed_files)
    }

    fn scan_application(
        &self,
        app: &AppRecord,
        mode: ScanMode,
        purpose: ScanPurpose,
        observed_files: Option<&HashMap<PathBuf, String>>,
        cancel: &Cancellation,
    ) -> Result<Scan> {
        self.require_uninstall_idle()?;
        let arp = registry::inventory_for_ownership(cancel)?;
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
        let ownership = InstallationOwnership::read(&arp, cancel)?;
        let claimed = self.exclusive_install_claim(app, &ownership);
        let directory = claimed.and_then(|(path, _)| self.inspect_install_directory(path));
        let former = observed_files
            .map(|files| former_installation(app, files))
            .transpose()?
            .flatten();
        let mut scan = Scan::new(Vec::new(), arp.warnings.clone());
        if mode == ScanMode::ForceRemoval {
            scan.bind_force_removal(self.force_removal_binding(
                app,
                &ownership,
                directory.as_deref(),
                cancel,
            )?);
        }
        let scope = if mode == ScanMode::AfterOfficialUninstall {
            claimed.zip(former.as_ref()).map(|((path, root), proof)| {
                uninstall::RegisteredScope::after_uninstall(path, root, proof)
            })
        } else {
            directory
                .as_deref()
                .map(uninstall::RegisteredScope::existing)
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
        if let Some(path) = directory
            .as_ref()
            .filter(|_| mode != ScanMode::AfterOfficialUninstall || scope.is_some())
        {
            self.scan_tree(
                &mut scan,
                path,
                MatchKind::ExactIdentity,
                "verified application installation directory",
                cancel,
            )?;
        }
        self.scan_named_files(app, &mut scan, &ownership, scope.as_ref(), cancel)?;
        self.scan_program_menu(app, &mut scan, &ownership, scope.as_ref(), cancel)?;
        if mode == ScanMode::AfterOfficialUninstall
            && matches!(app.id, AppId::WindowsRegistry(_))
            && let Some(observed_files) = observed_files
        {
            self.add_observed_app_data_files(app, &mut scan, &ownership, observed_files, cancel)?;
        }
        if mode == ScanMode::AfterOfficialUninstall && scope.is_none() {
            if let Some(original) = app.install_location.as_deref() {
                let reason = "the original installation directory could not be verified from before uninstall";
                let canonical = canonical_claim_path(original).ok();
                scan.warnings.push(reason.into());
                for proposal in &mut scan.proposals {
                    if matches!(&proposal.target, Target::File(path)
                        if paths_overlap(path, original)
                            || canonical.as_deref().is_some_and(|directory| paths_overlap(path, directory)))
                    {
                        proposal.access = Access::ReadOnly(reason.into());
                    }
                }
            }
        }
        match &app.id {
            AppId::WindowsRegistry(address) => {
                self.scan_registry(app, &arp, &mut scan, cancel)?;
                if let Some(scope) = &scope {
                    scan_startup_registrations(scope, &mut scan, purpose, cancel)?;
                    let startup_source = if mode == ScanMode::ForceRemoval {
                        Some(StartupShortcutSource::ForceRemoval(address))
                    } else {
                        observed_files.map(StartupShortcutSource::Observed)
                    };
                    if let Some(source) = startup_source {
                        self.add_startup_shortcuts(&mut scan, &ownership, scope, source, cancel)?;
                    }
                    if mode == ScanMode::AfterOfficialUninstall
                        && let Some(observed) = observed_files
                    {
                        self.add_observed_desktop_shortcuts(
                            &mut scan, &ownership, address, scope, observed, cancel,
                        )?;
                    }
                }
                if mode == ScanMode::ForceRemoval {
                    scan.proposals.extend(force_registration(&arp, address));
                }
                if matches!(
                    mode,
                    ScanMode::AfterOfficialUninstall | ScanMode::ForceRemoval
                ) {
                    scan_nested_app_settings(app, &arp, &mut scan, cancel)?;
                }
            }
            AppId::WindowsPackage(full_name) => {
                if let Some(observed_files) = observed_files {
                    self.add_package_shortcuts(&mut scan, &ownership, observed_files, cancel)?;
                }
                if purpose == ScanPurpose::Preview && mode == ScanMode::AfterOfficialUninstall {
                    self.report_package_data(full_name, &mut scan);
                }
            }
            AppId::Package { .. } => {}
        }
        if let (ScanPurpose::Preview, Some(scope)) = (purpose, scope.as_ref()) {
            discover_system_registrations(scope, &mut scan, cancel)?;
        }
        Ok(scan)
    }

    fn capture_app_data_files(
        &self,
        directory: &Path,
        observed: &mut HashMap<PathBuf, String>,
        warnings: &mut Vec<String>,
        cancel: &Cancellation,
    ) -> Result<()> {
        let mut pending = vec![(directory.to_path_buf(), 0)];
        let mut remaining = APP_DATA_ENTRY_LIMIT;
        let mut reached_limit = false;
        while let Some((path, depth)) = pending.pop() {
            cancel.check()?;
            remaining -= 1;
            let snapshot = match self.files.inspect(&path) {
                Ok(snapshot) if same_path(&snapshot.path, &path) => snapshot,
                Ok(_) => continue,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    warnings.push(format!(
                        "could not inspect AppData entry {}: {error}",
                        path.display()
                    ));
                    continue;
                }
            };
            if snapshot.disposition == FileDisposition::Directory && depth < APP_DATA_DEPTH {
                match self.files.children(&path) {
                    Ok(children) => {
                        let capacity = remaining - pending.len();
                        reached_limit |= children.len() > capacity;
                        pending.extend(
                            children
                                .into_iter()
                                .take(capacity)
                                .rev()
                                .map(|child| (child, depth + 1)),
                        );
                    }
                    Err(error) => warnings.push(format!(
                        "could not scan AppData directory {}: {error}",
                        path.display()
                    )),
                }
            } else if snapshot.is_local_regular_file() && category_for_path(&path) == Category::File
            {
                observed.insert(snapshot.path.clone(), serde_json::to_string(&snapshot)?);
            }
        }
        if reached_limit {
            warnings.push(format!(
                "AppData scan reached its entry limit in {}",
                directory.display()
            ));
        }
        Ok(())
    }

    fn add_observed_app_data_files(
        &self,
        app: &AppRecord,
        scan: &mut Scan,
        ownership: &InstallationOwnership<'_>,
        observed: &HashMap<PathBuf, String>,
        cancel: &Cancellation,
    ) -> Result<()> {
        if observed.is_empty() {
            return Ok(());
        }
        let directories: Vec<_> = self
            .files
            .app_data_directories(&app.name)
            .into_iter()
            .filter(|directory| ownership.app_data_directory_is_exclusive(app, directory))
            .collect();
        if directories.is_empty() {
            return Ok(());
        }
        let mut paths: Vec<_> = observed
            .iter()
            .filter(|(path, _)| {
                category_for_path(path) == Category::File
                    && directories.iter().any(|directory| below(path, directory))
            })
            .collect();
        paths.sort_unstable_by_key(|(path, _)| *path);
        for (path, expected) in paths {
            cancel.check()?;
            if scan.proposals.len() >= MAX_CANDIDATES {
                scan.warnings
                    .push("AppData preview reached its candidate limit".into());
                break;
            }
            let snapshot = match self.files.inspect(path) {
                Ok(snapshot)
                    if snapshot.is_local_regular_file() && same_path(&snapshot.path, path) =>
                {
                    snapshot
                }
                Ok(_) => continue,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    scan.warnings.push(format!(
                        "could not recheck AppData file {}: {error}",
                        path.display()
                    ));
                    continue;
                }
            };
            let fingerprint = serde_json::to_string(&snapshot)?;
            if &fingerprint == expected {
                scan.push_observed(
                    Proposal {
                        target: Target::File(snapshot.path),
                        category: Category::File,
                        evidence: MatchKind::AppName,
                        reason: "file was present before uninstall under the exact app name in current-user AppData".into(),
                        risk: Risk::High,
                        access: Access::Allowed,
                    },
                    fingerprint,
                );
            }
        }
        Ok(())
    }

    fn capture_startup_shortcuts(
        &self,
        scope: &uninstall::RegisteredScope,
        observed: &mut HashMap<PathBuf, String>,
        warnings: &mut Vec<String>,
        cancel: &Cancellation,
    ) -> Result<()> {
        cancel.check()?;
        for path in self.bounded_startup_shortcut_paths(warnings) {
            cancel.check()?;
            if let Some((snapshot, _)) = self.read_scoped_startup_shortcut(&path, scope, warnings) {
                observed.insert(snapshot.path.clone(), serde_json::to_string(&snapshot)?);
            }
        }
        Ok(())
    }

    fn bounded_startup_shortcut_paths(&self, warnings: &mut Vec<String>) -> Vec<PathBuf> {
        let mut paths = match self.files.startup_shortcut_paths() {
            Ok(paths) => paths,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Vec::new(),
            Err(error) => {
                warnings.push(format!(
                    "could not read the current user Startup folder: {error}"
                ));
                return Vec::new();
            }
        };
        if paths.len() > MAX_CANDIDATES {
            warnings.push("Startup shortcut discovery reached its entry limit".into());
        }
        paths.truncate(MAX_CANDIDATES);
        paths
    }

    fn read_scoped_startup_shortcut(
        &self,
        path: &Path,
        scope: &uninstall::RegisteredScope,
        warnings: &mut Vec<String>,
    ) -> Option<(FileSnapshot, PathBuf)> {
        match self
            .files
            .read_startup_shortcut(path, |target| scope.startup_shortcut_identity(target))
        {
            Ok(result) => result,
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => {
                warnings.push(format!(
                    "could not verify Startup shortcut {}: {error}",
                    path.display()
                ));
                None
            }
        }
    }

    fn add_startup_shortcuts(
        &self,
        scan: &mut Scan,
        ownership: &InstallationOwnership<'_>,
        scope: &uninstall::RegisteredScope,
        source: StartupShortcutSource<'_>,
        cancel: &Cancellation,
    ) -> Result<()> {
        cancel.check()?;
        let mut paths = match source {
            StartupShortcutSource::Observed(observed) => observed
                .keys()
                .filter(|path| self.files.is_startup_shortcut(path))
                .cloned()
                .collect(),
            StartupShortcutSource::ForceRemoval(_) => {
                self.bounded_startup_shortcut_paths(&mut scan.warnings)
            }
        };
        paths.sort_unstable();
        for path in paths {
            cancel.check()?;
            if scan.proposals.len() >= MAX_CANDIDATES {
                break;
            }
            if ownership.another_owns(None, &path) {
                continue;
            }
            let Some((snapshot, executable)) =
                self.read_scoped_startup_shortcut(&path, scope, &mut scan.warnings)
            else {
                continue;
            };
            let fingerprint = serde_json::to_string(&snapshot)?;
            let reason = match source {
                StartupShortcutSource::Observed(observed)
                    if observed.get(&path) == Some(&fingerprint) =>
                {
                    format!(
                        "current-user Startup shortcut still points directly to the original executable {}",
                        executable.display()
                    )
                }
                StartupShortcutSource::ForceRemoval(address)
                    if !ownership.another_owns(Some(address), &executable) =>
                {
                    format!(
                        "current-user Startup shortcut points directly to {} in the verified force-removal install directory",
                        executable.display()
                    )
                }
                _ => continue,
            };
            scan.push_observed(
                Proposal {
                    target: Target::File(snapshot.path),
                    category: Category::Startup,
                    evidence: MatchKind::ExactIdentity,
                    reason,
                    risk: Risk::High,
                    access: Access::Allowed,
                },
                fingerprint,
            );
        }
        Ok(())
    }

    fn force_removal_binding(
        &self,
        app: &AppRecord,
        ownership: &InstallationOwnership<'_>,
        directory: Option<&Path>,
        cancel: &Cancellation,
    ) -> Result<String> {
        cancel.check()?;
        let address = registry_application(&app.id)
            .ok_or_else(|| Error::Rejected("force removal requires a Win32 registration".into()))?;
        let arp = ownership.inventory;
        let entry = arp
            .entries
            .iter()
            .find(|entry| &entry.address == address)
            .filter(|entry| {
                !is_protected_entry(entry) && !entry.no_remove && !entry.windows_installer
            })
            .ok_or_else(|| {
                Error::Rejected("uninstall registration changed or is protected".into())
            })?;
        let current = desktop_record(entry);
        if !arp.warnings.is_empty()
            || current.name != app.name
            || current.publisher != app.publisher
            || current.version != app.version
            || current.install_location != app.install_location
        {
            return Err(Error::Rejected(
                "could not verify the current uninstall record for force removal".into(),
            ));
        }
        let record = registry::force_registration(address, Some(entry))?.ok_or_else(|| {
            Error::Rejected("force removal requires an unchanged, unmanaged Win32 registration with literal uninstall commands or no commands".into())
        })?;
        if record.programs.iter().all(Option::is_none) {
            return Ok(record.binding);
        }
        if let Some(directory) = directory {
            let scope = uninstall::RegisteredScope::existing(directory)?;
            let mut all_missing = true;
            for program in record.programs.iter().flatten() {
                cancel.check()?;
                if !scope.missing_uninstaller(program)? {
                    all_missing = false;
                    break;
                }
            }
            if all_missing {
                return Ok(record.binding);
            }
        }
        let failures = self
            .failed_uninstalls
            .lock()
            .map_err(|_| io::Error::other("could not read the last Windows uninstall result"))?;
        let unavailable = || {
            Error::Rejected(
            "force removal requires missing uninstall commands, missing executables in the verified application directory, or a verified failure from this session".into(),
        )
        };
        let failure = failures
            .get(address)
            .filter(|failure| {
                failure.audited
                    && failure.binding == record.binding
                    && failure.recorded.elapsed() < FAILED_UNINSTALL_AGE
            })
            .ok_or_else(unavailable)?;
        let verified_directory = if entry.install_location_absent {
            Some(self.inferred_win32_scope(entry, ownership)?.directory)
        } else {
            directory.map(Path::to_path_buf)
        };
        let verified_directory = verified_directory
            .filter(|verified| same_path(verified, &failure.directory))
            .ok_or_else(unavailable)?;
        let scope = uninstall::RegisteredScope::existing(&verified_directory)?;
        if !record
            .programs
            .iter()
            .flatten()
            .all(|program| scope.contains_uninstaller(program))
        {
            return Err(unavailable());
        }
        failure.action.revalidate_failed_images()?;
        cancel.check()?;
        Ok(record.binding)
    }

    fn exclusive_install_scope(
        &self,
        app: &AppRecord,
        ownership: &InstallationOwnership<'_>,
    ) -> Option<PathBuf> {
        let (path, _) = self.exclusive_install_claim(app, ownership)?;
        self.inspect_install_directory(path)
    }

    fn exclusive_install_claim<'a>(
        &'a self,
        app: &'a AppRecord,
        ownership: &InstallationOwnership<'_>,
    ) -> Option<(&'a Path, &'a Path)> {
        let path = app.install_location.as_deref()?;
        if !ownership.inventory.warnings.is_empty()
            || !self.files.allows_registration_location(path)
            || ownership.another_owns(registry_application(&app.id), path)
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
        ownership: &InstallationOwnership<'_>,
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
                        ownership,
                        (child.clone(), evidence),
                        scope,
                        cancel,
                    )?;
                }
                if publisher_path_matches(app, &child) {
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
                                        ownership,
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

    fn capture_desktop_shortcuts(
        &self,
        scope: &uninstall::RegisteredScope,
        ownership: &InstallationOwnership<'_>,
        selected: &RegistryTarget,
        observed: &mut HashMap<PathBuf, String>,
        warnings: &mut Vec<String>,
        cancel: &Cancellation,
    ) -> Result<()> {
        let paths =
            self.user_shortcut_paths(self.files.default_user_shortcut_desktop(), warnings, cancel)?;
        let mut bytes_remaining = SHORTCUT_EXECUTABLE_BYTE_BUDGET;
        let mut unreadable = 0;
        for path in paths {
            cancel.check()?;
            if bytes_remaining == 0 {
                warnings.push("shortcut target verification reached its read limit".into());
                break;
            }
            if ownership.another_owns(None, &path)
                || ownership.another_matches_file_stem(Some(selected), &path)
            {
                continue;
            }
            let mut observe = || -> io::Result<_> {
                let (snapshot, bytes) = self.files.read_shortcut(&path)?;
                let Some(target) = shortcuts::startup_target(&bytes)? else {
                    return Ok(None);
                };
                if !snapshot.is_local_regular_file()
                    || ownership.another_owns(Some(selected), &target.path)
                {
                    return Ok(None);
                }
                let Some(executable) =
                    scope.observe_direct_shortcut_executable(&target, &mut bytes_remaining)?
                else {
                    return Ok(None);
                };
                let fingerprint = serde_json::to_string(&snapshot).map_err(io::Error::other)?;
                Ok(Some((
                    snapshot.path,
                    ObservedDesktopShortcut {
                        fingerprint,
                        executable,
                    },
                )))
            };
            match observe() {
                Ok(Some((path, proof))) => {
                    observed.insert(path, serde_json::to_string(&proof)?);
                }
                Ok(None) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    unreadable += 1;
                    if unreadable == 1 {
                        warnings.push(format!(
                            "could not verify shortcut {}: {error}",
                            path.display()
                        ));
                    }
                }
            }
        }
        if unreadable > 1 {
            warnings.push(format!(
                "shortcut verification skipped {unreadable} unreadable entries"
            ));
        }
        Ok(())
    }

    fn add_observed_desktop_shortcuts(
        &self,
        scan: &mut Scan,
        ownership: &InstallationOwnership<'_>,
        selected: &RegistryTarget,
        scope: &uninstall::RegisteredScope,
        observed: &HashMap<PathBuf, String>,
        cancel: &Cancellation,
    ) -> Result<()> {
        let mut paths: Vec<_> = observed.iter().collect();
        paths.sort_unstable_by_key(|(path, _)| *path);
        let mut verified = HashSet::new();
        for (path, evidence) in paths {
            cancel.check()?;
            if scan.proposals.len() >= MAX_CANDIDATES {
                break;
            }
            let Ok(evidence) = serde_json::from_str::<ObservedDesktopShortcut>(evidence) else {
                // Other observations bind install directories, AppData, or Startup.
                continue;
            };
            match self.verify_observed_desktop_shortcut(path, &evidence, scope, ownership, selected)
            {
                Ok(Some(shortcut)) => {
                    let path = shortcut.snapshot.path;
                    let target = Target::File(path.clone());
                    verified.insert(target.clone());
                    scan.require_post_uninstall_file_guard(path);
                    scan.push_observed(
                        Proposal {
                            target,
                            category: Category::Shortcut,
                            evidence: MatchKind::ExactIdentity,
                            reason: format!(
                                "the unchanged shortcut pointed directly to the former executable {}, which is now absent",
                                shortcut.executable.display()
                            ),
                            risk: Risk::High,
                            access: Access::Allowed,
                        },
                        evidence.fingerprint,
                    );
                }
                Ok(None) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => scan.warnings.push(format!("{}: {error}", path.display())),
            }
        }
        // Exact prior attribution supersedes only name-based hints. Shared or
        // protected ownership must still veto any duplicate.
        scan.proposals.retain(|proposal| {
            !matches!(&proposal.access, Access::ReadOnly(reason)
                if (reason == FUZZY_NAME_HINT || reason == MISSING_SHORTCUT_NAME_HINT)
                    && verified.contains(&proposal.target))
        });
        Ok(())
    }

    fn verify_observed_desktop_shortcut(
        &self,
        path: &Path,
        evidence: &ObservedDesktopShortcut,
        scope: &uninstall::RegisteredScope,
        ownership: &InstallationOwnership<'_>,
        selected: &RegistryTarget,
    ) -> io::Result<Option<VerifiedDesktopShortcut>> {
        if ownership.another_owns(None, path)
            || ownership.another_matches_file_stem(Some(selected), path)
            || !self
                .files
                .check_observed_ordinary_shortcut_scope(path, usize::from(START_MENU_DEPTH))?
        {
            return Ok(None);
        }
        let (snapshot, bytes) = self.files.read_shortcut(path)?;
        let fingerprint = serde_json::to_string(&snapshot).map_err(io::Error::other)?;
        if fingerprint != evidence.fingerprint || !snapshot.is_local_regular_file() {
            return Ok(None);
        }
        let Some(target) = shortcuts::startup_target(&bytes)? else {
            return Ok(None);
        };
        if ownership.another_owns(Some(selected), &target.path) {
            return Ok(None);
        }
        let Some(target_parent) =
            scope.pin_missing_shortcut_executable(&target, &evidence.executable)?
        else {
            return Ok(None);
        };
        Ok(Some(VerifiedDesktopShortcut {
            snapshot,
            executable: target.path,
            target_parent,
        }))
    }

    fn observe_package_shortcuts(
        &self,
        targets: &[msix::PackageShortcutTarget],
        warnings: &mut Vec<String>,
        cancel: &Cancellation,
    ) -> Result<HashMap<PathBuf, String>> {
        let mut observed = HashMap::new();
        if targets.is_empty() {
            return Ok(observed);
        }
        let mut identities = HashMap::new();
        for target in targets {
            let identity = Some(target.aumid.as_str());
            identities
                .entry(target.pidl.as_slice())
                .and_modify(|known| {
                    if *known != identity {
                        *known = None;
                    }
                })
                .or_insert(identity);
        }
        let mut unreadable = 0;
        for path in
            self.user_shortcut_paths(self.files.user_shortcut_desktop(), warnings, cancel)?
        {
            cancel.check()?;
            match self.observe_package_shortcut(&path, &identities) {
                Ok(Some((path, evidence))) => {
                    observed.insert(path, serde_json::to_string(&evidence)?);
                }
                Ok(None) => {}
                Err(error) => {
                    unreadable += 1;
                    if unreadable == 1 {
                        warnings.push(format!(
                            "could not inspect {} as an MSIX shortcut: {error}",
                            path.display()
                        ));
                    }
                }
            }
        }
        if unreadable > 1 {
            warnings.push(format!(
                "MSIX shortcut discovery skipped {unreadable} unreadable entries"
            ));
        }
        Ok(observed)
    }

    fn user_shortcut_paths(
        &self,
        desktop: Option<PathBuf>,
        warnings: &mut Vec<String>,
        cancel: &Cancellation,
    ) -> Result<Vec<PathBuf>> {
        let mut pending = Vec::new();
        let mut paths = Vec::new();
        if let Some(programs) = self.files.start_menu_programs() {
            pending.push((programs, Some(0)));
        }
        if let Some(desktop) = desktop {
            // A Desktop is an immediate-only scope, unlike the dedicated Programs tree.
            pending.push((desktop, None));
        }
        let mut visited = 0;
        let mut unreadable = 0;
        while let Some((folder, program_depth)) = pending.pop() {
            cancel.check()?;
            let children = if program_depth.is_some() {
                self.files.program_menu_children(&folder)
            } else {
                self.files.children(&folder)
            };
            let children = match children {
                Ok(children) => children,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                    ) =>
                {
                    continue;
                }
                Err(error) => {
                    unreadable += 1;
                    if unreadable == 1 {
                        warnings.push(format!(
                            "could not read shortcuts in {}: {error}",
                            folder.display()
                        ));
                    }
                    continue;
                }
            };
            for path in children {
                cancel.check()?;
                if visited == MAX_CANDIDATES {
                    warnings.push("shortcut discovery reached its entry limit".into());
                    return Ok(paths);
                }
                visited += 1;
                if !path
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("lnk"))
                {
                    if let Some(depth) = program_depth.filter(|depth| *depth < START_MENU_DEPTH) {
                        pending.push((path, Some(depth + 1)));
                    }
                    continue;
                }
                if self.files.is_user_shortcut(&path) {
                    paths.push(path);
                }
            }
        }
        if unreadable > 1 {
            warnings.push(format!(
                "shortcut discovery skipped {unreadable} unreadable folders"
            ));
        }
        Ok(paths)
    }

    fn observe_package_shortcut(
        &self,
        path: &Path,
        identities: &HashMap<&[u8], Option<&str>>,
    ) -> io::Result<Option<(PathBuf, ObservedPackageShortcut)>> {
        let (snapshot, bytes) = self.files.read_shortcut(path)?;
        let Some(id_list) = shortcuts::packaged_target_id(&bytes)? else {
            return Ok(None);
        };
        let Some(Some(aumid)) = identities.get(id_list) else {
            return Ok(None);
        };
        self.files
            .quarantine_slot(&snapshot, &Uuid::nil().to_string())?;
        let evidence = ObservedPackageShortcut {
            aumid: (*aumid).to_owned(),
            fingerprint: serde_json::to_string(&snapshot).map_err(io::Error::other)?,
        };
        Ok(Some((snapshot.path, evidence)))
    }

    fn add_package_shortcuts(
        &self,
        scan: &mut Scan,
        ownership: &InstallationOwnership<'_>,
        observed: &HashMap<PathBuf, String>,
        cancel: &Cancellation,
    ) -> Result<()> {
        if !ownership.inventory.warnings.is_empty() {
            return Ok(());
        }
        let mut paths: Vec<_> = observed.iter().collect();
        paths.sort_unstable_by_key(|(path, _)| *path);
        let mut verified = HashSet::new();
        for (path, evidence) in paths {
            cancel.check()?;
            if scan.proposals.len() == MAX_CANDIDATES {
                scan.warnings
                    .push("MSIX shortcut preview reached its candidate limit".into());
                break;
            }
            if !self.files.is_user_shortcut(path) || ownership.another_owns(None, path) {
                continue;
            }
            let evidence: ObservedPackageShortcut = serde_json::from_str(evidence)?;
            match self.inspect_file(path) {
                Ok(current)
                    if current.access == Access::Allowed
                        && current.fingerprint == evidence.fingerprint =>
                {
                    let target = Target::File(path.clone());
                    verified.insert(target.clone());
                    scan.push_observed(
                        Proposal {
                            target,
                            category: Category::Shortcut,
                            evidence: MatchKind::ExactIdentity,
                            reason: format!(
                                "current-user shortcut points to the former MSIX application {}",
                                evidence.aumid
                            ),
                            risk: Risk::High,
                            access: Access::Allowed,
                        },
                        current.fingerprint,
                    );
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => scan.warnings.push(format!("{}: {error}", path.display())),
            }
        }
        // Only exact verified links supersede display-name hints. Leave any
        // other read-only reasons in place so they still veto a duplicate.
        scan.proposals.retain(|proposal| {
            !matches!(&proposal.access, Access::ReadOnly(reason)
                if reason == PACKAGE_NAME_HINT && verified.contains(&proposal.target))
        });
        Ok(())
    }

    fn report_package_data(&self, full_name: &str, scan: &mut Scan) {
        let remaining = msix::package_family_name(full_name).and_then(|family| {
            self.files
                .remaining_package_directory(&family.to_string_lossy())
        });
        match remaining {
            Ok(Some(path)) => scan.warnings.push(format!(
                "Windows still has a managed package data directory at {}. UninstallAny leaves its contents to Windows.",
                path.display()
            )),
            Ok(None) => {}
            Err(error) => scan.warnings.push(format!(
                "could not check the Windows-managed package data directory: {error}"
            )),
        }
    }

    fn scan_program_menu(
        &self,
        app: &AppRecord,
        scan: &mut Scan,
        ownership: &InstallationOwnership<'_>,
        scope: Option<&uninstall::RegisteredScope>,
        cancel: &Cancellation,
    ) -> Result<()> {
        cancel.check()?;
        let Some(root) = self.files.start_menu_programs() else {
            return Ok(());
        };
        let mut pending = vec![(root, 0)];
        let mut remaining = MAX_CANDIDATES;
        while let Some((folder, depth)) = pending.pop() {
            cancel.check()?;
            let children = match self.files.program_menu_children(&folder) {
                Ok(children) => children,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                    ) =>
                {
                    continue;
                }
                Err(error) => {
                    scan.warnings.push(format!("{}: {error}", folder.display()));
                    continue;
                }
            };
            for child in children {
                cancel.check()?;
                if remaining == 0 || scan.proposals.len() >= MAX_CANDIDATES {
                    scan.warnings
                        .push("Start Menu scan reached its entry limit".into());
                    return Ok(());
                }
                remaining -= 1;
                let evidence = path_name_match(app, &child, false);
                if child
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("lnk"))
                {
                    if let Some(evidence) = evidence {
                        self.add_named_path(
                            scan,
                            app,
                            ownership,
                            (child, evidence),
                            scope,
                            cancel,
                        )?;
                    }
                } else if depth < START_MENU_DEPTH
                    && (evidence == Some(MatchKind::AppName) || publisher_path_matches(app, &child))
                {
                    pending.push((child, depth + 1));
                }
            }
        }
        Ok(())
    }

    fn add_named_path(
        &self,
        scan: &mut Scan,
        app: &AppRecord,
        ownership: &InstallationOwnership<'_>,
        (path, evidence): (PathBuf, MatchKind),
        scope: Option<&uninstall::RegisteredScope>,
        cancel: &Cancellation,
    ) -> Result<()> {
        let selected = registry_application(&app.id);
        let inventory = ownership.inventory;
        let restriction = if matches!(app.id, AppId::WindowsPackage(_)) {
            Some(PACKAGE_NAME_HINT)
        } else if !inventory.warnings.is_empty() {
            Some(ARP_INCOMPLETE)
        } else if ownership.another_owns(selected, &path)
            || ownership.another_matches_file_stem(selected, &path)
        {
            Some("another application may own this object")
        } else {
            None
        };
        let category = category_for_path(&path);
        if let (None, Category::Shortcut, Some(scope)) = (restriction, category, scope) {
            match self.inspect_shortcut(&path, scope, evidence) {
                Ok(Some((proposal, fingerprint))) => {
                    scan.push_observed(proposal, fingerprint);
                    return Ok(());
                }
                Ok(None) => {}
                Err(error) => scan.warnings.push(format!("{}: {error}", path.display())),
            }
        }
        let restriction =
            restriction.or_else(|| (evidence == MatchKind::FuzzyName).then_some(FUZZY_NAME_HINT));
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
        name_evidence: MatchKind,
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
        } else if reference.evidence != MatchKind::ExactIdentity
            && !matches!(
                name_evidence,
                MatchKind::AppName | MatchKind::PublisherAndApp
            )
        {
            Access::ReadOnly(MISSING_SHORTCUT_NAME_HINT.into())
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
        let Some(publisher) = registry_settings_publisher(app) else {
            return cancel.check();
        };
        let settings_access = if registry_settings_are_shared(app, inventory) {
            Access::ReadOnly(
                "the registry branch could also belong to another installed application".into(),
            )
        } else {
            Access::Allowed
        };
        for (hive, view) in std::iter::once((RegistryHive::CurrentUser, RegistryView::Native))
            .chain(
                registry::machine_views()
                    .iter()
                    .copied()
                    .map(|view| (RegistryHive::LocalMachine, view)),
            )
        {
            cancel.check()?;
            let target = RegistryTarget {
                hive,
                view,
                key: format!(r"Software\{publisher}\{}", app.name),
                value: None,
            };
            add_owned_registry_values(scan, target, &settings_access);
        }
        Ok(())
    }
}

impl FileStore for Backend {
    fn inspect_file(&self, path: &Path) -> io::Result<Inspection> {
        let snapshot = if self.files.is_startup_shortcut(path) {
            match self.files.read_startup_shortcut(path, |target| {
                uninstall::pin_startup_shortcut_target(target).map(|(_, identity)| Some(identity))
            })? {
                Some((snapshot, _)) => snapshot,
                None => self.files.inspect(path)?,
            }
        } else if path
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

    fn restore_file_after_ordinary_files(&self, path: &Path, expected: &str) -> bool {
        decode_snapshot(path, expected).is_ok_and(|snapshot| snapshot.is_startup_shortcut())
    }

    fn file_backup_path(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<PathBuf> {
        self.files
            .quarantine_slot(&decode_snapshot(path, expected)?, &slot.to_string())
    }

    fn quarantine_file(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<()> {
        self.require_uninstall_idle()?;
        self.files
            .quarantine(&decode_snapshot(path, expected)?, &slot.to_string())
    }

    fn file_is_quarantined(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<bool> {
        self.files
            .quarantined(&decode_snapshot(path, expected)?, &slot.to_string())
    }

    fn restore_file(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<()> {
        self.require_uninstall_idle()?;
        self.files
            .restore(&decode_snapshot(path, expected)?, &slot.to_string())
    }

    fn verify_file_restored(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<bool> {
        self.files
            .verify_restored(&decode_snapshot(path, expected)?, &slot.to_string())
    }

    fn can_purge_quarantined(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<bool> {
        self.require_uninstall_idle()?;
        self.files
            .can_purge(&decode_snapshot(path, expected)?, &slot.to_string())
    }

    fn purge_quarantined(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<()> {
        self.require_uninstall_idle()?;
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
        self.require_uninstall_idle()?;
        registry::remove(target, expected, None, write)
    }

    fn restore_registry(&self, target: &RegistryTarget, snapshot: &[u8]) -> io::Result<()> {
        self.require_uninstall_idle()?;
        registry::restore(target, snapshot, None)
    }

    fn remove_registry_with_receipt(
        &self,
        target: &RegistryTarget,
        expected: &str,
        operation_id: Uuid,
        write: &mut RegistryBackupWriter<'_>,
    ) -> io::Result<()> {
        self.require_uninstall_idle()?;
        registry::remove(target, expected, Some(operation_id), write)
    }

    fn restore_registry_with_receipt(
        &self,
        target: &RegistryTarget,
        snapshot: &[u8],
        operation_id: Uuid,
    ) -> io::Result<()> {
        self.require_uninstall_idle()?;
        registry::restore(target, snapshot, Some(operation_id))
    }

    fn registry_change_receipt(
        &self,
        target: &RegistryTarget,
        snapshot: &[u8],
        operation_id: Uuid,
    ) -> io::Result<Option<RegistryChangeReceipt>> {
        registry::change_receipt(target, snapshot, operation_id)
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
        self.files.check_report_path(path)
    }

    fn write_audit_export(
        &self,
        path: &Path,
        cancel: &Cancellation,
        write: impl FnOnce(&mut dyn io::Write) -> Result<()>,
    ) -> Result<()> {
        self.files.write_audit_export(path, cancel, write)
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
    // Identify our machine MSI by its registration, independent of display text.
    let is_own_machine_msi = entry.windows_installer
        && entry.address.hive == RegistryHive::LocalMachine
        && entry.address.value.is_none()
        && entry
            .address
            .key
            .rsplit_once('\\')
            .is_some_and(|(parent, product)| {
                parent.eq_ignore_ascii_case(registry::UNINSTALL_KEY)
                    && product.eq_ignore_ascii_case(OWN_MSI_PRODUCT_CODE)
            });
    is_own_machine_msi
        || entry.system_component
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
        FileDisposition::Directory => Access::ReadOnly(
            "directory retained; Windows cannot require it to be empty during a quarantine move"
                .into(),
        ),
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

fn publisher_path_matches(app: &AppRecord, path: &Path) -> bool {
    app.publisher
        .as_deref()
        .zip(path.file_name().and_then(OsStr::to_str))
        .is_some_and(|(publisher, name)| {
            match_name(publisher, None, name, None) == Some(MatchKind::AppName)
        })
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

fn registry_settings_publisher(app: &AppRecord) -> Option<&str> {
    let publisher = app
        .publisher
        .as_deref()
        .filter(|name| is_registry_component(name))?;
    (is_registry_component(&app.name)
        && match_name(&app.name, Some(publisher), &app.name, Some(publisher))
            == Some(MatchKind::PublisherAndApp))
    .then_some(publisher)
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

fn matching_settings_name(left: &str, right: &str) -> bool {
    windows_eq(OsStr::new(left), OsStr::new(right))
        || match_name(left, None, right, None) == Some(MatchKind::AppName)
}

fn competing_settings_apps<'a>(
    selected: &AppId,
    publisher: &str,
    inventory: &'a registry::Inventory,
) -> Vec<&'a str> {
    let selected = registry_application(selected);
    inventory
        .entries
        .iter()
        .filter(|entry| {
            selected != Some(&entry.address)
                && entry
                    .publisher
                    .as_deref()
                    .is_none_or(|name| matching_settings_name(name, publisher))
        })
        .map(|entry| entry.display_name.as_str())
        .collect()
}

fn settings_app_conflict(name: &str, competing: &[&str]) -> bool {
    competing
        .iter()
        .any(|candidate| matching_settings_name(candidate, name))
}

fn scan_nested_app_settings(
    app: &AppRecord,
    inventory: &registry::Inventory,
    scan: &mut Scan,
    cancel: &Cancellation,
) -> Result<()> {
    cancel.check()?;
    let Some(publisher) = registry_settings_publisher(app) else {
        return Ok(());
    };
    if registry_settings_are_shared(app, inventory) {
        return Ok(());
    }
    let competing = competing_settings_apps(&app.id, publisher, inventory);
    let root = RegistryTarget {
        hive: RegistryHive::CurrentUser,
        view: RegistryView::Native,
        key: format!(r"Software\{publisher}\{}", app.name),
        value: None,
    };
    if is_protected_registry_target(&root) || settings_app_conflict(&app.name, &competing) {
        return Ok(());
    }

    let mut pending = vec![(root, 0)];
    let mut subkeys_remaining = NESTED_SETTINGS_SUBKEY_LIMIT;
    let mut values_remaining = registry::MAX_NESTED_SETTINGS_VALUES;
    while let Some((key, depth)) = pending.pop() {
        cancel.check()?;
        let plan_remaining = MAX_CANDIDATES.saturating_sub(scan.proposals.len());
        if plan_remaining == 0 || values_remaining == 0 {
            scan.warnings
                .push("nested registry settings reached the candidate limit".into());
            break;
        }
        let subkey_limit =
            (depth < registry::MAX_NESTED_SETTINGS_DEPTH).then_some(subkeys_remaining);
        let value_limit = (depth != 0).then_some(
            values_remaining.min(u32::try_from(plan_remaining).map_err(io::Error::other)?),
        );
        let (subkeys, values) =
            match registry::bounded_app_settings_entries(&key, subkey_limit, value_limit) {
                Ok(entries) => entries,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    scan.warnings.push(format!(
                        "could not complete nested registry settings scan at {}: {error}",
                        key.key
                    ));
                    break;
                }
            };
        // Count entries before applying policy. Rejected or empty subkeys still
        // consume the enumeration budget for this application.
        subkeys_remaining -= u32::try_from(subkeys.len()).map_err(io::Error::other)?;
        values_remaining -= u32::try_from(values.len()).map_err(io::Error::other)?;
        for value in values {
            cancel.check()?;
            if !registry::is_named_app_setting(&value) {
                continue;
            }
            scan.proposals.push(Proposal {
                target: Target::Registry(RegistryTarget {
                    value: Some(value),
                    ..key.clone()
                }),
                category: Category::Registry,
                evidence: MatchKind::PublisherAndApp,
                reason: "nested setting below the exact current-user publisher and app key".into(),
                risk: Risk::High,
                access: Access::Allowed,
            });
        }
        for leaf in subkeys {
            cancel.check()?;
            if !is_registry_component(&leaf) {
                continue;
            }
            let child = RegistryTarget {
                key: format!("{}\\{leaf}", key.key),
                ..key.clone()
            };
            if registry::is_nested_app_settings_key(&child)
                && !settings_app_conflict(&leaf, &competing)
            {
                pending.push((child, depth + 1));
            }
        }
    }
    Ok(())
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
    add_application_paths(scan, current_user, scope, purpose, cancel)?;
    if purpose == ScanPurpose::Recheck {
        return Ok(());
    }
    // App Paths is shared across WOW64 views. Keep one address for this key.
    add_application_paths(
        scan,
        (RegistryHive::LocalMachine, RegistryView::Native),
        scope,
        purpose,
        cancel,
    )?;
    for &view in registry::machine_views() {
        cancel.check()?;
        if scan.proposals.len() >= MAX_CANDIDATES {
            break;
        }
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
    (hive, view): (RegistryHive, uninstallany_core::RegistryView),
    scope: &uninstall::RegisteredScope,
    purpose: ScanPurpose,
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
        match registry::executable_value(&executable, scope) {
            Ok(Some(value)) => {
                scan.push_observed(
                    Proposal {
                        target: Target::Registry(executable),
                        category: Category::Registry,
                        evidence: MatchKind::ExactIdentity,
                        reason: "current-user App Paths default names a verified executable in the former installation".into(),
                        risk: Risk::High,
                        access: Access::Allowed,
                    },
                    value.fingerprint,
                );
                continue;
            }
            Ok(None) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                ) => {}
            Err(error) => scan.warnings.push(format!("{}: {error}", executable.key)),
        }
        if purpose == ScanPurpose::Recheck {
            continue;
        }
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
                    "App Paths default did not meet the verified current-user cleanup conditions"
                        .into(),
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
    let Some(value) = registry::executable_value(target, scope)? else {
        return Ok(None);
    };
    Ok(Some((
        Proposal {
            target: Target::Registry(target.clone()),
            category: Category::Startup,
            evidence: MatchKind::ExactIdentity,
            reason: format!(
                "current-user startup value directly launches {} in the verified installation directory",
                value.executable.display()
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
            install_location_absent: true,
            display_icon: None,
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
    fn uninstall_registration_rejects_changes_to_command_or_provider() {
        let mut reviewed = entry("editor", "Example Editor", Some("Example Publisher"));
        reviewed.uninstall_string = Some(r"C:\Example\uninstall.exe /remove".into());
        reviewed.quiet_uninstall_string = Some(r"C:\Example\uninstall.exe /quiet".into());
        let mut current = reviewed.clone();
        current.estimated_size_kib = Some(42);
        current.install_date = Some("20261126".into());
        assert!(reviewed.same_uninstall_registration(&current));

        current.uninstall_string = Some(r"C:\Example\uninstall.exe /other".into());
        assert!(!reviewed.same_uninstall_registration(&current));
        current = reviewed.clone();
        current.quiet_uninstall_string = None;
        assert!(!reviewed.same_uninstall_registration(&current));
        current = reviewed.clone();
        current.windows_installer = true;
        assert!(!reviewed.same_uninstall_registration(&current));
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
            ..registry::Inventory::default()
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
            ..registry::Inventory::default()
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

    #[test]
    fn standalone_app_data_ownership_rejects_names_and_registered_path_claims() {
        let original = entry("editor", "Example Editor", Some("Example Publisher"));
        let app = desktop_record(&original);
        let directory = Path::new(r"C:\Users\Example\AppData\Local\Example Editor");
        let mut inventory = registry::Inventory {
            entries: vec![original.clone()],
            ..registry::Inventory::default()
        };
        let has_exclusive_directory = |inventory: &registry::Inventory| {
            InstallationOwnership {
                inventory,
                paths: Vec::new(),
            }
            .app_data_directory_is_exclusive(&app, directory)
        };
        assert!(has_exclusive_directory(&inventory));

        inventory.entries.push(entry(
            "other-editor",
            "example-editor",
            Some("Other Publisher"),
        ));
        assert!(!has_exclusive_directory(&inventory));
        inventory.entries.pop();
        inventory
            .entries
            .push(entry("other-app", "Another Editor", Some("example-editor")));
        assert!(!has_exclusive_directory(&inventory));
        inventory.entries.pop();

        let ownership = InstallationOwnership {
            inventory: &inventory,
            paths: vec![RegisteredPath {
                owner: &original.address,
                reported: directory.join("program.exe"),
                canonical: None,
                parsed: true,
            }],
        };
        assert!(!ownership.app_data_directory_is_exclusive(&app, directory));

        inventory
            .warnings
            .push("Could not read one registry view".into());
        assert!(!has_exclusive_directory(&inventory));
    }

    #[test]
    fn unnamed_executable_claim_blocks_its_directory_without_claiming_siblings() -> Result<()> {
        let hidden = entry("hidden", "", None).address;
        let selected = entry("editor", "Example Editor", None).address;
        let inventory = registry::Inventory {
            path_claims: vec![registry::InstallPathClaims {
                address: hidden.clone(),
                directory: None,
                icon: None,
                uninstall: Some(r#""C:\Apps\Example Editor\shared.exe" /uninstall"#.into()),
                quiet_uninstall: None,
            }],
            ..registry::Inventory::default()
        };
        let cancel = Cancellation::default();
        let ownership = InstallationOwnership::read(&inventory, &cancel)?;
        let directory = Path::new(r"C:\Apps\Example Editor");
        assert!(ownership.another_owns(Some(&selected), directory));
        assert!(ownership.another_owns(None, directory));
        assert!(!ownership.another_owns(Some(&hidden), directory));
        assert!(!ownership.another_owns(None, Path::new(r"C:\Apps\Example Editor Plus")));
        assert!(!ownership.another_owns(None, &directory.join("unrelated.exe")));
        Ok(())
    }
}
