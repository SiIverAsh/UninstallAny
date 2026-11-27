//! Linux application inventory, scoped native removal and guarded residual scans.

#![cfg(any(target_os = "linux", all(unix, test)))]

mod appimage;
mod appimage_launcher;
mod command;
mod desktop;
mod dpkg;
#[cfg(all(target_os = "linux", feature = "dpkg-helper"))]
mod dpkg_helper;
#[cfg(target_os = "linux")]
mod dpkg_transport;
#[cfg(target_os = "linux")]
mod flatpak;
mod inventory;
#[cfg(target_os = "linux")]
mod pacman_transport;
mod paths;
mod scan;
mod snap;
#[cfg(target_os = "linux")]
mod system_helper;

pub use snap::{SnapSnapshot, SnapSnapshotHistory};

#[cfg(all(target_os = "linux", feature = "dpkg-helper"))]
pub use dpkg_helper::run as run_dpkg_helper;

use std::{
    collections::HashMap,
    ffi::OsString,
    io::{self, IsTerminal},
    num::{NonZeroU16, NonZeroU64},
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
};

use uninstallany_core::{
    AppId, AppRecord, ApplicationUninstall, Cancellation, Engine, Error, FileStore, Inspection,
    Inventory, Journal, OfficialExecution, OfficialIntent, OfficialOutcome, PlatformBackend,
    PostUninstallScan, RegistryBackupWriter, RegistryStore, RegistryTarget, Result, RuleRoot,
    RuleTarget, Scan, ScanMode,
};
use uninstallany_unix::{UnixFiles, user_home};
use uuid::Uuid;

use crate::{
    command::{NativeResult, Program, query, run_confirmed},
    inventory::{Source, app_id_from_ref, valid_snap_instance},
    paths::LinuxPaths,
};

const FLATPAK_INVENTORY: &[Source] = &[Source::FlatpakUser, Source::FlatpakSystem];

/// Opens the Linux backend for one ordinary user. Paths come from the user's
/// account and the XDG base-directory settings, with protected data boundaries.
pub fn open() -> io::Result<Engine<impl PlatformBackend, impl Journal>> {
    if rustix::process::geteuid().is_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "run UninstallAny as your normal account",
        ));
    }
    let paths = LinuxPaths::from_home(user_home()?);
    let files = paths.files()?;
    let backend = LinuxBackend {
        paths,
        files: files.clone(),
    };
    Ok(Engine::new(backend, files))
}

/// Reads the recorded Snap snapshot references without contacting snapd.
pub fn snap_snapshot_history(cancel: &Cancellation) -> Result<SnapSnapshotHistory> {
    let paths = LinuxPaths::from_home(user_home()?);
    snap::history(&paths.files()?, cancel)
}

struct LinuxBackend {
    paths: LinuxPaths,
    files: UnixFiles,
}

enum NativeAction {
    #[cfg(target_os = "linux")]
    SystemPackage {
        helper: Program,
        installation: system_helper::SystemHelper,
        arguments: Vec<OsString>,
    },
    Flatpak {
        scope: &'static str,
        reference: String,
    },
    Snap {
        instance: String,
    },
}

struct PreparedOfficial {
    program: Program,
    action: NativeAction,
}

impl LinuxBackend {
    #[cfg(target_os = "linux")]
    fn prepare_pacman(app: &AppRecord, name: &str) -> Result<(OfficialIntent, PreparedOfficial)> {
        let version = app.version.as_deref().ok_or_else(|| {
            Error::Rejected("the reviewed pacman package version is unavailable".into())
        })?;
        let (program, helper) = pacman_transport::launcher()?;
        let arguments = pacman_transport::removal_arguments(name, version)?;
        let intent = OfficialIntent {
            application: app.name.clone(),
            method: format!("pacman package removal {name} ({version})"),
            quiet: false,
            notice: "Administrator approval is required. The helper checks the exact package and dependencies under the pacman database lock. Package scripts and Arch system hooks may run.".into(),
        };
        let action = NativeAction::SystemPackage {
            helper,
            installation: pacman_transport::HELPER,
            arguments,
        };
        Ok((intent, PreparedOfficial { program, action }))
    }

    fn installed_packages(&self, required: &[Source], cancel: &Cancellation) -> Result<Inventory> {
        let mut result = Inventory::default();
        for source in inventory::PACKAGE_SOURCES {
            cancel.check()?;
            match inventory::visit(source, &self.paths.home, &self.paths.data, cancel) {
                Ok(Some(inventory)) => {
                    result.applications.extend(inventory.applications);
                    result.warnings.extend(inventory.warnings);
                }
                Ok(None) if required.contains(&source) => result.warnings.push(format!(
                    "{} inventory: the trusted package-manager executable is unavailable",
                    source.manager()
                )),
                Ok(None) => {}
                Err(Error::Cancelled) => return Err(Error::Cancelled),
                Err(error) => result
                    .warnings
                    .push(format!("{} inventory: {error}", source.manager())),
            }
        }
        Ok(result)
    }

    #[cfg(target_os = "linux")]
    fn observe_flatpak_directory(
        &self,
        reference: &str,
        cancel: &Cancellation,
    ) -> Result<(HashMap<PathBuf, String>, Vec<String>)> {
        let app_id = app_id_from_ref(reference)
            .ok_or_else(|| Error::Rejected("the Flatpak application ID is invalid".into()))?;
        let path = self.paths.flatpak_data.join(app_id);
        let mut observed = HashMap::new();
        let mut warnings = Vec::new();
        cancel.check()?;
        match self.files.pin_linux_flatpak_data_directory(&path) {
            Ok((inspection, _)) => match flatpak::require_inactive(app_id, cancel) {
                Ok(()) => {
                    observed.insert(path, inspection.fingerprint);
                }
                Err(Error::Cancelled) => return Err(Error::Cancelled),
                Err(error) => warnings.push(format!("Flatpak data was kept: {error}")),
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => warnings.push(format!("{}: {error}", path.display())),
        }
        Ok((observed, warnings))
    }

    #[cfg(target_os = "linux")]
    fn pin_removed_flatpak_directory(
        &self,
        reference: &str,
        path: &Path,
        expected: &str,
        cancel: &Cancellation,
    ) -> Result<std::fs::File> {
        cancel.check()?;
        let app_id = app_id_from_ref(reference)
            .ok_or_else(|| Error::Rejected("the Flatpak application ID is invalid".into()))?;
        if path != self.paths.flatpak_data.join(app_id) {
            return Err(Error::Rejected("the Flatpak sandbox path differs".into()));
        }
        let (inspection, directory) = self.files.pin_linux_flatpak_data_directory(path)?;
        if inspection.fingerprint != expected {
            return Err(Error::Rejected(
                "the Flatpak sandbox contents changed after the pre-uninstall scan".into(),
            ));
        }
        let program = Program::find("flatpak").ok_or_else(|| {
            Error::Rejected("the trusted Flatpak executable is no longer available".into())
        })?;
        flatpak::require_absent_and_inactive(
            &program,
            &self.paths.home,
            &self.paths.data,
            app_id,
            cancel,
        )?;
        Ok(directory)
    }
}

impl PlatformBackend for LinuxBackend {
    type Official = PreparedOfficial;

    fn rule_root(&self, root: RuleRoot) -> Option<PathBuf> {
        match root {
            RuleRoot::LinuxConfig => Some(self.paths.config.clone()),
            RuleRoot::LinuxData => Some(self.paths.data.clone()),
            RuleRoot::LinuxCache => Some(self.paths.cache.clone()),
            _ => None,
        }
    }

    fn probe_rule_target(&self, path: &Path) -> io::Result<Option<RuleTarget>> {
        self.files.probe_rule_target(path)
    }

    fn inventory(&self, cancel: &Cancellation) -> Result<Inventory> {
        let mut result = self.installed_packages(&[], cancel)?;
        desktop::augment(&mut result, &self.files, &self.paths, cancel)?;
        result
            .applications
            .sort_unstable_by(|left, right| left.name.cmp(&right.name));
        Ok(result)
    }

    fn scan(&self, app: &AppRecord, mode: ScanMode, cancel: &Cancellation) -> Result<Scan> {
        let required = match Source::identify(&app.id) {
            Some((Source::FlatpakUser | Source::FlatpakSystem, _)) => FLATPAK_INVENTORY,
            _ => &[],
        };
        let packages = self.installed_packages(required, cancel)?;
        scan::application(app, mode, &self.files, &self.paths, &packages, cancel)
    }

    fn scan_after_official_uninstall(
        &self,
        app: &AppRecord,
        observed_files: &HashMap<PathBuf, String>,
        phase: PostUninstallScan,
        cancel: &Cancellation,
    ) -> Result<Scan> {
        let mut scan = match phase {
            PostUninstallScan::Preview => self.scan(app, ScanMode::AfterOfficialUninstall, cancel),
            PostUninstallScan::Recheck => {
                self.scan_for_cleanup_recheck(app, ScanMode::AfterOfficialUninstall, cancel)
            }
        }?;
        #[cfg(target_os = "linux")]
        if let Some((Source::FlatpakUser | Source::FlatpakSystem, reference)) =
            Source::identify(&app.id)
        {
            let Some(app_id) = app_id_from_ref(reference) else {
                return Ok(scan);
            };
            let path = self.paths.flatpak_data.join(app_id);
            let Some(expected) = observed_files.get(&path) else {
                return Ok(scan);
            };
            match self.pin_removed_flatpak_directory(reference, &path, expected, cancel) {
                Ok(_) => scan::add_verified_flatpak_directory(&mut scan, path, expected.clone()),
                Err(Error::Cancelled) => return Err(Error::Cancelled),
                Err(error) => scan
                    .warnings
                    .push(format!("Flatpak data was kept: {error}")),
            }
            return Ok(scan);
        }
        if !matches!(Source::identify(&app.id), Some((Source::AppImage, _))) {
            return Ok(scan);
        }
        let image = appimage::path_for_id(&app.id, &self.paths)?;
        let menu = self.paths.data.join("applications");
        let mut observed: Vec<_> = observed_files.iter().collect();
        observed.sort_unstable_by_key(|(path, _)| *path);
        for (path, expected) in observed {
            cancel.check()?;
            match appimage::pin_launcher(&self.files, &menu, image, path) {
                Ok(Some((fingerprint, _))) if fingerprint == *expected => {
                    scan::add_verified_appimage_launcher(&mut scan, path.clone(), fingerprint);
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => scan.warnings.push(format!("{}: {error}", path.display())),
            }
        }
        Ok(scan)
    }

    fn pin_post_uninstall_file(
        &self,
        app: &AppRecord,
        path: &Path,
        observed_files: &HashMap<PathBuf, String>,
        cancel: &Cancellation,
    ) -> Result<impl Sized> {
        cancel.check()?;
        let expected = observed_files
            .get(path)
            .ok_or_else(|| Error::Rejected("the path has no pre-uninstall evidence".into()))?;
        #[cfg(target_os = "linux")]
        if let Some((Source::FlatpakUser | Source::FlatpakSystem, reference)) =
            Source::identify(&app.id)
        {
            return self.pin_removed_flatpak_directory(reference, path, expected, cancel);
        }
        let image = appimage::path_for_id(&app.id, &self.paths)?;
        let menu = self.paths.data.join("applications");
        let launcher = appimage::pin_launcher(&self.files, &menu, image, path)?;
        let Some((_, file)) = launcher.filter(|(fingerprint, _)| fingerprint == expected) else {
            return Err(Error::Rejected(
                "the launcher changed after it was attributed to the AppImage".into(),
            ));
        };
        if !self.files.local_entry_absent(image)? {
            return Err(Error::Rejected(
                "the AppImage path is occupied again".into(),
            ));
        }
        Ok(file)
    }

    fn scan_portable(&self, directory: &Path, cancel: &Cancellation) -> Result<Scan> {
        let installed = self.inventory(cancel)?;
        scan::portable(directory, &self.files, &self.paths, &installed, cancel)
    }

    fn prepare_application_uninstall(
        &self,
        app: &AppRecord,
        _retention_days: NonZeroU16,
        cancel: &Cancellation,
    ) -> Result<(OfficialIntent, ApplicationUninstall<Self::Official>)> {
        cancel.check()?;
        if !matches!(Source::identify(&app.id), Some((Source::AppImage, _))) {
            let (intent, command) = self.prepare_official(app)?;
            return Ok((intent, ApplicationUninstall::Official(command)));
        }
        let path = appimage::path_for_id(&app.id, &self.paths)?;
        if app.install_location.as_deref() != Some(path) {
            return Err(Error::Rejected(
                "the AppImage installation identity changed".into(),
            ));
        }
        let fingerprint = appimage::inspect(&self.files, path, cancel)?;
        let intent = OfficialIntent {
            application: app.name.clone(),
            method: "Move the AppImage file to quarantine".into(),
            quiet: true,
            notice: "Close the application before continuing. Only the AppImage file will be moved. The file can be restored from quarantine.".into(),
        };
        Ok((
            intent,
            ApplicationUninstall::QuarantineBundle {
                fingerprint,
                observed_files: HashMap::new(),
            },
        ))
    }

    fn run_bundle_uninstall(
        &self,
        app: &AppRecord,
        mut observed_files: HashMap<PathBuf, String>,
        cancel: &Cancellation,
        quarantine: impl FnOnce() -> Result<()>,
    ) -> Result<OfficialExecution> {
        cancel.check()?;
        let path = appimage::path_for_id(&app.id, &self.paths)?;
        let menu = self.paths.data.join("applications");
        let warnings =
            appimage::observe_launchers(&self.files, &menu, path, &mut observed_files, cancel)?;
        cancel.check()?;
        quarantine()?;
        Ok(OfficialExecution {
            outcome: OfficialOutcome::Completed,
            warnings,
            read_only_residuals: Vec::new(),
            observed_files,
            post_uninstall_check: None,
        })
    }

    fn check_file_cleanup_application(&self, app: &AppId) -> Result<()> {
        if matches!(Source::identify(app), Some((Source::AppImage, _))) {
            let path = appimage::path_for_id(app, &self.paths)?;
            appimage::inspect(&self.files, path, &Cancellation::default())?;
        }
        Ok(())
    }

    fn prepare_official(&self, app: &AppRecord) -> Result<(OfficialIntent, Self::Official)> {
        let Some((source, id)) = Source::identify(&app.id) else {
            return Err(Error::Rejected(
                "unsupported Linux application source".into(),
            ));
        };
        if app.system_component || !app.official_uninstall_available {
            return Err(Error::Rejected(
                "this package has no approved removal action for the current account".into(),
            ));
        }
        #[cfg(target_os = "linux")]
        if source == Source::Pacman {
            return Self::prepare_pacman(app, id);
        }
        #[cfg(target_os = "linux")]
        if source == Source::Dpkg {
            let version = app.version.as_deref().ok_or_else(|| {
                Error::Rejected("the installed Debian package version is unavailable".into())
            })?;
            let request = dpkg::DpkgRequest::parse(id, version)?;
            let (program, helper) = dpkg_transport::HELPER.launcher()?;
            let intent = OfficialIntent {
                application: app.name.clone(),
                method: format!("Debian package removal {} ({})", request.id, request.version),
                quiet: false,
                notice: "System administrator approval is required. The helper will recheck this package under dpkg's lock and simulate removal before removing it. Package configuration files are retained. dpkg may run normal maintainer scripts and triggers.".into(),
            };
            let action = NativeAction::SystemPackage {
                helper,
                installation: dpkg_transport::HELPER,
                arguments: vec![request.id.into(), request.version.into()],
            };
            return Ok((intent, PreparedOfficial { program, action }));
        }
        let (action, method, notice) = match source {
            Source::FlatpakUser | Source::FlatpakSystem => {
                let app_id = app_id_from_ref(id)
                    .ok_or_else(|| Error::Rejected("the Flatpak application ID is invalid".into()))?;
                #[cfg(target_os = "linux")]
                flatpak::check_context(app_id)?;
                let scope = source.flatpak_scope().ok_or_else(|| {
                    Error::Rejected("Flatpak installation scope is absent".into())
                })?;
                (
                    NativeAction::Flatpak {
                        scope,
                        reference: id.into(),
                    },
                    format!("Flatpak uninstall {scope} {id}"),
                    format!("Close {app_id} before continuing. Flatpak removes this one ref. Eligible sandbox data can be reviewed separately."),
                )
            }
            Source::Snap if valid_snap_instance(id) => (
                NativeAction::Snap {
                    instance: id.into(),
                },
                format!("Snap snapshot and removal of {id}"),
                "Close this app and stop its services before continuing. Snap will create a data snapshot and record its ID before removal.".into(),
            ),
            _ => {
                return Err(Error::Rejected(
                    "no supported exact native uninstall transaction".into(),
                ));
            }
        };
        let program = source.command().and_then(Program::find).ok_or_else(|| {
            Error::Rejected("the trusted package-manager executable is unavailable".into())
        })?;
        Ok((
            OfficialIntent {
                application: app.name.clone(),
                method,
                quiet: true,
                notice,
            },
            PreparedOfficial { program, action },
        ))
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
        let home = &self.paths.home;
        let data = &self.paths.data;
        let PreparedOfficial { program, action } = command;
        let (outcome, warnings, observed_files) = match action {
            #[cfg(target_os = "linux")]
            NativeAction::SystemPackage {
                helper,
                installation,
                arguments,
            } => {
                helper.revalidate()?;
                installation.require_policy()?;
                let args: Vec<_> = [
                    "--disable-internal-agent".into(),
                    installation.executable.into(),
                    "remove".into(),
                ]
                .into_iter()
                .chain(arguments)
                .collect();
                let (status, _, diagnostics) = command::run_approved(
                    program.command(home, data)?,
                    args,
                    Stdio::null(),
                    cancel,
                )?;
                let outcome = match status.code() {
                    Some(126) => OfficialOutcome::Cancelled,
                    _ => classify(status),
                };
                let warnings = (!diagnostics.trim().is_empty())
                    .then_some(diagnostics)
                    .into_iter()
                    .collect();
                (outcome, warnings, HashMap::new())
            }
            NativeAction::Flatpak { scope, reference } => {
                #[cfg(target_os = "linux")]
                let (observed_files, warnings) =
                    self.observe_flatpak_directory(&reference, cancel)?;
                #[cfg(not(target_os = "linux"))]
                let (observed_files, warnings) = (HashMap::new(), Vec::new());
                let args = [
                    "uninstall",
                    scope,
                    "--no-related",
                    "--noninteractive",
                    "--assumeyes",
                    "--",
                ];
                let args = args
                    .into_iter()
                    .map(OsString::from)
                    .chain([reference.into()])
                    .collect();
                let result =
                    run_confirmed(program.command(home, data)?, args, Stdio::null(), cancel)?;
                (classify(result.status), warnings, observed_files)
            }
            NativeAction::Snap { instance } => {
                let (outcome, warnings) = remove_snap(
                    &instance,
                    cancel,
                    |step| {
                        // Snap enables native PolicyKit interaction only with a TTY on stdin.
                        let input = if io::stdin().is_terminal() {
                            Stdio::inherit()
                        } else {
                            Stdio::null()
                        };
                        run_confirmed(
                            program.command(home, data)?,
                            vec![step.into(), instance.clone().into()],
                            input,
                            cancel,
                        )
                    },
                    |set_id| snap::record(&self.files, &instance, set_id),
                    |revision| {
                        let current = query(&program, home, data, &["list", &instance], cancel)?;
                        Ok(snap::matches_installed_revision(
                            &current, &instance, revision,
                        ))
                    },
                )?;
                (outcome, warnings, HashMap::new())
            }
        };
        Ok(OfficialExecution {
            outcome,
            warnings,
            read_only_residuals: Vec::new(),
            observed_files,
            post_uninstall_check: None,
        })
    }

    fn verify_finished_official_after_cancel(&self) -> bool {
        // A completed, detached package transaction still needs an absence check.
        true
    }

    fn official_uninstall_absent(&self, app: &AppId, cancel: &Cancellation) -> Result<bool> {
        let Some((source, _id)) = Source::identify(app) else {
            return Ok(false);
        };
        if source == Source::AppImage {
            cancel.check()?;
            let path = appimage::path_for_id(app, &self.paths)?;
            return Ok(self.files.local_entry_absent(path)?);
        }
        if source == Source::Dpkg {
            // The display inventory intentionally omits incomplete package states.
            return Ok(false);
        }
        #[cfg(target_os = "linux")]
        if source == Source::Pacman {
            return pacman_transport::verify_removed(_id, cancel);
        }
        let inventory = inventory::visit(source, &self.paths.home, &self.paths.data, cancel)?
            .ok_or_else(|| {
                Error::Rejected(
                    "the original package manager is no longer available for verification".into(),
                )
            })?;
        inventory::is_absent(inventory, app)
    }

    fn verify_official_uninstall_absence(
        &self,
        app: &AppRecord,
        cancel: &Cancellation,
    ) -> Result<bool> {
        #[cfg(target_os = "linux")]
        if let Some((Source::Dpkg, id)) = Source::identify(&app.id) {
            let version = app.version.as_deref().ok_or_else(|| {
                Error::Rejected("the reviewed Debian package version is unavailable".into())
            })?;
            let request = dpkg::DpkgRequest::parse(id, version)?;
            return dpkg_transport::verify_removed(
                request,
                &self.paths.home,
                &self.paths.data,
                cancel,
            );
        }
        self.official_uninstall_absent(&app.id, cancel)
    }
}

fn remove_snap(
    instance: &str,
    cancel: &Cancellation,
    mut run: impl FnMut(&'static str) -> Result<NativeResult>,
    record: impl FnOnce(NonZeroU64) -> Result<()>,
    revision_matches: impl FnOnce(&str) -> Result<bool>,
) -> Result<(OfficialOutcome, Vec<String>)> {
    let save = run("save")?;
    let saved = save
        .status
        .success()
        .then(|| snap::parse_saved_set(&save.output, instance))
        .flatten()
        .ok_or_else(|| Error::Rejected(
            "Snap did not report one completed data snapshot for this instance; the snap has been kept".into(),
        ))?;
    let set_id = saved.id;
    let snapshot = format!("Snap data snapshot {set_id} for {instance} was saved.");
    // Persist the native reference before the next cancellable or mutating step.
    record(set_id).map_err(|error| {
        Error::Rejected(format!(
            "{snapshot} Removal stopped because the snapshot record could not be written: {error}"
        ))
    })?;
    // Cancelling while the snapshot was running must not start a second command.
    let removal = cancel.check().and_then(|()| {
        let revision = saved.revision.ok_or_else(|| {
            Error::Rejected("Removal stopped because the snapshot revision could not be read.".into())
        })?;
        if !revision_matches(revision)? {
            return Err(Error::Rejected(
                "Removal stopped because the installed Snap revision no longer matches the snapshot.".into(),
            ));
        }
        run("remove")
    });
    match removal {
        Ok(result) => Ok((classify(result.status), vec![snapshot])),
        Err(Error::Cancelled) => Ok((
            OfficialOutcome::Cancelled,
            vec![
                snapshot,
                "Snap removal was cancelled before it started.".into(),
            ],
        )),
        Err(error) => Err(Error::Rejected(format!("{snapshot} {error}"))),
    }
}

fn classify(status: ExitStatus) -> OfficialOutcome {
    if status.success() {
        OfficialOutcome::Completed
    } else if let Some(code) = status.code() {
        OfficialOutcome::Failed(code.unsigned_abs())
    } else {
        OfficialOutcome::Unverified(0)
    }
}

impl FileStore for LinuxBackend {
    fn inspect_file(&self, path: &Path) -> io::Result<Inspection> {
        self.files.inspect_file(path)
    }

    fn file_backup_path(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<PathBuf> {
        self.files.file_backup_path(path, expected, slot)
    }

    fn quarantine_file(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<()> {
        self.files.quarantine_file(path, expected, slot)
    }

    fn quarantine_file_with_cancel(
        &self,
        path: &Path,
        expected: &str,
        slot: Uuid,
        cancel: &Cancellation,
    ) -> Result<()> {
        self.files
            .quarantine_file_with_cancel(path, expected, slot, cancel)
    }

    fn file_is_quarantined(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<bool> {
        self.files.file_is_quarantined(path, expected, slot)
    }

    fn restore_file(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<()> {
        self.files.restore_file(path, expected, slot)
    }

    fn verify_file_restored(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<bool> {
        self.files.verify_file_restored(path, expected, slot)
    }

    fn can_purge_quarantined(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<bool> {
        self.files.can_purge_quarantined(path, expected, slot)
    }

    fn purge_quarantined(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<()> {
        self.files.purge_quarantined(path, expected, slot)
    }
}

impl RegistryStore for LinuxBackend {
    fn inspect_registry(&self, _target: &RegistryTarget) -> io::Result<Inspection> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn remove_registry(
        &self,
        _target: &RegistryTarget,
        _expected: &str,
        _write: &mut RegistryBackupWriter<'_>,
    ) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn restore_registry(&self, _target: &RegistryTarget, _snapshot: &[u8]) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::ExitStatusExt;

    use super::{
        Cancellation, Error, ExitStatus, NativeResult, OfficialOutcome, Result, remove_snap, snap,
    };

    #[test]
    fn cancellation_during_snap_snapshot_does_not_start_removal() -> Result<()> {
        let cancel = Cancellation::default();
        let (outcome, warnings) = remove_snap(
            "example",
            &cancel,
            |step| {
                assert_eq!(step, "save");
                cancel.cancel();
                Ok(NativeResult {
                    status: ExitStatus::from_raw(0),
                    output: "43 example".into(),
                })
            },
            |set_id| {
                assert_eq!(set_id.get(), 43);
                Ok(())
            },
            |_| panic!("a cancelled operation must not check the installed revision"),
        )?;
        assert_eq!(outcome, OfficialOutcome::Cancelled);
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("snapshot 43"))
        );
        Ok(())
    }

    #[test]
    fn failure_to_record_snap_snapshot_keeps_the_instance() {
        let cancel = Cancellation::default();
        let result = remove_snap(
            "example",
            &cancel,
            |step| {
                assert_eq!(step, "save");
                Ok(NativeResult {
                    status: ExitStatus::from_raw(0),
                    output: "43 example".into(),
                })
            },
            |_| Err(Error::Rejected("no storage".into())),
            |_| panic!("a failed receipt must not check the installed revision"),
        );
        assert!(matches!(result, Err(Error::Rejected(reason)) if reason.contains("snapshot 43")));
    }

    #[test]
    fn snap_snapshot_must_name_the_reviewed_instance() {
        let native_output = "Set   Snap       Age  Version Revision  Size   Notes\n43    example    0s   1.0     9         512B   -\n";
        assert!(
            snap::parse_saved_set(native_output, "example")
                .is_some_and(|set| set.id.get() == 43 && set.revision == Some("9"))
        );
        assert!(snap::parse_saved_set(native_output, "example_variant").is_none());
        assert!(snap::parse_saved_set("saved example", "example").is_none());
        assert!(snap::parse_saved_set("0 example", "example").is_none());
        assert!(snap::parse_saved_set("43 example\n44 example", "example").is_none());
    }

    #[test]
    fn snap_removal_stops_if_the_installed_revision_changed() {
        let result = remove_snap(
            "example",
            &Cancellation::default(),
            |step| {
                assert_eq!(step, "save");
                Ok(NativeResult {
                    status: ExitStatus::from_raw(0),
                    output: "43 example 0s 1.0 9 512B -".into(),
                })
            },
            |_| Ok(()),
            |revision| {
                Ok(snap::matches_installed_revision(
                    "Name Version Rev Tracking Publisher Notes\nexample 1.0 10 latest/stable example -",
                    "example",
                    revision,
                ))
            },
        );
        assert!(
            matches!(result, Err(Error::Rejected(reason)) if reason.contains("no longer matches"))
        );
    }
}
