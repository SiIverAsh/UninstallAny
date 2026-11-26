//! Linux application inventory, scoped native removal and guarded residual scans.

#![cfg(any(target_os = "linux", all(unix, test)))]

mod command;
mod desktop;
mod inventory;
mod paths;
mod scan;

use std::{
    ffi::OsString,
    io,
    path::{Path, PathBuf},
    process::ExitStatus,
};

use uninstallany_core::{
    AppId, AppRecord, Cancellation, Engine, Error, FileStore, Inspection, Inventory, Journal,
    OfficialIntent, OfficialOutcome, PlatformBackend, RegistryBackupWriter, RegistryStore,
    RegistryTarget, Result, RuleRoot, RuleTarget, Scan, ScanMode,
};
use uninstallany_unix::{UnixFiles, user_home};
use uuid::Uuid;

use crate::{
    command::{Program, run_confirmed},
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

struct LinuxBackend {
    paths: LinuxPaths,
    files: UnixFiles,
}

enum NativeAction {
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

    fn scan(&self, app: &AppRecord, _mode: ScanMode, cancel: &Cancellation) -> Result<Scan> {
        let required = match Source::identify(&app.id) {
            Some((Source::FlatpakUser | Source::FlatpakSystem, _)) => FLATPAK_INVENTORY,
            _ => &[],
        };
        let packages = self.installed_packages(required, cancel)?;
        scan::application(app, &self.files, &self.paths, &packages, cancel)
    }

    fn scan_portable(&self, directory: &Path, cancel: &Cancellation) -> Result<Scan> {
        let installed = self.inventory(cancel)?;
        scan::portable(directory, &self.files, &self.paths, &installed, cancel)
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
        let (action, method, notice) = match source {
            Source::FlatpakUser | Source::FlatpakSystem if app_id_from_ref(id).is_some() => {
                let scope = source.flatpak_scope().ok_or_else(|| {
                    Error::Rejected("Flatpak installation scope is absent".into())
                })?;
                (
                    NativeAction::Flatpak {
                        scope,
                        reference: id.into(),
                    },
                    format!("Flatpak uninstall {scope} {id}"),
                    "Flatpak removes this one application ref. Its data and granted permissions are retained for review.",
                )
            }
            Source::Snap if valid_snap_instance(id) => (
                NativeAction::Snap {
                    instance: id.into(),
                },
                format!("Snap snapshot and removal of {id}"),
                "Snap will first create a native data snapshot. Removal stops if the snapshot cannot be created.",
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
                notice: notice.into(),
            },
            PreparedOfficial { program, action },
        ))
    }

    fn run_official(&self, command: Self::Official) -> Result<OfficialOutcome> {
        let home = &self.paths.home;
        let data = &self.paths.data;
        let PreparedOfficial { program, action } = command;
        let status = match action {
            NativeAction::Flatpak { scope, reference } => {
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
                run_confirmed(program, home, data, args)?.status
            }
            NativeAction::Snap { instance } => {
                let save = run_confirmed(
                    program.clone(),
                    home,
                    data,
                    vec!["save".into(), instance.clone().into()],
                )?;
                if !save.status.success() || !snapshot_contains(&save.output, &instance) {
                    return Err(Error::Rejected(
                        "Snap did not report a completed data snapshot for this instance; the snap has been kept".into(),
                    ));
                }
                run_confirmed(program, home, data, vec!["remove".into(), instance.into()])?.status
            }
        };
        Ok(classify(status))
    }

    fn official_uninstall_absent(&self, app: &AppId, cancel: &Cancellation) -> Result<bool> {
        let Some((source, _)) = Source::identify(app) else {
            return Ok(false);
        };
        let inventory = inventory::visit(source, &self.paths.home, &self.paths.data, cancel)?
            .ok_or_else(|| {
                Error::Rejected(
                    "the original package manager is no longer available for verification".into(),
                )
            })?;
        inventory::is_absent(inventory, app)
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

fn snapshot_contains(output: &str, instance: &str) -> bool {
    output.lines().any(|line| {
        let mut columns = line.split_whitespace();
        columns
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|set| set > 0)
            && columns.next() == Some(instance)
    })
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

    fn file_is_quarantined(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<bool> {
        self.files.file_is_quarantined(path, expected, slot)
    }

    fn restore_file(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<()> {
        self.files.restore_file(path, expected, slot)
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
    use super::snapshot_contains;

    #[test]
    fn snap_snapshot_must_name_the_reviewed_instance() {
        let native_output = "Set   Snap       Age  Version Revision  Size   Notes\n43    example    0s   1.0     9         512B   -\n";
        assert!(snapshot_contains(native_output, "example"));
        assert!(!snapshot_contains(native_output, "example_variant"));
        assert!(!snapshot_contains("saved example", "example"));
        assert!(!snapshot_contains("0 example", "example"));
    }
}
