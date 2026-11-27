//! Native macOS application inventory and guarded cleanup for UninstallAny.

#![cfg(target_os = "macos")]

mod activity;
mod app_groups;
mod app_signature;
mod blessed_helpers;
mod brew;
mod brew_review;
mod brew_uninstall;
mod bundle;
mod expiry_plan;
#[cfg(feature = "privileged-inspection")]
mod helper_client;
mod inventory_metadata;
mod launch_agents;
mod plist;
mod receipt;
mod scan;
#[cfg(feature = "privileged-inspection")]
mod selected_bundle;
#[cfg(feature = "privileged-inspection")]
mod system_backup_expiry;
#[cfg(feature = "privileged-inspection")]
mod system_backup_inventory;
#[cfg(feature = "privileged-inspection")]
mod system_backup_restore;
mod vendor;

pub use expiry_plan::MacExpiryPlan;
#[cfg(feature = "privileged-inspection")]
pub use helper_client::{
    ConfirmedPrivilegedExpiry, ConfirmedPrivilegedHelperRegistration, ConfirmedPrivilegedRestore,
    ConfirmedStandaloneQuarantine, PrivilegedBundleInspection, PrivilegedExpiryOutcome,
    PrivilegedExpiryPreview, PrivilegedHelperRegistrationPreview, PrivilegedHelperServiceState,
    PrivilegedQuarantineCursor, PrivilegedQuarantineOutcome, PrivilegedQuarantinePage,
    PrivilegedQuarantineRecord, PrivilegedQuarantineState, PrivilegedQuarantineStatus,
    PrivilegedRestoreOutcome, PrivilegedRestorePreview, PrivilegedStandaloneQuarantinePreview,
    expire_privileged_quarantine, inspect_privileged_application, list_privileged_quarantine_page,
    prepare_privileged_helper_registration, prepare_privileged_restore,
    prepare_privileged_standalone_quarantine,
    prepare_privileged_standalone_quarantine_with_retention, preview_privileged_expiry,
    privileged_helper_service_state, quarantine_privileged_standalone_application,
    query_privileged_quarantine, register_privileged_helper, restore_privileged_application,
    verify_privileged_quarantine_authorization,
};

#[cfg(feature = "privileged-inspection")]
pub use selected_bundle::{
    SystemHelperActivation, prepare_selected_system_application, prepare_system_helper_activation,
};
#[cfg(feature = "privileged-inspection")]
pub use system_backup_inventory::{SystemBackups, read_system_backups};
#[cfg(feature = "privileged-inspection")]
pub use system_backup_restore::{SystemRestoreReview, prepare_system_restore};

use std::{
    collections::{HashMap, HashSet},
    io,
    num::NonZeroU16,
    path::{Path, PathBuf},
    thread,
};

use uninstallany_core::{
    Access, AppId, AppRecord, ApplicationUninstall, Cancellation, Category, Engine, Error,
    FileStore, Inspection, Inventory, Journal, MatchKind, OfficialExecution, OfficialIntent,
    OfficialOutcome, PlatformBackend, PostUninstallScan, Proposal, RegistryBackupWriter,
    RegistryStore, RegistryTarget, Result, Risk, RuleRoot, RuleTarget, Scan, ScanMode, Target,
    match_name,
};
use uninstallany_unix::{UnixFiles, macos_portable_location as portable_scope, user_home};
use uuid::Uuid;

use activity::bundle_is_running;

const SYSTEM_RESIDUAL_SCOPE: &str = "This review covers only verified files and directories in your Library. The application bundle and services are kept.";
const MAX_ADDITIONAL_CASK_BUNDLES: usize = 1_024;

/// Opens the macOS backend for the effective standard user.
///
/// Filesystem mutations remain accessible only through the core's confirmation
/// and journal pipeline. The same guard is used by inventory and mutation.
pub fn open() -> io::Result<Engine<impl PlatformBackend, impl Journal>> {
    let backend = MacBackend::new(user_home()?)?;
    let journal = backend.files.clone();
    Ok(Engine::new(backend, journal))
}

struct MacBackend {
    files: UnixFiles,
    home: PathBuf,
    application_roots: [PathBuf; 3],
}

#[derive(Default)]
struct BundleConflicts {
    identifier: bool,
    residual_name: bool,
}

enum MacUninstall {
    Vendor(Box<vendor::Prepared>),
    Homebrew {
        command: Box<brew_uninstall::Prepared>,
        observed_files: HashMap<PathBuf, String>,
    },
    #[cfg(feature = "privileged-inspection")]
    SystemQuarantine(Box<selected_bundle::PreparedSystemUninstall>),
}

impl MacBackend {
    fn new(home: PathBuf) -> io::Result<Self> {
        let application_roots = [
            PathBuf::from(bundle::APPLICATIONS),
            home.join("Applications"),
            PathBuf::from("/System/Applications"),
        ];
        let roots = application_roots
            .iter()
            .cloned()
            .chain(std::iter::once(home.clone()))
            .chain(scan::scan_roots(&home))
            .chain(brew::PREFIXES.into_iter().map(PathBuf::from))
            .chain([receipt::DIRECTORY, blessed_helpers::HELPER_ROOT].map(PathBuf::from))
            .collect();
        let protected = [
            PathBuf::from("/System"),
            PathBuf::from("/Library"),
            PathBuf::from(blessed_helpers::HELPER_ROOT),
            PathBuf::from(receipt::DIRECTORY),
            PathBuf::from("/opt/homebrew"),
            PathBuf::from("/usr/local"),
            home.join("Documents"),
            home.join("Desktop"),
            home.join("Downloads"),
            home.join("Movies"),
            home.join("Music"),
            home.join("Pictures"),
            home.join("Public"),
        ];
        let state = home.join("Library/Application Support/UninstallAny");
        let files = UnixFiles::new(roots, protected.into(), state)?
            .with_application_roots(application_roots[..2].to_vec())?
            .with_portable_applications()?
            .with_macos_cache_directories()?
            .with_macos_saved_state_directories()?
            .with_macos_sandbox_directories()?
            .with_macos_webkit_website_data()?
            .with_macos_http_storage()?
            .with_user_launch_agents()?;
        Ok(Self {
            files,
            home,
            application_roots,
        })
    }

    fn installed_bundles(
        &self,
        cancel: &Cancellation,
        warnings: &mut Vec<String>,
    ) -> Result<Vec<bundle::Bundle>> {
        bundle::discover(&self.files, &self.application_roots, cancel, warnings)
    }

    fn bundle_inventory(
        &self,
        cancel: &Cancellation,
        include: impl Fn(&AppId, Option<&Path>) -> bool,
    ) -> Result<Inventory> {
        let mut inventory = Inventory::default();
        let bundles = self.installed_bundles(cancel, &mut inventory.warnings)?;
        let mut cask_warnings = Vec::new();
        let casks = brew::discover(&self.files, &self.home, cancel, &mut cask_warnings)?;
        let allow_vendor = cask_warnings.is_empty();
        inventory.warnings.extend(cask_warnings);
        self.add_bundle_records(
            &mut inventory,
            &bundles,
            (casks, allow_vendor),
            cancel,
            include,
        )?;
        Ok(inventory)
    }

    fn require_idle_application_data(&self, path: &Path) -> io::Result<()> {
        let bundle_id = path.ancestors().find_map(|ancestor| {
            self.files
                .macos_saved_state_bundle_id(ancestor)
                .or_else(|| {
                    self.files
                        .macos_sandbox_application_support_bundle_id(ancestor)
                })
                .or_else(|| self.files.macos_webkit_website_data_bundle_id(ancestor))
                .or_else(|| self.files.macos_http_storage_bundle_id(ancestor))
        });
        if bundle_id.is_some_and(bundle_is_running) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "quit the application before changing its local application data",
            ));
        }
        Ok(())
    }

    fn scan_system_application_residuals(
        &self,
        path: &Path,
        cancel: &Cancellation,
    ) -> Result<Scan> {
        let reviewed_directory = self.files.local_directory_identity(path)?;
        let selected = bundle::read(&self.files, path)?;
        if selected.is_system() {
            return Err(Error::Rejected(
                "macOS system applications are protected".into(),
            ));
        }

        let inventory = self.bundle_inventory(cancel, |_, location| location == Some(path))?;
        let mut matches = inventory.applications.iter();
        let (Some(app), None) = (matches.next(), matches.next()) else {
            return Err(Error::Rejected(
                "The reviewed path does not identify one current installed application.".into(),
            ));
        };
        let catalogued_identity_matches = match &app.id {
            AppId::Package { manager, .. } if manager == bundle::MANAGER => {
                app.id == selected.record().id
            }
            AppId::Package { manager, id } if manager == brew::MANAGER => brew::CaskId::parse(id)
                .is_some_and(|cask| cask.bundle_id() == Some(selected.identifier.as_str())),
            _ => false,
        };
        if app.system_component || !catalogued_identity_matches {
            return Err(Error::Rejected(
                "The installed application identity could not be confirmed.".into(),
            ));
        }

        let mut scan = self.scan(app, ScanMode::Leftovers, cancel)?;
        cancel.check()?;
        if self.files.local_directory_identity(path)? != reviewed_directory
            || bundle::read(&self.files, path)?.identifier != selected.identifier
        {
            return Err(Error::Rejected(
                "The application bundle changed during its residual scan.".into(),
            ));
        }
        // This portable route is deliberately residual-only even on a host
        // where the ordinary application scan can move the whole bundle.
        let library = self.home.join("Library");
        for proposal in &mut scan.proposals {
            let is_local_residual = matches!(&proposal.target, Target::File(candidate)
                if candidate.starts_with(&library) && candidate != &library && !candidate.starts_with(path))
                && matches!(proposal.category, Category::File | Category::Directory);
            if !is_local_residual && proposal.access == Access::Allowed {
                proposal.access = Access::ReadOnly(SYSTEM_RESIDUAL_SCOPE.into());
            }
        }
        if !scan.proposals.iter().any(|proposal| {
            matches!(&proposal.target, Target::File(candidate) if candidate.as_path() == path)
        }) {
            scan.proposals.push(bundle_proposal(
                path,
                Access::ReadOnly(SYSTEM_RESIDUAL_SCOPE.into()),
            ));
        }
        scan.warnings.extend(inventory.warnings);
        scan.warnings.insert(0, SYSTEM_RESIDUAL_SCOPE.into());
        cancel.check()?;
        Ok(scan)
    }

    fn scan_bundle_candidate(
        &self,
        scan: &mut Scan,
        path: &Path,
        app_id: &str,
        shared_or_unknown: bool,
        cancel: &Cancellation,
    ) -> Result<()> {
        let Some(inspection) = self.inspect_bundle_for_quarantine(
            scan,
            path,
            app_id,
            shared_or_unknown,
            None,
            cancel,
        )?
        else {
            return Ok(());
        };
        let proposal = bundle_proposal(path, inspection.access);
        if proposal.access == Access::Allowed {
            scan.push_observed(proposal, inspection.fingerprint);
        } else {
            scan.proposals.push(proposal);
        }
        Ok(())
    }

    fn inspect_bundle_for_quarantine(
        &self,
        scan: &mut Scan,
        path: &Path,
        app_id: &str,
        shared_or_unknown: bool,
        installed_catalog: Option<&[bundle::Bundle]>,
        cancel: &Cancellation,
    ) -> Result<Option<Inspection>> {
        cancel.check()?;
        let Ok(local) = bundle::read(&self.files, path) else {
            return Ok(None);
        };
        if local.identifier != app_id || local.is_system() {
            return Ok(None);
        }
        if shared_or_unknown {
            return Ok(Some(bundle_read_only(
                "a duplicate application or incomplete discovery prevents ownership verification",
            )));
        }
        let has_background_items = self.scan_bundle_services(path, scan, cancel)?;
        if has_background_items {
            return Ok(Some(bundle_read_only(
                "background services require the vendor's deregistration procedure",
            )));
        }
        let mut warnings = Vec::new();
        let casks = brew::discover(&self.files, &self.home, cancel, &mut warnings)?;
        cancel.check()?;
        // The ordinary preview can check additional targets and direct
        // ownership against the same late Homebrew discovery.
        if let Some(installed_catalog) = installed_catalog {
            let conflicts = self.check_additional_cask_bundles(
                (app_id, None),
                Some(path),
                (installed_catalog, &casks),
                cancel,
                &mut warnings,
            )?;
            if conflicts.identifier {
                scan.warnings.extend(warnings);
                return Ok(Some(bundle_read_only(
                    "a duplicate application or incomplete discovery prevents ownership verification",
                )));
            }
        }
        let native_managed = casks
            .iter()
            .any(|cask| cask.could_own_bundle(&self.files, path));
        if native_managed || !warnings.is_empty() {
            scan.warnings.extend(warnings);
            return Ok(Some(bundle_read_only(
                "Homebrew ownership could not be excluded",
            )));
        }
        if activity::at_location(&self.files, Some(path), &local.identifier) {
            return Ok(Some(bundle_read_only(
                "quit the application before quarantining its bundle",
            )));
        }
        let Inspection {
            fingerprint,
            access,
        } = self.files.inspect_file(path)?;
        let access = match access {
            Access::Allowed => match receipt::has_no_claim(&self.files, path, cancel) {
                Ok(true) => Access::Allowed,
                Ok(false) => {
                    Access::ReadOnly("an installer receipt claims part of this application".into())
                }
                Err(error) => {
                    cancel.check()?;
                    Access::ReadOnly(format!("could not verify installer ownership: {error}"))
                }
            },
            rejected => rejected,
        };
        Ok(Some(Inspection {
            fingerprint,
            access,
        }))
    }

    fn scan_bundle_services(
        &self,
        path: &Path,
        scan: &mut Scan,
        cancel: &Cancellation,
    ) -> Result<bool> {
        let embedded = bundle::scan_background_items(&self.files, path, scan, cancel)?;
        let legacy = blessed_helpers::scan(&self.files, path, scan, cancel)?;
        Ok(embedded || legacy)
    }

    fn add_bundle_records(
        &self,
        inventory: &mut Inventory,
        bundles: &[bundle::Bundle],
        (casks, allow_vendor): (Vec<brew::Cask>, bool),
        cancel: &Cancellation,
        include: impl Fn(&AppId, Option<&Path>) -> bool,
    ) -> Result<()> {
        let mut system_helper_enabled = None;
        let paths: HashMap<_, _> = bundles
            .iter()
            .enumerate()
            .map(|(index, bundle)| (bundle.path.as_path(), index))
            .collect();
        let mut directory_ids = None;
        let mut candidates = Vec::with_capacity(casks.len());
        let mut claims = vec![0; bundles.len()];
        for cask in casks {
            cancel.check()?;
            let mut selected = None;
            for path in cask.app_paths() {
                let catalogued = paths.get(path).copied().or_else(|| {
                    let candidate = self.files.local_directory_identity(path).ok()?;
                    let identities = directory_ids.get_or_insert_with(|| {
                        bundles
                            .iter()
                            .enumerate()
                            .filter_map(|(index, bundle)| {
                                Some((
                                    self.files.local_directory_identity(&bundle.path).ok()?,
                                    index,
                                ))
                            })
                            .collect::<HashMap<_, _>>()
                    });
                    identities.get(&candidate).copied()
                });
                if let Some(index) = catalogued {
                    claims[index] += 1;
                    if cask.path() == Some(path) {
                        selected = Some(index);
                    }
                }
            }
            candidates.push((cask, selected));
        }
        let mut merged = vec![false; bundles.len()];
        for (cask, selected) in candidates {
            cancel.check()?;
            let matched = selected.filter(|index| claims[*index] == 1);
            // Assign ownership before filtering so a merged cask cannot
            // reappear as a standalone application.
            if let Some(index) = matched {
                merged[index] = true;
            }
            let removable = allow_vendor && matched.is_some() && cask.supports_native_removal();
            let mut record = cask.record(matched.map(|index| &bundles[index]));
            record.official_uninstall_available =
                removable && !record.system_component && brew_uninstall::available(&record);
            if include(&record.id, record.install_location.as_deref()) {
                inventory.applications.push(record);
            }
        }
        for (index, bundle) in bundles.iter().enumerate() {
            cancel.check()?;
            if merged[index] {
                continue;
            }
            let mut record = bundle.record();
            if !include(&record.id, record.install_location.as_deref()) {
                continue;
            }
            record.official_uninstall_available = allow_vendor
                && claims[index] == 0
                && !record.system_component
                && (bundle.path.starts_with(&self.application_roots[1])
                    || self
                        .files
                        .validate_macos_application_bundle_location(&bundle.path)
                        .is_ok()
                    || vendor::available(&self.files, &record, &self.application_roots[..2])
                    || (bundle::is_selected_system_application(&bundle.path)
                        .is_ok_and(|selected| selected)
                        && *system_helper_enabled.get_or_insert_with(|| {
                            self.system_helper_is_enabled(&mut inventory.warnings)
                        })));
            inventory.applications.push(record);
        }
        Ok(())
    }

    fn system_helper_is_enabled(&self, warnings: &mut Vec<String>) -> bool {
        #[cfg(feature = "privileged-inspection")]
        let reason = {
            if let Err(error) = self
                .files
                .require_trusted_local_directory(&self.application_roots[0])
            {
                warnings.push(format!("System application quarantine is unavailable because the Applications directory cannot be verified: {error}"));
                return false;
            }
            match privileged_helper_service_state() {
                Ok(PrivilegedHelperServiceState::Enabled) => return true,
                Ok(PrivilegedHelperServiceState::NotRegistered) => "System application quarantine requires the bundled macOS helper to be registered.".into(),
                Ok(PrivilegedHelperServiceState::RequiresApproval) => "Approve the registered macOS helper in System Settings to enable system application quarantine.".into(),
                Ok(PrivilegedHelperServiceState::NotFound) => "This installation is missing its bundled macOS helper or launch definition.".into(),
                Err(error) => format!("Could not verify the macOS helper for system application quarantine: {error}"),
            }
        };
        #[cfg(not(feature = "privileged-inspection"))]
        let reason = "This build does not include the signed helper required for system application quarantine.".into();
        warnings.push(reason);
        false
    }

    fn require_vendor_homebrew_exclusion(&self, path: &Path, cancel: &Cancellation) -> Result<()> {
        let mut warnings = Vec::new();
        let casks = brew::discover(&self.files, &self.home, cancel, &mut warnings)?;
        if let Some(warning) = warnings.first() {
            return Err(Error::Rejected(format!(
                "Homebrew ownership could not be excluded before vendor uninstall. {warning}"
            )));
        }
        if casks
            .iter()
            .any(|cask| cask.could_own_bundle(&self.files, path))
        {
            return Err(Error::Rejected(
                "Homebrew may own this application bundle. The vendor uninstall is unavailable."
                    .into(),
            ));
        }
        Ok(())
    }

    fn check_additional_cask_bundles(
        &self,
        (identifier, name): (&str, Option<&str>),
        selected: Option<&Path>,
        (catalogued, casks): (&[bundle::Bundle], &[brew::Cask]),
        cancel: &Cancellation,
        warnings: &mut Vec<String>,
    ) -> Result<BundleConflicts> {
        let known: HashSet<_> = catalogued
            .iter()
            .map(|entry| entry.path.as_path())
            .collect();
        let selected_directory =
            selected.and_then(|path| self.files.local_directory_identity(path).ok());
        let mut checked = HashSet::new();
        let mut conflicts = BundleConflicts::default();
        for path in casks.iter().flat_map(brew::Cask::app_paths) {
            cancel.check()?;
            if known.contains(path) || Some(path) == selected || !checked.insert(path) {
                continue;
            }
            if checked.len() > MAX_ADDITIONAL_CASK_BUNDLES {
                warnings
                    .push("Homebrew application ownership review reached its entry limit".into());
                break;
            }
            match bundle::read(&self.files, path) {
                Ok(bundle) => {
                    let shares_identifier = bundle.identifier.eq_ignore_ascii_case(identifier);
                    let shares_name =
                        name.is_some_and(|name| could_claim_residual_name(name, &bundle));
                    if !shares_identifier && !shares_name {
                        continue;
                    }
                    // The same directory can be named in more than one way
                    // on a case-insensitive volume.
                    let same_directory = selected_directory.as_ref().is_some_and(|selected| {
                        self.files
                            .local_directory_identity(path)
                            .is_ok_and(|current| &current == selected)
                    });
                    if same_directory {
                        continue;
                    }
                    conflicts.residual_name |= shares_name;
                    if shares_identifier {
                        conflicts.identifier = true;
                        break;
                    }
                }
                // A missing Info.plist can also produce NotFound. Only skip
                // the target if the whole bundle path is absent.
                Err(error)
                    if error.kind() == io::ErrorKind::NotFound
                        && self
                            .files
                            .probe_discovery_target(path)
                            .is_err_and(|error| error.kind() == io::ErrorKind::NotFound) => {}
                Err(error) => warnings.push(format!(
                    "Could not read Homebrew application bundle {}: {error}",
                    path.display()
                )),
            }
        }
        Ok(conflicts)
    }

    fn standalone_bundle_target<'a>(&self, app: &'a AppRecord) -> Result<(&'a Path, &'a str)> {
        let unsupported = || {
            Error::Rejected("ordinary bundle uninstall requires a standalone application in an Applications folder".into())
        };
        let AppId::Package { manager, id } = &app.id else {
            return Err(unsupported());
        };
        let path = app.install_location.as_deref().ok_or_else(unsupported)?;
        if manager != bundle::MANAGER || app.system_component || !bundle::is_app(path) {
            return Err(unsupported());
        }
        if !path.starts_with(&self.application_roots[1]) {
            self.files
                .validate_macos_application_bundle_location(path)?;
        }
        let identifier = bundle::identifier_from_app_id(id).ok_or_else(unsupported)?;
        Ok((path, identifier))
    }

    fn standalone_launch_agents(
        &self,
        path: &Path,
        identifier: &str,
        cancel: &Cancellation,
    ) -> Result<HashMap<PathBuf, String>> {
        let observations = launch_agents::capture_before_uninstall(
            &self.files,
            &self.home,
            path,
            identifier,
            cancel,
        )?;
        for (agent, fingerprint) in &observations {
            cancel.check()?;
            let state =
                launch_agents::require_attributed_inactive(&self.files, agent, fingerprint, cancel);
            cancel.check()?;
            state.map_err(|error| {
                Error::Rejected(format!(
                    "Could not confirm that LaunchAgent {} is inactive: {error}",
                    agent.display()
                ))
            })?;
        }
        Ok(observations)
    }

    fn homebrew_launch_state(
        &self,
        command: &brew_uninstall::Prepared,
        cancel: &Cancellation,
    ) -> Result<HashMap<PathBuf, String>> {
        let path = command.application_path();
        if self.scan_bundle_services(path, &mut Scan::default(), cancel)? {
            return Err(Error::Rejected(
                "The application has background services that require their own uninstall procedure.".into(),
            ));
        }
        self.standalone_launch_agents(path, command.bundle_identifier(), cancel)
    }

    fn prepare_homebrew(
        &self,
        app: &AppRecord,
        cancel: &Cancellation,
    ) -> Result<(OfficialIntent, MacUninstall)> {
        let (intent, command) = brew_uninstall::prepare(&self.files, &self.home, app, cancel)?;
        let observed_files = self.homebrew_launch_state(&command, cancel)?;
        Ok((
            intent,
            MacUninstall::Homebrew {
                command: Box::new(command),
                observed_files,
            },
        ))
    }

    fn scan_application(
        &self,
        app: &AppRecord,
        mode: ScanMode,
        pre_uninstall_files: Option<&HashMap<PathBuf, String>>,
        cancel: &Cancellation,
    ) -> Result<Scan> {
        let AppId::Package { manager, id } = &app.id else {
            return Err(Error::Rejected(
                "This application is not managed by a macOS backend.".into(),
            ));
        };
        if manager == receipt::MANAGER {
            return receipt::scan(&self.files, &self.home, app, cancel);
        }
        if mode == ScanMode::AfterOfficialUninstall
            && !self.verify_official_uninstall_absence(app, cancel)?
        {
            return Err(Error::Rejected(
                "the previous application path could not be confirmed vacant".into(),
            ));
        }
        let cask = if manager == brew::MANAGER {
            Some(brew::CaskId::parse(id).ok_or_else(|| {
                Error::Rejected("The selected Homebrew cask identifier is invalid.".into())
            })?)
        } else {
            None
        };
        let identity = match manager.as_str() {
            bundle::MANAGER => bundle::identifier_from_app_id(id).map(str::to_owned),
            brew::MANAGER => cask
                .as_ref()
                .and_then(|id| id.bundle_id())
                .map(str::to_owned),
            _ => return Err(Error::Rejected("Unknown macOS application source.".into())),
        };
        let mut warnings = Vec::new();
        // System applications participate separately in name-only attribution.
        let bundles = bundle::discover(
            &self.files,
            &self.application_roots[..2],
            cancel,
            &mut warnings,
        )?;
        let additional_cask_conflicts = if let Some(identifier) = identity.as_deref() {
            let casks = brew::discover(&self.files, &self.home, cancel, &mut warnings)?;
            self.check_additional_cask_bundles(
                (identifier, Some(&app.name)),
                app.install_location.as_deref(),
                (&bundles, &casks),
                cancel,
                &mut warnings,
            )?
        } else {
            BundleConflicts::default()
        };
        let bundle_conflict = additional_cask_conflicts.identifier
            || !warnings.is_empty()
            || identity.as_ref().is_some_and(|identity| {
                bundles.iter().any(|bundle| {
                    bundle.identifier.eq_ignore_ascii_case(identity)
                        && app
                            .install_location
                            .as_deref()
                            .is_none_or(|path| path != bundle.path.as_path())
                })
            });
        let catalogued = bundles.iter().any(|bundle| {
            app.install_location.as_deref() == Some(bundle.path.as_path())
                && identity.as_deref() == Some(bundle.identifier.as_str())
        });
        // A manually chosen bundle may have an identical installation outside
        // the catalog. Its own tree can still be reviewed as a separate object.
        let library_uncertain =
            bundle_conflict || (mode != ScanMode::AfterOfficialUninstall && !catalogued);
        let write_denial = if library_uncertain {
            Some(scan::OWNERSHIP_UNCERTAIN)
        } else if identity.as_deref().is_some_and(|identifier| {
            activity::at_location(&self.files, app.install_location.as_deref(), identifier)
        }) {
            Some(scan::APPLICATION_RUNNING)
        } else {
            None
        };
        let name_attribution_uncertain = if write_denial.is_some()
            || match_name(&app.name, None, &app.name, None) != Some(MatchKind::AppName)
        {
            false
        } else if additional_cask_conflicts.residual_name
            || bundles.iter().any(|bundle| {
                app.install_location.as_deref() != Some(bundle.path.as_path())
                    && could_claim_residual_name(&app.name, bundle)
            })
        {
            true
        } else {
            // System apps can share a display name with a third-party app.
            // Gaps in this catalog affect only the weaker name evidence.
            let warning_count = warnings.len();
            let system_bundles = bundle::discover(
                &self.files,
                &self.application_roots[2..],
                cancel,
                &mut warnings,
            )?;
            warnings.len() != warning_count
                || system_bundles
                    .iter()
                    .any(|bundle| could_claim_residual_name(&app.name, bundle))
        };
        let target = app.install_location.as_deref().zip(identity.as_deref());
        let group_identifiers = match target {
            Some((path, identifier)) if mode != ScanMode::AfterOfficialUninstall => {
                match app_groups::read(&self.files, path, identifier, None, cancel) {
                    Ok(groups) => groups,
                    Err(Error::Cancelled) => return Err(Error::Cancelled),
                    Err(error) => {
                        warnings.push(format!(
                            "Could not read signed App Groups for {}: {error}",
                            path.display(),
                        ));
                        Vec::new()
                    }
                }
            }
            _ => Vec::new(),
        };
        let search = scan::Search {
            home: &self.home,
            app,
            mode,
            identifier: identity.as_deref(),
            group_identifiers: &group_identifiers,
            write_denial,
            name_attribution_uncertain,
            pre_uninstall_files,
        };
        let mut result = scan::application(&self.files, &search, cancel)?;
        if mode == ScanMode::AfterOfficialUninstall {
            scan::http_storage_after_uninstall(&self.files, &mut result, &search, cancel)?;
        }
        if let Some(cask) = cask.filter(|_| mode != ScanMode::AfterOfficialUninstall) {
            if !app.official_uninstall_available {
                result.warnings.push(brew::UNINSTALL_UNAVAILABLE.into());
            }
            match brew::add_review(&self.files, &self.home, &cask, &mut result, cancel) {
                Ok(()) => {}
                Err(Error::Cancelled) => return Err(Error::Cancelled),
                Err(error) => result.warnings.push(format!(
                    "Could not review local Homebrew declarations for {}: {error}",
                    app.name,
                )),
            }
        }
        result.warnings.extend(warnings);
        if let Some((path, identifier)) = target {
            if manager == bundle::MANAGER
                && (mode == ScanMode::ForceRemoval || !app.official_uninstall_available)
            {
                self.scan_bundle_candidate(&mut result, path, identifier, bundle_conflict, cancel)?;
            } else if catalogued {
                self.scan_bundle_services(path, &mut result, cancel)?;
            }
        }
        // A bundle can start during the scan. Recheck before returning
        // selectable targets, including during the execution-time rescan.
        cancel.check()?;
        if identity.is_some() {
            result.bind_file_cleanup_application(app.id.clone());
        }
        if result
            .proposals
            .iter()
            .any(|entry| entry.access == Access::Allowed)
            && identity.as_deref().is_some_and(|identifier| {
                activity::at_location(&self.files, app.install_location.as_deref(), identifier)
            })
        {
            for entry in &mut result.proposals {
                if entry.access == Access::Allowed {
                    entry.access = Access::ReadOnly(scan::APPLICATION_RUNNING.into());
                }
            }
        }
        Ok(result)
    }
}

impl PlatformBackend for MacBackend {
    type Official = MacUninstall;

    fn rule_root(&self, root: RuleRoot) -> Option<PathBuf> {
        let area = match root {
            RuleRoot::MacosApplicationSupport => "Application Support",
            RuleRoot::MacosCaches => "Caches",
            RuleRoot::MacosPreferences => "Preferences",
            _ => return None,
        };
        Some(self.home.join("Library").join(area))
    }

    fn probe_rule_target(&self, path: &Path) -> io::Result<Option<RuleTarget>> {
        self.files.probe_rule_target(path)
    }

    fn inventory(&self, cancel: &Cancellation) -> Result<Inventory> {
        cancel.check()?;
        let mut inventory = thread::scope(|scope| {
            let read_receipts = || receipt::inventory(&self.files, &self.home, cancel);
            let worker = thread::Builder::new()
                .name("uninstallany-installer-inventory".into())
                .spawn_scoped(scope, read_receipts);
            let bundles = self.bundle_inventory(cancel, |_, _| true);
            let (mut inventory, receipts) = match worker {
                Ok(worker) => {
                    // Join even if bundle discovery failed. The worker owns
                    // its Core Foundation objects and shares the caller token.
                    let result = worker.join();
                    let inventory = bundles?;
                    let receipts = match result {
                        Ok(receipts) => receipts?,
                        Err(_) => Inventory {
                            warnings: vec![
                                "Installer receipt inventory stopped unexpectedly.".into(),
                            ],
                            ..Inventory::default()
                        },
                    };
                    (inventory, receipts)
                }
                Err(error) => {
                    let mut inventory = bundles?;
                    inventory.warnings.push(format!(
                        "Could not start parallel Installer receipt inventory: {error}. Reading receipts sequentially."
                    ));
                    (inventory, read_receipts()?)
                }
            };
            cancel.check()?;
            inventory.applications.extend(receipts.applications);
            inventory.warnings.extend(receipts.warnings);
            Ok::<_, Error>(inventory)
        })?;
        inventory
            .applications
            .sort_by(|left, right| left.name.cmp(&right.name));
        Ok(inventory)
    }

    fn inventory_for_display(&self, cancel: &Cancellation) -> Result<Inventory> {
        let mut inventory = self.inventory(cancel)?;
        inventory_metadata::populate(&self.files, &mut inventory, cancel)?;
        Ok(inventory)
    }

    fn lookup_application(
        &self,
        identity: &AppId,
        cancel: &Cancellation,
    ) -> Result<Option<AppRecord>> {
        cancel.check()?;
        let AppId::Package { manager, id } = identity else {
            return Ok(None);
        };
        match manager.as_str() {
            receipt::MANAGER => receipt::lookup(&self.files, &self.home, id, cancel),
            bundle::MANAGER | brew::MANAGER => Ok(self
                .bundle_inventory(cancel, |id, _| id == identity)?
                .applications
                .into_iter()
                .next()),
            _ => Ok(None),
        }
    }

    fn scan(&self, app: &AppRecord, mode: ScanMode, cancel: &Cancellation) -> Result<Scan> {
        self.scan_application(app, mode, None, cancel)
    }

    fn scan_after_official_uninstall(
        &self,
        app: &AppRecord,
        observed_files: &HashMap<PathBuf, String>,
        _phase: PostUninstallScan,
        cancel: &Cancellation,
    ) -> Result<Scan> {
        self.scan_application(
            app,
            ScanMode::AfterOfficialUninstall,
            Some(observed_files),
            cancel,
        )
    }

    fn scan_portable(&self, path: &Path, cancel: &Cancellation) -> Result<Scan> {
        cancel.check()?;
        if bundle::is_selected_system_application(path)? {
            return self.scan_system_application_residuals(path, cancel);
        }
        if !portable_scope(&self.home, path) {
            return Err(Error::Rejected("Choose an individual portable application directory in a non-personal location under your home.".into()));
        }
        if bundle::is_app(path) {
            let bundle = bundle::read(&self.files, path)?;
            if bundle.is_system() {
                return Err(Error::Rejected(
                    "macOS system applications are protected".into(),
                ));
            }
            return self.scan(&bundle.record(), ScanMode::Leftovers, cancel);
        }
        let entries = self.files.list(path)?;
        let mut scan = Scan::default();
        scan::scan_children(&self.files, &mut scan, entries, true, cancel)?;
        Ok(scan)
    }

    fn check_file_cleanup_application(&self, application: &AppId) -> Result<()> {
        let running = match application {
            AppId::Package { manager, id } if manager == bundle::MANAGER => {
                bundle::identifier_from_app_id(id)
                    .map(|identifier| activity::for_app_id(id, identifier))
            }
            AppId::Package { manager, id } if manager == brew::MANAGER => {
                brew::CaskId::parse(id).and_then(|cask| cask.bundle_id().map(bundle_is_running))
            }
            _ => None,
        }
        .ok_or_else(|| Error::Rejected("the cleanup application's Bundle ID is unknown".into()))?;
        if running {
            return Err(Error::Rejected(scan::APPLICATION_RUNNING.into()));
        }
        Ok(())
    }

    fn prepare_official(&self, app: &AppRecord) -> Result<(OfficialIntent, Self::Official)> {
        if matches!(&app.id, AppId::Package { manager, .. } if manager == brew::MANAGER) {
            return self.prepare_homebrew(app, &Cancellation::default());
        }
        if !matches!(&app.id, AppId::Package { manager, .. } if manager == bundle::MANAGER) {
            return Err(Error::Rejected(
                "no verified vendor uninstaller for this application source".into(),
            ));
        }
        let vendor::Review {
            prepared,
            unavailable,
        } = vendor::review(&self.files, app, &self.application_roots[..2])?;
        let command =
            prepared.ok_or_else(|| {
                Error::Rejected(unavailable.unwrap_or_else(|| {
                    "no independently verified vendor uninstaller was found".into()
                }))
            })?;
        Ok((command.intent(), MacUninstall::Vendor(Box::new(command))))
    }

    fn prepare_application_uninstall(
        &self,
        app: &AppRecord,
        _retention_days: NonZeroU16,
        cancel: &Cancellation,
    ) -> Result<(OfficialIntent, ApplicationUninstall<Self::Official>)> {
        cancel.check()?;
        if matches!(&app.id, AppId::Package { manager, .. } if manager == brew::MANAGER) {
            let (intent, command) = self.prepare_homebrew(app, cancel)?;
            return Ok((intent, ApplicationUninstall::Official(command)));
        }
        if !matches!(&app.id, AppId::Package { manager, .. } if manager == bundle::MANAGER)
            || app.system_component
        {
            return Err(Error::Rejected(
                "this application source has no supported uninstall action".into(),
            ));
        }
        let vendor::Review {
            prepared,
            unavailable,
        } = vendor::review(&self.files, app, &self.application_roots[..2])?;
        if let Some(command) = prepared {
            self.require_vendor_homebrew_exclusion(command.application_path(), cancel)?;
            return Ok((
                command.intent(),
                ApplicationUninstall::Official(MacUninstall::Vendor(Box::new(command))),
            ));
        }
        let quarantine_notice = |notice: &str| match &unavailable {
            Some(reason) => format!("{reason} {notice}"),
            None => notice.into(),
        };
        #[cfg(feature = "privileged-inspection")]
        if let Some((mut intent, command)) = selected_bundle::prepare_catalogued_system_uninstall(
            self,
            app,
            _retention_days,
            cancel,
        )? {
            intent.notice = quarantine_notice(&intent.notice);
            return Ok((
                intent,
                ApplicationUninstall::PlatformQuarantine(MacUninstall::SystemQuarantine(Box::new(
                    command,
                ))),
            ));
        }

        let (path, identifier) = self.standalone_bundle_target(app)?;
        let mut warnings = Vec::new();
        let bundles = bundle::discover(
            &self.files,
            &self.application_roots[..2],
            cancel,
            &mut warnings,
        )?;
        let duplicate = bundles.iter().any(|bundle| {
            bundle.path.as_path() != path && bundle.identifier.eq_ignore_ascii_case(identifier)
        });
        let mut review = Scan::default();
        let inspection = self
            .inspect_bundle_for_quarantine(
                &mut review,
                path,
                identifier,
                duplicate || !warnings.is_empty(),
                Some(&bundles),
                cancel,
            )?
            .ok_or_else(|| {
                Error::Rejected("the application bundle could not be verified".into())
            })?;
        if let Access::ReadOnly(reason) = inspection.access {
            return Err(Error::Rejected(reason));
        }
        let observed_files = self.standalone_launch_agents(path, identifier, cancel)?;
        cancel.check()?;
        Ok((
            OfficialIntent {
                application: app.name.clone(),
                method: format!("Quarantine application bundle ({})", path.display()),
                quiet: false,
                notice: quarantine_notice(
                    "This moves the reviewed application bundle to reversible quarantine. Leftovers are scanned after uninstall and require a separate selection and confirmation.",
                ),
            },
            ApplicationUninstall::QuarantineBundle {
                fingerprint: inspection.fingerprint,
                observed_files,
            },
        ))
    }

    fn run_bundle_uninstall(
        &self,
        app: &AppRecord,
        observed_files: HashMap<PathBuf, String>,
        cancel: &Cancellation,
        quarantine: impl FnOnce() -> Result<()>,
    ) -> Result<OfficialExecution> {
        cancel.check()?;
        let (path, identifier) = self.standalone_bundle_target(app)?;
        if vendor::review(&self.files, app, &self.application_roots[..2])?
            .prepared
            .is_some()
        {
            return Err(Error::Rejected(
                "a verified vendor uninstaller is now available; review the uninstall again".into(),
            ));
        }
        let current_agents = launch_agents::capture_before_uninstall(
            &self.files,
            &self.home,
            path,
            identifier,
            cancel,
        )?;
        if current_agents != observed_files {
            return Err(Error::Rejected(
                "the application's LaunchAgents changed; review the uninstall again".into(),
            ));
        }
        let groups =
            app_groups::UninstallAppGroups::capture(&self.files, path, identifier, cancel)?;
        cancel.check()?;
        // The core binds this one call to the confirmed bundle, preserving its
        // file fingerprint, reversible quarantine, and durable audit path.
        quarantine()?;
        let supplemental = groups.resolve_after_move(&self.files, &self.home, cancel);
        Ok(OfficialExecution {
            outcome: OfficialOutcome::Completed,
            warnings: supplemental.warnings,
            read_only_residuals: supplemental.proposals,
            observed_files,
            post_uninstall_check: None,
        })
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
        let command = match command {
            MacUninstall::Vendor(command) => *command,
            MacUninstall::Homebrew {
                command,
                observed_files,
            } => {
                if self.homebrew_launch_state(&command, cancel)? != observed_files {
                    return Err(Error::Rejected(
                        "The application's LaunchAgents changed. Review the uninstall again."
                            .into(),
                    ));
                }
                let mut execution =
                    brew_uninstall::uninstall(&self.files, &self.home, *command, cancel)?;
                execution.observed_files.extend(observed_files);
                return Ok(execution);
            }
            #[cfg(feature = "privileged-inspection")]
            MacUninstall::SystemQuarantine(command) => return command.execute(self, cancel),
        };
        cancel.check()?;
        self.require_vendor_homebrew_exclusion(command.application_path(), cancel)?;
        let vendor::VendorExecution {
            outcome,
            mut warnings,
            app_groups,
            receipt_payloads,
            observed_files,
            incomplete_application,
            post_uninstall_check,
        } = vendor::uninstall(
            &self.files,
            &self.home,
            command,
            &self.application_roots[..2],
            cancel,
        )?;
        let residuals = match incomplete_application {
            _ if cancel.check().is_err() => Ok(Scan::default()),
            Some((mut app, bundle_id)) => {
                // The old location may now contain a different bundle.
                app.install_location = None;
                scan::application(
                    &self.files,
                    &scan::Search {
                        home: &self.home,
                        app: &app,
                        mode: ScanMode::Leftovers,
                        identifier: Some(bundle_id.as_str()),
                        group_identifiers: &app_groups,
                        write_denial: Some(scan::OWNERSHIP_UNCERTAIN),
                        name_attribution_uncertain: false,
                        pre_uninstall_files: None,
                    },
                    cancel,
                )
            }
            None if !app_groups.is_empty() => {
                scan::declared_groups(&self.files, &self.home, &app_groups, cancel)
            }
            None => Ok(Scan::default()),
        };
        let mut read_only_residuals = match residuals {
            Ok(scan) => {
                warnings.extend(scan.warnings);
                scan.proposals
            }
            Err(Error::Cancelled) => Vec::new(),
            Err(error) => {
                warnings.push(error.to_string());
                Vec::new()
            }
        };
        if !receipt_payloads.is_empty() && cancel.check().is_ok() {
            match receipt::vendor_payload_residuals(receipt_payloads, cancel) {
                Ok(scan) => {
                    warnings.extend(scan.warnings);
                    read_only_residuals.extend(scan.proposals);
                }
                Err(Error::Cancelled) => {}
                Err(error) => {
                    warnings.push(format!("Could not inspect Installer leftovers: {error}"))
                }
            }
        }
        Ok(OfficialExecution {
            outcome,
            warnings,
            read_only_residuals,
            observed_files,
            post_uninstall_check,
        })
    }

    fn verify_finished_official_after_cancel(&self) -> bool {
        true
    }

    fn verify_official_uninstall_absence(
        &self,
        app: &AppRecord,
        cancel: &Cancellation,
    ) -> Result<bool> {
        cancel.check()?;
        if matches!(&app.id, AppId::Package { manager, .. } if manager == brew::MANAGER) {
            return brew_uninstall::verify_absent(&self.files, app, cancel);
        }
        if !matches!(&app.id, AppId::Package { manager, .. } if manager == bundle::MANAGER) {
            return Ok(false);
        }
        let path = app.install_location.as_deref().ok_or_else(|| {
            Error::Rejected("the previous macOS application path is unknown".into())
        })?;
        // Absence is about the reviewed location. Wider discovery happens
        // during the scan because it determines whether data is shared.
        Ok(bundle::original_bundle_absent(
            &self.files,
            path,
            &self.application_roots[..2],
        )?)
    }

    fn recheck_uninstall_absence_before_each_file(&self) -> bool {
        true
    }

    fn official_uninstall_absent(&self, app: &AppId, cancel: &Cancellation) -> Result<bool> {
        cancel.check()?;
        if let AppId::Package { manager, .. } = app {
            if manager == bundle::MANAGER {
                let mut warnings = Vec::new();
                let bundles = bundle::discover(
                    &self.files,
                    &self.application_roots[..2],
                    cancel,
                    &mut warnings,
                )?;
                return Ok(
                    warnings.is_empty() && !bundles.iter().any(|bundle| &bundle.record().id == app)
                );
            }
        }
        Ok(false)
    }
}

impl FileStore for MacBackend {
    fn inspect_file(&self, path: &Path) -> io::Result<Inspection> {
        self.files.inspect_file(path)
    }

    fn file_backup_path(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<PathBuf> {
        self.files.file_backup_path(path, expected, slot)
    }

    fn quarantine_file(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<()> {
        self.quarantine_file_with_cancel(path, expected, slot, &Cancellation::default())
            .map_err(|error| match error {
                Error::Io(error) => error,
                error => io::Error::other(error),
            })
    }

    fn quarantine_file_with_cancel(
        &self,
        path: &Path,
        expected: &str,
        slot: Uuid,
        cancel: &Cancellation,
    ) -> Result<()> {
        cancel.check()?;
        self.require_idle_application_data(path)?;
        if path.parent() == Some(self.home.join("Library/LaunchAgents").as_path()) {
            let inactive =
                launch_agents::require_inactive(&self.files, &self.home, path, expected, cancel);
            cancel.check()?;
            inactive?;
        }
        if bundle::is_app(path) {
            let bundle = bundle::read(&self.files, path)?;
            let mut warnings = Vec::new();
            let installed = bundle::discover(
                &self.files,
                &self.application_roots[..2],
                cancel,
                &mut warnings,
            )?;
            let casks = brew::discover(&self.files, &self.home, cancel, &mut warnings)?;
            let shared = installed.iter().any(|other| {
                other.identifier.eq_ignore_ascii_case(&bundle.identifier)
                    && path != other.path.as_path()
            });
            let managed = casks
                .iter()
                .any(|cask| cask.could_own_bundle(&self.files, path));
            let has_background_items =
                self.scan_bundle_services(path, &mut Scan::default(), cancel)?;
            if bundle.is_system()
                || shared
                || managed
                || has_background_items
                || !warnings.is_empty()
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "bundle is protected or became shared, package-managed, or unverifiable after preview",
                ).into());
            }
            let unclaimed = receipt::has_no_claim(&self.files, path, cancel);
            cancel.check()?;
            if !unclaimed? {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "an installer receipt now claims part of this application",
                )
                .into());
            }
            // Receipt queries can take several seconds. Recheck the attributed
            // user jobs after those queries so a new registration stops the move.
            self.standalone_launch_agents(path, &bundle.identifier, cancel)?;
            if activity::at_location(&self.files, Some(path), &bundle.identifier) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "the application is running; quit it before quarantining the bundle",
                )
                .into());
            }
        }
        self.files
            .quarantine_file_with_cancel(path, expected, slot, cancel)
    }

    fn file_is_quarantined(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<bool> {
        self.files.file_is_quarantined(path, expected, slot)
    }

    fn recoverable_detached_file_backup(
        &self,
        path: &Path,
        expected: &str,
        slot: Uuid,
    ) -> io::Result<Option<PathBuf>> {
        self.files
            .recoverable_detached_file_backup(path, expected, slot)
    }

    fn restore_file(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<()> {
        self.require_idle_application_data(path)?;
        if path.parent() == Some(self.home.join("Library/LaunchAgents").as_path()) {
            launch_agents::require_inactive_at_restore(&self.home, path)?;
        }
        self.files.restore_file(path, expected, slot)
    }

    fn verify_file_restored(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<bool> {
        self.files.verify_file_restored(path, expected, slot)
    }

    fn can_purge_quarantined(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<bool> {
        self.files.can_purge_quarantined(path, expected, slot)
    }

    fn has_pending_quarantine_purge(
        &self,
        path: &Path,
        expected: &str,
        slot: Uuid,
    ) -> io::Result<bool> {
        self.files
            .has_pending_quarantine_purge(path, expected, slot)
    }

    fn purge_quarantined(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<()> {
        self.files.purge_quarantined(path, expected, slot)
    }
}

impl RegistryStore for MacBackend {
    fn inspect_registry(&self, _target: &RegistryTarget) -> io::Result<Inspection> {
        Err(registry_unsupported())
    }

    fn remove_registry(
        &self,
        _target: &RegistryTarget,
        _expected: &str,
        _write: &mut RegistryBackupWriter<'_>,
    ) -> io::Result<()> {
        Err(registry_unsupported())
    }

    fn restore_registry(&self, _target: &RegistryTarget, _snapshot: &[u8]) -> io::Result<()> {
        Err(registry_unsupported())
    }
}

fn registry_unsupported() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "macOS has no Windows registry")
}

fn could_claim_residual_name(application: &str, other: &bundle::Bundle) -> bool {
    [other.name.as_str(), other.identifier.as_str()]
        .into_iter()
        .any(|name| match_name(application, None, name, None) == Some(MatchKind::AppName))
}

fn bundle_read_only(reason: &str) -> Inspection {
    Inspection {
        fingerprint: String::new(),
        access: Access::ReadOnly(reason.into()),
    }
}

fn bundle_proposal(path: &Path, access: Access) -> Proposal {
    Proposal {
        target: Target::File(path.to_path_buf()),
        category: Category::Directory,
        evidence: MatchKind::ExactIdentity,
        reason: "application metadata matches the selected bundle identifier".into(),
        risk: Risk::High,
        access,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portable_preview_allows_owned_tools_but_refuses_personal_and_bundle_internals() {
        let home = Path::new("/Users/test-user");
        assert!(portable_scope(home, &home.join("Tools/Example Editor")));
        assert!(portable_scope(home, &home.join("Applications/Example.app")));
        for path in [
            home.to_path_buf(),
            home.join("Applications"),
            home.join("Downloads/Example"),
            home.join("pIcTuReS/Example"),
            home.join("Library/Example"),
            home.join(".ssh/private"),
            home.join("Applications/Example.app/Contents"),
            home.join("Tools/../Documents"),
            PathBuf::from("/Applications/Example.app"),
        ] {
            assert!(!portable_scope(home, &path), "{}", path.display());
        }
    }

    #[test]
    #[ignore = "read-only smoke for an actual standard-user macOS host"]
    fn native_inventory_reads_system_bundles_and_receipt_sources_without_journal() -> Result<()> {
        let backend = MacBackend::new(user_home()?)?;
        let result = backend.inventory(&Cancellation::default())?;
        let count =
            |source: &str| {
                result.applications.iter().filter(|app| {
            matches!(&app.id, AppId::Package { manager, .. } if manager == source)
        }).count()
            };
        let bundles = count(bundle::MANAGER);
        let receipts = count(receipt::MANAGER);
        let casks = count(brew::MANAGER);
        assert!(bundles > 0);
        assert!(result.applications.iter().any(|app| {
            app.system_component
                && app
                    .install_location
                    .as_ref()
                    .is_some_and(|path| path.starts_with("/System/Applications"))
        }));
        assert!(
            receipts > 0
                || result
                    .warnings
                    .iter()
                    .any(|warning| warning.contains("installer receipts"))
        );
        let missing_id = AppId::Package {
            manager: brew::MANAGER.into(),
            id: "0:uninstallany-test-cask-never-installed:org.example.Fixture".into(),
        };
        let missing = AppRecord {
            id: missing_id,
            name: "UninstallAny test fixture".into(),
            publisher: None,
            version: None,
            install_location: Some(PathBuf::from("/Applications/UninstallAny test fixture.app")),
            size_bytes: None,
            install_date: None,
            system_component: false,
            official_uninstall_available: true,
        };
        assert!(matches!(
            backend.prepare_official(&missing),
            Err(Error::Rejected(_))
        ));
        println!(
            "Read-only inventory returned {bundles} bundles, {receipts} receipts, {casks} casks."
        );
        for warning in result.warnings.iter().take(6) {
            println!("Inventory diagnostic: {warning}");
        }
        Ok(())
    }
}
