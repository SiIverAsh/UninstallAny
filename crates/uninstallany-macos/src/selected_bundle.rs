use std::{
    collections::HashMap,
    fs::File,
    io,
    num::NonZeroU16,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use uninstallany_core::{
    Access, AppId, AppRecord, Artifact, AuditEvent, Cancellation, Error, FileStore, Journal,
    OfficialExecution, OfficialIntent, OfficialOutcome, PlatformBackend, Result, Scan,
};
use uninstallany_unix::user_home;
use uuid::Uuid;

use crate::{
    MacBackend, PrivilegedHelperRegistrationPreview, PrivilegedHelperServiceState,
    PrivilegedQuarantineOutcome, PrivilegedStandaloneQuarantinePreview, activity,
    app_groups::UninstallAppGroups, brew, bundle, prepare_privileged_helper_registration,
    prepare_privileged_standalone_quarantine_with_retention, privileged_helper_service_state,
    quarantine_privileged_standalone_application, receipt, register_privileged_helper, vendor,
};

const QUARANTINE_ACTION: &str = "macos_system_quarantine";
// Security.framework cancellation is translated to Darwin ECANCELED by the helper.
const DARWIN_ECANCELED: i32 = 89;

/// A single-use preview of enabling the signed helper for a selected app.
pub struct SystemHelperActivation {
    app: AppRecord,
    directories: ActivationDirectories,
    observed_files: HashMap<PathBuf, String>,
    registration: PrivilegedHelperRegistrationPreview,
}

impl SystemHelperActivation {
    /// Returns the catalogued application for the activation confirmation.
    pub fn application(&self) -> &AppRecord {
        &self.app
    }

    /// Revalidates the selection and registers the helper after user approval.
    /// Application quarantine requires a new preview and confirmation.
    pub fn register(self, cancel: &Cancellation) -> Result<PrivilegedHelperServiceState> {
        cancel.check()?;
        let backend = MacBackend::new(user_home()?)?;
        let current = activation_application(&backend, &self.app.id, cancel)?;
        if current.install_location != self.app.install_location
            || current.name != self.app.name
            || current.version != self.app.version
        {
            return Err(Error::Rejected(
                "The selected application changed. Review helper activation again.".into(),
            ));
        }
        let path = activation_path(&current)?;
        let current_files = verify_activation_target(&backend, &current, path, cancel)?;
        if current_files != self.observed_files {
            return Err(Error::Rejected(
                "The application's LaunchAgents changed. Review helper activation again.".into(),
            ));
        }
        self.directories.require_current(&backend, path)?;
        let registration = self.registration.confirm()?;
        cancel.check()?;
        // Preserve the native result if cancellation coincides with registration.
        Ok(register_privileged_helper(registration)?)
    }
}

/// Previews setup for a standalone, catalogued app under trusted `/Applications`.
/// macOS may require administrator approval before launching the helper.
pub fn prepare_system_helper_activation(
    app_id: &AppId,
    cancel: &Cancellation,
) -> Result<SystemHelperActivation> {
    cancel.check()?;
    let backend = MacBackend::new(user_home()?)?;
    let app = activation_application(&backend, app_id, cancel)?;
    let path = activation_path(&app)?;
    let directories = ActivationDirectories::open(&backend, path)?;
    let observed_files = verify_activation_target(&backend, &app, path, cancel)?;
    let registration = prepare_privileged_helper_registration();
    cancel.check()?;
    let registration = registration?;
    directories.require_current(&backend, path)?;
    Ok(SystemHelperActivation {
        app,
        directories,
        observed_files,
        registration,
    })
}

struct ActivationDirectories {
    applications: File,
    bundle: File,
}

impl ActivationDirectories {
    fn open(backend: &MacBackend, path: &Path) -> Result<Self> {
        let applications = File::from(
            backend
                .files
                .open_trusted_local_directory(&backend.application_roots[0])?,
        );
        let bundle = File::from(backend.files.open_trusted_local_directory(path)?);
        let applications_metadata = applications.metadata()?;
        let bundle_metadata = bundle.metadata()?;
        if applications_metadata.uid() != 0
            || bundle_metadata.uid() != 0
            || applications_metadata.dev() != bundle_metadata.dev()
        {
            return Err(Error::Rejected(
                "Helper activation requires a root-owned application on the same local volume as /Applications.".into(),
            ));
        }
        Ok(Self {
            applications,
            bundle,
        })
    }

    fn require_current(&self, backend: &MacBackend, path: &Path) -> Result<()> {
        let named = Self::open(backend, path)?;
        // Holding both original descriptors keeps their inodes from being
        // reused while the user reviews the registration.
        for (held, current) in [
            (&self.applications, &named.applications),
            (&self.bundle, &named.bundle),
        ] {
            let held = held.metadata()?;
            let current = current.metadata()?;
            if (held.dev(), held.ino()) != (current.dev(), current.ino()) {
                return Err(Error::Rejected(
                    "The application directory changed. Review helper activation again.".into(),
                ));
            }
        }
        Ok(())
    }
}

fn activation_application(
    backend: &MacBackend,
    app_id: &AppId,
    cancel: &Cancellation,
) -> Result<AppRecord> {
    if !matches!(app_id, AppId::Package { manager, .. } if manager == bundle::MANAGER) {
        return Err(Error::Rejected(
            "Helper activation requires a catalogued standalone macOS application.".into(),
        ));
    }
    backend.lookup_application(app_id, cancel)?.ok_or_else(|| {
        Error::Rejected("The selected application is no longer in the catalog.".into())
    })
}

fn activation_path(app: &AppRecord) -> Result<&Path> {
    let unsupported = || {
        Error::Rejected(
            "Helper activation requires an application directly in /Applications.".into(),
        )
    };
    let path = app.install_location.as_deref().ok_or_else(unsupported)?;
    if !bundle::is_selected_system_application(path)? {
        return Err(unsupported());
    }
    Ok(path)
}

fn verify_activation_target(
    backend: &MacBackend,
    app: &AppRecord,
    path: &Path,
    cancel: &Cancellation,
) -> Result<HashMap<PathBuf, String>> {
    cancel.check()?;
    let selected = read_system_bundle(backend, path)?;
    verify_catalogued_identity(&selected, app)?;
    if backend
        .files
        .validate_macos_application_bundle_location(path)
        .is_ok()
    {
        return Err(Error::Rejected(
            "Use the ordinary application review for this user-writable bundle.".into(),
        ));
    }
    verify_local_selection(backend, &selected, cancel)?;
    let unclaimed = receipt::has_no_claim(&backend.files, path, cancel);
    cancel.check()?;
    if !unclaimed? {
        return Err(Error::Rejected(
            "An Installer receipt claims part of this application.".into(),
        ));
    }
    backend.standalone_launch_agents(path, &selected.identifier, cancel)
}

/// Previews one explicitly selected system-scope standalone application.
///
/// Ordinary portable paths return `None` for the standard scanner.
/// Requires an already enabled signed helper. The preview performs no move
/// and requests no administrator authorization.
pub fn prepare_selected_system_application(
    path: &Path,
    retention_days: NonZeroU16,
    cancel: &Cancellation,
) -> Result<Option<PrivilegedStandaloneQuarantinePreview>> {
    cancel.check()?;
    if !bundle::is_selected_system_application(path)? {
        return Ok(None);
    }

    let backend = MacBackend::new(user_home()?)?;
    let selected = read_system_bundle(&backend, path)?;
    if backend.files.inspect_file(path)?.access == Access::Allowed {
        return Err(Error::Rejected(
            "Use the ordinary application review for this user-writable bundle.".into(),
        ));
    }
    require_enabled_helper()?;
    verify_local_selection(&backend, &selected, cancel)?;
    request_helper_preview(&selected, retention_days, cancel).map(Some)
}

/// A single catalogued application and its immutable signed-helper preview.
pub(super) struct PreparedSystemUninstall {
    app: AppRecord,
    preview: PrivilegedStandaloneQuarantinePreview,
    observed_files: HashMap<PathBuf, String>,
}

/// Prepares the privileged uninstall alternative for an exact catalogued app.
pub(super) fn prepare_catalogued_system_uninstall(
    backend: &MacBackend,
    app: &AppRecord,
    retention_days: NonZeroU16,
    cancel: &Cancellation,
) -> Result<Option<(OfficialIntent, PreparedSystemUninstall)>> {
    cancel.check()?;
    let Some(path) = app.install_location.as_deref() else {
        return Ok(None);
    };
    if !bundle::is_selected_system_application(path)? {
        return Ok(None);
    }
    let selected = read_system_bundle(backend, path)?;
    if backend
        .files
        .validate_macos_application_bundle_location(path)
        .is_ok()
    {
        return Ok(None);
    }
    verify_catalogued_identity(&selected, app)?;
    require_enabled_helper()?;
    verify_local_selection(backend, &selected, cancel)?;
    let observed_files = backend.standalone_launch_agents(path, &selected.identifier, cancel)?;
    let preview = request_helper_preview(&selected, retention_days, cancel)?;
    write_quarantine_audit(backend, preview.operation_id(), path, "reviewed", None)?;

    let intent = OfficialIntent {
        application: app.name.clone(),
        method: format!("Quarantine system application bundle ({})", path.display()),
        quiet: false,
        notice: format!(
            "macOS requests administrator approval to move this standalone application bundle to reversible quarantine for {retention_days} days. Leftovers are scanned after uninstall and require a separate selection and confirmation."
        ),
    };
    Ok(Some((
        intent,
        PreparedSystemUninstall {
            app: app.clone(),
            preview,
            observed_files,
        },
    )))
}

impl PreparedSystemUninstall {
    /// Submits a fresh, revalidated preview and retains the native receipt state.
    pub(super) fn execute(
        self,
        backend: &MacBackend,
        cancel: &Cancellation,
    ) -> Result<OfficialExecution> {
        let Self {
            app,
            preview,
            observed_files,
        } = self;
        let operation = preview.operation_id();
        let path = preview.path().to_owned();
        let confirmed = (|| {
            cancel.check()?;
            let selected = read_system_bundle(backend, &path)?;
            if backend
                .files
                .validate_macos_application_bundle_location(&path)
                .is_ok()
            {
                return Err(Error::Rejected(
                    "The application is now eligible for ordinary review.".into(),
                ));
            }
            verify_catalogued_identity(&selected, &app)?;
            require_enabled_helper()?;
            verify_local_selection(backend, &selected, cancel)?;
            let current = backend.standalone_launch_agents(&path, &selected.identifier, cancel)?;
            if current != observed_files {
                return Err(Error::Rejected(
                    "The application's LaunchAgents changed. Review the uninstall again.".into(),
                ));
            }
            let groups =
                UninstallAppGroups::capture(&backend.files, &path, &selected.identifier, cancel)?;
            cancel.check()?;
            Ok((preview.confirm()?, groups))
        })();
        let (confirmed, groups) = match confirmed {
            Ok(confirmed) => confirmed,
            Err(error) => return finish_without_move(backend, operation, &path, error),
        };

        // The local start record makes an interrupted helper transaction discoverable.
        write_quarantine_audit(backend, operation, &path, "starting", None)?;
        if let Err(error) = cancel.check() {
            return finish_without_move(backend, operation, &path, error);
        }
        let result = quarantine_privileged_standalone_application(confirmed);
        // A cancellation received during the authorization prompt cannot undo an
        // already submitted operation. Always retain its actual receipt and audit it.
        let (outcome, status, backup, mut warnings) = match result {
            Ok(PrivilegedQuarantineOutcome::Quarantined(receipt)) => {
                if let Some(record) = receipt.record {
                    (
                        OfficialOutcome::Completed,
                        "applied",
                        Some(record.backup_path),
                        Vec::new(),
                    )
                } else {
                    (
                        OfficialOutcome::Unverified(0),
                        "reply_uncertain",
                        None,
                        vec![format!(
                            "System quarantine {operation} did not return a backup record. Review the operation before retrying."
                        )],
                    )
                }
            }
            Ok(PrivilegedQuarantineOutcome::ReviewRequired(receipt)) => {
                let detail = if receipt.os_error > 0 {
                    format!(" ({})", io::Error::from_raw_os_error(receipt.os_error))
                } else {
                    String::new()
                };
                (
                    OfficialOutcome::Unverified(0),
                    "needs_review",
                    receipt.record.map(|record| record.backup_path),
                    vec![format!(
                        "System quarantine {operation} needs review before retrying{detail}."
                    )],
                )
            }
            Ok(PrivilegedQuarantineOutcome::ReplyUncertain { error, .. }) => (
                OfficialOutcome::Unverified(0),
                "reply_uncertain",
                None,
                vec![format!(
                    "System quarantine {operation} could not be verified. Review the operation before retrying. {error}"
                )],
            ),
            Err(error) if error.raw_os_error() == Some(DARWIN_ECANCELED) => {
                (OfficialOutcome::Cancelled, "cancelled", None, Vec::new())
            }
            Err(error) => return finish_without_move(backend, operation, &path, error.into()),
        };
        if let Err(error) =
            write_quarantine_audit(backend, operation, &path, status, backup.as_deref())
        {
            let detail = format!(
                "System quarantine {operation} could not record its final audit event. {error}"
            );
            if outcome == OfficialOutcome::Completed {
                return Err(Error::AuditAfterChange(detail));
            }
            warnings.push(detail);
        }
        let (observed_files, read_only_residuals) = if outcome == OfficialOutcome::Completed {
            let residuals = groups.resolve_after_move(&backend.files, &backend.home, cancel);
            warnings.extend(residuals.warnings);
            (observed_files, residuals.proposals)
        } else {
            (HashMap::new(), Vec::new())
        };
        Ok(OfficialExecution {
            outcome,
            warnings,
            read_only_residuals,
            observed_files,
            post_uninstall_check: None,
        })
    }
}

fn read_system_bundle(backend: &MacBackend, path: &Path) -> Result<bundle::Bundle> {
    let selected = bundle::read(&backend.files, path)?;
    if selected.is_system() {
        return Err(Error::Rejected(
            "macOS system applications are protected.".into(),
        ));
    }
    Ok(selected)
}

fn verify_catalogued_identity(selected: &bundle::Bundle, app: &AppRecord) -> Result<()> {
    if app.system_component
        || app.install_location.as_deref() != Some(selected.path.as_path())
        || app.id != selected.record().id
        || app.name != selected.name
        || app.version != selected.version
    {
        return Err(Error::Rejected(
            "The selected bundle no longer matches the installed application.".into(),
        ));
    }
    Ok(())
}

fn request_helper_preview(
    selected: &bundle::Bundle,
    retention_days: NonZeroU16,
    cancel: &Cancellation,
) -> Result<PrivilegedStandaloneQuarantinePreview> {
    cancel.check()?;
    // Local checks preserve the ordinary backend's ownership and vendor
    // boundaries. Only the signed helper can approve the privileged move.
    let preview = prepare_privileged_standalone_quarantine_with_retention(
        &selected.path,
        &selected.identifier,
        retention_days,
    );
    cancel.check()?;
    preview.map_err(Error::from)
}

fn write_quarantine_audit(
    backend: &MacBackend,
    operation: Uuid,
    path: &Path,
    status: &str,
    backup: Option<&Path>,
) -> Result<()> {
    let mut event = AuditEvent::new(path.display().to_string(), QUARANTINE_ACTION, status);
    event.batch_id = Some(operation);
    event.operation_id = Some(operation);
    event.backup = backup.map(|path| path.display().to_string());
    backend.files.create(
        Uuid::new_v4(),
        Artifact::Event,
        &serde_json::to_vec(&event)?,
    )?;
    Ok(())
}

fn finish_without_move(
    backend: &MacBackend,
    operation: Uuid,
    path: &Path,
    error: Error,
) -> Result<OfficialExecution> {
    let status = if matches!(error, Error::Cancelled) {
        "cancelled"
    } else {
        "skipped"
    };
    if let Err(audit_error) = write_quarantine_audit(backend, operation, path, status, None) {
        return Err(Error::Rejected(format!(
            "System quarantine {operation} could not proceed. {error}. The audit also failed. {audit_error}"
        )));
    }
    Err(error)
}

fn require_enabled_helper() -> Result<()> {
    use PrivilegedHelperServiceState as State;
    let reason = match privileged_helper_service_state()? {
        State::Enabled => return Ok(()),
        State::NotRegistered => "The signed macOS helper has not been enabled.",
        State::RequiresApproval => "The macOS helper is awaiting administrator approval.",
        State::NotFound => "The installed app is missing its signed macOS helper.",
    };
    Err(Error::Rejected(reason.into()))
}

fn verify_local_selection(
    backend: &MacBackend,
    selected: &bundle::Bundle,
    cancel: &Cancellation,
) -> Result<()> {
    cancel.check()?;
    let path = &selected.path;
    if vendor::review(
        &backend.files,
        &selected.record(),
        &backend.application_roots[..2],
    )?
    .prepared
    .is_some()
    {
        return Err(Error::Rejected(
            "Use the verified vendor uninstaller shown in the application list.".into(),
        ));
    }
    if activity::at_location(&backend.files, Some(path), &selected.identifier) {
        return Err(Error::Rejected(
            "Quit the application before reviewing system quarantine.".into(),
        ));
    }
    if backend.scan_bundle_services(path, &mut Scan::default(), cancel)? {
        return Err(Error::Rejected(
            "Use the vendor's procedure to deregister the application's background services."
                .into(),
        ));
    }

    let mut warnings = Vec::new();
    let installed = bundle::discover(
        &backend.files,
        &backend.application_roots[..2],
        cancel,
        &mut warnings,
    )?;
    let duplicate = installed.iter().any(|other| {
        other.path != *path && other.identifier.eq_ignore_ascii_case(&selected.identifier)
    });
    if duplicate || !warnings.is_empty() {
        return Err(Error::Rejected(
            "A duplicate application or incomplete discovery prevents ownership verification."
                .into(),
        ));
    }

    let casks = brew::discover(&backend.files, &backend.home, cancel, &mut warnings)?;
    if !warnings.is_empty()
        || casks
            .iter()
            .any(|cask| cask.could_own_bundle(&backend.files, path))
    {
        return Err(Error::Rejected(
            "Homebrew ownership could not be excluded.".into(),
        ));
    }
    Ok(())
}
