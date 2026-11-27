use std::{
    collections::HashMap,
    io,
    num::NonZeroU16,
    path::{Path, PathBuf},
};
use uuid::Uuid;

use crate::{
    Access, AppId, AppRecord, Cancellation, Inventory, OfficialIntent, OfficialOutcome, Proposal,
    RegistryTarget, Result, RuleRoot, RuleTarget, Scan, ScanMode,
};

/// Native identity and permission established by a no-follow inspection.
#[derive(Debug)]
pub struct Inspection {
    pub fingerprint: String,
    pub access: Access,
}

/// Writes both the public .reg file and the private typed restoration snapshot.
pub type RegistryBackupWriter<'a> = dyn FnMut(&[u8], &[u8]) -> io::Result<()> + 'a;

/// The latest change proven by a receipt committed with a registry operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryChangeReceipt {
    /// The exact backed-up object was removed.
    Applied,
    /// The exact backup was restored and may no longer be applied.
    Restored,
}

/// Filesystem operations whose implementations revalidate identity at mutation.
pub trait FileStore {
    /// Reopens the exact target without following links.
    fn inspect_file(&self, path: &Path) -> io::Result<Inspection>;
    /// Returns the intended private backup path without writing to disk.
    fn file_backup_path(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<PathBuf>;
    /// Moves the verified object to its private slot, refusing replacements.
    fn quarantine_file(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<()>;
    /// Moves one verified object, allowing cancellation before the move starts.
    /// Implementations must finish verification and recovery after attempting a move.
    fn quarantine_file_with_cancel(
        &self,
        path: &Path,
        expected: &str,
        slot: Uuid,
        cancel: &Cancellation,
    ) -> Result<()> {
        cancel.check()?;
        Ok(self.quarantine_file(path, expected, slot)?)
    }
    /// Tests whether the recorded object is present in its private slot.
    fn file_is_quarantined(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<bool>;
    /// Finds an intact backup detached for disposal before deletion was committed.
    /// The result is an observed display path, never a restore authorization.
    fn recoverable_detached_file_backup(
        &self,
        _path: &Path,
        _expected: &str,
        _slot: Uuid,
    ) -> io::Result<Option<PathBuf>> {
        Ok(None)
    }
    /// Identifies a recorded file that needs another file to be restored first.
    ///
    /// The engine also uses this order in reverse when quarantining startup
    /// files. Classify the recorded path and fingerprint without inspecting disk.
    fn restore_file_after_ordinary_files(&self, _path: &Path, _expected: &str) -> bool {
        false
    }
    /// Restores the verified object without overwriting anything at the destination.
    fn restore_file(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<()>;
    /// Verifies a durable restore after an interruption, without moving any files.
    ///
    /// Implementations must prove both the original object's identity and the
    /// absence of its quarantine entry before reporting success.
    fn verify_file_restored(&self, _path: &Path, _expected: &str, _slot: Uuid) -> io::Result<bool> {
        Ok(false)
    }
    /// Checks if this exact quarantined object can be permanently removed.
    fn can_purge_quarantined(
        &self,
        _path: &Path,
        _expected: &str,
        _slot: Uuid,
    ) -> io::Result<bool> {
        Ok(false)
    }
    /// Verifies that an interrupted purge of this exact slot can be resumed.
    ///
    /// A pending purge is ineligible for ordinary restoration. Implementations
    /// must verify their durable purge state before permitting a new preview.
    fn has_pending_quarantine_purge(
        &self,
        _path: &Path,
        _expected: &str,
        _slot: Uuid,
    ) -> io::Result<bool> {
        Ok(false)
    }
    /// Permanently removes one verified slot without following links.
    fn purge_quarantined(&self, _path: &Path, _expected: &str, _slot: Uuid) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// Exact registry operations with backup as a precondition on removal.
pub trait RegistryStore {
    /// Reads the object in its precise view without following registry links.
    fn inspect_registry(&self, target: &RegistryTarget) -> io::Result<Inspection>;
    /// Verifies identity, calls the backup writer, and commits one scoped removal.
    fn remove_registry(
        &self,
        target: &RegistryTarget,
        expected: &str,
        write: &mut RegistryBackupWriter<'_>,
    ) -> io::Result<()>;
    /// Restores only the supplied target from the typed snapshot without replacing a conflict.
    fn restore_registry(&self, target: &RegistryTarget, snapshot: &[u8]) -> io::Result<()>;

    /// Removes the target and can commit a receipt in the same transaction.
    ///
    /// A native receipt must bind the operation ID, exact target and typed
    /// backup snapshot. It may only be published after the backup writer succeeds.
    fn remove_registry_with_receipt(
        &self,
        target: &RegistryTarget,
        expected: &str,
        _operation_id: Uuid,
        write: &mut RegistryBackupWriter<'_>,
    ) -> io::Result<()> {
        self.remove_registry(target, expected, write)
    }

    /// Restores a target and can commit a terminal receipt in the same transaction.
    ///
    /// An existing terminal receipt must prevent a duplicate restore. A native
    /// receipt may be absent for a legacy backup with a valid journal receipt.
    fn restore_registry_with_receipt(
        &self,
        target: &RegistryTarget,
        snapshot: &[u8],
        _operation_id: Uuid,
    ) -> io::Result<()> {
        self.restore_registry(target, snapshot)
    }

    /// Reads the exact native receipt without changing the target or journal.
    ///
    /// Match the operation ID, target and snapshot. Use `None` only if there
    /// is no receipt. Return an error for conflicting or unreadable evidence.
    /// Target presence, absence or matching contents cannot prove a commit.
    fn registry_change_receipt(
        &self,
        _target: &RegistryTarget,
        _snapshot: &[u8],
        _operation_id: Uuid,
    ) -> io::Result<Option<RegistryChangeReceipt>> {
        Ok(None)
    }
}

/// Supplemental verification held in memory from uninstall through file cleanup.
pub type PostUninstallCheck = Box<dyn Fn(&Cancellation) -> Result<()> + Send + Sync>;

/// Result of an official command and optional evidence for its residual preview.
pub struct OfficialExecution {
    /// Native outcome, subject to the core's separate absence check.
    pub outcome: OfficialOutcome,
    /// Diagnostics to display alongside the native result.
    pub warnings: Vec<String>,
    /// Supplemental evidence from a finished command that cannot authorize cleanup.
    ///
    /// An unverified result may include this evidence once the command has
    /// exited. Leave it empty if waiting was interrupted or cancelled.
    pub read_only_residuals: Vec<Proposal>,
    /// Exact filesystem fingerprints observed while the original app was present.
    ///
    /// These are attribution evidence for a fresh scan after verified
    /// completion. They never authorize a write by themselves.
    pub observed_files: HashMap<PathBuf, String>,
    /// Revalidates additional native proof after independently checking absence.
    pub post_uninstall_check: Option<PostUninstallCheck>,
}

/// A single reviewed action for removing an application's installation.
pub enum ApplicationUninstall<Command> {
    /// Runs the verified vendor or package-manager command.
    Official(Command),
    /// Quarantines the installation through a platform-managed backup store.
    PlatformQuarantine(Command),
    /// Quarantines only the reviewed installation directory through the core journal.
    QuarantineBundle {
        /// Native fingerprint of the installation directory in the uninstall preview.
        fingerprint: String,
        /// Exact file identities captured while the bundle still exists.
        observed_files: HashMap<PathBuf, String>,
    },
}

/// Whether a verified uninstall is being previewed or rechecked for writes.
#[derive(Clone, Copy, Debug)]
pub enum PostUninstallScan {
    /// Builds the dry-run preview.
    Preview,
    /// Rechecks attribution and eligibility for approved items.
    Recheck,
}

/// Entry points for system inventory, scans and official uninstallation.
pub trait PlatformBackend: FileStore + RegistryStore {
    /// Opaque prepared native command that is kept in memory through confirmation.
    type Official;

    /// Acquires the platform's guard for a confirmed mutation.
    ///
    /// The engine holds it through fresh preflight checks, writes and their
    /// outcome audit. The default only checks cancellation.
    fn begin_mutation(&self, cancel: &Cancellation) -> Result<impl Sized> {
        cancel.check()
    }

    /// Reads application inventory and source warnings.
    fn inventory(&self, cancel: &Cancellation) -> Result<Inventory>;
    /// Reads the current record for one exact identity from its inventory source.
    ///
    /// A source-specific lookup must preserve the ownership and removal
    /// eligibility checks used by the full inventory.
    fn lookup_application(&self, id: &AppId, cancel: &Cancellation) -> Result<Option<AppRecord>> {
        Ok(self
            .inventory(cancel)?
            .applications
            .into_iter()
            .find(|app| &app.id == id))
    }
    /// Reads the desktop inventory and any optional display metadata.
    ///
    /// Confirmation uses current records without optional display metadata.
    fn inventory_for_display(&self, cancel: &Cancellation) -> Result<Inventory> {
        self.inventory(cancel)
    }
    /// Finds residual objects from inventory-backed or pre-uninstall evidence.
    fn scan(&self, app: &AppRecord, mode: ScanMode, cancel: &Cancellation) -> Result<Scan>;
    /// Rechecks attribution, access, and risk before approved cleanup writes.
    ///
    /// An override may omit display-only sources whose proposals cannot
    /// affect ownership, access, or risk for any selectable target. Keep
    /// restrictive duplicate proposals for targets eligible for approval.
    fn scan_for_cleanup_recheck(
        &self,
        app: &AppRecord,
        mode: ScanMode,
        cancel: &Cancellation,
    ) -> Result<Scan> {
        self.scan(app, mode, cancel)
    }
    /// Revalidates scan-bound force-removal evidence before each approved write.
    fn check_force_removal_binding(
        &self,
        _app: &AppId,
        _binding: &str,
        cancel: &Cancellation,
    ) -> Result<()> {
        cancel.check()
    }
    /// Revalidates force-removal evidence for a file immediately before isolation.
    ///
    /// The default uses the same binding check as registry writes. Platforms
    /// can also recheck attribution that depends on the specific file.
    fn check_force_removal_file(
        &self,
        app: &AppId,
        binding: &str,
        _path: &Path,
        cancel: &Cancellation,
    ) -> Result<()> {
        self.check_force_removal_binding(app, binding, cancel)
    }
    /// Rechecks application ownership after backup and before a registry write.
    /// Implementations must only read because the backend can hold a transaction.
    fn check_registry_cleanup_application(
        &self,
        _app: &AppId,
        _mode: ScanMode,
        _target: &RegistryTarget,
        cancel: &Cancellation,
    ) -> Result<()> {
        cancel.check()
    }
    /// Scans the independently verified former installation with native evidence.
    fn scan_after_official_uninstall(
        &self,
        app: &AppRecord,
        _observed_files: &HashMap<PathBuf, String>,
        phase: PostUninstallScan,
        cancel: &Cancellation,
    ) -> Result<Scan> {
        match phase {
            PostUninstallScan::Preview => self.scan(app, ScanMode::AfterOfficialUninstall, cancel),
            PostUninstallScan::Recheck => {
                self.scan_for_cleanup_recheck(app, ScanMode::AfterOfficialUninstall, cancel)
            }
        }
    }
    /// Rejects leftover cleanup when a related installation has appeared.
    /// This does not change the separately verified outcome of the uninstall.
    fn check_cleanup_after_uninstall(&self, _app: &AppRecord, cancel: &Cancellation) -> Result<()> {
        cancel.check()
    }
    /// Revalidates native observations that authorize leftover cleanup only.
    fn check_cleanup_observations(
        &self,
        _app: &AppRecord,
        _observed_files: &HashMap<PathBuf, String>,
        _cancel: &Cancellation,
    ) -> Result<()> {
        Ok(())
    }
    /// Revalidates a marked file after staging its backup intent.
    /// The engine holds the returned guard through quarantine.
    fn pin_post_uninstall_file(
        &self,
        _app: &AppRecord,
        _path: &Path,
        _observed_files: &HashMap<PathBuf, String>,
        cancel: &Cancellation,
    ) -> Result<impl Sized> {
        cancel.check()?;
        Err::<(), _>(crate::Error::Rejected(
            "the required post-uninstall file guard is unavailable on this platform".into(),
        ))
    }
    /// Finds residual objects in an explicitly selected portable application location.
    fn scan_portable(&self, directory: &Path, cancel: &Cancellation) -> Result<Scan>;
    /// Rechecks a scan-bound application immediately before quarantining a file.
    fn check_file_cleanup_application(&self, _application: &AppId) -> Result<()> {
        Ok(())
    }
    /// Opts in to checking original installation absence before each file move.
    fn recheck_uninstall_absence_before_each_file(&self) -> bool {
        false
    }
    /// Resolves a rule's fixed discovery scope using native account paths.
    fn rule_root(&self, _root: RuleRoot) -> Option<PathBuf> {
        None
    }
    /// Reads the type and address of a suggested rule target without following links.
    fn probe_rule_target(&self, _path: &Path) -> io::Result<Option<RuleTarget>> {
        Ok(None)
    }
    /// Prepares the exact official action plus a user-readable description.
    fn prepare_official(&self, app: &AppRecord) -> Result<(OfficialIntent, Self::Official)>;
    /// Prepares the uninstall method to display before confirming any change.
    fn prepare_application_uninstall(
        &self,
        app: &AppRecord,
        _retention_days: NonZeroU16,
        cancel: &Cancellation,
    ) -> Result<(OfficialIntent, ApplicationUninstall<Self::Official>)> {
        cancel.check()?;
        let (intent, command) = self.prepare_official(app)?;
        Ok((intent, ApplicationUninstall::Official(command)))
    }
    /// Runs native checks and residual discovery around the core's single approved move.
    fn run_bundle_uninstall(
        &self,
        _app: &AppRecord,
        observed_files: HashMap<PathBuf, String>,
        cancel: &Cancellation,
        quarantine: impl FnOnce() -> Result<()>,
    ) -> Result<OfficialExecution>
    where
        Self: Sized,
    {
        cancel.check()?;
        quarantine()?;
        Ok(OfficialExecution {
            outcome: OfficialOutcome::Completed,
            warnings: Vec::new(),
            read_only_residuals: Vec::new(),
            observed_files,
            post_uninstall_check: None,
        })
    }
    /// Runs the prepared command and reports native completion.
    fn run_official(&self, command: Self::Official) -> Result<OfficialOutcome>;
    /// Runs the prepared command with the caller's cancellation token.
    ///
    /// The default checks cancellation before using the synchronous backend.
    fn run_official_with_cancel(
        &self,
        command: Self::Official,
        cancel: &Cancellation,
    ) -> Result<OfficialExecution> {
        cancel.check()?;
        Ok(OfficialExecution {
            outcome: self.run_official(command)?,
            warnings: Vec::new(),
            read_only_residuals: Vec::new(),
            observed_files: HashMap::new(),
            post_uninstall_check: None,
        })
    }
    /// Records a native official outcome after the core has saved its audit event.
    fn record_audited_official_outcome(&self, _app: &AppRecord, _outcome: &OfficialOutcome) {}

    /// Completes bounded read-only verification after a native command reports completion.
    /// Opting in keeps a late cancellation from interrupting that verification.
    fn verify_finished_official_after_cancel(&self) -> bool {
        false
    }
    /// Verifies absence using the inventory source that owns this identity.
    fn official_uninstall_absent(&self, id: &AppId, cancel: &Cancellation) -> Result<bool> {
        let inventory = self.inventory(cancel)?;
        Ok(
            inventory.warnings.is_empty()
                && !inventory.applications.iter().any(|app| &app.id == id),
        )
    }

    /// Verifies absence of the installation captured before the official action.
    ///
    /// Backends with path-based installations can check the original location.
    /// Other backends continue to verify through the application's native ID.
    fn verify_official_uninstall_absence(
        &self,
        app: &AppRecord,
        cancel: &Cancellation,
    ) -> Result<bool> {
        self.official_uninstall_absent(&app.id, cancel)
    }
}
