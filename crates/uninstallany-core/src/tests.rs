use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    io,
    num::NonZeroU16,
    path::{Path, PathBuf},
    rc::Rc,
};

use uuid::Uuid;

use crate::*;

const AUDIT_WRITE_FAILURE: &str = "intentional audit write failure";
const CLEANUP_INELIGIBLE: &str = "fixture application reappeared during cleanup";
const CLEANUP_OBSERVATION_CHANGED: &str = "fixture cleanup observation changed";

#[derive(Clone, Debug)]
struct MockFile {
    stamp: String,
    access: Access,
    reason: &'static str,
}

#[derive(Default)]
struct MockState {
    files: HashMap<PathBuf, MockFile>,
    shared_files: HashSet<PathBuf>,
    rule_targets: Vec<PathBuf>,
    quarantine: HashMap<Uuid, (PathBuf, MockFile)>,
    quarantine_read_failures: HashSet<Uuid>,
    rollback_sync_failure: Option<PathBuf>,
    purge_ineligible: HashSet<PathBuf>,
    purge_failure_after_removal: bool,
    registry: HashMap<RegistryTarget, String>,
    registry_receipts: Option<HashMap<Uuid, MockRegistryReceipt>>,
    applications: Vec<AppRecord>,
    bundle_uninstall: Option<AppId>,
    launches: Vec<AppId>,
    official_absence_checks: Vec<AppId>,
    official_error: Option<&'static str>,
    cancel_on_official_completion: Option<Cancellation>,
    cleanup_checks_before_rejection: Option<usize>,
    cleanup_observations: Option<MockCleanupObservations>,
    cancel_during_scan: bool,
    next_scan_error: Option<io::Error>,
    scan_count: usize,
}

struct MockRegistryReceipt {
    target: RegistryTarget,
    snapshot: Vec<u8>,
    state: RegistryChangeReceipt,
}

struct MockCleanupObservations {
    files: HashMap<PathBuf, String>,
    checks_before_rejection: usize,
    checks: usize,
}

impl MockCleanupObservations {
    fn new(checks_before_rejection: usize) -> Self {
        Self {
            files: HashMap::from([(path("apps/old-install"), "original identity".into())]),
            checks_before_rejection,
            checks: 0,
        }
    }
}

#[derive(Clone, Default)]
struct Fake(Rc<RefCell<MockState>>);

#[derive(Clone, Default)]
struct MemoryJournal(Rc<RefCell<MemoryState>>);

#[derive(Default)]
struct MemoryState {
    records: HashMap<String, Vec<u8>>,
    fail: Option<Artifact>,
    fail_event: Option<(&'static str, &'static str)>,
    cancel_after_create: Option<(Artifact, Cancellation)>,
    block_export: bool,
}

impl Journal for MemoryJournal {
    fn create(&self, id: Uuid, artifact: Artifact, bytes: &[u8]) -> io::Result<()> {
        let mut state = self.0.borrow_mut();
        let fail_event = artifact == Artifact::Event
            && state.fail_event.is_some_and(|(action, result)| {
                serde_json::from_slice::<AuditEvent>(bytes)
                    .is_ok_and(|event| event.action == action && event.result == result)
            });
        if state.fail == Some(artifact) || fail_event {
            return Err(io::Error::other(AUDIT_WRITE_FAILURE));
        }
        let key = artifact.file_name(id);
        if state.records.contains_key(&key) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        state.records.insert(key, bytes.to_vec());
        if let Some((_, cancel)) = state
            .cancel_after_create
            .as_ref()
            .filter(|(kind, _)| *kind == artifact)
        {
            cancel.cancel();
        }
        Ok(())
    }

    fn read(&self, id: Uuid, artifact: Artifact) -> io::Result<Option<Vec<u8>>> {
        Ok(self
            .0
            .borrow()
            .records
            .get(&artifact.file_name(id))
            .cloned())
    }

    fn list(&self, artifact: Artifact) -> io::Result<Vec<Uuid>> {
        Ok(self
            .0
            .borrow()
            .records
            .keys()
            .filter_map(|name| artifact.id(name))
            .collect())
    }

    fn location(&self, id: Uuid, artifact: Artifact) -> PathBuf {
        path(&format!("state/{}", artifact.file_name(id)))
    }

    fn check_export_path(&self, _path: &Path) -> io::Result<()> {
        if self.0.borrow().block_export {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(())
    }
}

#[test]
fn audit_export_orders_receipts_and_omits_private_inputs() -> Result<()> {
    let journal = MemoryJournal::default();
    let operation = Uuid::from_u128(4);
    let batch = Uuid::from_u128(5);
    let audit = |action: &str, result: &str| AuditEvent {
        time_unix_ms: 100,
        batch_id: Some(batch),
        operation_id: Some(operation),
        object: "vendor cache".into(),
        action: action.into(),
        result: result.into(),
        backup: Some("backup/cache".into()),
    };
    let purge_operation = Uuid::from_u128(3);
    let purge = AuditEvent {
        time_unix_ms: 200,
        operation_id: Some(purge_operation),
        ..audit("purge_quarantine", "purged")
    };
    for (id, artifact, event) in [
        (purge_operation, Artifact::Purged, purge),
        (operation, Artifact::Restored, audit("restore", "restored")),
        (
            Uuid::from_u128(9),
            Artifact::Event,
            audit("cleanup", "staged"),
        ),
        (operation, Artifact::Applied, audit("cleanup", "applied")),
        (
            Uuid::from_u128(8),
            Artifact::Event,
            audit("restore", "starting"),
        ),
        (
            Uuid::from_u128(7),
            Artifact::Event,
            audit("scan", "legacy raw secret"),
        ),
    ] {
        journal.create(id, artifact, &serde_json::to_vec(&event)?)?;
    }
    journal.create(Uuid::from_u128(6), Artifact::Event, b"{invalid")?;
    journal.create(
        Uuid::from_u128(10),
        Artifact::Applied,
        &serde_json::to_vec(&audit("cleanup", "applied"))?,
    )?;
    journal.create(
        operation,
        Artifact::RegistrySnapshot,
        b"registry secret data",
    )?;
    journal.create(
        operation,
        Artifact::Preferences,
        b"private preferences data",
    )?;

    let local = tempfile::tempdir()?;
    let destination = local.path().canonicalize()?.join("audit.jsonl");
    let engine = Engine::new(Fake::default(), journal);
    let report = engine.export_audit(&destination, &Cancellation::default())?;
    assert_eq!(report.written, 6);
    assert_eq!(report.warnings.len(), 2);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&destination)?.permissions().mode() & 0o777,
            0o600
        );
    }
    let raw = std::fs::read_to_string(destination)?;
    assert!(!raw.contains("secret"));
    assert!(!raw.contains("private preferences"));
    let rows = raw
        .lines()
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<serde_json::Result<Vec<_>>>()?;
    assert_eq!(
        rows.iter()
            .filter_map(|row| row["result"].as_str())
            .collect::<Vec<_>>(),
        [
            "staged",
            "details_omitted",
            "applied",
            "starting",
            "restored",
            "purged"
        ]
    );
    assert_eq!(rows[2]["record_kind"], "applied");
    assert_eq!(rows[2]["backup"], "backup/cache");
    assert_eq!(rows[4]["record_kind"], "restored");
    assert_eq!(rows[5]["record_kind"], "purged");
    Ok(())
}

#[test]
fn audit_export_preserves_existing_files_and_honors_cancellation() -> Result<()> {
    let engine = Engine::new(Fake::default(), MemoryJournal::default());
    let local = tempfile::tempdir()?;
    let directory = local.path().canonicalize()?;
    let existing = directory.join("existing.jsonl");
    std::fs::write(&existing, "preserve this")?;
    let result = engine.export_audit(&existing, &Cancellation::default());
    assert!(
        matches!(result, Err(Error::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists)
    );
    assert_eq!(std::fs::read_to_string(existing)?, "preserve this");

    let cancel = Cancellation::default();
    cancel.cancel();
    let destination = directory.join("cancelled.jsonl");
    assert!(matches!(
        engine.export_audit(&destination, &cancel),
        Err(Error::Cancelled)
    ));
    assert!(!destination.exists());
    Ok(())
}

#[test]
fn audit_export_respects_a_native_destination_rejection() -> Result<()> {
    let journal = MemoryJournal::default();
    journal.0.borrow_mut().block_export = true;
    let engine = Engine::new(Fake::default(), journal);
    let local = tempfile::tempdir()?;
    let destination = local.path().canonicalize()?.join("audit.jsonl");
    assert!(matches!(
        engine.export_audit(&destination, &Cancellation::default()),
        Err(Error::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied
    ));
    assert_eq!(std::fs::read_dir(local.path())?.count(), 0);
    Ok(())
}

#[cfg(unix)]
#[test]
fn audit_export_rejects_a_linked_destination_directory() -> Result<()> {
    let engine = Engine::new(Fake::default(), MemoryJournal::default());
    let local = tempfile::tempdir()?;
    let directory = local.path().canonicalize()?;
    let actual = directory.join("actual");
    let alias = directory.join("alias");
    std::fs::create_dir(&actual)?;
    std::os::unix::fs::symlink(&actual, &alias)?;
    assert!(matches!(
        engine.export_audit(&alias.join("audit.jsonl"), &Cancellation::default()),
        Err(Error::Rejected(_))
    ));
    assert!(!actual.join("audit.jsonl").exists());
    Ok(())
}

impl FileStore for Fake {
    fn inspect_file(&self, path: &Path) -> io::Result<Inspection> {
        let state = self.0.borrow();
        let file = state.files.get(path).ok_or(io::ErrorKind::NotFound)?;
        Ok(Inspection {
            fingerprint: file.stamp.clone(),
            access: file.access.clone(),
        })
    }

    fn file_backup_path(&self, original: &Path, expected: &str, slot: Uuid) -> io::Result<PathBuf> {
        if self.inspect_file(original)?.fingerprint != expected {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(path(&format!("quarantine/{slot}")))
    }

    fn quarantine_file(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<()> {
        let mut state = self.0.borrow_mut();
        let file = state.files.get(path).ok_or(io::ErrorKind::NotFound)?;
        if file.stamp != expected || file.access != Access::Allowed {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if path.file_name().is_some_and(|name| name == "locked.dll") {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if state.rollback_sync_failure.as_deref() == Some(path) {
            return Err(io::Error::other(Error::FileChangeNeedsReview(
                "fixture reverse rename completed but directory sync failed".into(),
            )));
        }
        let file = state.files.remove(path).ok_or(io::ErrorKind::NotFound)?;
        state.quarantine.insert(slot, (path.to_path_buf(), file));
        if path
            .file_name()
            .is_some_and(|name| name == "sync-error.dll")
        {
            return Err(io::Error::other(
                "fixture moved before directory sync failed",
            ));
        }
        Ok(())
    }

    fn file_is_quarantined(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<bool> {
        let state = self.0.borrow();
        if state.quarantine_read_failures.contains(&slot) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(state
            .quarantine
            .get(&slot)
            .is_some_and(|(original, file)| original == path && file.stamp == expected))
    }

    fn restore_file(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<()> {
        if !self.file_is_quarantined(path, expected, slot)? {
            return Err(io::ErrorKind::NotFound.into());
        }
        let mut state = self.0.borrow_mut();
        if state.files.contains_key(path) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        if state.rollback_sync_failure.as_deref() == Some(path) {
            return Err(io::Error::other(Error::FileChangeNeedsReview(
                "fixture reverse rename completed but directory sync failed".into(),
            )));
        }
        let (_, file) = state
            .quarantine
            .remove(&slot)
            .ok_or(io::ErrorKind::NotFound)?;
        state.files.insert(path.to_path_buf(), file);
        Ok(())
    }

    fn can_purge_quarantined(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<bool> {
        let present = self.file_is_quarantined(path, expected, slot)?;
        Ok(present && !self.0.borrow().purge_ineligible.contains(path))
    }

    fn purge_quarantined(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<()> {
        if !self.can_purge_quarantined(path, expected, slot)? {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let mut state = self.0.borrow_mut();
        state.quarantine.remove(&slot);
        if state.purge_failure_after_removal {
            return Err(io::Error::other(
                "fixture removed before directory sync failed",
            ));
        }
        Ok(())
    }
}

impl RegistryStore for Fake {
    fn inspect_registry(&self, target: &RegistryTarget) -> io::Result<Inspection> {
        let state = self.0.borrow();
        let value = state.registry.get(target).ok_or(io::ErrorKind::NotFound)?;
        Ok(Inspection {
            fingerprint: value.clone(),
            access: Access::Allowed,
        })
    }

    fn remove_registry(
        &self,
        target: &RegistryTarget,
        expected: &str,
        write: &mut RegistryBackupWriter<'_>,
    ) -> io::Result<()> {
        let mut state = self.0.borrow_mut();
        let value = state.registry.get(target).ok_or(io::ErrorKind::NotFound)?;
        if value != expected {
            return Err(io::ErrorKind::InvalidData.into());
        }
        write(b"fake .reg", value.as_bytes())?;
        state.registry.remove(target);
        Ok(())
    }

    fn restore_registry(&self, target: &RegistryTarget, snapshot: &[u8]) -> io::Result<()> {
        let mut state = self.0.borrow_mut();
        if state.registry.contains_key(target) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        let value = String::from_utf8(snapshot.to_vec()).map_err(io::Error::other)?;
        state.registry.insert(target.clone(), value);
        Ok(())
    }

    fn remove_registry_with_receipt(
        &self,
        target: &RegistryTarget,
        expected: &str,
        operation_id: Uuid,
        write: &mut RegistryBackupWriter<'_>,
    ) -> io::Result<()> {
        let mut written_snapshot = Vec::new();
        self.remove_registry(target, expected, &mut |export, snapshot| {
            write(export, snapshot)?;
            written_snapshot.extend_from_slice(snapshot);
            Ok(())
        })?;
        if let Some(receipts) = &mut self.0.borrow_mut().registry_receipts {
            receipts.insert(
                operation_id,
                MockRegistryReceipt {
                    target: target.clone(),
                    snapshot: written_snapshot,
                    state: RegistryChangeReceipt::Applied,
                },
            );
        }
        Ok(())
    }

    fn restore_registry_with_receipt(
        &self,
        target: &RegistryTarget,
        snapshot: &[u8],
        operation_id: Uuid,
    ) -> io::Result<()> {
        self.restore_registry(target, snapshot)?;
        if let Some(receipts) = &mut self.0.borrow_mut().registry_receipts {
            receipts.insert(
                operation_id,
                MockRegistryReceipt {
                    target: target.clone(),
                    snapshot: snapshot.to_vec(),
                    state: RegistryChangeReceipt::Restored,
                },
            );
        }
        Ok(())
    }

    fn registry_change_receipt(
        &self,
        target: &RegistryTarget,
        snapshot: &[u8],
        operation_id: Uuid,
    ) -> io::Result<Option<RegistryChangeReceipt>> {
        let state = self.0.borrow();
        let receipt = state
            .registry_receipts
            .as_ref()
            .and_then(|receipts| receipts.get(&operation_id));
        match receipt {
            Some(receipt)
                if &receipt.target == target && receipt.snapshot.as_slice() == snapshot =>
            {
                Ok(Some(receipt.state))
            }
            Some(_) => Err(io::ErrorKind::InvalidData.into()),
            None => Ok(None),
        }
    }
}

impl PlatformBackend for Fake {
    type Official = AppId;

    fn inventory(&self, cancel: &Cancellation) -> Result<Inventory> {
        cancel.check()?;
        Ok(Inventory {
            applications: self.0.borrow().applications.clone(),
            warnings: Vec::new(),
        })
    }

    fn scan(&self, _app: &AppRecord, _mode: ScanMode, cancel: &Cancellation) -> Result<Scan> {
        self.scan_portable(&path("apps"), cancel)
    }

    fn scan_portable(&self, _directory: &Path, cancel: &Cancellation) -> Result<Scan> {
        cancel.check()?;
        let mut state = self.0.borrow_mut();
        state.scan_count += 1;
        if std::mem::take(&mut state.cancel_during_scan) {
            cancel.cancel();
            cancel.check()?;
        }
        if let Some(error) = state.next_scan_error.take() {
            return Err(error.into());
        }
        let mut proposals: Vec<_> = state
            .files
            .iter()
            .map(|(path, file)| Proposal {
                target: Target::File(path.clone()),
                category: Category::File,
                evidence: MatchKind::ExactIdentity,
                reason: file.reason.into(),
                risk: Risk::Normal,
                access: Access::Allowed,
            })
            .collect();
        proposals.extend(state.registry.keys().map(|key| Proposal {
            target: Target::Registry(key.clone()),
            category: Category::Registry,
            evidence: MatchKind::PublisherAndApp,
            reason: "matched test registry item".into(),
            risk: Risk::Normal,
            access: Access::Allowed,
        }));
        proposals.extend(state.shared_files.iter().map(|path| Proposal {
            target: Target::File(path.clone()),
            category: Category::File,
            evidence: MatchKind::AppName,
            reason: "a second application can own this path".into(),
            risk: Risk::Normal,
            access: Access::ReadOnly("shared file".into()),
        }));
        proposals.sort_by_key(|proposal| proposal.target.display());
        Ok(Scan::new(proposals, Vec::new()))
    }

    fn rule_root(&self, root: RuleRoot) -> Option<PathBuf> {
        (root == RuleRoot::MacosCaches).then(|| path("rule-fixture"))
    }

    fn probe_rule_target(&self, path: &Path) -> io::Result<Option<RuleTarget>> {
        Ok(self
            .0
            .borrow()
            .rule_targets
            .iter()
            .any(|target| target == path)
            .then(|| RuleTarget {
                path: path.to_path_buf(),
                category: Category::File,
            }))
    }

    fn prepare_official(&self, app: &AppRecord) -> Result<(OfficialIntent, Self::Official)> {
        let intent = OfficialIntent {
            application: app.name.clone(),
            method: "fake".into(),
            quiet: true,
            notice: String::new(),
        };
        Ok((intent, app.id.clone()))
    }

    fn prepare_application_uninstall(
        &self,
        app: &AppRecord,
        _retention_days: NonZeroU16,
        cancel: &Cancellation,
    ) -> Result<(OfficialIntent, ApplicationUninstall<Self::Official>)> {
        cancel.check()?;
        let (intent, command) = self.prepare_official(app)?;
        if self.0.borrow().bundle_uninstall.as_ref() != Some(&app.id) {
            return Ok((intent, ApplicationUninstall::Official(command)));
        }
        let path = app
            .install_location
            .as_deref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        Ok((
            intent,
            ApplicationUninstall::QuarantineBundle {
                fingerprint: self.inspect_file(path)?.fingerprint,
                observed_files: HashMap::new(),
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
        quarantine()?;
        self.0
            .borrow_mut()
            .applications
            .retain(|item| item.id != app.id);
        Ok(OfficialExecution {
            outcome: OfficialOutcome::Completed,
            warnings: Vec::new(),
            read_only_residuals: Vec::new(),
            observed_files,
            post_uninstall_check: None,
        })
    }

    fn run_official(&self, command: Self::Official) -> Result<OfficialOutcome> {
        let mut state = self.0.borrow_mut();
        state.launches.push(command.clone());
        if let Some(reason) = state.official_error {
            return Err(Error::Rejected(reason.into()));
        }
        if command == application("fails").id {
            return Ok(OfficialOutcome::Failed(1));
        }
        state.applications.retain(|app| app.id != command);
        if command == application("unverified").id {
            return Ok(OfficialOutcome::Unverified(0));
        }
        if let Some(cancel) = &state.cancel_on_official_completion {
            cancel.cancel();
        }
        Ok(OfficialOutcome::Completed)
    }

    fn run_official_with_cancel(
        &self,
        command: Self::Official,
        cancel: &Cancellation,
    ) -> Result<OfficialExecution> {
        cancel.check()?;
        let outcome = self.run_official(command)?;
        let state = self.0.borrow();
        let observed_files = state
            .cleanup_observations
            .as_ref()
            .map(|observations| observations.files.clone())
            .unwrap_or_default();
        Ok(OfficialExecution {
            outcome,
            warnings: Vec::new(),
            read_only_residuals: Vec::new(),
            observed_files,
            post_uninstall_check: None,
        })
    }

    fn verify_finished_official_after_cancel(&self) -> bool {
        self.0.borrow().cancel_on_official_completion.is_some()
    }

    fn official_uninstall_absent(&self, id: &AppId, cancel: &Cancellation) -> Result<bool> {
        let inventory = self.inventory(cancel)?;
        self.0.borrow_mut().official_absence_checks.push(id.clone());
        Ok(
            inventory.warnings.is_empty()
                && !inventory.applications.iter().any(|app| &app.id == id),
        )
    }

    fn check_cleanup_after_uninstall(&self, _app: &AppRecord, cancel: &Cancellation) -> Result<()> {
        cancel.check()?;
        let mut state = self.0.borrow_mut();
        let Some(remaining) = &mut state.cleanup_checks_before_rejection else {
            return Ok(());
        };
        if *remaining == 0 {
            return Err(Error::Rejected(CLEANUP_INELIGIBLE.into()));
        }
        *remaining -= 1;
        Ok(())
    }

    fn check_cleanup_observations(
        &self,
        _app: &AppRecord,
        observed_files: &HashMap<PathBuf, String>,
        cancel: &Cancellation,
    ) -> Result<()> {
        cancel.check()?;
        let mut state = self.0.borrow_mut();
        let Some(mock) = &mut state.cleanup_observations else {
            return Ok(());
        };
        assert_eq!(observed_files, &mock.files);
        mock.checks += 1;
        if mock.checks > mock.checks_before_rejection {
            return Err(Error::Rejected(CLEANUP_OBSERVATION_CHANGED.into()));
        }
        Ok(())
    }
}

fn path(relative: &str) -> PathBuf {
    #[cfg(windows)]
    let root = Path::new(r"C:\");
    #[cfg(unix)]
    let root = Path::new("/");
    root.join(relative)
}

fn application(id: &str) -> AppRecord {
    AppRecord {
        id: AppId::Package {
            manager: "fixture".into(),
            id: id.into(),
        },
        name: id.into(),
        version: None,
        publisher: None,
        install_location: None,
        size_bytes: None,
        install_date: None,
        system_component: false,
        official_uninstall_available: true,
    }
}

fn file(stamp: &str) -> MockFile {
    MockFile {
        stamp: stamp.into(),
        access: Access::Allowed,
        reason: "exact test file",
    }
}

fn registry_target() -> RegistryTarget {
    RegistryTarget {
        hive: RegistryHive::CurrentUser,
        view: RegistryView::Native,
        key: r"Software\Studio Eight\Example Tool".into(),
        value: Some("TestSetting".into()),
    }
}

#[test]
fn inspect_residuals_cannot_confirm_otherwise_writable_candidates() -> Result<()> {
    let fake = Fake::default();
    let app = application("Example Editor");
    let residual = path("apps/Editor/config");
    {
        let mut state = fake.0.borrow_mut();
        state.applications.push(app.clone());
        state.files.insert(residual.clone(), file("original"));
    }
    let engine = Engine::new(fake.clone(), MemoryJournal::default());
    let cancel = Cancellation::default();
    let plan = engine.inspect_residuals(&app.id, &cancel)?;
    let candidate_id = {
        let mut candidates = plan.candidates();
        let candidate = candidates.next().expect("residual candidate");
        assert!(candidates.next().is_none());
        assert_eq!(candidate.target, Target::File(residual.clone()));
        assert!(matches!(candidate.access, Access::ReadOnly(_)));
        assert!(!candidate.default_selected());
        candidate.id
    };
    assert!(matches!(
        plan.confirm(&[candidate_id]),
        Err(Error::Rejected(_))
    ));
    let state = fake.0.borrow();
    assert!(state.files.contains_key(&residual));
    assert!(state.quarantine.is_empty());
    Ok(())
}

#[test]
fn bundle_uninstall_and_residuals_share_one_batch_and_restore_the_bundle_first() -> Result<()> {
    let fake = Fake::default();
    let bundle = path("z-apps/Editor.app");
    let residual = path("a-cache/Editor-settings");
    let app = AppRecord {
        install_location: Some(bundle.clone()),
        ..application("Example Editor")
    };
    {
        let mut state = fake.0.borrow_mut();
        state.bundle_uninstall = Some(app.id.clone());
        state.applications.push(app.clone());
        state.files.insert(bundle.clone(), file("bundle"));
        state.files.insert(residual.clone(), file("settings"));
    }
    let engine = Engine::new(fake.clone(), MemoryJournal::default());
    let cancel = Cancellation::default();
    let confirmed = engine.prepare_uninstall(&app.id, &cancel)?.confirm()?;
    let report = engine.run_uninstall(confirmed, &cancel)?;
    assert_eq!(report.outcome, OfficialOutcome::Completed);
    let batch = report
        .application_backup_batch
        .expect("bundle backup batch");
    assert!(!fake.0.borrow().files.contains_key(&bundle));
    assert!(fake.0.borrow().files.contains_key(&residual));

    let plan = report.cleanup.expect("post-uninstall residual preview");
    let selected: Vec<_> = plan.candidates().map(|candidate| candidate.id).collect();
    assert_eq!(selected.len(), 1);
    let cleanup = engine.apply(plan.confirm(&selected)?, &cancel)?;
    assert_eq!(cleanup.batch_id, batch);
    assert!(matches!(
        cleanup.items.as_slice(),
        [item] if matches!(item.result, ChangeResult::Applied)
    ));

    let restore = engine.prepare_restore(batch)?;
    let restored = engine.restore(restore.confirm()?, &cancel)?;
    let [application, settings] = restored.items.as_slice() else {
        panic!("expected both objects in the shared restore batch");
    };
    assert_eq!(application.target, Target::File(bundle.clone()).display());
    assert_eq!(settings.target, Target::File(residual.clone()).display());
    assert!(matches!(application.result, ChangeResult::Restored));
    assert!(matches!(settings.result, ChangeResult::Restored));
    let state = fake.0.borrow();
    assert!(state.files.contains_key(&bundle));
    assert!(state.files.contains_key(&residual));
    assert!(state.quarantine.is_empty());
    Ok(())
}

#[test]
fn apply_rejects_fresh_shared_owners_even_if_the_object_fingerprint_is_unchanged() -> Result<()> {
    let fake = Fake::default();
    let app = application("Example Editor");
    let shared = path("apps/Editor/shared");
    let exclusive = path("apps/Editor/exclusive");
    {
        let mut state = fake.0.borrow_mut();
        state.applications.push(app.clone());
        state.files.insert(shared.clone(), file("unchanged"));
        state.files.insert(exclusive, file("exclusive"));
    }
    let engine = Engine::new(fake.clone(), MemoryJournal::default());
    let cancel = Cancellation::default();
    let preview = engine.scan(&app.id, &cancel)?;
    let selected: Vec<_> = preview
        .candidates()
        .filter(|candidate| candidate.default_selected())
        .map(|candidate| candidate.id)
        .collect();
    assert_eq!(selected.len(), 2);
    let confirmed = preview.confirm(&selected)?;
    fake.0.borrow_mut().shared_files.insert(shared.clone());
    let report = engine.apply(confirmed, &cancel)?;
    assert!(report.items.iter().any(|item| matches!(
        &item.result, ChangeResult::Skipped(reason) if reason.contains("ownership")
    )));
    assert!(
        report
            .items
            .iter()
            .any(|item| matches!(item.result, ChangeResult::Applied))
    );
    let state = fake.0.borrow();
    assert!(state.files.contains_key(&shared));
    assert_eq!(state.quarantine.len(), 1);
    Ok(())
}

#[test]
fn custom_rules_preserve_native_candidates_and_never_authorize_rule_only_items() -> Result<()> {
    let fake = Fake::default();
    let mut app = application("Example Editor");
    app.id = AppId::Package {
        manager: "macos-bundle".into(),
        id: "org.example.Editor:fixture".into(),
    };
    let native = path("rule-fixture/Editor/native");
    let hinted = path("rule-fixture/Editor/hinted");
    {
        let mut state = fake.0.borrow_mut();
        state.applications.push(app.clone());
        state.files.insert(native.clone(), file("native"));
        state.rule_targets.extend([native.clone(), hinted.clone()]);
    }
    let mut engine = Engine::new(fake.clone(), MemoryJournal::default());
    let rules = r#"
version = 1
[[rules]]
id = "existing-editor-path"
scope = "macos"
app_match = { kind = "macos_bundle", id = "org.example.Editor" }
root_id = "macos_caches"
relative_path = "Editor/native"
evidence = "Independently discovered file"

[[rules]]
id = "other-editor-path"
scope = "macos"
app_match = { kind = "macos_bundle", id = "org.example.Editor" }
root_id = "macos_caches"
relative_path = "Editor/hinted"
evidence = "Additional possible file"
"#;
    assert_eq!(engine.load_custom_rules(rules.as_bytes())?, 2);
    assert!(
        engine
            .load_custom_rules(b"invalid rules".as_slice())
            .is_err()
    );
    let cancel = Cancellation::default();
    let plan = engine.scan(&app.id, &cancel)?;
    let entries: Vec<_> = plan.candidates().collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].target, Target::File(native));
    assert!(entries[0].default_selected());
    assert_eq!(entries[1].target, Target::File(hinted));
    assert_eq!(entries[1].evidence, MatchKind::RuleHint);
    assert_eq!(entries[1].confidence, Confidence::Low);
    assert!(!entries[1].default_selected());
    assert!(plan.confirm(&[1]).is_err());
    assert!(fake.0.borrow().quarantine.is_empty());

    engine.clear_custom_rules();
    assert_eq!(engine.scan(&app.id, &cancel)?.candidates().count(), 1);
    Ok(())
}

#[test]
fn dry_run_checks_permissions_and_leaves_files_and_registry_unchanged() -> Result<()> {
    let fake = Fake::default();
    let original = path("apps/tool.dll");
    let link_target = path("apps/link/target.dll");
    let shared = path("apps/shared/cache");
    let setting = registry_target();
    {
        let mut state = fake.0.borrow_mut();
        state.files.insert(original.clone(), file("same"));
        state.files.insert(
            link_target.clone(),
            MockFile {
                access: Access::ReadOnly("middle symlink".into()),
                ..file("link")
            },
        );
        state.files.insert(
            shared.clone(),
            MockFile {
                access: Access::ReadOnly("other application owns the directory".into()),
                ..file("shared")
            },
        );
        state.registry.insert(setting.clone(), "old data".into());
    }
    let journal = MemoryJournal::default();
    let engine = Engine::new(fake.clone(), journal.clone());
    let cancel = Cancellation::default();
    let plan = engine.scan_portable(&path("apps"), &cancel)?;
    assert_eq!(
        plan.candidates()
            .filter(|candidate| candidate.default_selected())
            .count(),
        1
    );
    assert!(
        plan.candidates()
            .filter(|candidate| candidate.access != Access::Allowed)
            .count()
            == 2
    );
    assert!(fake.0.borrow().quarantine.is_empty());
    assert!(fake.0.borrow().launches.is_empty());
    assert!(fake.0.borrow().files.contains_key(&original));
    assert_eq!(
        fake.0.borrow().registry.get(&setting).map(String::as_str),
        Some("old data")
    );
    assert!(journal.manifests()?.is_empty());
    assert!(
        journal
            .0
            .borrow()
            .records
            .keys()
            .all(|name| name.ends_with(".event.json"))
    );
    Ok(())
}

#[test]
fn cancelling_cleanup_preflight_preserves_the_full_preview_for_a_new_selection() -> Result<()> {
    for during_scan in [true, false] {
        let fake = Fake::default();
        let first = path("apps/a-first.dll");
        let second = path("apps/z-second.dll");
        fake.0.borrow_mut().files.extend([
            (first.clone(), file("first")),
            (second.clone(), file("second")),
        ]);
        let journal = MemoryJournal::default();
        let engine = Engine::new(fake.clone(), journal.clone());
        let cancel = Cancellation::default();
        let plan = engine.scan_portable(&path("apps"), &cancel)?;
        let id = plan.id();
        let mode = plan.mode();
        if during_scan {
            fake.0.borrow_mut().cancel_during_scan = true;
        } else {
            journal.0.borrow_mut().cancel_after_create = Some((Artifact::Event, cancel.clone()));
        }

        let CleanupAttempt::RetryableBeforeApply {
            plan,
            error: Error::Cancelled,
        } = engine.apply_cleanup_preview(plan, &[0], &cancel)?
        else {
            panic!("preflight cancellation must return the original preview");
        };
        assert_eq!(plan.id(), id);
        assert_eq!(plan.mode(), mode);
        assert_eq!(plan.candidates().count(), 2);
        assert_eq!(fake.0.borrow().scan_count, 2);
        assert!(fake.0.borrow().quarantine.is_empty());
        assert!(journal.manifests()?.is_empty());

        journal.0.borrow_mut().cancel_after_create = None;
        let retry = Cancellation::default();
        let CleanupAttempt::Reported(report) = engine.apply_cleanup_preview(*plan, &[1], &retry)?
        else {
            panic!("a fresh confirmation must apply the changed selection");
        };
        assert_eq!(report.batch_id, id);
        assert_eq!(report.items.len(), 1);
        assert!(matches!(report.items[0].result, ChangeResult::Applied));
        let state = fake.0.borrow();
        assert!(state.files.contains_key(&first));
        assert!(!state.files.contains_key(&second));
    }
    Ok(())
}

#[test]
fn cancelled_cleanup_does_not_return_a_preview_when_recheck_audit_fails() -> Result<()> {
    let fake = Fake::default();
    let original = path("apps/tool.dll");
    fake.0
        .borrow_mut()
        .files
        .insert(original.clone(), file("before"));
    let journal = MemoryJournal::default();
    let engine = Engine::new(fake.clone(), journal.clone());
    let cancel = Cancellation::default();
    let plan = engine.scan_portable(&path("apps"), &cancel)?;
    fake.0.borrow_mut().cancel_during_scan = true;
    journal.0.borrow_mut().fail = Some(Artifact::Event);

    assert!(matches!(
        engine.apply_cleanup_preview(plan, &[0], &cancel),
        Err(Error::Io(error)) if error.to_string() == AUDIT_WRITE_FAILURE
    ));
    assert!(matches!(cancel.check(), Err(Error::Cancelled)));
    assert!(fake.0.borrow().files.contains_key(&original));
    assert!(journal.manifests()?.is_empty());
    Ok(())
}

#[test]
fn cancellation_after_a_cleanup_change_returns_the_applied_and_skipped_rows() -> Result<()> {
    let fake = Fake::default();
    let first = path("apps/a-first.dll");
    let second = path("apps/z-second.dll");
    fake.0.borrow_mut().files.extend([
        (first.clone(), file("first")),
        (second.clone(), file("second")),
    ]);
    let journal = MemoryJournal::default();
    let engine = Engine::new(fake.clone(), journal.clone());
    let cancel = Cancellation::default();
    let plan = engine.scan_portable(&path("apps"), &cancel)?;
    journal.0.borrow_mut().cancel_after_create = Some((Artifact::Applied, cancel.clone()));

    let CleanupAttempt::Reported(report) = engine.apply_cleanup_preview(plan, &[0, 1], &cancel)?
    else {
        panic!("an already started batch must return its outcomes");
    };
    assert_eq!(report.items.len(), 2);
    assert!(matches!(report.items[0].result, ChangeResult::Applied));
    assert!(matches!(report.items[1].result, ChangeResult::Skipped(_)));
    let state = fake.0.borrow();
    assert!(!state.files.contains_key(&first));
    assert!(state.files.contains_key(&second));
    assert_eq!(journal.manifests()?.len(), 1);
    Ok(())
}

#[test]
fn invalid_selection_and_failed_recheck_preserve_the_preview_for_a_fresh_recheck() -> Result<()> {
    const SCAN_FAILURE: &str = "intentional cleanup recheck failure";
    let fake = Fake::default();
    let original = path("apps/tool.dll");
    fake.0
        .borrow_mut()
        .files
        .insert(original.clone(), file("before"));
    let journal = MemoryJournal::default();
    let engine = Engine::new(fake.clone(), journal.clone());
    let cancel = Cancellation::default();
    let plan = engine.scan_portable(&path("apps"), &cancel)?;
    let id = plan.id();

    let CleanupAttempt::RetryableBeforeApply {
        plan,
        error: Error::Rejected(reason),
    } = engine.apply_cleanup_preview(plan, &[1], &cancel)?
    else {
        panic!("an invalid selection must retain the preview");
    };
    assert!(reason.contains("not eligible for cleanup"));
    assert_eq!(plan.id(), id);
    assert_eq!(fake.0.borrow().scan_count, 1);

    fake.0.borrow_mut().next_scan_error = Some(io::Error::other(SCAN_FAILURE));
    let CleanupAttempt::RetryableBeforeApply {
        plan,
        error: Error::Io(error),
    } = engine.apply_cleanup_preview(*plan, &[0], &cancel)?
    else {
        panic!("an audited recheck I/O failure must retain the preview");
    };
    assert_eq!(error.to_string(), SCAN_FAILURE);
    assert_eq!(plan.id(), id);
    assert_eq!(fake.0.borrow().scan_count, 2);
    assert!(journal.manifests()?.is_empty());
    let events = journal
        .list(Artifact::Event)?
        .into_iter()
        .map(|id| crate::state::read_json::<AuditEvent>(&journal, id, Artifact::Event))
        .collect::<Result<Vec<_>>>()?;
    assert!(
        events
            .into_iter()
            .flatten()
            .any(|event| { event.action == "recheck_cleanup" && event.result == "failed" })
    );

    fake.0.borrow_mut().shared_files.insert(original.clone());
    let CleanupAttempt::Reported(report) = engine.apply_cleanup_preview(*plan, &[0], &cancel)?
    else {
        panic!("the new attempt must report the changed attribution");
    };
    assert_eq!(report.batch_id, id);
    assert_eq!(report.items.len(), 1);
    assert!(matches!(report.items[0].result, ChangeResult::Skipped(_)));
    let state = fake.0.borrow();
    assert_eq!(state.scan_count, 3);
    assert!(state.files.contains_key(&original));
    assert!(state.quarantine.is_empty());
    assert!(journal.manifests()?.is_empty());
    Ok(())
}

#[test]
fn target_replacement_is_rejected_after_confirmation() -> Result<()> {
    let fake = Fake::default();
    let target = path("apps/tool.dll");
    fake.0
        .borrow_mut()
        .files
        .insert(target.clone(), file("first"));
    let engine = Engine::new(fake.clone(), MemoryJournal::default());
    let cancel = Cancellation::default();
    let confirmed = engine
        .scan_portable(&path("apps"), &cancel)?
        .confirm(&[0])?;
    fake.0
        .borrow_mut()
        .files
        .insert(target.clone(), file("different"));
    let report = engine.apply(confirmed, &cancel)?;
    assert!(matches!(report.items[0].result, ChangeResult::Skipped(_)));
    assert!(fake.0.borrow().quarantine.is_empty());
    assert_eq!(fake.0.borrow().files[&target].stamp, "different");
    Ok(())
}

#[test]
fn registry_backup_failure_leaves_the_original_value_and_others_continue() -> Result<()> {
    let fake = Fake::default();
    let target = registry_target();
    fake.0
        .borrow_mut()
        .registry
        .insert(target.clone(), "old data".into());
    fake.0
        .borrow_mut()
        .files
        .insert(path("apps/tool.dll"), file("stamp"));
    let journal = MemoryJournal::default();
    let engine = Engine::new(fake.clone(), journal.clone());
    let cancel = Cancellation::default();
    let plan = engine.scan_portable(&path("apps"), &cancel)?;
    journal.0.borrow_mut().fail = Some(Artifact::RegistryExport);
    let report = engine.apply(plan.confirm(&[0, 1])?, &cancel)?;
    assert_eq!(
        report
            .items
            .iter()
            .filter(|item| matches!(item.result, ChangeResult::Applied))
            .count(),
        1
    );
    assert_eq!(fake.0.borrow().registry[&target], "old data");
    assert_eq!(fake.0.borrow().quarantine.len(), 1);
    Ok(())
}

#[test]
fn app_paths_default_is_cleaned_before_its_executable_and_restored_after_it() -> Result<()> {
    let fake = Fake::default();
    let app = application("Scope Sample");
    let executable = path("apps/Scope Sample.exe");
    let app_path = RegistryTarget {
        hive: RegistryHive::CurrentUser,
        view: RegistryView::Native,
        key: r"Software\Microsoft\Windows\CurrentVersion\App Paths\Scope Sample.exe".into(),
        value: Some(String::new()),
    };
    {
        let mut state = fake.0.borrow_mut();
        state.applications.push(app.clone());
        state.files.insert(executable.clone(), file("image"));
        state
            .registry
            .insert(app_path.clone(), executable.display().to_string());
    }
    let engine = Engine::new(fake, MemoryJournal::default());
    let cancel = Cancellation::default();
    let plan = engine.scan(&app.id, &cancel)?;
    let file_target = Target::File(executable);
    let registry_target = Target::Registry(app_path);
    assert_eq!(
        plan.candidates().next().map(|candidate| &candidate.target),
        Some(&file_target)
    );
    let selection: Vec<_> = plan.candidates().map(|candidate| candidate.id).collect();
    let report = engine.apply(plan.confirm(&selection)?, &cancel)?;
    let file_display = file_target.display();
    let registry_display = registry_target.display();
    let [registry, file] = report.items.as_slice() else {
        panic!("expected App Paths and file cleanup results");
    };
    assert_eq!(registry.target, registry_display);
    assert_eq!(file.target, file_display);
    assert!(matches!(registry.result, ChangeResult::Applied));
    assert!(matches!(file.result, ChangeResult::Applied));

    let restore = engine.prepare_restore(report.batch_id)?;
    let report = engine.restore(restore.confirm()?, &cancel)?;
    let [file, registry] = report.items.as_slice() else {
        panic!("expected file and App Paths restoration results");
    };
    assert_eq!(file.target, file_display);
    assert_eq!(registry.target, registry_display);
    assert!(matches!(file.result, ChangeResult::Restored));
    assert!(matches!(registry.result, ChangeResult::Restored));
    Ok(())
}

#[test]
fn restore_keeps_conflicting_files_and_restores_the_exact_registry_value() -> Result<()> {
    let fake = Fake::default();
    let path = path("apps/tool.dll");
    let key = registry_target();
    fake.0
        .borrow_mut()
        .files
        .insert(path.clone(), file("before"));
    fake.0
        .borrow_mut()
        .registry
        .insert(key.clone(), "fixture value".into());
    let journal = MemoryJournal::default();
    let engine = Engine::new(fake.clone(), journal.clone());
    let cancel = Cancellation::default();
    let directory = path
        .parent()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let plan = engine.scan_portable(directory, &cancel)?;
    let report = engine.apply(plan.confirm(&[0, 1])?, &cancel)?;
    assert_eq!(
        report
            .items
            .iter()
            .filter(|item| matches!(item.result, ChangeResult::Applied))
            .count(),
        2
    );
    assert!(
        journal
            .0
            .borrow()
            .records
            .keys()
            .any(|name| name.ends_with(".reg"))
    );
    fake.0.borrow_mut().files.insert(path.clone(), file("new"));
    let report = engine.restore(engine.prepare_restore(report.batch_id)?.confirm()?, &cancel)?;
    assert_eq!(
        report
            .items
            .iter()
            .filter(|item| matches!(item.result, ChangeResult::Restored))
            .count(),
        1
    );
    assert_eq!(fake.0.borrow().files[&path].stamp, "new");
    assert_eq!(fake.0.borrow().registry[&key], "fixture value");
    assert_eq!(fake.0.borrow().quarantine.len(), 1);
    Ok(())
}

#[test]
fn registry_transaction_receipts_recover_without_writing_the_backup_list() -> Result<()> {
    let fake = Fake::default();
    let key = registry_target();
    {
        let mut state = fake.0.borrow_mut();
        state.registry.insert(key.clone(), "fixture value".into());
        state.registry_receipts = Some(HashMap::new());
    }
    let journal = MemoryJournal::default();
    let engine = Engine::new(fake.clone(), journal.clone());
    let cancel = Cancellation::default();
    journal.0.borrow_mut().fail = Some(Artifact::Applied);
    let cleanup = engine
        .scan_portable(&path("apps"), &cancel)?
        .confirm(&[0])?;
    let changed = engine.apply(cleanup, &cancel)?;
    assert!(matches!(
        changed.items[0].result,
        ChangeResult::NeedsReview(_)
    ));
    assert!(!fake.0.borrow().registry.contains_key(&key));

    let before_list = journal.0.borrow().records.clone();
    let inventory = engine.backups()?;
    assert!(inventory.warnings.is_empty());
    assert_eq!(inventory.items[0].state, RecoveryState::Applied);
    assert_eq!(journal.0.borrow().records, before_list);

    let restore = engine.prepare_restore(changed.batch_id)?.confirm()?;
    let stale_restore = engine.prepare_restore(changed.batch_id)?.confirm()?;
    journal.0.borrow_mut().fail = Some(Artifact::Restored);
    let restored = engine.restore(restore, &cancel)?;
    assert!(matches!(
        restored.items[0].result,
        ChangeResult::NeedsReview(_)
    ));
    assert_eq!(fake.0.borrow().registry[&key], "fixture value");

    // A later absence cannot turn the prior restore into a new authorization.
    fake.0.borrow_mut().registry.remove(&key);
    let before_list = journal.0.borrow().records.clone();
    let inventory = engine.backups()?;
    assert!(inventory.warnings.is_empty());
    assert_eq!(inventory.items[0].state, RecoveryState::Restored);
    assert_eq!(journal.0.borrow().records, before_list);
    let rejected = engine.restore(stale_restore, &cancel)?;
    assert!(matches!(rejected.items[0].result, ChangeResult::Skipped(_)));
    assert!(!fake.0.borrow().registry.contains_key(&key));
    Ok(())
}

#[test]
fn an_unverifiable_slot_keeps_its_manifest_visible_for_review() -> Result<()> {
    let fake = Fake::default();
    let original = path("apps/tool.dll");
    fake.0
        .borrow_mut()
        .files
        .insert(original.clone(), file("before"));
    let engine = Engine::new(fake.clone(), MemoryJournal::default());
    let cancel = Cancellation::default();
    let confirmed = engine
        .scan_portable(&path("apps"), &cancel)?
        .confirm(&[0])?;
    let report = engine.apply(confirmed, &cancel)?;
    let id = report.items[0]
        .backup_id
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    fake.0.borrow_mut().quarantine_read_failures.insert(id);

    let inventory = engine.backups()?;
    assert_eq!(inventory.items.len(), 1);
    assert_eq!(inventory.items[0].id, id);
    assert_eq!(inventory.items[0].batch_id, report.batch_id);
    assert_eq!(inventory.items[0].target, original.display().to_string());
    assert_eq!(inventory.items[0].state, RecoveryState::NeedsReview);
    assert_eq!(inventory.warnings.len(), 1);
    let restore = engine.prepare_restore(report.batch_id)?;
    assert_eq!(restore.entries().len(), 0);
    assert_eq!(restore.warnings().len(), 1);
    assert!(fake.0.borrow().quarantine.contains_key(&id));
    Ok(())
}

#[test]
fn a_file_moved_before_its_audit_receipt_can_be_recovered() -> Result<()> {
    let fake = Fake::default();
    let original = path("apps/tool.dll");
    fake.0
        .borrow_mut()
        .files
        .insert(original.clone(), file("before"));
    let journal = MemoryJournal::default();
    let engine = Engine::new(fake.clone(), journal.clone());
    let cancel = Cancellation::default();
    let confirmed = engine
        .scan_portable(&path("apps"), &cancel)?
        .confirm(&[0])?;
    journal.0.borrow_mut().fail = Some(Artifact::Applied);
    let report = engine.apply(confirmed, &cancel)?;
    assert!(matches!(
        report.items[0].result,
        ChangeResult::NeedsReview(_)
    ));
    let reopened = Engine::new(fake.clone(), journal.clone());
    journal.0.borrow_mut().fail = None;
    let restore = reopened.prepare_restore(report.batch_id)?;
    assert_eq!(restore.entries().len(), 1);
    reopened.restore(restore.confirm()?, &cancel)?;
    assert!(fake.0.borrow().files.contains_key(&original));
    assert!(fake.0.borrow().quarantine.is_empty());
    Ok(())
}

#[test]
fn rollback_sync_failure_stops_cleanup_and_restore_batches() -> Result<()> {
    for restoring in [false, true] {
        let first = path("apps/a-first.dll");
        let later = path("apps/z-later.dll");
        let fake = Fake::default();
        fake.0.borrow_mut().files.extend([
            (first.clone(), file("first")),
            (later.clone(), file("later")),
        ]);
        let journal = MemoryJournal::default();
        let engine = Engine::new(fake.clone(), journal.clone());
        let cancel = Cancellation::default();
        let cleanup = engine
            .scan_portable(&path("apps"), &cancel)?
            .confirm(&[0, 1])?;
        let report = if restoring {
            let applied = engine.apply(cleanup, &cancel)?;
            fake.0.borrow_mut().rollback_sync_failure = Some(first.clone());
            let restore = engine.prepare_restore(applied.batch_id)?.confirm()?;
            engine.restore(restore, &cancel)?
        } else {
            fake.0.borrow_mut().rollback_sync_failure = Some(first.clone());
            engine.apply(cleanup, &cancel)?
        };
        assert!(matches!(
            report.items[0].result,
            ChangeResult::NeedsReview(_)
        ));
        assert!(matches!(report.items[1].result, ChangeResult::Skipped(_)));
        let state = fake.0.borrow();
        if restoring {
            assert!(state.files.is_empty());
            assert_eq!(state.quarantine.len(), 2);
            assert!(journal.list(Artifact::Restored)?.is_empty());
        } else {
            assert!(state.files.contains_key(&first) && state.files.contains_key(&later));
            assert!(state.quarantine.is_empty());
            assert!(journal.list(Artifact::Applied)?.is_empty());
            let id = report.items[0]
                .backup_id
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
            let receipt = crate::state::read_json::<AuditEvent>(
                &journal,
                id,
                Artifact::QuarantineNeedsReview,
            )?
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
            assert_eq!(receipt.operation_id, Some(id));
            assert_eq!(receipt.result, "needs_review");
            let reopened = Engine::new(fake.clone(), journal.clone());
            assert_eq!(
                reopened.backups()?.items[0].state,
                RecoveryState::NeedsReview
            );
            assert_eq!(
                reopened.prepare_restore(report.batch_id)?.entries().len(),
                0
            );
            set_expiry(&journal, id, 1)?;
            assert_eq!(reopened.prepare_expiry_cleanup(&cancel)?.items().len(), 0);

            let directory = tempfile::tempdir()?;
            let output = directory.path().canonicalize()?.join("audit.jsonl");
            reopened.export_audit(&output, &cancel)?;
            let exported = std::fs::read_to_string(output)?;
            assert_eq!(
                exported
                    .lines()
                    .filter(|line| line.contains("\"result\":\"needs_review\""))
                    .count(),
                1
            );
            assert!(exported.contains("\"record_kind\":\"quarantine_needs_review\""));
        }
    }
    Ok(())
}

#[test]
fn quarantine_failure_after_a_move_is_reported_as_reviewable() -> Result<()> {
    let fake = Fake::default();
    let original = path("apps/sync-error.dll");
    fake.0
        .borrow_mut()
        .files
        .insert(original.clone(), file("before"));
    let journal = MemoryJournal::default();
    let engine = Engine::new(fake.clone(), journal);
    let cancel = Cancellation::default();
    let confirmed = engine
        .scan_portable(&path("apps"), &cancel)?
        .confirm(&[0])?;
    let report = engine.apply(confirmed, &cancel)?;
    assert!(matches!(
        report.items[0].result,
        ChangeResult::NeedsReview(_)
    ));
    assert!(!fake.0.borrow().files.contains_key(&original));
    let restore = engine.prepare_restore(report.batch_id)?;
    assert_eq!(restore.entries().len(), 1);
    assert_eq!(
        restore.entries().next().map(|entry| entry.state),
        Some(RecoveryState::Applied)
    );
    Ok(())
}

fn set_expiry(journal: &MemoryJournal, id: Uuid, timestamp: u64) -> Result<()> {
    use crate::state::BackupRecord;

    let mut record = BackupRecord::load(journal, id)?;
    record.expires_unix_ms = timestamp;
    journal.0.borrow_mut().records.insert(
        Artifact::Manifest.file_name(id),
        serde_json::to_vec(&record)?,
    );
    Ok(())
}

#[test]
fn expiry_review_excludes_unexpired_unsupported_and_registry_backups() -> Result<()> {
    let fake = Fake::default();
    for name in ["alpha.dll", "beta.dll", "fresh.dll", "app-directory"] {
        fake.0
            .borrow_mut()
            .files
            .insert(path(&format!("apps/{name}")), file(name));
    }
    fake.0
        .borrow_mut()
        .purge_ineligible
        .insert(path("apps/app-directory"));
    fake.0
        .borrow_mut()
        .registry
        .insert(registry_target(), "configuration".into());
    let journal = MemoryJournal::default();
    let engine = Engine::new(fake.clone(), journal.clone());
    let cancel = Cancellation::default();
    let plan = engine.scan_portable(&path("apps"), &cancel)?;
    let ids: Vec<_> = plan.candidates().map(|entry| entry.id).collect();
    let changes = engine.apply(plan.confirm(&ids)?, &cancel)?;
    let backups = engine.backups()?;
    for backup in backups.items {
        if !backup.target.ends_with("fresh.dll") {
            set_expiry(&journal, backup.id, 1)?;
        }
    }
    let review = engine.prepare_expiry_cleanup(&cancel)?;
    assert_eq!(review.items().len(), 2);
    assert!(review.warnings().is_empty());
    assert!(
        engine
            .prepare_expiry_cleanup(&cancel)?
            .confirm(&[])
            .is_err()
    );
    assert!(
        engine
            .prepare_expiry_cleanup(&cancel)?
            .confirm(&[Uuid::nil()])
            .is_err()
    );
    let selected = review
        .items()
        .find(|entry| entry.target.ends_with("alpha.dll"))
        .expect("alpha is eligible")
        .id;
    assert!(
        engine
            .prepare_expiry_cleanup(&cancel)?
            .confirm(&[selected, selected])
            .is_err()
    );
    assert_eq!(fake.0.borrow().quarantine.len(), 4);
    let report = engine.apply_expiry_cleanup(review.confirm(&[selected])?, &cancel)?;
    assert!(matches!(report.items[0].result, ChangeResult::Purged));
    assert_eq!(report.items[0].backup_id, Some(selected));
    assert!(journal.read(selected, Artifact::Purged)?.is_some());
    assert_eq!(fake.0.borrow().quarantine.len(), 3);
    let purged = engine
        .backups()?
        .items
        .into_iter()
        .find(|item| item.id == selected);
    assert_eq!(purged.map(|item| item.state), Some(RecoveryState::Purged));
    assert_eq!(engine.prepare_restore(changes.batch_id)?.entries().len(), 4);
    Ok(())
}

#[test]
fn expiry_cleanup_rejects_a_changed_manifest_or_slot() -> Result<()> {
    let fake = Fake::default();
    fake.0
        .borrow_mut()
        .files
        .insert(path("apps/alpha.dll"), file("before"));
    fake.0
        .borrow_mut()
        .files
        .insert(path("apps/beta.dll"), file("before"));
    let journal = MemoryJournal::default();
    let engine = Engine::new(fake.clone(), journal.clone());
    let cancel = Cancellation::default();
    let plan = engine.scan_portable(&path("apps"), &cancel)?;
    let changes = engine.apply(plan.confirm(&[0, 1])?, &cancel)?;
    let ids: Vec<_> = changes
        .items
        .iter()
        .map(|item| item.backup_id.expect("fixture backup"))
        .collect();
    for id in &ids {
        set_expiry(&journal, *id, 1)?;
    }
    let approved = engine.prepare_expiry_cleanup(&cancel)?.confirm(&ids)?;
    set_expiry(&journal, ids[0], u64::MAX)?;
    fake.0
        .borrow_mut()
        .quarantine
        .get_mut(&ids[1])
        .expect("fixture backup")
        .1
        .stamp = "different".into();
    let report = engine.apply_expiry_cleanup(approved, &cancel)?;
    assert!(
        report
            .items
            .iter()
            .all(|item| matches!(item.result, ChangeResult::Skipped(_)))
    );
    assert_eq!(fake.0.borrow().quarantine.len(), 2);
    assert!(journal.list(Artifact::Purged)?.is_empty());
    Ok(())
}

#[test]
fn removal_before_native_sync_failure_needs_review_without_a_purge_receipt() -> Result<()> {
    let fake = Fake::default();
    fake.0
        .borrow_mut()
        .files
        .insert(path("apps/alpha.dll"), file("before"));
    let journal = MemoryJournal::default();
    let engine = Engine::new(fake.clone(), journal.clone());
    let cancel = Cancellation::default();
    let plan = engine.scan_portable(&path("apps"), &cancel)?;
    let changes = engine.apply(plan.confirm(&[0])?, &cancel)?;
    let id = changes.items[0].backup_id.expect("fixture backup");
    set_expiry(&journal, id, 1)?;
    let approved = engine.prepare_expiry_cleanup(&cancel)?.confirm(&[id])?;
    fake.0.borrow_mut().purge_failure_after_removal = true;
    let outcome = engine.apply_expiry_cleanup_with_status(approved, &cancel)?;
    assert!(!outcome.can_continue);
    assert!(matches!(
        outcome.report.items[0].result,
        ChangeResult::NeedsReview(_)
    ));
    assert!(journal.list(Artifact::Purged)?.is_empty());
    assert_eq!(engine.backups()?.items[0].state, RecoveryState::NeedsReview);
    Ok(())
}

#[test]
fn expiry_start_audit_failure_stops_later_deletions() -> Result<()> {
    let fake = Fake::default();
    for name in ["alpha.dll", "beta.dll"] {
        fake.0
            .borrow_mut()
            .files
            .insert(path("apps").join(name), file("before"));
    }
    let journal = MemoryJournal::default();
    let engine = Engine::new(fake.clone(), journal.clone());
    let cancel = Cancellation::default();
    let plan = engine.scan_portable(&path("apps"), &cancel)?;
    let applied = engine.apply(plan.confirm(&[0, 1])?, &cancel)?;
    let ids: Vec<_> = applied
        .items
        .iter()
        .filter_map(|item| item.backup_id)
        .collect();
    assert_eq!(ids.len(), 2);
    for id in &ids {
        set_expiry(&journal, *id, 1)?;
    }
    let approved = engine.prepare_expiry_cleanup(&cancel)?.confirm(&ids)?;
    journal.0.borrow_mut().fail_event = Some(("purge_quarantine", "starting"));

    let outcome = engine.apply_expiry_cleanup_with_status(approved, &cancel)?;

    assert!(!outcome.can_continue);
    assert_eq!(outcome.report.items.len(), 2);
    assert!(matches!(
        &outcome.report.items[0].result,
        ChangeResult::Skipped(reason) if reason.contains(AUDIT_WRITE_FAILURE)
    ));
    assert!(matches!(
        &outcome.report.items[1].result,
        ChangeResult::Skipped(reason) if reason.contains("previous change needs review")
    ));
    assert_eq!(fake.0.borrow().quarantine.len(), 2);
    assert!(journal.list(Artifact::Purged)?.is_empty());
    Ok(())
}

#[test]
fn official_queue_keeps_failures_independent_and_scans_after_verified_removal() -> Result<()> {
    let fake = Fake::default();
    let fails = application("fails");
    let succeeds = application("succeeds");
    fake.0
        .borrow_mut()
        .applications
        .extend([fails.clone(), succeeds.clone()]);
    let engine = Engine::new(fake.clone(), MemoryJournal::default());
    let cancel = Cancellation::default();
    let first = engine.prepare_uninstall(&fails.id, &cancel)?.confirm()?;
    let second = engine.prepare_uninstall(&succeeds.id, &cancel)?.confirm()?;
    assert!(fake.0.borrow().launches.is_empty());
    let mut outcomes = engine
        .run_uninstall_queue([first, second], &cancel)
        .into_iter();
    let first = outcomes
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?
        .result?;
    let second = outcomes
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?
        .result?;
    assert_eq!(first.outcome, OfficialOutcome::Failed(1));
    assert!(first.cleanup.is_none());
    assert_eq!(second.outcome, OfficialOutcome::Completed);
    assert!(second.cleanup.is_some());
    assert_eq!(fake.0.borrow().scan_count, 1);
    Ok(())
}

#[test]
fn official_uninstall_rejects_lost_eligibility_after_confirmation() -> Result<()> {
    let fake = Fake::default();
    let app = AppRecord {
        publisher: Some("Studio Eight".into()),
        version: Some("1.0".into()),
        install_location: Some(path("apps/example-tool")),
        ..application("Example Tool")
    };
    fake.0.borrow_mut().applications.push(app.clone());
    let engine = Engine::new(fake.clone(), MemoryJournal::default());
    let cancel = Cancellation::default();
    let confirmed = engine.prepare_uninstall(&app.id, &cancel)?.confirm()?;

    fake.0.borrow_mut().applications[0].official_uninstall_available = false;

    assert!(matches!(
        engine.run_uninstall(confirmed, &cancel),
        Err(Error::Rejected(reason))
            if reason == "the application no longer has an available uninstall action"
    ));
    assert!(fake.0.borrow().launches.is_empty());
    Ok(())
}

#[test]
fn failed_uninstall_start_audit_prevents_native_execution() -> Result<()> {
    let fake = Fake::default();
    let app = application("audit-start");
    fake.0.borrow_mut().applications.push(app.clone());
    let journal = MemoryJournal::default();
    journal.0.borrow_mut().fail_event = Some(("official_uninstall", "starting"));
    let engine = Engine::new(fake.clone(), journal);
    let cancel = Cancellation::default();
    let confirmed = engine.prepare_uninstall(&app.id, &cancel)?.confirm()?;

    assert!(matches!(
        engine.run_uninstall(confirmed, &cancel),
        Err(Error::Io(error)) if error.to_string() == AUDIT_WRITE_FAILURE
    ));
    let state = fake.0.borrow();
    assert!(state.launches.is_empty());
    assert!(state.official_absence_checks.is_empty());
    assert_eq!(state.applications[0].id, app.id);
    Ok(())
}

#[test]
fn uninstall_audit_failures_preserve_verified_completion_without_cleanup() -> Result<()> {
    for event in [
        ("official_uninstall", "Completed"),
        ("verify_official_uninstall", "completed"),
    ] {
        let fake = Fake::default();
        let app = application("audit-completion");
        fake.0.borrow_mut().applications.push(app.clone());
        let journal = MemoryJournal::default();
        journal.0.borrow_mut().fail_event = Some(event);
        let engine = Engine::new(fake.clone(), journal);
        let cancel = Cancellation::default();
        let confirmed = engine.prepare_uninstall(&app.id, &cancel)?.confirm()?;

        let report = engine.run_uninstall(confirmed, &cancel)?;
        assert_eq!(report.outcome, OfficialOutcome::Completed);
        assert!(report.cleanup.is_none());
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains(AUDIT_WRITE_FAILURE)),
            "missing audit diagnostic for {event:?}"
        );
        let state = fake.0.borrow();
        assert_eq!(state.launches, [app.id.clone()]);
        assert_eq!(state.official_absence_checks, [app.id]);
        assert!(state.applications.is_empty());
    }
    Ok(())
}

#[test]
fn uninstall_retains_native_error_when_its_outcome_audit_fails() -> Result<()> {
    const NATIVE_FAILURE: &str = "intentional native uninstall failure";
    let fake = Fake::default();
    let app = application("audit-native-error");
    {
        let mut state = fake.0.borrow_mut();
        state.applications.push(app.clone());
        state.official_error = Some(NATIVE_FAILURE);
    }
    let journal = MemoryJournal::default();
    journal.0.borrow_mut().fail_event = Some(("official_uninstall", "rejected"));
    let engine = Engine::new(fake.clone(), journal);
    let cancel = Cancellation::default();
    let confirmed = engine.prepare_uninstall(&app.id, &cancel)?.confirm()?;

    let Err(error) = engine.run_uninstall(confirmed, &cancel) else {
        panic!("the native failure must be reported");
    };
    let detail = error.to_string();
    assert!(detail.contains(NATIVE_FAILURE));
    assert!(detail.contains(AUDIT_WRITE_FAILURE));
    let state = fake.0.borrow();
    assert_eq!(state.launches, [app.id]);
    assert!(state.official_absence_checks.is_empty());
    Ok(())
}

#[test]
fn cleanup_guard_rejection_preserves_verified_uninstall_without_scanning() -> Result<()> {
    let app = application("cleanup-preview");
    let fake = Fake(Rc::new(RefCell::new(MockState {
        applications: vec![app.clone()],
        cleanup_checks_before_rejection: Some(0),
        ..MockState::default()
    })));
    let engine = Engine::new(fake.clone(), MemoryJournal::default());
    let cancel = Cancellation::default();
    let confirmed = engine.prepare_uninstall(&app.id, &cancel)?.confirm()?;

    let report = engine.run_uninstall(confirmed, &cancel)?;

    assert_eq!(report.outcome, OfficialOutcome::Completed);
    assert!(report.cleanup.is_none());
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains(CLEANUP_INELIGIBLE))
    );
    let state = fake.0.borrow();
    assert_eq!(state.official_absence_checks, [app.id]);
    assert_eq!(state.scan_count, 0);
    Ok(())
}

#[test]
fn cleanup_observation_rejection_preserves_verified_uninstall_without_scanning() -> Result<()> {
    let app = application("changed-cleanup-observation");
    let fake = Fake(Rc::new(RefCell::new(MockState {
        applications: vec![app.clone()],
        cleanup_observations: Some(MockCleanupObservations::new(0)),
        ..MockState::default()
    })));
    let engine = Engine::new(fake.clone(), MemoryJournal::default());
    let cancel = Cancellation::default();
    let confirmed = engine.prepare_uninstall(&app.id, &cancel)?.confirm()?;
    let report = engine.run_uninstall(confirmed, &cancel)?;

    assert_eq!(report.outcome, OfficialOutcome::Completed);
    assert!(report.cleanup.is_none());
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains(CLEANUP_OBSERVATION_CHANGED))
    );
    let state = fake.0.borrow();
    assert_eq!(state.official_absence_checks, [app.id]);
    assert_eq!(state.scan_count, 0);
    assert_eq!(
        state.cleanup_observations.as_ref().map(|mock| mock.checks),
        Some(1)
    );
    Ok(())
}

#[test]
fn changed_cleanup_observation_blocks_rescan_and_both_mutation_boundaries() -> Result<()> {
    for accepted_checks in [1, 2] {
        let app = application("cleanup-observation-changes");
        let residual = path("apps/leftover.dll");
        let setting = registry_target();
        let fake = Fake(Rc::new(RefCell::new(MockState {
            applications: vec![app.clone()],
            files: HashMap::from([(residual.clone(), file("intact"))]),
            registry: HashMap::from([(setting.clone(), "intact".into())]),
            cleanup_observations: Some(MockCleanupObservations::new(accepted_checks)),
            ..MockState::default()
        })));
        let journal = MemoryJournal::default();
        let engine = Engine::new(fake.clone(), journal.clone());
        let cancel = Cancellation::default();
        let confirmed = engine.prepare_uninstall(&app.id, &cancel)?.confirm()?;
        let uninstall = engine.run_uninstall(confirmed, &cancel)?;
        assert_eq!(uninstall.outcome, OfficialOutcome::Completed);
        let preview = uninstall
            .cleanup
            .expect("the first observation check permits preview");
        let selected: Vec<_> = preview.candidates().map(|candidate| candidate.id).collect();
        let applied = engine.apply(preview.confirm(&selected)?, &cancel);

        let expected_checks = if accepted_checks == 1 {
            assert!(
                matches!(applied, Err(Error::Rejected(reason)) if reason == CLEANUP_OBSERVATION_CHANGED)
            );
            2
        } else {
            let report = applied?;
            assert_eq!(report.items.len(), 2);
            assert!(report.items.iter().all(|item| {
                matches!(&item.result, ChangeResult::Skipped(reason) if reason == CLEANUP_OBSERVATION_CHANGED)
            }));
            4
        };
        let state = fake.0.borrow();
        assert_eq!(
            state.cleanup_observations.as_ref().map(|mock| mock.checks),
            Some(expected_checks)
        );
        assert_eq!(state.files[&residual].stamp, "intact");
        assert_eq!(state.registry[&setting], "intact");
        assert!(state.quarantine.is_empty());
        assert!(journal.list(Artifact::RegistryExport)?.is_empty());
    }
    Ok(())
}

#[test]
fn cleanup_guard_rejects_file_and_registry_changes_mid_batch() -> Result<()> {
    let app = application("cleanup-batch");
    let first_file = path("apps/first.dll");
    let second_file = path("apps/second.dll");
    let setting = registry_target();
    let fake = Fake(Rc::new(RefCell::new(MockState {
        applications: vec![app.clone()],
        files: HashMap::from([
            (first_file.clone(), file("first")),
            (second_file.clone(), file("second")),
        ]),
        registry: HashMap::from([(setting.clone(), "unchanged".into())]),
        // Permit the preview, the recheck, and the first file's move.
        cleanup_checks_before_rejection: Some(3),
        ..MockState::default()
    })));
    let journal = MemoryJournal::default();
    let engine = Engine::new(fake.clone(), journal.clone());
    let cancel = Cancellation::default();
    let confirmed = engine.prepare_uninstall(&app.id, &cancel)?.confirm()?;
    let uninstall = engine.run_uninstall(confirmed, &cancel)?;
    let plan = uninstall
        .cleanup
        .ok_or_else(|| Error::Rejected("expected a cleanup preview".into()))?;
    let selected: Vec<_> = plan.candidates().map(|candidate| candidate.id).collect();

    let report = engine.apply(plan.confirm(&selected)?, &cancel)?;

    let [applied, skipped_file, skipped_registry] = report.items.as_slice() else {
        panic!("expected three cleanup results, got {:?}", report.items);
    };
    assert!(matches!(applied.result, ChangeResult::Applied));
    assert_eq!(
        skipped_file.target,
        Target::File(second_file.clone()).display()
    );
    assert!(matches!(
        &skipped_file.result,
        ChangeResult::Skipped(reason) if reason == CLEANUP_INELIGIBLE
    ));
    assert!(skipped_file.backup_id.is_some());
    assert_eq!(
        skipped_registry.target,
        Target::Registry(setting.clone()).display()
    );
    assert!(matches!(
        &skipped_registry.result,
        ChangeResult::Skipped(reason) if reason == CLEANUP_INELIGIBLE
    ));
    assert!(skipped_registry.backup_id.is_none());
    let state = fake.0.borrow();
    assert_eq!(state.scan_count, 2);
    assert_eq!(state.quarantine.len(), 1);
    assert!(!state.files.contains_key(&first_file));
    assert!(state.files.contains_key(&second_file));
    assert_eq!(
        state.registry.get(&setting).map(String::as_str),
        Some("unchanged")
    );
    assert!(journal.list(Artifact::RegistryExport)?.is_empty());
    Ok(())
}

#[test]
fn late_cancellation_keeps_verified_native_completion_and_stops_the_queue() -> Result<()> {
    let finished_app = application("finished");
    let pending_app = application("pending");
    let cancel = Cancellation::default();
    let fake = Fake(Rc::new(RefCell::new(MockState {
        applications: vec![finished_app.clone(), pending_app.clone()],
        cancel_on_official_completion: Some(cancel.clone()),
        ..MockState::default()
    })));
    let journal = MemoryJournal::default();
    let engine = Engine::new(fake.clone(), journal.clone());
    let first = engine
        .prepare_uninstall(&finished_app.id, &cancel)?
        .confirm()?;
    let second = engine
        .prepare_uninstall(&pending_app.id, &cancel)?
        .confirm()?;
    let mut outcomes = engine
        .run_uninstall_queue([first, second], &cancel)
        .into_iter();
    let report = outcomes
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?
        .result?;
    assert_eq!(report.outcome, OfficialOutcome::Completed);
    assert!(report.cleanup.is_none());
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| { warning == "Leftover scan cancelled after uninstall completed." })
    );
    assert!(matches!(
        outcomes.next().map(|row| row.result),
        Some(Err(Error::Cancelled))
    ));
    assert_eq!(fake.0.borrow().launches, [finished_app.id]);
    assert_eq!(fake.0.borrow().scan_count, 0);

    let events = journal
        .list(Artifact::Event)?
        .into_iter()
        .map(|id| crate::state::read_json::<AuditEvent>(&journal, id, Artifact::Event))
        .collect::<Result<Vec<_>>>()?;
    assert!(events.into_iter().flatten().any(|event| {
        event.object == finished_app.name
            && event.action == "verify_official_uninstall"
            && event.result == "completed"
    }));
    Ok(())
}

#[test]
fn confirmation_is_bound_to_the_engine_that_generated_the_plan() -> Result<()> {
    let fake = Fake::default();
    fake.0
        .borrow_mut()
        .files
        .insert(path("apps/tool.dll"), file("same"));
    let journal = MemoryJournal::default();
    let first = Engine::new(fake.clone(), journal.clone());
    let second = Engine::new(fake.clone(), journal);
    let cancel = Cancellation::default();
    let confirmed = first.scan_portable(&path("apps"), &cancel)?.confirm(&[0])?;
    assert!(second.apply(confirmed, &cancel).is_err());
    assert!(fake.0.borrow().quarantine.is_empty());
    Ok(())
}

#[test]
fn unverified_native_completion_stays_unverified_when_inventory_entry_disappears() -> Result<()> {
    let fake = Fake::default();
    let app = application("unverified");
    fake.0.borrow_mut().applications.push(app.clone());
    let engine = Engine::new(fake.clone(), MemoryJournal::default());
    let cancel = Cancellation::default();
    let confirmed = engine.prepare_uninstall(&app.id, &cancel)?.confirm()?;
    let result = engine.run_uninstall(confirmed, &cancel)?;
    assert_eq!(result.outcome, OfficialOutcome::Unverified(0));
    assert!(result.cleanup.is_none());
    assert!(fake.0.borrow().applications.is_empty());
    assert_eq!(fake.0.borrow().scan_count, 0);
    Ok(())
}

#[test]
fn restore_rejects_a_replaced_manifest_and_corrupt_registry_snapshot() -> Result<()> {
    let fake = Fake::default();
    let stamp = file("before");
    let original = path("apps/tool.dll");
    let key = registry_target();
    fake.0.borrow_mut().files.insert(original.clone(), stamp);
    fake.0
        .borrow_mut()
        .registry
        .insert(key.clone(), "fixture".into());
    let journal = MemoryJournal::default();
    let engine = Engine::new(fake.clone(), journal.clone());
    let cancel = Cancellation::default();
    let plan = engine.scan_portable(&path("apps"), &cancel)?;
    let change = engine.apply(plan.confirm(&[0, 1])?, &cancel)?;
    let restore = engine.prepare_restore(change.batch_id)?.confirm()?;
    let file_backup = change
        .items
        .iter()
        .find(|item| item.target == original.to_string_lossy())
        .and_then(|item| item.backup_id)
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    let file_manifest = Artifact::Manifest.file_name(file_backup);
    {
        let mut state = journal.0.borrow_mut();
        for (name, bytes) in &mut state.records {
            if name == &file_manifest {
                let mut record: serde_json::Value = serde_json::from_slice(bytes)?;
                record["backup"] = serde_json::Value::String("unexpected location".into());
                *bytes = serde_json::to_vec(&record)?;
            } else if name.ends_with(".registry.json") {
                *bytes = b"unexpected setting".to_vec();
            }
        }
    }
    let report = engine.restore(restore, &cancel)?;
    assert!(
        report
            .items
            .iter()
            .all(|item| matches!(item.result, ChangeResult::Skipped(_)))
    );
    assert_eq!(report.items.len(), 2);
    assert!(!fake.0.borrow().files.contains_key(&original));
    assert!(!fake.0.borrow().registry.contains_key(&key));
    assert_eq!(fake.0.borrow().quarantine.len(), 1);
    Ok(())
}

#[test]
fn preferences_survive_restart_and_reject_an_invalid_rule_edit() -> Result<()> {
    let fake = Fake::default();
    let journal = MemoryJournal::default();
    let mut first = Engine::new(fake.clone(), journal.clone());
    let initial = first.restore_preferences()?;
    assert_eq!(initial.retention_days.get(), 14);
    assert!(initial.custom_rules.is_empty());

    let rules = r#"
version = 1
[[rules]]
id = "sample-macos-cache"
scope = "macos"
app_match = { kind = "macos_bundle", id = "org.example.Editor" }
root_id = "macos_caches"
relative_path = "org.example.Editor/Cache"
evidence = "test helper cache"
"#;
    assert_eq!(first.persist_custom_rules(rules.into())?, 1);
    let days = NonZeroU16::new(45).ok_or(io::Error::from(io::ErrorKind::InvalidInput))?;
    first.persist_retention(days)?;
    assert!(first.persist_custom_rules("invalid = [".into()).is_err());
    journal.create(Uuid::new_v4(), Artifact::Preferences, b"{not-json")?;

    let mut reopened = Engine::new(fake.clone(), journal.clone());
    let loaded = reopened.restore_preferences()?;
    assert_eq!(loaded.retention_days, days);
    assert_eq!(loaded.custom_rules, rules);
    assert_eq!(loaded.warnings.len(), 1);
    assert_eq!(reopened.persist_custom_rules(" \n".into())?, 0);

    let cleared = Engine::new(fake, journal).restore_preferences()?;
    assert_eq!(cleared.retention_days, days);
    assert!(cleared.custom_rules.is_empty());
    Ok(())
}

#[test]
fn persisting_retention_changes_only_new_backup_deadlines() -> Result<()> {
    use crate::state::BackupRecord;

    const MILLIS_PER_HOUR: u64 = 60 * 60 * 1000;
    const MILLIS_PER_DAY: u64 = 24 * MILLIS_PER_HOUR;

    let fake = Fake::default();
    let journal = MemoryJournal::default();
    let mut engine = Engine::new(fake.clone(), journal.clone());
    let cancel = Cancellation::default();
    let directory = path("apps");
    fake.0
        .borrow_mut()
        .files
        .insert(directory.join("earlier.dll"), file("earlier"));
    let earlier = engine.scan_portable(&directory, &cancel)?.confirm(&[0])?;
    let earlier = engine.apply(earlier, &cancel)?;
    assert!(matches!(earlier.items[0].result, ChangeResult::Applied));
    let earlier_id = earlier.items[0]
        .backup_id
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    let earlier_deadline = BackupRecord::load(&journal, earlier_id)?.expires_unix_ms;

    let shorter = NonZeroU16::MIN;
    engine.persist_retention(shorter)?;
    fake.0
        .borrow_mut()
        .files
        .insert(directory.join("later.dll"), file("later"));
    let later = engine.scan_portable(&directory, &cancel)?.confirm(&[0])?;
    let later = engine.apply(later, &cancel)?;
    assert!(matches!(later.items[0].result, ChangeResult::Applied));
    let later_id = later.items[0]
        .backup_id
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    let later_deadline = BackupRecord::load(&journal, later_id)?.expires_unix_ms;

    assert_eq!(
        BackupRecord::load(&journal, earlier_id)?.expires_unix_ms,
        earlier_deadline
    );
    // Anchor to the first stored deadline so normal delays between
    // operations do not affect the comparison.
    let reduction_days = u64::from(DEFAULT_RETENTION_DAYS.get() - shorter.get());
    let expected_deadline = earlier_deadline.saturating_sub(reduction_days * MILLIS_PER_DAY);
    assert!(later_deadline.abs_diff(expected_deadline) < MILLIS_PER_HOUR);
    Ok(())
}
