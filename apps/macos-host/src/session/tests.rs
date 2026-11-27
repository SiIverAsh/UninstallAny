use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    io,
    num::NonZeroU16,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use tauri::ipc::IpcResponse;
use uninstallany_core::{
    AppId, AppRecord, Artifact, Cancellation, ChangeReport, ChangeResult, DEFAULT_RETENTION_DAYS,
    Engine, Error, FileStore, Inspection, Inventory, ItemResult, Journal, OfficialIntent,
    OfficialOutcome, PlatformBackend, RegistryBackupWriter, RegistryStore, RegistryTarget, Result,
    Scan, ScanMode,
};
use uuid::Uuid;

use super::{Session, expiry_response};

const PREFERENCE_FAILURE: &str = "fixture preference storage is unavailable";
const PREFERENCE_WRITE_FAILURE: &str = "fixture preference write failed";
const EMPTY_SCAN_WARNING: &str = "fixture could not inspect an optional residual directory";

struct FixtureState {
    preferences_available: Cell<bool>,
    app_uninstalled: Cell<bool>,
}

impl FixtureState {
    fn new(preferences_available: bool) -> Self {
        Self {
            preferences_available: Cell::new(preferences_available),
            app_uninstalled: Cell::new(false),
        }
    }
}

#[derive(Clone, Copy)]
struct Fixture<'a>(&'a FixtureState);

macro_rules! unexpected_calls {
    ($(fn $method:ident($($argument:ty),*) -> $output:ty;)*) => {
        $(fn $method(&self $(, _: $argument)*) -> $output {
            unreachable!("unexpected fixture call to {}", stringify!($method))
        })*
    };
}

impl FileStore for Fixture<'_> {
    unexpected_calls! {
        fn inspect_file(&Path) -> io::Result<Inspection>;
        fn file_backup_path(&Path, &str, Uuid) -> io::Result<PathBuf>;
        fn quarantine_file(&Path, &str, Uuid) -> io::Result<()>;
        fn file_is_quarantined(&Path, &str, Uuid) -> io::Result<bool>;
        fn restore_file(&Path, &str, Uuid) -> io::Result<()>;
    }
}

impl RegistryStore for Fixture<'_> {
    unexpected_calls! {
        fn inspect_registry(&RegistryTarget) -> io::Result<Inspection>;
        fn remove_registry(&RegistryTarget, &str, &mut RegistryBackupWriter<'_>) -> io::Result<()>;
        fn restore_registry(&RegistryTarget, &[u8]) -> io::Result<()>;
    }
}

impl Journal for Fixture<'_> {
    fn create(&self, _: Uuid, artifact: Artifact, _: &[u8]) -> io::Result<()> {
        assert_eq!(artifact, Artifact::Event);
        Ok(())
    }

    fn list(&self, artifact: Artifact) -> io::Result<Vec<Uuid>> {
        if artifact == Artifact::Preferences && !self.0.preferences_available.get() {
            return Err(io::Error::other(PREFERENCE_FAILURE));
        }
        Ok(Vec::new())
    }

    unexpected_calls! {
        fn read(Uuid, Artifact) -> io::Result<Option<Vec<u8>>>;
        fn location(Uuid, Artifact) -> PathBuf;
        fn check_export_path(&Path) -> io::Result<()>;
    }
}

#[derive(Default)]
struct PreferencesJournal {
    records: RefCell<HashMap<Uuid, Vec<u8>>>,
    fail_write: Cell<bool>,
}

impl Journal for &PreferencesJournal {
    fn create(&self, id: Uuid, artifact: Artifact, bytes: &[u8]) -> io::Result<()> {
        if artifact == Artifact::Event {
            return Ok(());
        }
        assert_eq!(artifact, Artifact::Preferences);
        if self.fail_write.get() {
            return Err(io::Error::other(PREFERENCE_WRITE_FAILURE));
        }
        let mut records = self.records.borrow_mut();
        if records.contains_key(&id) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        records.insert(id, bytes.to_vec());
        Ok(())
    }

    fn read(&self, id: Uuid, artifact: Artifact) -> io::Result<Option<Vec<u8>>> {
        assert_eq!(artifact, Artifact::Preferences);
        Ok(self.records.borrow().get(&id).cloned())
    }

    fn list(&self, artifact: Artifact) -> io::Result<Vec<Uuid>> {
        assert_eq!(artifact, Artifact::Preferences);
        Ok(self.records.borrow().keys().copied().collect())
    }

    unexpected_calls! {
        fn location(Uuid, Artifact) -> PathBuf;
        fn check_export_path(&Path) -> io::Result<()>;
    }
}

impl PlatformBackend for Fixture<'_> {
    type Official = ();

    fn inventory(&self, cancel: &Cancellation) -> Result<Inventory> {
        cancel.check()?;
        if self.0.app_uninstalled.get() {
            return Ok(Inventory::default());
        }
        Ok(Inventory {
            applications: vec![AppRecord {
                id: app_id(),
                name: "Fixture App".into(),
                publisher: None,
                version: None,
                install_location: None,
                size_bytes: None,
                install_date: None,
                system_component: false,
                official_uninstall_available: true,
            }],
            warnings: Vec::new(),
        })
    }

    fn prepare_official(&self, app: &AppRecord) -> Result<(OfficialIntent, Self::Official)> {
        Ok((
            OfficialIntent {
                application: app.name.clone(),
                method: "Fixture uninstaller".into(),
                quiet: false,
                notice: String::new(),
            },
            (),
        ))
    }

    fn run_official(&self, _: Self::Official) -> Result<OfficialOutcome> {
        self.0.app_uninstalled.set(true);
        Ok(OfficialOutcome::Completed)
    }

    fn scan(&self, _: &AppRecord, mode: ScanMode, cancel: &Cancellation) -> Result<Scan> {
        cancel.check()?;
        assert_eq!(mode, ScanMode::AfterOfficialUninstall);
        assert!(self.0.app_uninstalled.get());
        Ok(Scan::new(Vec::new(), vec![EMPTY_SCAN_WARNING.into()]))
    }

    unexpected_calls! {
        fn scan_portable(&Path, &Cancellation) -> Result<Scan>;
    }
}

fn app_id() -> AppId {
    AppId::Package {
        manager: "macos-bundle".into(),
        id: "fixture-app".into(),
    }
}

#[derive(Deserialize)]
struct InventoryResponse {
    applications: Vec<ApplicationResponse>,
    warnings: Vec<String>,
}

#[derive(Deserialize)]
struct ApplicationResponse {
    official_uninstall_available: bool,
}

#[derive(Deserialize)]
struct PreferencesResponse {
    retention_days: u16,
}

fn cached_retention(
    session: &Session<Fixture<'_>, &PreferencesJournal>,
    cancel: &Cancellation,
) -> std::result::Result<u16, Box<dyn std::error::Error>> {
    let prefs: PreferencesResponse = session.load_preferences(cancel)?.body()?.deserialize()?;
    Ok(prefs.retention_days)
}

#[test]
fn inventory_disables_uninstall_until_preferences_recover()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let state = FixtureState::new(false);
    let fixture = Fixture(&state);
    let mut session = Session::new(Engine::new(fixture, fixture));
    let cancel = Cancellation::default();

    let inventory: InventoryResponse = session.list_applications(&cancel)?.body()?.deserialize()?;
    assert_eq!(inventory.applications.len(), 1);
    assert!(!inventory.applications[0].official_uninstall_available);
    assert!(
        matches!(inventory.warnings.as_slice(), [warning] if warning.contains(PREFERENCE_FAILURE))
    );
    assert!(session.load_preferences(&cancel).is_err());

    state.preferences_available.set(true);
    let inventory: InventoryResponse = session.list_applications(&cancel)?.body()?.deserialize()?;
    assert!(inventory.applications[0].official_uninstall_available);
    assert!(inventory.warnings.is_empty());
    session.load_preferences(&cancel)?;
    session.review_uninstall(vec![app_id()], &cancel)?;
    assert!(session.uninstall.is_some());
    Ok(())
}

#[test]
fn unavailable_preferences_block_removal_while_backups_are_readable() -> Result<()> {
    let state = FixtureState::new(false);
    let fixture = Fixture(&state);
    let mut session = Session::new(Engine::new(fixture, fixture));
    let cancel = Cancellation::default();
    let missing_id = Uuid::nil();

    let errors = [
        session.review_uninstall(vec![app_id()], &cancel).err(),
        session
            .run_uninstall(missing_id, &cancel, |_, _| unreachable!())
            .err(),
        session.apply_cleanup(missing_id, &[0], &cancel).err(),
    ];
    for error in errors {
        assert!(
            matches!(error, Some(Error::Rejected(message)) if message.contains(PREFERENCE_FAILURE))
        );
    }
    assert!(session.uninstall.is_none());
    #[cfg(not(all(target_os = "macos", feature = "macos-privileged-helper")))]
    session.list_backups(&cancel)?;
    session.review_restore(missing_id, &cancel)?;
    assert!(session.restore.is_none());
    Ok(())
}

#[test]
fn verified_uninstall_with_no_leftovers_keeps_warnings_without_a_cleanup_plan()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    #[derive(Deserialize)]
    struct UninstallResponse {
        outcome: std::result::Result<OfficialOutcome, String>,
        #[serde(rename = "cleanup")]
        _empty_cleanup: (),
        warnings: Vec<String>,
    }

    let state = FixtureState::new(true);
    let fixture = Fixture(&state);
    let mut session = Session::new(Engine::new(fixture, fixture));
    let cancel = Cancellation::default();
    session.review_uninstall(vec![app_id()], &cancel)?;
    let ticket = session
        .uninstall
        .as_ref()
        .expect("uninstall was reviewed")
        .ticket;

    let rows: Vec<UninstallResponse> = session
        .run_uninstall(ticket, &cancel, |_, _| {})?
        .body()?
        .deserialize()?;
    let [row] = rows.as_slice() else {
        panic!("one uninstall was approved");
    };
    assert_eq!(row.outcome, Ok(OfficialOutcome::Completed));
    assert_eq!(row.warnings, [EMPTY_SCAN_WARNING]);
    assert!(session.cleanup.is_empty());
    Ok(())
}

#[test]
fn entirely_rejected_uninstall_review_preserves_the_reason_without_a_ticket() {
    let state = FixtureState::new(true);
    let fixture = Fixture(&state);
    let mut session = Session::new(Engine::new(fixture, fixture));
    let missing = AppId::Package {
        manager: "macos-bundle".into(),
        id: "missing-fixture-app".into(),
    };
    assert!(matches!(
        session.review_uninstall(vec![missing], &Cancellation::default()),
        Err(Error::Rejected(message)) if message.contains("application is no longer present")
    ));
    assert!(session.uninstall.is_none());
}

#[test]
fn custom_rules_are_persisted_and_invalid_edits_leave_them_active() -> Result<()> {
    let state = FixtureState::new(true);
    let fixture = Fixture(&state);
    let journal = PreferencesJournal::default();
    let mut session = Session::new(Engine::new(fixture, &journal));
    let cancel = Cancellation::default();
    let text = r#"version = 1
[[rules]]
id = "fixture-cache"
scope = "macos"
app_match = { kind = "macos_bundle", id = "org.example.Fixture" }
root_id = "macos_caches"
relative_path = "FixtureCache"
evidence = "Fixture application cache"
"#;

    let saved = session.set_custom_rules(text.into(), &cancel)?;
    assert_eq!(saved.count, 1);
    assert_eq!(saved.text, text);
    assert!(
        session
            .set_custom_rules(text.replace("FixtureCache", "../FixtureCache"), &cancel)
            .is_err()
    );
    assert_eq!(session.require_preferences()?.custom_rules, text);
    let reopened = Session::new(Engine::new(fixture, &journal));
    assert_eq!(reopened.require_preferences()?.custom_rules, text);

    let cleared = session.set_custom_rules(" \n".into(), &cancel)?;
    assert_eq!(cleared.count, 0);
    assert_eq!(cleared.text, " \n");
    assert!(session.require_preferences()?.custom_rules.is_empty());
    let reopened = Session::new(Engine::new(fixture, &journal));
    assert!(reopened.require_preferences()?.custom_rules.is_empty());
    Ok(())
}

#[test]
fn changed_retention_is_persisted_and_invalidates_the_uninstall_review()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let state = FixtureState::new(true);
    let fixture = Fixture(&state);
    let journal = PreferencesJournal::default();
    let mut session = Session::new(Engine::new(fixture, &journal));
    let cancel = Cancellation::default();
    let days = NonZeroU16::new(30).expect("fixture retention is nonzero");
    session.review_uninstall(vec![app_id()], &cancel)?;
    let ticket = session
        .uninstall
        .as_ref()
        .expect("uninstall was reviewed")
        .ticket;

    assert_eq!(
        session.set_retention(DEFAULT_RETENTION_DAYS, &cancel)?,
        DEFAULT_RETENTION_DAYS.get(),
    );
    assert_eq!(
        session.uninstall.as_ref().map(|review| review.ticket),
        Some(ticket)
    );

    assert_eq!(session.set_retention(days, &cancel)?, days.get());
    assert_eq!(session.engine.retention_days(), days);
    assert_eq!(cached_retention(&session, &cancel)?, days.get());
    assert!(session.uninstall.is_none());

    let reopened = Session::new(Engine::new(fixture, &journal));
    assert_eq!(cached_retention(&reopened, &cancel)?, days.get());
    Ok(())
}

#[test]
fn failed_retention_save_preserves_existing_preferences_and_uninstall_review()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let state = FixtureState::new(true);
    let fixture = Fixture(&state);
    let journal = PreferencesJournal::default();
    let mut session = Session::new(Engine::new(fixture, &journal));
    let cancel = Cancellation::default();
    let previous_days = NonZeroU16::new(7).expect("fixture retention is nonzero");
    let days = NonZeroU16::new(30).expect("fixture retention is nonzero");
    session.set_retention(previous_days, &cancel)?;
    session.review_uninstall(vec![app_id()], &cancel)?;
    let ticket = session
        .uninstall
        .as_ref()
        .expect("uninstall was reviewed")
        .ticket;

    journal.fail_write.set(true);
    let Err(error) = session.set_retention(days, &cancel) else {
        panic!("a failed preference write must be reported");
    };
    assert!(error.to_string().contains(PREFERENCE_WRITE_FAILURE));
    assert_eq!(session.engine.retention_days(), previous_days);
    assert_eq!(cached_retention(&session, &cancel)?, previous_days.get());
    assert_eq!(
        session.uninstall.as_ref().map(|review| review.ticket),
        Some(ticket)
    );

    let reopened = Session::new(Engine::new(fixture, &journal));
    assert_eq!(cached_retention(&reopened, &cancel)?, previous_days.get());
    Ok(())
}

#[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
#[test]
fn an_uninstall_ticket_cannot_activate_the_system_helper() -> Result<()> {
    let state = FixtureState::new(true);
    let fixture = Fixture(&state);
    let mut session = Session::new(Engine::new(fixture, fixture));
    let cancel = Cancellation::default();
    session.review_uninstall(vec![app_id()], &cancel)?;
    let ticket = session
        .uninstall
        .as_ref()
        .expect("uninstall was reviewed")
        .ticket;

    assert!(matches!(
        session.run_helper_activation(ticket, &cancel),
        Err(Error::Rejected(message)) if message.contains("preview is no longer available")
    ));
    assert_eq!(
        session.uninstall.as_ref().map(|review| review.ticket),
        Some(ticket)
    );
    assert!(session.helper_activation.is_none());
    Ok(())
}

#[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
#[test]
fn system_backup_ids_cannot_be_reinterpreted_as_local_batches() {
    use uninstallany_core::{BackupInventory, BackupSummary, RecoveryState};

    let state = FixtureState::new(true);
    let fixture = Fixture(&state);
    let mut session = Session::new(Engine::new(fixture, fixture));
    let operation = Uuid::new_v4();
    let system = || BackupInventory {
        items: vec![BackupSummary {
            id: operation,
            batch_id: operation,
            target: "/Applications/System Fixture.app".into(),
            backup: "/var/db/system-backup/payload.app".into(),
            expires_unix_ms: 1,
            state: RecoveryState::Applied,
        }],
        warnings: Vec::new(),
    };
    let local = BackupInventory {
        items: vec![BackupSummary {
            id: Uuid::new_v4(),
            batch_id: operation,
            target: "/local/residual".into(),
            backup: "/local/quarantine/residual".into(),
            expires_unix_ms: 1,
            state: RecoveryState::Applied,
        }],
        warnings: Vec::new(),
    };

    session.merge_system_backups(BackupInventory::default(), system());
    let merged = session.merge_system_backups(local, system());

    assert!(session.system_backup_ids.contains(&operation));
    assert_eq!(merged.items.len(), 1);
    assert_eq!(merged.items[0].state, RecoveryState::NeedsReview);
    assert_eq!(merged.warnings.len(), 1);
}

#[test]
fn expiry_response_returns_every_confirmed_purge()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    #[derive(Deserialize)]
    struct PurgeResponse {
        batch_id: Uuid,
        items: Vec<PurgedItem>,
    }

    #[derive(Deserialize)]
    struct PurgedItem {
        target: String,
        backup_id: Uuid,
        result: String,
    }

    let batch_id = Uuid::new_v4();
    let expected = [
        ("/first/residual", Uuid::new_v4()),
        ("/second/residual", Uuid::new_v4()),
    ];
    let report = ChangeReport {
        batch_id,
        items: expected
            .iter()
            .map(|&(target, id)| ItemResult {
                target: target.into(),
                backup_id: Some(id),
                result: ChangeResult::Purged,
            })
            .collect(),
    };
    let response: PurgeResponse = expiry_response(report)?.body()?.deserialize()?;
    assert_eq!(response.batch_id, batch_id);
    assert_eq!(response.items.len(), expected.len());
    for (item, (target, id)) in response.items.iter().zip(expected) {
        assert_eq!(item.target, target);
        assert_eq!(item.backup_id, id);
        assert_eq!(item.result, "Purged");
    }
    Ok(())
}

#[test]
fn expiry_response_reports_distinct_counts_for_a_partial_purge() {
    let outcomes = [
        ChangeResult::Purged,
        ChangeResult::Skipped("fixture declined approval".into()),
        ChangeResult::Skipped("fixture lost eligibility".into()),
        ChangeResult::NeedsReview("fixture removal pending".into()),
        ChangeResult::NeedsReview("fixture result uncertain".into()),
        ChangeResult::NeedsReview("fixture audit unavailable".into()),
    ];
    let report = ChangeReport {
        batch_id: Uuid::new_v4(),
        items: outcomes
            .into_iter()
            .enumerate()
            .map(|(index, result)| ItemResult {
                target: format!("/fixture/{index}"),
                backup_id: Some(Uuid::new_v4()),
                result,
            })
            .collect(),
    };
    assert!(matches!(
        expiry_response(report),
        Err(Error::Rejected(message))
            if message.contains("1 permanently removed, 2 skipped, 3 require review")
    ));
}

#[test]
fn an_uninstall_ticket_cannot_purge_expired_backups() -> Result<()> {
    let state = FixtureState::new(true);
    let fixture = Fixture(&state);
    let mut session = Session::new(Engine::new(fixture, fixture));
    let cancel = Cancellation::default();
    session.review_uninstall(vec![app_id()], &cancel)?;
    let ticket = session
        .uninstall
        .as_ref()
        .expect("uninstall was reviewed")
        .ticket;

    assert!(matches!(
        session.purge_expired(ticket, vec![Uuid::new_v4()], &cancel),
        Err(Error::Rejected(message)) if message.contains("preview is no longer available")
    ));
    assert_eq!(
        session.uninstall.as_ref().map(|review| review.ticket),
        Some(ticket)
    );
    assert!(session.expiry.is_none());
    Ok(())
}
