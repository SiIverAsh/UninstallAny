use super::*;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use uninstallany_core::{Artifact, Journal};

pub(super) struct Fixture {
    _directory: tempfile::TempDir,
    pub(super) scope: PathBuf,
    protected: PathBuf,
    pub(super) state: PathBuf,
    pub(super) guard: UnixFiles,
}

impl Fixture {
    pub(super) fn new() -> io::Result<Self> {
        let directory = tempfile::tempdir()?;
        let home = directory.path().canonicalize()?;
        let scope = home.join("candidates");
        let protected = scope.join("protected");
        fs::create_dir_all(&protected)?;
        let state = home.join("test-state");
        let uid = rustix::process::geteuid().as_raw();
        let guard = UnixFiles::with_account(
            vec![scope.clone()],
            vec![protected.clone()],
            state.clone(),
            home,
            uid,
        )?;
        Ok(Self {
            _directory: directory,
            scope,
            protected,
            state,
            guard,
        })
    }
}

#[cfg(target_os = "linux")]
#[test]
fn flatpak_data_quarantine_requires_a_private_unchanged_tree() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let home = parent_path(&fixture.scope)?;
    let root = home.join(".var/app");
    let app = root.join("org.example.Editor");
    let files = UnixFiles::with_account(
        vec![root.clone()],
        Vec::new(),
        fixture.state.clone(),
        home.to_path_buf(),
        rustix::process::geteuid().as_raw(),
    )?
    .with_linux_flatpak_data_directories(&root)?;
    assert!(matches!(
        files.pin_linux_flatpak_data_directory(&app),
        Err(error) if error.kind() == io::ErrorKind::NotFound
    ));

    let configuration = app.join("config");
    let document = configuration.join("preferences");
    fs::create_dir_all(&configuration)?;
    fs::write(&document, b"original")?;
    let nested_link = configuration.join("link");
    symlink(&fixture.scope, &nested_link)?;
    let app_alias = root.join("org.example.Alias");
    symlink(&app, &app_alias)?;
    assert!(matches!(
        files.inspect_file(&app_alias)?.access,
        Access::ReadOnly(_)
    ));
    assert!(matches!(
        files.inspect_file(&configuration)?.access,
        Access::ReadOnly(_)
    ));

    let first = files.inspect_file(&app)?;
    assert_eq!(first.access, Access::Allowed);
    let slot = Uuid::new_v4();
    fs::write(&document, b"updated preferences")?;
    assert!(matches!(
        files.quarantine_file(&app, &first.fingerprint, slot),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied
    ));

    let (current, directory) = files.pin_linux_flatpak_data_directory(&app)?;
    assert_eq!(files.inspect_file(&app)?.fingerprint, current.fingerprint);
    files.quarantine_file(&app, &current.fingerprint, slot)?;
    assert!(!app.exists());
    assert!(directory.metadata()?.is_dir());
    assert!(files.file_is_quarantined(&app, &current.fingerprint, slot)?);
    assert!(!files.can_purge_quarantined(&app, &current.fingerprint, slot)?);

    files.restore_file(&app, &current.fingerprint, slot)?;
    assert!(files.verify_file_restored(&app, &current.fingerprint, slot)?);
    assert_eq!(fs::read(document)?, b"updated preferences");
    assert_eq!(fs::read_link(nested_link)?, fixture.scope);
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn audit_export_keeps_a_file_created_before_publication() -> uninstallany_core::Result<()> {
    let fixture = Fixture::new()?;
    let destination = fixture.scope.join("report.jsonl");
    let cancel = Cancellation::default();
    let result = fixture
        .guard
        .write_audit_export(&destination, &cancel, |output| {
            io::Write::write_all(output, b"{}\n")?;
            fs::write(&destination, b"existing")?;
            Ok(())
        });
    assert!(matches!(
        result,
        Err(uninstallany_core::Error::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists
    ));
    assert_eq!(fs::read(&destination)?, b"existing");
    assert_eq!(fs::read_dir(&fixture.scope)?.count(), 2);
    Ok(())
}

#[test]
fn mutation_denies_paths_outside_scope_and_inside_protected_trees() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let file = fixture.protected.join("kept");
    fs::write(&file, b"protected")?;
    assert_eq!(fixture.guard.read_regular(&file, 9)?, b"protected");
    assert!(matches!(
        fixture.guard.inspect_file(&file)?.access,
        Access::ReadOnly(_)
    ));
    assert!(
        fixture
            .guard
            .inspect_file(&fixture.scope.join("../outside"))
            .is_err()
    );
    assert!(
        fixture
            .guard
            .inspect_file(&fixture.scope.join("./protected/kept"))
            .is_err()
    );
    assert!(!fixture.state.exists());
    Ok(())
}

#[test]
fn cancellation_at_the_rename_boundary_preserves_the_source() -> uninstallany_core::Result<()> {
    let fixture = Fixture::new()?;
    let path = fixture.scope.join("candidate");
    fs::write(&path, b"retained")?;
    let inspected = fixture.guard.inspect_file(&path)?;
    assert_eq!(inspected.access, Access::Allowed);
    let slot = Uuid::new_v4();
    let cancel = Cancellation::default();
    let result = fixture
        .guard
        .quarantine_verified(&path, &inspected.fingerprint, slot, || {
            cancel.cancel();
            cancel.check()
        });
    assert!(matches!(result, Err(uninstallany_core::Error::Cancelled)));
    assert_eq!(fs::read(&path)?, b"retained");
    assert!(
        !fixture
            .guard
            .file_is_quarantined(&path, &inspected.fingerprint, slot)?
    );
    Ok(())
}

#[test]
fn traversal_never_opens_a_link_and_isolation_moves_only_a_terminal_link() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let target = fixture.protected.join("kept");
    fs::write(&target, b"protected")?;
    let alias = fixture.scope.join("alias");
    symlink(&fixture.protected, &alias)?;
    assert!(fixture.guard.list(&alias).is_err());
    assert!(fixture.guard.read_prefix(&alias.join("kept"), 4).is_err());
    assert!(fixture.guard.read_regular(&alias, 100).is_err());
    assert!(matches!(
        fixture.guard.inspect_file(&alias.join("kept"))?.access,
        Access::ReadOnly(_)
    ));
    let verified = fixture.guard.inspect_file(&alias)?;
    assert_eq!(verified.access, Access::Allowed);
    let slot = Uuid::new_v4();
    fixture
        .guard
        .quarantine_file(&alias, &verified.fingerprint, slot)?;
    assert!(!alias.exists());
    assert!(
        fixture
            .guard
            .file_is_quarantined(&alias, &verified.fingerprint, slot)?
    );
    assert_eq!(fs::read(&target)?, b"protected");
    fixture
        .guard
        .restore_file(&alias, &verified.fingerprint, slot)?;
    assert_eq!(fs::read_link(&alias)?, fixture.protected);
    Ok(())
}

#[test]
fn rule_probes_keep_links_and_protected_trees_out_of_suggestions() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let regular = fixture.scope.join("valid-cache");
    fs::write(&regular, b"cache")?;
    let target = fixture
        .guard
        .probe_rule_target(&regular)?
        .ok_or_else(|| io::Error::other("fixture rule target disappeared"))?;
    assert_eq!(target.path, regular);
    assert_eq!(target.category, Category::File);

    let protected = fixture.protected.join("kept");
    fs::write(&protected, b"protected")?;
    assert!(fixture.guard.probe_rule_target(&protected).is_err());
    let link = fixture.scope.join("link-to-protected");
    symlink(&fixture.protected, &link)?;
    assert!(fixture.guard.probe_rule_target(&link)?.is_none());
    assert!(fixture.guard.probe_rule_target(&link.join("kept")).is_err());
    assert_eq!(fs::read(&protected)?, b"protected");
    assert!(!fixture.state.exists());
    Ok(())
}

#[test]
fn source_replacement_and_shared_hard_links_are_never_taken() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let path = fixture.scope.join("object");
    let moved = fixture.scope.join("old-object");
    fs::write(&path, b"before")?;
    let inspected = fixture.guard.inspect_file(&path)?;
    assert_eq!(inspected.access, Access::Allowed);
    fs::rename(&path, &moved)?;
    fs::write(&path, b"after")?;
    assert!(
        fixture
            .guard
            .quarantine_file(&path, &inspected.fingerprint, Uuid::new_v4())
            .is_err()
    );
    assert_eq!(fs::read(&path)?, b"after");
    fs::hard_link(&path, fixture.scope.join("other-name"))?;
    assert!(matches!(
        fixture.guard.inspect_file(&path)?.access,
        Access::ReadOnly(_)
    ));
    Ok(())
}

#[test]
fn restoration_preserves_a_new_target_and_refuses_a_different_parent() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let parent = fixture.scope.join("owned-dir");
    fs::create_dir(&parent)?;
    let path = parent.join("file");
    fs::write(&path, b"original")?;
    let inspected = fixture.guard.inspect_file(&path)?;
    let slot = Uuid::new_v4();
    fixture
        .guard
        .quarantine_file(&path, &inspected.fingerprint, slot)?;
    assert!(
        fixture
            .guard
            .restore_file(&parent.join("another-name"), &inspected.fingerprint, slot)
            .is_err()
    );
    fs::write(&path, b"new")?;
    assert!(
        fixture
            .guard
            .restore_file(&path, &inspected.fingerprint, slot)
            .is_err()
    );
    assert_eq!(fs::read(&path)?, b"new");
    let other = fixture.scope.join("renamed-dir");
    fs::rename(&parent, &other)?;
    fs::create_dir(&parent)?;
    assert!(
        fixture
            .guard
            .restore_file(&path, &inspected.fingerprint, slot)
            .is_err()
    );
    assert!(
        fixture
            .guard
            .file_is_quarantined(&path, &inspected.fingerprint, slot)?
    );
    fs::rename(&parent, fixture.scope.join("vacant"))?;
    fs::rename(&other, &parent)?;
    fs::rename(&path, parent.join("new"))?;
    fixture
        .guard
        .restore_file(&path, &inspected.fingerprint, slot)?;
    assert_eq!(fs::read(&path)?, b"original");
    Ok(())
}

#[test]
fn purging_a_terminal_link_preserves_its_target_and_new_original() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let target = fixture.protected.join("kept");
    let link = fixture.scope.join("terminal-link");
    fs::write(&target, b"keep target")?;
    symlink(&target, &link)?;
    let isolated = fixture.guard.inspect_file(&link)?;
    let slot = Uuid::new_v4();
    fixture
        .guard
        .quarantine_file(&link, &isolated.fingerprint, slot)?;
    fs::write(&link, b"keep replacement")?;
    assert!(
        fixture
            .guard
            .can_purge_quarantined(&link, &isolated.fingerprint, slot)?
    );
    fixture
        .guard
        .purge_quarantined(&link, &isolated.fingerprint, slot)?;
    assert!(
        !fixture
            .guard
            .file_is_quarantined(&link, &isolated.fingerprint, slot)?
    );
    assert_eq!(fs::read(&target)?, b"keep target");
    assert_eq!(fs::read(&link)?, b"keep replacement");
    Ok(())
}

#[test]
fn purging_refuses_replacement_of_the_quarantine_slot() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let original = fixture.scope.join("regular");
    fs::write(&original, b"keep original")?;
    let isolated = fixture.guard.inspect_file(&original)?;
    let slot = Uuid::new_v4();
    let backup = fixture
        .guard
        .file_backup_path(&original, &isolated.fingerprint, slot)?;
    fixture
        .guard
        .quarantine_file(&original, &isolated.fingerprint, slot)?;
    let moved = backup.with_extension("fixture");
    fs::rename(&backup, &moved)?;
    fs::write(&backup, b"keep replacement")?;
    assert!(
        fixture
            .guard
            .can_purge_quarantined(&original, &isolated.fingerprint, slot)
            .is_err()
    );
    assert!(
        fixture
            .guard
            .purge_quarantined(&original, &isolated.fingerprint, slot)
            .is_err()
    );
    assert_eq!(fs::read(&moved)?, b"keep original");
    assert_eq!(fs::read(&backup)?, b"keep replacement");
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn extended_acl_shared_writes_make_owned_objects_read_only() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let parent = fixture.scope.join("own-dir");
    fs::create_dir(&parent)?;
    let file = parent.join("example");
    fs::write(&file, b"fixture")?;
    assert_eq!(fixture.guard.inspect_file(&file)?.access, Access::Allowed);
    let chmod = |path: &Path, entry: &str| -> io::Result<()> {
        let output = std::process::Command::new("/bin/chmod")
            .args(["+a", entry])
            .arg(path)
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other(String::from_utf8_lossy(&output.stderr)));
        }
        Ok(())
    };
    chmod(&parent, "everyone deny delete")?;
    assert_eq!(fixture.guard.inspect_file(&file)?.access, Access::Allowed);
    chmod(&file, "everyone allow write")?;
    assert!(matches!(
        fixture.guard.inspect_file(&file)?.access,
        Access::ReadOnly(_)
    ));
    let sibling = parent.join("sibling");
    fs::write(&sibling, b"fixture")?;
    assert_eq!(
        fixture.guard.inspect_file(&sibling)?.access,
        Access::Allowed
    );
    chmod(&parent, "everyone allow add_file")?;
    assert!(matches!(
        fixture.guard.inspect_file(&sibling)?.access,
        Access::ReadOnly(_)
    ));
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn a_differently_normalized_path_cannot_reach_a_protected_inode() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let protected = fixture.scope.join("Prótécted");
    fs::create_dir(&protected)?;
    fs::write(protected.join("kept"), b"protected")?;
    let mut guard = fixture.guard;
    guard
        .protected_nodes
        .push(native::protected_id(&protected)?);
    guard.protected.push(protected);
    let alias = fixture.scope.join("Pro\u{301}te\u{301}cted/kept");
    assert_eq!(guard.read_regular(&alias, 9)?, b"protected");
    assert!(matches!(
        guard.inspect_file(&alias)?.access,
        Access::ReadOnly(_)
    ));
    Ok(())
}

#[test]
fn journals_are_lazy_private_and_refuse_replacements() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let id = Uuid::new_v4();
    assert!(fixture.guard.read(id, Artifact::Manifest)?.is_none());
    assert!(fixture.guard.manifests()?.is_empty());
    assert!(!fixture.state.exists());
    fixture.guard.create(id, Artifact::Manifest, b"first")?;
    assert!(
        fixture
            .guard
            .create(id, Artifact::Manifest, b"second")
            .is_err()
    );
    assert_eq!(
        fixture.guard.read(id, Artifact::Manifest)?.as_deref(),
        Some(b"first".as_slice())
    );
    assert_eq!(fixture.guard.manifests()?, vec![id]);
    assert_eq!(
        fs::metadata(&fixture.state)?.permissions().mode() & 0o077,
        0
    );
    let artifact = fixture.guard.location(id, Artifact::Manifest);
    assert_eq!(fs::metadata(&artifact)?.permissions().mode() & 0o077, 0);
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn reopening_the_journal_with_user_launch_agents_preserves_access() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let previous = Uuid::new_v4();
    fixture
        .guard
        .create(previous, Artifact::Event, b"previous")?;

    let home = fixture.guard.home.clone();
    let launch_agents = home.join("Library/LaunchAgents");
    let reopened = UnixFiles::with_account(
        vec![home.clone(), launch_agents],
        vec![fixture.protected],
        fixture.state,
        home,
        fixture.guard.uid,
    )?
    .with_user_launch_agents()?;

    reopened.create(Uuid::new_v4(), Artifact::Event, b"current")?;
    assert_eq!(
        reopened.read(previous, Artifact::Event)?.as_deref(),
        Some(b"previous".as_slice())
    );
    assert!(matches!(
        reopened
            .inspect_file(&reopened.location(previous, Artifact::Event))?
            .access,
        Access::ReadOnly(_)
    ));
    Ok(())
}

#[test]
fn bounded_reads_distinguish_metadata_files_from_large_prefix_sources() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let executable = fixture.scope.join("example");
    fs::write(&executable, b"header-rest")?;
    assert_eq!(fixture.guard.read_prefix(&executable, 6)?, b"header");
    assert!(fixture.guard.read_regular(&executable, 6).is_err());
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn observed_prefix_identifies_the_regular_file_and_refuses_a_link() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let report = fixture.scope.join("report.ips");
    let link = fixture.scope.join("link.ips");
    fs::write(&report, b"header-body")?;
    symlink(&report, &link)?;
    let (prefix, observed) = fixture
        .guard
        .read_macos_observed_regular_prefix(&report, 6)?;
    assert_eq!(prefix, b"header");
    assert_eq!(observed.access, Access::Allowed);
    assert_eq!(
        fixture.guard.inspect_file(&report)?.fingerprint,
        observed.fingerprint
    );
    assert!(
        fixture
            .guard
            .read_macos_observed_regular_prefix(&link, 6)
            .is_err()
    );
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn only_exact_private_webkit_website_data_can_be_quarantined() -> io::Result<()> {
    let mut fixture = Fixture::new()?;
    let root = fixture.guard.home.join("Library/WebKit");
    fixture.guard.roots.push(root.clone());
    let files = fixture.guard.with_macos_webkit_website_data()?;
    let application = root.join("org.example.Browser");
    let website_data = application.join("WebsiteData");
    let named_store = application.join("WebsiteDataStore");
    let global_store = root.join("WebsiteData");
    let linked_data = root.join("org.example.Linked/WebsiteData");
    for directory in [&website_data, &named_store, &global_store] {
        fs::create_dir_all(directory)?;
    }
    fs::create_dir_all(parent_path(&linked_data)?)?;
    symlink(&global_store, &linked_data)?;
    let database = website_data.join("storage");
    fs::write(&database, b"website data")?;

    for path in [
        &application,
        &named_store,
        &global_store,
        &linked_data,
        &database,
    ] {
        assert!(matches!(
            files.inspect_file(path)?.access,
            Access::ReadOnly(_)
        ));
    }
    let reviewed = files.inspect_macos_webkit_website_data(&website_data)?;
    assert_eq!(reviewed.access, Access::Allowed);
    let slot = Uuid::new_v4();
    files.quarantine_file(&website_data, &reviewed.fingerprint, slot)?;
    assert!(!website_data.exists());
    assert!(named_store.is_dir() && global_store.is_dir());
    files.restore_file(&website_data, &reviewed.fingerprint, slot)?;
    assert_eq!(fs::read(database)?, b"website data");
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn only_exact_sandbox_webkit_default_website_data_can_be_quarantined() -> io::Result<()> {
    let mut fixture = Fixture::new()?;
    let user_webkit = fixture.guard.home.join("Library/WebKit");
    let containers = fixture.guard.home.join("Library/Containers");
    fs::create_dir_all(&user_webkit)?;
    fixture
        .guard
        .roots
        .extend([user_webkit, containers.clone()]);
    let files = fixture
        .guard
        .with_macos_sandbox_directories()?
        .with_macos_webkit_website_data()?;
    let identifier = "org.example.Browser";
    let container = containers.join(identifier);
    let webkit = container.join("Data/Library/WebKit");
    let website_data = webkit.join("WebsiteData");
    let named_store = webkit.join("WebsiteDataStore");
    let case_default_name = webkit.join("websitedata");
    let case_webkit = container.join("data/library/webkit");
    let case_store = case_webkit.join("websitedata");
    let case_named = case_webkit.join("websitedatastore");
    let system_store = containers.join("com.apple.Fixture/Data/Library/WebKit/WebsiteData");
    for directory in [
        &website_data,
        &named_store,
        &case_default_name,
        &case_store,
        &case_named,
        &system_store,
    ] {
        fs::create_dir_all(directory)?;
    }
    let data = website_data.join("storage");
    let named_item = named_store.join("named-data");
    let case_item = case_named.join("case-data");
    fs::write(&data, b"default data")?;
    fs::write(&named_item, b"named data")?;
    fs::write(&case_item, b"case data")?;

    for refused in [
        &webkit,
        &data,
        &named_store,
        &named_item,
        &case_default_name,
        &case_store,
        &case_item,
        &system_store,
    ] {
        assert_eq!(files.macos_webkit_website_data_bundle_id(refused), None);
        assert!(files.inspect_macos_webkit_website_data(refused).is_err());
        assert!(matches!(
            files.inspect_file(refused)?.access,
            Access::ReadOnly(_)
        ));
    }
    assert_eq!(
        files.macos_webkit_website_data_bundle_id(&website_data),
        Some(identifier)
    );

    let reviewed = files.inspect_macos_webkit_website_data(&website_data)?;
    assert_eq!(reviewed.access, Access::Allowed);
    let slot = Uuid::new_v4();
    files.quarantine_file(&website_data, &reviewed.fingerprint, slot)?;
    assert!(!website_data.exists());
    assert_eq!(fs::read(&named_item)?, b"named data");
    assert_eq!(fs::read(&case_item)?, b"case data");
    assert!(system_store.is_dir());
    let held = fixture.state.join(QUARANTINE_DIR).join(slot.to_string());
    assert_eq!(fs::read(held.join("storage"))?, b"default data");
    files.restore_file(&website_data, &reviewed.fingerprint, slot)?;
    assert_eq!(fs::read(data)?, b"default data");
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn sandbox_application_support_quarantines_only_the_exact_verified_group() -> io::Result<()> {
    let mut fixture = Fixture::new()?;
    let root = fixture.guard.home.join("Library/Containers");
    fixture.guard.roots.push(root.clone());
    let files = fixture.guard.with_macos_sandbox_directories()?;
    let identifier = "org.example.Editor";
    let container = root.join(identifier);
    let support = container.join("Data/Library/Application Support");
    let application = support.join(identifier);
    let nested = application.join("Store");
    let mismatched = support.join("org.example.Other");
    let system_identifier = "com.apple.Fixture";
    let system = root
        .join(system_identifier)
        .join("Data/Library/Application Support")
        .join(system_identifier);
    for directory in [&nested, &mismatched, &system] {
        fs::create_dir_all(directory)?;
    }
    for refused in [&container, &support, &nested, &mismatched, &system] {
        assert_eq!(
            files.macos_sandbox_application_support_bundle_id(refused),
            None
        );
        assert!(
            files
                .inspect_macos_sandbox_application_support(refused)
                .is_err()
        );
        assert!(matches!(
            files.inspect_file(refused)?.access,
            Access::ReadOnly(_)
        ));
    }
    assert_eq!(
        files.macos_sandbox_application_support_bundle_id(&application),
        Some(identifier)
    );

    let database = nested.join("data.sqlite");
    let wal = nested.join("data.sqlite-wal");
    fs::write(&database, b"database")?;
    fs::write(&wal, b"wal")?;
    let before_link = files.inspect_macos_sandbox_application_support(&application)?;
    assert_eq!(before_link.access, Access::Allowed);
    let outside = fixture.protected.join("outside");
    let link = nested.join("linked-data");
    fs::write(&outside, b"preserved")?;
    symlink(&outside, &link)?;

    let slot = Uuid::new_v4();
    let held = fixture.state.join(QUARANTINE_DIR).join(slot.to_string());
    assert!(
        files
            .inspect_macos_sandbox_application_support(&application)
            .is_err()
    );
    assert!(
        files
            .quarantine_file(&application, &before_link.fingerprint, slot)
            .is_err()
    );
    assert!(application.is_dir());
    assert!(!held.exists());
    assert_eq!(fs::read_link(&link)?, outside);
    assert_eq!(fs::read(&outside)?, b"preserved");
    fs::remove_file(&link)?;

    let reviewed = files.inspect_macos_sandbox_application_support(&application)?;
    assert_eq!(reviewed.access, Access::Allowed);
    files.quarantine_file(&application, &reviewed.fingerprint, slot)?;
    assert!(!application.exists());
    assert!(mismatched.is_dir() && system.is_dir());
    assert_eq!(fs::read(held.join("Store/data.sqlite"))?, b"database");
    assert_eq!(fs::read(held.join("Store/data.sqlite-wal"))?, b"wal");
    files.restore_file(&application, &reviewed.fingerprint, slot)?;
    assert!(!held.exists());
    assert_eq!(fs::read(database)?, b"database");
    assert_eq!(fs::read(wal)?, b"wal");
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn http_storage_is_quarantined_as_one_verified_database() -> io::Result<()> {
    let mut fixture = Fixture::new()?;
    let root = fixture.guard.home.join("Library/HTTPStorages");
    fixture.guard.roots.push(root.clone());
    let files = fixture.guard.with_macos_http_storage()?;
    let application = root.join("org.example.Browser");
    let absent_database = root.join("org.example.NoDatabase");
    let linked_database = root.join("org.example.Linked");
    let system_application = root.join("com.apple.Safari");
    for directory in [
        &application,
        &absent_database,
        &linked_database,
        &system_application,
    ] {
        fs::create_dir_all(directory)?;
    }
    let database = application.join("httpstorages.sqlite");
    let wal = application.join("httpstorages.sqlite-wal");
    fs::write(&database, b"database")?;
    fs::write(&wal, b"wal")?;
    fs::write(absent_database.join("httpstorages.sqlite-shm"), b"shm")?;
    fs::write(system_application.join("httpstorages.sqlite"), b"protected")?;
    symlink(&database, linked_database.join("httpstorages.sqlite"))?;

    for path in [
        &root,
        &absent_database,
        &linked_database,
        &system_application,
    ] {
        assert!(matches!(
            files.inspect_file(path)?.access,
            Access::ReadOnly(_)
        ));
    }

    let reviewed = files.inspect_macos_http_storage(&application)?;
    let extra = application.join("other-data");
    fs::write(&extra, b"keep")?;
    let slot = Uuid::new_v4();
    assert!(
        files
            .quarantine_file(&application, &reviewed.fingerprint, slot)
            .is_err()
    );
    assert_eq!(fs::read(&extra)?, b"keep");
    fs::remove_file(extra)?;

    let reviewed = files.inspect_macos_http_storage(&application)?;
    assert_eq!(reviewed.access, Access::Allowed);
    files.quarantine_file(&application, &reviewed.fingerprint, slot)?;
    assert!(!application.exists());
    files.restore_file(&application, &reviewed.fingerprint, slot)?;
    assert_eq!(fs::read(database)?, b"database");
    assert_eq!(fs::read(wal)?, b"wal");
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn missing_bundle_metadata_does_not_hide_an_occupied_quarantine_slot() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let guard = fixture
        .guard
        .with_application_roots(vec![fixture.scope.clone()])?;
    let bundle = fixture.scope.join("Example.app");
    let contents = bundle.join("Contents");
    fs::create_dir_all(&contents)?;
    fs::write(contents.join("Info.plist"), b"fixture metadata")?;
    let reviewed = guard.inspect_file(&bundle)?;
    assert_eq!(reviewed.access, Access::Allowed);
    let slot = Uuid::new_v4();
    guard.quarantine_file(&bundle, &reviewed.fingerprint, slot)?;
    let held = fixture.state.join(QUARANTINE_DIR).join(slot.to_string());
    fs::rename(
        held.join("Contents/Info.plist"),
        held.join("unverified-info"),
    )?;
    assert!(
        guard
            .file_is_quarantined(&bundle, &reviewed.fingerprint, slot)
            .is_err()
    );
    assert!(held.is_dir());
    assert!(!bundle.exists());
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn only_the_complete_verified_app_bundle_can_be_quarantined_and_restored() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let guard = fixture
        .guard
        .with_application_roots(vec![fixture.scope.clone()])?;
    let bundle = fixture.scope.join("Example.app");
    let contents = bundle.join("Contents");
    let resources = contents.join("Resources");
    fs::create_dir_all(&resources)?;
    fs::write(contents.join("Info.plist"), b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>org.example.Stub</string></dict></plist>")?;
    let asset = resources.join("data");
    fs::write(&asset, b"bundle asset")?;
    let outside = fixture.protected.join("outside");
    fs::write(&outside, b"outside")?;
    symlink(&outside, resources.join("external-link"))?;
    assert!(matches!(
        guard.inspect_file(&asset)?.access,
        Access::ReadOnly(_)
    ));
    assert!(matches!(
        guard.inspect_file(&resources)?.access,
        Access::ReadOnly(_)
    ));
    let original = guard.inspect_file(&bundle)?;
    assert_eq!(original.access, Access::Allowed);
    fs::write(&asset, b"changed asset")?;
    assert!(
        guard
            .quarantine_file(&bundle, &original.fingerprint, Uuid::new_v4())
            .is_err()
    );
    assert!(bundle.exists());
    let verified = guard.inspect_file(&bundle)?;
    assert_eq!(verified.access, Access::Allowed);
    let slot = Uuid::new_v4();
    guard.quarantine_file(&bundle, &verified.fingerprint, slot)?;
    assert!(!bundle.exists());
    assert_eq!(fs::read(&outside)?, b"outside");
    assert!(guard.file_is_quarantined(&bundle, &verified.fingerprint, slot)?);
    let quarantine = guard.open_store(QUARANTINE_DIR, false)?;
    let expiry = guard.can_purge_quarantined(&bundle, &verified.fingerprint, slot);
    if native::require_apfs(&quarantine).is_ok() {
        assert!(expiry?);
    } else {
        assert!(expiry.is_err());
    }
    // Exercise refusal using an unknown slot. The verified backup is still
    // needed for the restore assertions below.
    assert!(
        guard
            .purge_quarantined(&bundle, &verified.fingerprint, Uuid::new_v4())
            .is_err()
    );
    guard.restore_file(&bundle, &verified.fingerprint, slot)?;
    assert_eq!(fs::read(&asset)?, b"changed asset");
    assert_eq!(fs::read_link(resources.join("external-link"))?, outside);
    Ok(())
}
