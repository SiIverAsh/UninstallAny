use std::{
    collections::HashSet,
    ffi::OsStr,
    io,
    path::{Path, PathBuf},
};

use uninstallany_core::{
    Access, AppRecord, Cancellation, Category, Error, Inventory, MatchKind, Proposal, Result, Risk,
    Scan, ScanMode, Target, match_name,
};
use uninstallany_unix::UnixFiles;

use crate::{
    desktop::{appimage_name, has_appimage_magic, read_launcher},
    inventory::{Source, app_id_from_ref},
    paths::LinuxPaths,
};

const MAX_PROPOSALS: usize = 4_000;
const DESCENT_LIMIT: usize = 5;
const SERVICE_SUFFIXES: &[&str] = &["service", "socket", "timer", "path", "automount", "mount"];
const LINK_OWNER_UNKNOWN: &str = "startup or service identity has not been independently verified";
const APP_COMPETITOR: &str = "the data path may also belong to another installed application";
const APPIMAGE_OWNER_UNKNOWN: &str = "the AppImage path does not establish ownership of its data";
const FLATPAK_DATA_REASON: &str = "Flatpak application ID identifies the sandbox directory";

pub(crate) fn application(
    app: &AppRecord,
    mode: ScanMode,
    files: &UnixFiles,
    paths: &LinuxPaths,
    inventory: &Inventory,
    cancel: &Cancellation,
) -> Result<Scan> {
    let Some((source, id)) = Source::identify(&app.id) else {
        return Err(Error::Rejected("unknown Linux application source".into()));
    };
    let mut scan = Scanner {
        files,
        cancel,
        scan: Scan::default(),
        seen: HashSet::new(),
    };
    scan.add_artifact(app, paths, source, mode)?;
    let match_names = SearchTerms::new(app, source, id);
    let shared = scan.is_shared(app, inventory, &match_names);
    let still_registered = match_names.namespace.is_some()
        && inventory
            .applications
            .iter()
            .any(|installed| installed.id == app.id);
    let data_access = if !inventory.warnings.is_empty() {
        Access::ReadOnly(
            "application ownership could not be confirmed from package inventory".into(),
        )
    } else if shared {
        Access::ReadOnly(APP_COMPETITOR.into())
    } else if still_registered {
        Access::ReadOnly("the Flatpak application is still installed".into())
    } else if match_names.namespace.is_some() {
        Access::ReadOnly("name-based Flatpak residuals do not establish data ownership".into())
    } else if source == Source::AppImage {
        Access::ReadOnly(APPIMAGE_OWNER_UNKNOWN.into())
    } else if matches!(source, Source::Dpkg | Source::Rpm | Source::Pacman) {
        Access::ReadOnly("the package name does not establish ownership of personal data".into())
    } else {
        Access::Allowed
    };
    scan.scan_user_data(app, paths, source, &match_names, data_access, shared)?;
    for (directories, kind) in [
        (paths.desktop_dirs.as_slice(), Category::Shortcut),
        (paths.autostart_dirs.as_slice(), Category::Startup),
        (paths.service_dirs.as_slice(), Category::Service),
    ] {
        scan.scan_registrations(directories, &match_names, kind)?;
    }
    for directory in &paths.system_settings_dirs {
        scan.scan_names(
            directory,
            &match_names,
            &Access::ReadOnly("system or package-managed location".into()),
            false,
        )?;
    }
    Ok(scan.scan)
}

pub(crate) fn add_verified_appimage_launcher(scan: &mut Scan, path: PathBuf, fingerprint: String) {
    let target = Target::File(path.clone());
    // Replace only the generic name hint. Other discovery restrictions still
    // participate in the core's deduplication and can veto a move.
    scan.proposals.retain(|proposal| {
        !(proposal.target == target
            && proposal.category == Category::Shortcut
            && matches!(&proposal.access, Access::ReadOnly(reason) if reason == LINK_OWNER_UNKNOWN))
    });
    if scan.proposals.len() >= MAX_PROPOSALS {
        return;
    }
    scan.require_post_uninstall_file_guard(path);
    scan.push_observed(
        Proposal {
            target,
            category: Category::Shortcut,
            evidence: MatchKind::ExactIdentity,
            reason: "this desktop entry points directly to the same AppImage as before uninstall"
                .into(),
            risk: Risk::Normal,
            access: Access::Allowed,
        },
        fingerprint,
    );
}

#[cfg(target_os = "linux")]
pub(crate) fn add_verified_flatpak_directory(scan: &mut Scan, path: PathBuf, fingerprint: String) {
    let target = Target::File(path.clone());
    scan.proposals.retain(|proposal| {
        !(proposal.target == target
            && proposal.category == Category::Directory
            && proposal.reason == FLATPAK_DATA_REASON)
    });
    if scan.proposals.len() >= MAX_PROPOSALS {
        return;
    }
    scan.require_post_uninstall_file_guard(path);
    scan.push_observed(
        Proposal {
            target,
            category: Category::Directory,
            evidence: MatchKind::ExactIdentity,
            reason: "the same Flatpak sandbox data directory was observed before uninstall; it can contain user files".into(),
            risk: Risk::High,
            access: Access::Allowed,
        },
        fingerprint,
    );
}

pub(crate) fn portable(
    directory: &Path,
    files: &UnixFiles,
    paths: &LinuxPaths,
    installed: &Inventory,
    cancel: &Cancellation,
) -> Result<Scan> {
    require_portable_scope(directory, paths, installed)?;
    let mut scanner = Scanner {
        files,
        cancel,
        scan: Scan::default(),
        seen: HashSet::new(),
    };
    // The store anchors traversal and refuses non-directories and symlink
    // parents. A portable path is specific to this user-approved review.
    files.list(directory)?;
    scanner.tree(
        directory.into(),
        MatchKind::AppName,
        "inside the explicitly selected portable application directory",
        &Access::Allowed,
        Risk::High,
    )?;
    Ok(scanner.scan)
}

fn require_portable_scope(
    directory: &Path,
    paths: &LinuxPaths,
    installed: &Inventory,
) -> Result<()> {
    let user_home = &paths.home;
    let collections = [
        user_home,
        &paths.config,
        &paths.data,
        &paths.cache,
        &user_home.join(".local"),
        &user_home.join(".local/bin"),
        &user_home.join("bin"),
    ];
    let managed_trees = [
        &paths.flatpak_data,
        &paths.snap_data,
        &paths.data.join("flatpak"),
        &paths.state,
    ];
    // Applications can have dedicated directories below a collection.
    // Managed trees can contain registrations or data owned elsewhere.
    let contains_collection = collections
        .into_iter()
        .chain(&paths.appimages)
        .any(|root| root.starts_with(directory));
    let overlaps_managed_tree = managed_trees
        .into_iter()
        .chain(&paths.desktop_dirs)
        .chain(&paths.autostart_dirs)
        .chain(&paths.service_dirs)
        .any(|root| directory.starts_with(root) || root.starts_with(directory));
    if !directory.starts_with(user_home) || contains_collection || overlaps_managed_tree {
        return Err(Error::Rejected(
            "choose a specific personal app directory outside shared or managed locations".into(),
        ));
    }
    if !installed.warnings.is_empty() {
        return Err(Error::Rejected(
            "the installed application inventory is incomplete; portable ownership cannot be verified"
                .into(),
        ));
    }
    if installed.applications.iter().any(|app| {
        app.install_location
            .as_ref()
            .is_some_and(|path| path.starts_with(directory) || directory.starts_with(path))
    }) {
        return Err(Error::Rejected(
            "the portable directory overlaps an application already in the inventory".into(),
        ));
    }
    Ok(())
}

struct SearchTerms<'a> {
    display: &'a str,
    publisher: Option<&'a str>,
    native_name: Option<&'a str>,
    namespace: Option<&'a str>,
}

impl<'a> SearchTerms<'a> {
    fn new(app: &'a AppRecord, source: Source, identity: &'a str) -> Self {
        let namespace = match source {
            Source::FlatpakUser | Source::FlatpakSystem => app_id_from_ref(identity),
            _ => None,
        };
        let native_name = match source {
            Source::Dpkg => identity.split_once(':').map(|(name, _)| name),
            Source::Rpm => identity
                .split_once('=')
                .and_then(|(name_arch, _)| name_arch.rsplit_once('.'))
                .map(|(name, _)| name),
            Source::Pacman | Source::Snap => Some(identity),
            _ => namespace,
        };
        Self {
            display: &app.name,
            publisher: app.publisher.as_deref(),
            native_name,
            namespace,
        }
    }

    fn name(&self, leaf: &str, publisher: Option<&str>) -> Option<MatchKind> {
        let display = match_name(self.display, self.publisher, leaf, publisher);
        let native = self
            .native_name
            .and_then(|name| match_name(name, self.publisher, leaf, publisher));
        display.max(native)
    }
}

struct Scanner<'a> {
    files: &'a UnixFiles,
    cancel: &'a Cancellation,
    scan: Scan,
    seen: HashSet<PathBuf>,
}

impl Scanner<'_> {
    fn add_artifact(
        &mut self,
        app: &AppRecord,
        paths: &LinuxPaths,
        source: Source,
        mode: ScanMode,
    ) -> Result<()> {
        let Some(path) = app.install_location.as_ref() else {
            return Ok(());
        };
        if source == Source::AppImage
            && mode != ScanMode::AfterOfficialUninstall
            && appimage_name(path)
            && paths
                .appimages
                .iter()
                .any(|directory| path.parent() == Some(directory.as_path()))
            && has_appimage_magic(&self.files.read_prefix(path, 11)?)
        {
            self.add(
                path.clone(),
                Category::File,
                MatchKind::ExactIdentity,
                "verified AppImage binary at its enumerated path",
                Risk::Normal,
                Access::ReadOnly("use the AppImage uninstall review to move the binary".into()),
            );
        } else if source == Source::Desktop {
            let access = match read_launcher(self.files, path)? {
                Some(launcher)
                    if launcher.flatpak_id.is_none()
                        && launcher.snap_id.is_none()
                        && path.parent() == Some(paths.data.join("applications").as_path()) =>
                {
                    Access::Allowed
                }
                _ => Access::ReadOnly(
                    "the launcher can belong to a package or shared desktop directory".into(),
                ),
            };
            self.add(
                path.clone(),
                Category::Shortcut,
                MatchKind::ExactIdentity,
                "enumerated desktop launcher",
                Risk::High,
                access,
            );
        }
        Ok(())
    }

    fn is_shared(
        &mut self,
        app: &AppRecord,
        inventory: &Inventory,
        terms: &SearchTerms<'_>,
    ) -> bool {
        self.scan
            .warnings
            .extend(inventory.warnings.iter().cloned());
        shared_inventory(app, inventory, terms)
    }

    fn scan_user_data(
        &mut self,
        app: &AppRecord,
        paths: &LinuxPaths,
        source: Source,
        terms: &SearchTerms<'_>,
        access: Access,
        shared: bool,
    ) -> Result<()> {
        if let Some(namespace) = terms.namespace {
            let sandbox_data = paths.flatpak_data.join(namespace);
            match self.files.list(&sandbox_data) {
                Ok(_) => {
                    self.add(
                        sandbox_data,
                        Category::Directory,
                        MatchKind::ExactIdentity,
                        FLATPAK_DATA_REASON,
                        Risk::High,
                        Access::ReadOnly(
                            "the sandbox directory needs verified pre-uninstall evidence".into(),
                        ),
                    );
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => self.warning(&sandbox_data, &error),
            }
        }
        if source == Source::Snap {
            let Some((_, identity)) = Source::identify(&app.id) else {
                return Ok(());
            };
            let path = paths.snap_data.join(identity);
            if self.files.list(&path).is_ok() {
                self.add(
                    path,
                    Category::Directory,
                    MatchKind::ExactIdentity,
                    "Snap app-data directory",
                    Risk::High,
                    Access::ReadOnly("Snap manages data snapshots for this directory".into()),
                );
            }
        }
        for directory in [&paths.config, &paths.data, &paths.cache] {
            self.scan_names(directory, terms, &access, !shared)?;
        }
        Ok(())
    }

    fn scan_names(
        &mut self,
        directory: &Path,
        terms: &SearchTerms<'_>,
        access: &Access,
        can_descend: bool,
    ) -> Result<()> {
        let entries = self.children(directory);
        for child in entries {
            self.cancel.check()?;
            if self.scan.proposals.len() >= MAX_PROPOSALS {
                break;
            }
            let Some(name) = child.file_name().and_then(OsStr::to_str) else {
                continue;
            };
            let Some(evidence) = terms.name(name, None).or_else(|| {
                let stem = child.file_stem().and_then(OsStr::to_str)?;
                terms.name(stem, None)
            }) else {
                continue;
            };
            if evidence >= MatchKind::AppName && can_descend {
                self.tree(
                    child,
                    evidence,
                    "strict application-name match in an app-data directory",
                    access,
                    Risk::High,
                )?;
            } else {
                let category = self.category(&child);
                let access = match access {
                    Access::Allowed => {
                        Access::ReadOnly("fuzzy name is insufficient to authorize cleanup".into())
                    }
                    read_only => read_only.clone(),
                };
                self.add(
                    child,
                    category,
                    evidence,
                    "application name matches the directory entry",
                    Risk::High,
                    access,
                );
            }
        }
        Ok(())
    }

    fn scan_registrations(
        &mut self,
        directories: &[PathBuf],
        terms: &SearchTerms<'_>,
        kind: Category,
    ) -> Result<()> {
        for directory in directories {
            let entries = self.children(directory);
            for path in entries {
                self.cancel.check()?;
                if self.scan.proposals.len() >= MAX_PROPOSALS {
                    return Ok(());
                }
                let Some(extension) = path.extension().and_then(OsStr::to_str) else {
                    continue;
                };
                let Ok(stem) = path.file_stem().unwrap_or_default().to_str().ok_or(()) else {
                    continue;
                };
                let evidence = match kind {
                    Category::Shortcut | Category::Startup if extension == "desktop" => {
                        match read_launcher(self.files, &path) {
                            Ok(Some(launcher))
                                if terms.namespace.is_some()
                                    && launcher.flatpak_id.as_deref() == terms.namespace =>
                            {
                                Some(MatchKind::ExactIdentity)
                            }
                            Ok(Some(launcher)) => {
                                terms.name(&launcher.name, None).max(terms.name(stem, None))
                            }
                            _ => terms.name(stem, None),
                        }
                    }
                    Category::Service if SERVICE_SUFFIXES.contains(&extension) => {
                        terms.name(stem, None)
                    }
                    _ => None,
                };
                if let Some(evidence) = evidence {
                    self.add(
                        path,
                        kind,
                        evidence,
                        "matching launcher, autostart entry or systemd unit",
                        Risk::High,
                        Access::ReadOnly(LINK_OWNER_UNKNOWN.into()),
                    );
                }
            }
        }
        Ok(())
    }

    fn tree(
        &mut self,
        root: PathBuf,
        evidence: MatchKind,
        reason: &str,
        access: &Access,
        risk: Risk,
    ) -> Result<()> {
        let mut pending = vec![(root, 0)];
        while let Some((path, depth)) = pending.pop() {
            self.cancel.check()?;
            let remaining = MAX_PROPOSALS.saturating_sub(self.scan.proposals.len());
            if remaining == 0 {
                self.scan.warnings.push(format!(
                    "residual scan capped at {MAX_PROPOSALS} candidates"
                ));
                break;
            }
            let listed = self.files.list(&path);
            let evidence = if depth > 0 && evidence == MatchKind::ExactIdentity {
                // An exact sandbox identifier establishes the namespace, not
                // ownership of individual documents stored beneath it.
                MatchKind::AppName
            } else {
                evidence
            };
            if let Ok(children) = listed {
                self.add(
                    path.clone(),
                    Category::Directory,
                    evidence,
                    reason,
                    risk,
                    Access::ReadOnly(
                        "directory retained; individual children can be reviewed".into(),
                    ),
                );
                if depth < DESCENT_LIMIT {
                    let budget = remaining.saturating_sub(pending.len()).saturating_sub(1);
                    pending.extend(
                        children
                            .into_iter()
                            .rev()
                            .take(budget)
                            .map(|child| (child, depth + 1)),
                    );
                } else if !children.is_empty() {
                    self.scan
                        .warnings
                        .push(format!("depth limit at {}", path.display()));
                }
            } else {
                self.add(path, Category::File, evidence, reason, risk, access.clone());
            }
        }
        Ok(())
    }

    fn children(&mut self, directory: &Path) -> Vec<PathBuf> {
        match self.files.list(directory) {
            Ok(children) => children,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => {
                self.warning(directory, &error);
                Vec::new()
            }
        }
    }

    fn category(&self, path: &Path) -> Category {
        if self.files.list(path).is_ok() {
            Category::Directory
        } else {
            Category::File
        }
    }

    fn add(
        &mut self,
        path: PathBuf,
        category: Category,
        evidence: MatchKind,
        reason: &str,
        risk: Risk,
        access: Access,
    ) {
        if self.seen.insert(path.clone()) {
            self.scan.proposals.push(Proposal {
                target: Target::File(path),
                category,
                evidence,
                reason: reason.into(),
                risk,
                access,
            });
        }
    }

    fn warning(&mut self, path: &Path, error: &io::Error) {
        self.scan
            .warnings
            .push(format!("{}: {error}", path.display()));
    }
}

fn shared_inventory(app: &AppRecord, inventory: &Inventory, terms: &SearchTerms<'_>) -> bool {
    !inventory.warnings.is_empty()
        || inventory.applications.iter().any(|other| {
            if other.id == app.id {
                return false;
            }
            if let Some(namespace) = terms.namespace {
                return Source::identify(&other.id).and_then(|(source, reference)| {
                    source
                        .flatpak_scope()
                        .and_then(|_| app_id_from_ref(reference))
                }) == Some(namespace);
            }
            terms
                .name(&other.name, other.publisher.as_deref())
                .is_some_and(|evidence| evidence >= MatchKind::AppName)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::record;

    #[test]
    fn portable_directory_requires_complete_inventory() {
        let paths = LinuxPaths::from_home(PathBuf::from("/portable-test-home"));
        let selected = paths.home.join("Applications/Editor");
        let inventory = Inventory {
            warnings: vec!["package inventory timed out".into()],
            ..Inventory::default()
        };
        assert!(matches!(
            require_portable_scope(&selected, &paths, &inventory),
            Err(Error::Rejected(reason)) if reason.contains("inventory is incomplete")
        ));
    }

    #[test]
    fn portable_scope_preserves_app_collections_and_managed_trees() {
        let mut paths = LinuxPaths::from_home(PathBuf::from("/portable-test-home"));
        let inventory = Inventory::default();
        let redirected = paths.home.join("redirected");
        paths.desktop_dirs.push(redirected.join("desktop/managed"));
        paths
            .autostart_dirs
            .push(redirected.join("autostart/managed"));
        paths.service_dirs.push(redirected.join("service/managed"));
        for name in ["desktop", "autostart", "service"] {
            let parent = redirected.join(name);
            let managed = parent.join("managed");
            for selected in [parent, managed.join("vendor"), managed] {
                assert!(require_portable_scope(&selected, &paths, &inventory).is_err());
            }
        }
        for collection in &paths.appimages {
            assert!(require_portable_scope(collection, &paths, &inventory).is_err());
        }
        let selected = paths.home.join("Applications/Editor");
        assert!(require_portable_scope(&selected, &paths, &inventory).is_ok());
    }

    #[test]
    fn user_and_system_flatpak_refs_share_one_data_directory() {
        let reference = "app/org.example.Editor/x86_64/stable";
        let application = record(Source::FlatpakUser, reference, "Example Editor");
        let terms = SearchTerms::new(&application, Source::FlatpakUser, reference);
        let mut inventory = Inventory {
            applications: vec![application.clone()],
            warnings: Vec::new(),
        };
        assert!(!shared_inventory(&application, &inventory, &terms));
        inventory.applications.push(record(
            Source::FlatpakSystem,
            reference,
            "Other display name",
        ));
        assert!(shared_inventory(&application, &inventory, &terms));
        inventory.applications.pop();
        inventory.applications.push(record(
            Source::FlatpakUser,
            "app/org.example.Editor/x86_64/beta",
            "Example Editor",
        ));
        assert!(shared_inventory(&application, &inventory, &terms));
    }

    #[test]
    fn unavailable_flatpak_scope_prevents_assuming_exclusive_data() {
        let reference = "app/org.example.Editor/x86_64/stable";
        let application = record(Source::FlatpakUser, reference, "Example Editor");
        let terms = SearchTerms::new(&application, Source::FlatpakUser, reference);
        let mut inventory = Inventory::default();
        assert!(!shared_inventory(&application, &inventory, &terms));
        inventory
            .warnings
            .push("flatpak-system inventory: executable is unavailable".into());
        assert!(shared_inventory(&application, &inventory, &terms));
    }
}
