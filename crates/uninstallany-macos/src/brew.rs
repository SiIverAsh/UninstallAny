use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs::{File, Metadata},
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::SystemTime,
};

use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uninstallany_core::{
    Access, AppId, AppRecord, Cancellation, Category, Error, MatchKind, Proposal, Result, Risk,
    Scan, Target,
};
use uninstallany_unix::{UnixFiles, macos_portable_location};

use crate::bundle::{self, Bundle};

pub(super) const MANAGER: &str = "homebrew-cask";
pub(super) const PREFIXES: [&str; 2] = ["/opt/homebrew", "/usr/local"];
const METADATA_DIR: &str = ".metadata";
const RECEIPT_FILE: &str = "INSTALL_RECEIPT.json";
const CONFIG_FILE: &str = "config.json";
const SYSTEM_APPLICATIONS: &str = "/Applications";
const MAX_METADATA_BYTES: usize = 2 * 1024 * 1024;
const MAX_CASKS: usize = 1_024;
const MAX_METADATA_ENTRIES: usize = 256;
const MAX_REVIEW_APP_TARGETS: usize = 64;
pub(super) const UNINSTALL_UNAVAILABLE: &str = "Homebrew's uninstall command can reload cask definitions and affect dependencies outside this preview.";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CaskId {
    prefix: usize,
    token: String,
    bundle_id: Option<String>,
}

impl CaskId {
    pub(super) fn parse(id: &str) -> Option<Self> {
        let (prefix, rest) = id.split_once(':')?;
        let prefix = prefix.parse::<usize>().ok()?;
        let (token, bundle_id) = rest.split_once(':')?;
        if prefix >= PREFIXES.len() || !valid_token(token) {
            return None;
        }
        let bundle_id = match bundle_id {
            "" => None,
            id if bundle::valid_identifier(id) => Some(id.to_owned()),
            _ => return None,
        };
        Some(Self {
            prefix,
            token: token.into(),
            bundle_id,
        })
    }

    pub(super) fn bundle_id(&self) -> Option<&str> {
        self.bundle_id.as_deref()
    }

    pub(super) fn install_dir(&self) -> PathBuf {
        Path::new(PREFIXES[self.prefix])
            .join("Caskroom")
            .join(&self.token)
    }

    fn as_app_id(&self) -> AppId {
        AppId::Package {
            manager: MANAGER.into(),
            id: format!(
                "{}:{}:{}",
                self.prefix,
                self.token,
                self.bundle_id.as_deref().unwrap_or_default()
            ),
        }
    }
}

#[derive(Deserialize)]
struct Receipt {
    #[serde(default)]
    source: Source,
    uninstall_artifacts: Option<Vec<Value>>,
    uninstall_flight_blocks: Option<bool>,
}

#[derive(Default, Deserialize)]
struct Source {
    version: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemovalSnapshot {
    version: Option<String>,
    artifacts: Option<Vec<Value>>,
    url_specs: Option<EmptyUrlSpecs>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyUrlSpecs {}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct UninstallEvidence {
    pub(super) prefix: &'static str,
    pub(super) token: String,
    pub(super) cask_dir: PathBuf,
    pub(super) snapshot_path: PathBuf,
    pub(super) app_path: PathBuf,
    pub(super) app_dir: PathBuf,
    pub(super) staged_app: PathBuf,
    pub(super) bundle_id: String,
    pub(super) version: String,
    pub(super) snapshot_digest: [u8; 32],
    pub(super) receipt_digest: [u8; 32],
    pub(super) config_digest: [u8; 32],
    directories: Vec<RemovalStamp>,
    app_directory: RemovalStamp,
    app: RemovalStamp,
    records: [RemovalStamp; 3],
    staging_fingerprint: [u8; 32],
    staged_link_identity: (u64, u64),
    app_fingerprint: String,
}

impl UninstallEvidence {
    pub(super) fn directory_identities(&self) -> [(u64, u64); 3] {
        [&self.directories[0], &self.app, &self.app_directory]
            .map(|stamp| (stamp.device, stamp.inode))
    }

    pub(super) fn staged_link_identity(&self) -> (u64, u64) {
        self.staged_link_identity
    }
}

#[derive(Debug, Eq, PartialEq)]
struct RemovalStamp {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl From<Metadata> for RemovalStamp {
    fn from(metadata: Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            mode: metadata.mode(),
            size: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

/// Binds one exact local cask installation and its app tree to native removal.
pub(super) fn prepare_uninstall_evidence(
    files: &UnixFiles,
    home: &Path,
    app: &AppRecord,
    cancel: &Cancellation,
) -> Result<UninstallEvidence> {
    cancel.check()?;
    let AppId::Package { manager, id } = &app.id else {
        return Err(removal_rejected(
            "the selected application is not a Homebrew cask",
        ));
    };
    let id = CaskId::parse(id)
        .filter(|id| manager == MANAGER && !app.system_component && id.as_app_id() == app.id)
        .ok_or_else(|| removal_rejected("the selected Homebrew cask is ineligible"))?;
    let (app_path, bundle_id) = app
        .install_location
        .as_deref()
        .zip(id.bundle_id())
        .ok_or_else(|| removal_rejected("the cask does not identify one installed bundle"))?;

    let cask_dir = id.install_dir();
    let cask_stamp = directory_stamp(files, &cask_dir)?;
    let owner = directory_stamp(files, home)?.owner;
    if owner == 0 || cask_stamp.owner != owner {
        return Err(removal_rejected(
            "the cask is not owned by the ordinary account",
        ));
    }
    let room = Path::new(PREFIXES[id.prefix]).join("Caskroom");
    require_listed_entry(files, &room, &cask_dir)?;

    let metadata = cask_dir.join(METADATA_DIR);
    let metadata_stamp = directory_stamp(files, &metadata)?;
    let receipt_path = metadata.join(RECEIPT_FILE);
    let config_path = metadata.join(CONFIG_FILE);
    let (receipt_bytes, receipt_stamp) = read_removal_file(files, &receipt_path, owner)?;
    let receipt: Receipt = decode_json(&receipt_bytes)?;
    let version = receipt
        .source
        .version
        .as_deref()
        .filter(|version| {
            !version.starts_with(['.', '-'])
                && relative_path(version).is_some_and(|path| path.components().count() == 1)
        })
        .ok_or_else(|| removal_rejected("the cask receipt does not record one literal version"))?;
    let artifact = removal_artifact(&receipt).ok_or_else(|| {
        removal_rejected("the receipt must declare exactly one app without uninstall hooks")
    })?;
    let (source, target) = receipt_app_args(artifact)
        .ok_or_else(|| removal_rejected("the receipt app declaration is invalid"))?;
    let source = literal_app_name(source)
        .ok_or_else(|| removal_rejected("the staged app must be a direct bundle"))?;

    let (config_bytes, config_stamp) = read_removal_file(files, &config_path, owner)?;
    let app_dir = recorded_removal_app_dir(&decode_json(&config_bytes)?, home)
        .ok_or_else(|| removal_rejected("the saved cask config lacks an exact supported appdir"))?;
    let target = target.unwrap_or(source);
    let destination = if target.starts_with('/') {
        resolve_directory(target, home)
    } else {
        literal_app_name(target).map(|name| app_dir.join(name))
    };
    if destination.as_deref().map(Path::as_os_str) != Some(app_path.as_os_str())
        || app_path.parent() != Some(app_dir.as_path())
        || !app_path
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| literal_app_name(name).is_some())
    {
        return Err(removal_rejected(
            "the saved app destination differs from the exact selected bundle",
        ));
    }
    require_listed_entry(files, &app_dir, app_path)?;
    let app_stamp = directory_stamp(files, app_path)?;
    let bundle = bundle::read(files, app_path)?;
    if app_stamp.owner != owner || bundle.is_system() || bundle.identifier != bundle_id {
        return Err(removal_rejected("the cask app bundle identifier changed"));
    }

    let version_dir = metadata.join(version);
    let staged_dir = cask_dir.join(version);
    let timestamp_dir = singleton_child(files, &version_dir)?;
    if timestamp_dir
        .file_name()
        .and_then(OsStr::to_str)
        .and_then(installation_date)
        .is_none()
    {
        return Err(removal_rejected(
            "the cask has no exact timestamped install snapshot",
        ));
    }
    let definitions = timestamp_dir.join("Casks");
    let snapshot_path = definitions.join(format!("{}.json", id.token));
    let staged_app = staged_dir.join(source);
    let directories = [
        &cask_dir,
        &metadata,
        &version_dir,
        &timestamp_dir,
        &definitions,
        &staged_dir,
    ];
    let directory_stamps = directories
        .iter()
        .map(|path| directory_stamp(files, path))
        .collect::<io::Result<Vec<_>>>()?;
    if directory_stamps.iter().any(|entry| entry.owner != owner) {
        return Err(removal_rejected(
            "the cask's local metadata or staging folders have foreign ownership",
        ));
    }
    let app_directory = directory_stamp(files, &app_dir)?;

    require_exact_children(files, &cask_dir, &[&metadata, &staged_dir])?;
    require_exact_children(
        files,
        &metadata,
        &[&receipt_path, &config_path, &version_dir],
    )?;
    require_exact_children(files, &version_dir, &[&timestamp_dir])?;
    require_exact_children(files, &timestamp_dir, &[&definitions])?;
    require_exact_children(files, &definitions, &[&snapshot_path])?;

    let (snapshot_bytes, snapshot_stamp) = read_removal_file(files, &snapshot_path, owner)?;
    let snapshot: RemovalSnapshot = decode_json(&snapshot_bytes)?;
    // Homebrew stages the snapshot, saves the config, then records the receipt.
    // Matching version text alone would also accept metadata from a reinstall.
    if snapshot
        .version
        .as_deref()
        .is_some_and(|observed| observed != version)
        || snapshot
            .artifacts
            .as_deref()
            .is_some_and(|saved| receipt.uninstall_artifacts.as_deref() != Some(saved))
        || snapshot.url_specs.is_some()
        || snapshot_stamp.modified >= config_stamp.modified
        || config_stamp.modified >= receipt_stamp.modified
    {
        return Err(removal_rejected(
            "the cask receipt, configuration, and snapshot must match one installation",
        ));
    }

    let staged_link_identity = require_staged_link(files, &staged_app, app_path)?;
    let staging_fingerprint = files.fingerprint_macos_homebrew_staging(&staged_app)?;
    let app_fingerprint = files.fingerprint_macos_homebrew_application(app_path)?;
    cancel.check()?;
    if directory_stamps[0] != cask_stamp
        || directory_stamps[1] != metadata_stamp
        || directory_stamp(files, &app_dir)? != app_directory
        || directory_stamp(files, app_path)? != app_stamp
        || bundle::read(files, app_path)?.identifier != bundle_id
    {
        return Err(removal_rejected(
            "the cask installation changed during review",
        ));
    }
    for (path, stamp) in directories.iter().zip(&directory_stamps) {
        if directory_stamp(files, path)? != *stamp {
            return Err(removal_rejected(
                "the cask directories changed during review",
            ));
        }
    }
    for (path, expected) in [
        (&receipt_path, &receipt_stamp),
        (&config_path, &config_stamp),
        (&snapshot_path, &snapshot_stamp),
    ] {
        if RemovalStamp::from(files.open_macos_homebrew_regular_file(path)?.metadata()?)
            != *expected
        {
            return Err(removal_rejected("the cask metadata changed during review"));
        }
    }
    if require_staged_link(files, &staged_app, app_path)? != staged_link_identity {
        return Err(removal_rejected(
            "the staged app link changed during review",
        ));
    }

    Ok(UninstallEvidence {
        prefix: PREFIXES[id.prefix],
        token: id.token.clone(),
        cask_dir,
        snapshot_path,
        app_path: app_path.into(),
        app_dir,
        staged_app,
        bundle_id: bundle_id.into(),
        version: version.into(),
        snapshot_digest: Sha256::digest(snapshot_bytes).into(),
        receipt_digest: Sha256::digest(receipt_bytes).into(),
        config_digest: Sha256::digest(config_bytes).into(),
        directories: directory_stamps,
        app_directory,
        app: app_stamp,
        records: [receipt_stamp, config_stamp, snapshot_stamp],
        staging_fingerprint,
        staged_link_identity,
        app_fingerprint,
    })
}

fn removal_artifact(receipt: &Receipt) -> Option<&Value> {
    if receipt.uninstall_flight_blocks != Some(false) {
        return None;
    }
    let mut app = None;
    let mut has_zap = false;
    for artifact in receipt.uninstall_artifacts.as_deref()? {
        if artifact.as_object()?.len() != 1 {
            return None;
        }
        match named_artifact(artifact)? {
            ("app", _) if app.is_none() => {
                receipt_app_args(artifact)?;
                app = Some(artifact);
            }
            // Only the selected app is passed to Homebrew's native action.
            ("zap", args) if !has_zap && declarative_zap(args) => has_zap = true,
            _ => return None,
        }
    }
    app
}

fn declarative_zap(args: &Value) -> bool {
    let Some([Value::Object(options)]) = args.as_array().map(Vec::as_slice) else {
        return false;
    };
    !options.is_empty()
        && options.iter().all(|(key, value)| {
            matches!(key.as_str(), "trash" | "delete" | "rmdir")
                && (value.is_string()
                    || value
                        .as_array()
                        .is_some_and(|items| items.iter().all(Value::is_string)))
        })
}

fn literal_app_name(name: &str) -> Option<&str> {
    let path = relative_path(name)?;
    (!name.starts_with(['.', '~']) && path.components().count() == 1 && bundle::is_app(path))
        .then_some(name)
}

fn recorded_removal_app_dir(config: &Value, home: &Path) -> Option<PathBuf> {
    for scope in ["explicit", "env", "default"] {
        let Some(directory) = config.get(scope)?.as_object()?.get("appdir") else {
            continue;
        };
        let literal = directory.as_str()?;
        let path = resolve_directory(literal, home)?;
        let eligible = path.as_os_str() == OsStr::new(literal)
            && (path == Path::new(SYSTEM_APPLICATIONS) || path == home.join("Applications"));
        return eligible.then_some(path);
    }
    None
}

fn read_removal_file(
    files: &UnixFiles,
    path: &Path,
    owner: u32,
) -> io::Result<(Vec<u8>, RemovalStamp)> {
    let mut file = files.open_macos_homebrew_regular_file(path)?;
    let expected = RemovalStamp::from(file.metadata()?);
    if expected.owner != owner {
        return Err(invalid_metadata(
            "the cask metadata must belong to the ordinary account",
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_METADATA_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_METADATA_BYTES || expected != RemovalStamp::from(file.metadata()?) {
        return Err(invalid_metadata(
            "the cask metadata is oversized or changed during review",
        ));
    }
    Ok((bytes, expected))
}

fn directory_stamp(files: &UnixFiles, path: &Path) -> io::Result<RemovalStamp> {
    let directory = File::from(files.open_macos_homebrew_directory(path)?);
    Ok(directory.metadata()?.into())
}

fn require_listed_entry(files: &UnixFiles, parent: &Path, expected: &Path) -> Result<()> {
    if !files
        .list(parent)?
        .iter()
        .any(|path| path.as_os_str() == expected.as_os_str())
    {
        return Err(removal_rejected(
            "the installation entry is absent or has different spelling",
        ));
    }
    Ok(())
}

fn require_exact_children(files: &UnixFiles, parent: &Path, expected: &[&Path]) -> Result<()> {
    let actual = files.list(parent)?;
    if actual.len() != expected.len()
        || actual.iter().any(|entry| {
            !expected
                .iter()
                .any(|path| entry.as_os_str() == path.as_os_str())
        })
    {
        return Err(removal_rejected(
            "the cask has extra or unverified files within its uninstall scope",
        ));
    }
    Ok(())
}

fn singleton_child(files: &UnixFiles, parent: &Path) -> Result<PathBuf> {
    let mut entries = files.list(parent)?;
    if entries.len() != 1 {
        return Err(removal_rejected(
            "the cask must have a single installed snapshot",
        ));
    }
    entries
        .pop()
        .ok_or_else(|| removal_rejected("the cask install snapshot is missing"))
}

fn require_staged_link(files: &UnixFiles, path: &Path, app: &Path) -> Result<(u64, u64)> {
    files
        .read_macos_homebrew_symlink(path)?
        .filter(|(target, _)| target.as_os_str() == app.as_os_str())
        .map(|(_, identity)| identity)
        .ok_or_else(|| {
            removal_rejected("the staged app link does not identify the exact installed bundle")
        })
}

fn removal_rejected(message: &str) -> Error {
    Error::Rejected(message.into())
}

#[derive(Default, Deserialize)]
struct Definition {
    version: Option<String>,
    artifacts: Option<Vec<Value>>,
    raw_artifacts: Option<Vec<Value>>,
    url_specs: Option<Value>,
    #[serde(default)]
    language_variations: Vec<LanguageVariation>,
    #[serde(default)]
    variations: BTreeMap<String, Definition>,
}

#[derive(Deserialize)]
struct LanguageVariation {
    artifacts: Option<Vec<Value>>,
    #[serde(default)]
    overrides: Definition,
    #[serde(default)]
    value: Value,
}

struct Snapshot {
    version: Option<String>,
    staged_source: Option<StagedSnapshot>,
    install_date: Option<String>,
    definition: Definition,
    internal: bool,
    native_removal_shape: bool,
}

struct StagedSnapshot {
    version: String,
    definition_path: PathBuf,
    definition_digest: [u8; 32],
}

struct CaskMetadata {
    receipt: Option<Receipt>,
    receipt_digest: Option<[u8; 32]>,
    snapshot: Option<Snapshot>,
    config: CaskConfig,
}

enum CaskConfig {
    Missing,
    RecordedAppDir(String),
    UnrecordedEnvironment([u8; 32]),
    Unverifiable,
}

impl CaskMetadata {
    fn app_evidence(
        &self,
        files: &UnixFiles,
        home: &Path,
        cask_dir: &Path,
        cancel: &Cancellation,
    ) -> Result<AppEvidence> {
        let home_applications = home.join("Applications");
        let paths = AppPaths {
            home,
            home_applications: &home_applications,
            app_dir: match &self.config {
                CaskConfig::RecordedAppDir(directory) => Some(directory.as_str()),
                _ => None,
            },
        };
        let mut evidence = AppEvidence::default();
        let mut staged_targets = StagedAppTargets::new();
        if let Some(receipt) = &self.receipt {
            if let Some(artifacts) = receipt
                .uninstall_artifacts
                .as_deref()
                .filter(|artifacts| !artifacts.is_empty())
            {
                evidence.observed = true;
                if let Some(root) = self.staged_root(files, cask_dir, receipt) {
                    staged_targets = evidence
                        .add_receipt_with_staged_links(files, &root, artifacts, &paths, cancel)?;
                    // Homebrew may write config during installation. The
                    // same config, receipt and snapshot must still apply.
                    if !staged_targets.is_empty()
                        && self.staged_root(files, cask_dir, receipt).as_deref()
                            != Some(root.as_path())
                    {
                        evidence.invalid = true;
                        staged_targets.clear();
                    }
                } else {
                    evidence.add(artifacts, ArtifactFormat::Named, &paths, None);
                }
            }
        }
        if let Some(snapshot) = &self.snapshot {
            evidence.add_definition(
                &snapshot.definition,
                snapshot.internal,
                &paths,
                &staged_targets,
            );
        }
        Ok(evidence)
    }

    fn staged_root(
        &self,
        files: &UnixFiles,
        cask_dir: &Path,
        receipt: &Receipt,
    ) -> Option<PathBuf> {
        if receipt.uninstall_flight_blocks != Some(false) {
            return None;
        }
        let snapshot = self.snapshot.as_ref()?;
        let staged = snapshot.staged_source.as_ref()?;
        let version = staged.version.as_str();
        if snapshot.version.as_deref() != Some(version)
            || receipt.source.version.as_deref() != Some(version)
            || snapshot
                .definition
                .artifacts
                .as_ref()
                .is_some_and(Vec::is_empty)
        {
            return None;
        }
        let metadata = cask_dir.join(METADATA_DIR);
        let backup_name = format!("{version}.upgrading");
        if !discovery_entry_absent(files, &cask_dir.join(&backup_name))
            || !discovery_entry_absent(files, &metadata.join(backup_name))
        {
            return None;
        }
        let config_path = metadata.join(CONFIG_FILE);
        let config_modified = match &self.config {
            CaskConfig::Missing if discovery_entry_absent(files, &config_path) => None,
            CaskConfig::UnrecordedEnvironment(digest) => {
                Some(trusted_record_time(files, &config_path, digest)?)
            }
            _ => return None,
        };
        // Homebrew stages the snapshot, installs artifacts and saves config,
        // then writes the receipt. The version alone cannot identify a reinstall.
        let receipt_modified = trusted_record_time(
            files,
            &metadata.join(RECEIPT_FILE),
            self.receipt_digest.as_ref()?,
        )?;
        let snapshot_modified =
            trusted_record_time(files, &staged.definition_path, &staged.definition_digest)?;
        if receipt_modified <= snapshot_modified
            || config_modified.is_some_and(|modified| {
                modified <= snapshot_modified || receipt_modified <= modified
            })
        {
            return None;
        }
        let root = cask_dir.join(version);
        let Some(url_specs) = &snapshot.definition.url_specs else {
            return Some(root);
        };
        match url_specs.as_object()?.get("only_path") {
            Some(Value::String(only_path)) => Some(root.join(relative_path(only_path)?)),
            Some(Value::Null) | None => Some(root),
            _ => None,
        }
    }
}

pub(super) struct Cask {
    id: CaskId,
    version: Option<String>,
    install_date: Option<String>,
    app_targets: BTreeSet<PathBuf>,
    unresolved_app_target: bool,
    native_removal_shape: bool,
}

impl Cask {
    pub(super) fn path(&self) -> Option<&Path> {
        if self.unresolved_app_target || self.app_targets.len() != 1 {
            return None;
        }
        self.app_targets.first().map(PathBuf::as_path)
    }

    pub(super) fn supports_native_removal(&self) -> bool {
        self.native_removal_shape && self.path().is_some()
    }

    pub(super) fn app_paths(&self) -> impl Iterator<Item = &Path> {
        self.app_targets.iter().map(PathBuf::as_path)
    }

    pub(super) fn could_own_bundle(&self, files: &UnixFiles, path: &Path) -> bool {
        self.unresolved_app_target
            || self.app_paths().any(|target| {
                could_contain_bundle(files, target, path)
                    || could_contain_bundle(files, path, target)
            })
    }

    pub(super) fn record(mut self, bundle: Option<&Bundle>) -> AppRecord {
        if let Some(bundle) = bundle {
            self.id.bundle_id = Some(bundle.identifier.clone());
            let mut app = bundle.record();
            app.id = self.id.as_app_id();
            app.version = app.version.or(self.version);
            app.install_date = self.install_date.or(app.install_date);
            return app;
        }
        let install_location = self.path().map(Path::to_path_buf);
        AppRecord {
            name: self.id.token.clone(),
            id: self.id.as_app_id(),
            publisher: None,
            version: self.version,
            install_location,
            size_bytes: None,
            install_date: self.install_date,
            system_component: false,
            official_uninstall_available: false,
        }
    }
}

fn could_contain_bundle(files: &UnixFiles, parent: &Path, child: &Path) -> bool {
    if child.starts_with(parent) {
        return true;
    }
    let parent = match files.local_directory_identity(parent) {
        Ok(identity) => identity,
        Err(error) => return error.kind() != io::ErrorKind::NotFound,
    };
    // Volume rules govern spelling equivalence. Checking each bundle ancestor
    // also protects a cask app nested inside the proposed quarantine directory.
    child
        .ancestors()
        .filter(|ancestor| bundle::is_app(ancestor))
        .any(|ancestor| match files.local_directory_identity(ancestor) {
            Ok(identity) => identity == parent,
            Err(error) => error.kind() != io::ErrorKind::NotFound,
        })
}

pub(super) fn discover(
    files: &UnixFiles,
    home: &Path,
    cancel: &Cancellation,
    warnings: &mut Vec<String>,
) -> Result<Vec<Cask>> {
    let mut found = Vec::new();
    for (prefix, path) in PREFIXES.iter().enumerate() {
        let room = Path::new(path).join("Caskroom");
        let entries = match files.list(&room) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                warnings.push(format!(
                    "could not enumerate Homebrew {}: {error}",
                    room.display()
                ));
                continue;
            }
        };
        if entries.len() > MAX_CASKS {
            warnings.push(format!(
                "Homebrew inventory {} reached its entry limit",
                room.display()
            ));
        }
        for entry in entries.into_iter().take(MAX_CASKS) {
            cancel.check()?;
            let Some(token) = entry
                .file_name()
                .and_then(OsStr::to_str)
                .filter(|name| valid_token(name))
            else {
                continue;
            };
            let id = CaskId {
                prefix,
                token: token.into(),
                bundle_id: None,
            };
            match read(files, home, &entry, id, cancel) {
                Ok(Some(cask)) => found.push(cask),
                Ok(None) => {}
                Err(Error::Cancelled) => return Err(Error::Cancelled),
                Err(error) => {
                    warnings.push(format!("could not read Homebrew cask {token}: {error}"))
                }
            }
        }
    }
    if let Some(cask) = found.iter().find(|cask| cask.unresolved_app_target) {
        warnings.push(format!(
            "Could not determine all application destinations for Homebrew cask {}.",
            cask.id.token
        ));
    }
    Ok(found)
}

fn read(
    files: &UnixFiles,
    home: &Path,
    cask_dir: &Path,
    id: CaskId,
    cancel: &Cancellation,
) -> Result<Option<Cask>> {
    let Some((metadata, evidence)) =
        read_cask_installation(files, home, cask_dir, &id.token, cancel)?
    else {
        return Ok(None);
    };
    let CaskMetadata {
        receipt,
        snapshot,
        config,
        ..
    } = metadata;
    let native_removal_shape = matches!(config, CaskConfig::RecordedAppDir(_))
        && receipt
            .as_ref()
            .is_some_and(|receipt| removal_artifact(receipt).is_some())
        && snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.native_removal_shape);
    let version = snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.version.clone())
        .or_else(|| receipt.and_then(|receipt| receipt.source.version));
    Ok(Some(Cask {
        id,
        version,
        install_date: snapshot.and_then(|snapshot| snapshot.install_date),
        app_targets: evidence.targets,
        unresolved_app_target: evidence.invalid || !evidence.observed,
        native_removal_shape,
    }))
}

fn read_cask_installation(
    files: &UnixFiles,
    home: &Path,
    cask_dir: &Path,
    token: &str,
    cancel: &Cancellation,
) -> Result<Option<(CaskMetadata, AppEvidence)>> {
    cancel.check()?;
    // Caskroom aliases may remain after a rename. Attribute the installation
    // only from its own directory, without opening the alias destination.
    if files.is_discovery_symlink(cask_dir)? {
        return Ok(None);
    }
    match files
        .probe_discovery_target(cask_dir)?
        .map(|entry| entry.category)
    {
        Some(Category::Directory) => {}
        Some(Category::File) => return Ok(None),
        _ => return Err(invalid_metadata("unverifiable Caskroom entry").into()),
    }
    let selected = files.local_directory_identity(cask_dir)?;
    let metadata = cask_dir.join(METADATA_DIR);
    let config = read_cask_config(files, &metadata.join(CONFIG_FILE), home)?;
    let allow_staged_evidence = matches!(
        &config,
        CaskConfig::Missing | CaskConfig::UnrecordedEnvironment(_)
    );
    let receipt_bytes = read_json_bytes(files, &metadata.join(RECEIPT_FILE))?;
    let receipt_digest = receipt_bytes
        .as_deref()
        .filter(|_| allow_staged_evidence)
        .map(|bytes| Sha256::digest(bytes).into());
    let receipt = receipt_bytes
        .map(|bytes| decode_json::<Receipt>(&bytes))
        .transpose()?;
    let snapshot = read_snapshot(files, &metadata, token, allow_staged_evidence, cancel)?;
    if receipt.is_none() && snapshot.is_none() {
        // A damaged Caskroom directory may still have an installed artifact.
        return Err(invalid_metadata("missing cask receipt and installed snapshot").into());
    }
    cancel.check()?;
    let installation = CaskMetadata {
        receipt,
        receipt_digest,
        snapshot,
        config,
    };
    let evidence = installation.app_evidence(files, home, cask_dir, cancel)?;
    if files.local_directory_identity(cask_dir)? != selected {
        return Err(invalid_metadata("the cask directory changed during ownership review").into());
    }
    Ok(Some((installation, evidence)))
}

/// Adds read-only app destinations and local receipt declarations for one cask.
pub(super) fn add_review(
    files: &UnixFiles,
    home: &Path,
    id: &CaskId,
    scan: &mut Scan,
    cancel: &Cancellation,
) -> Result<()> {
    let cask_dir = Path::new(PREFIXES[id.prefix])
        .join("Caskroom")
        .join(&id.token);
    let Some((metadata, evidence)) =
        read_cask_installation(files, home, &cask_dir, &id.token, cancel)?
    else {
        return Err(invalid_metadata("the selected cask has no independent local record").into());
    };
    if evidence.invalid || !evidence.observed {
        scan.warnings
            .push("The local cask metadata does not resolve every application destination.".into());
    }
    if evidence.targets.len() > MAX_REVIEW_APP_TARGETS {
        scan.warnings
            .push("Homebrew app destinations reached the preview limit.".into());
    }
    for path in evidence.targets.into_iter().take(MAX_REVIEW_APP_TARGETS) {
        cancel.check()?;
        match files.probe_discovery_target(&path) {
            Ok(Some(entry)) if entry.category == Category::Directory => {
                scan.proposals.push(Proposal {
                    target: Target::File(path),
                    category: Category::Directory,
                    evidence: MatchKind::RuleHint,
                    reason: "the local cask record declares this app destination".into(),
                    risk: Risk::High,
                    access: Access::ReadOnly("This is a recorded Homebrew destination".into()),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => scan.warnings.push(format!(
                "Could not inspect the recorded Homebrew app target {}: {error}",
                path.display(),
            )),
        }
    }
    if let Some(receipt) = metadata.receipt {
        if receipt.uninstall_flight_blocks == Some(true) {
            scan.warnings.push(
                "The local Homebrew receipt records code hooks with effects unavailable for review."
                    .into(),
            );
        }
        if let Some(artifacts) = receipt.uninstall_artifacts {
            return crate::brew_review::append(scan, home, &artifacts, cancel);
        }
    }
    scan.warnings
        .push("The local Homebrew receipt does not include uninstall declarations.".into());
    Ok(())
}

fn read_cask_config(files: &UnixFiles, path: &Path, home: &Path) -> io::Result<CaskConfig> {
    let Some(bytes) = read_json_bytes(files, path)? else {
        return Ok(CaskConfig::Missing);
    };
    let config = decode_json::<Value>(&bytes)?;
    if let Some(directory) = app_dir(&config) {
        return Ok(CaskConfig::RecordedAppDir(directory.into()));
    }
    let explicit_has_no_app_dir = config
        .get("explicit")
        .and_then(Value::as_object)
        .is_some_and(|explicit| !explicit.contains_key("appdir"));
    let default_is_valid = match config.get("default") {
        Some(Value::Object(default)) => default.get("appdir").is_none_or(|value| {
            value
                .as_str()
                .and_then(|directory| resolve_directory(directory, home))
                .is_some()
        }),
        _ => false,
    };
    // Homebrew can load a null env from disk but then evaluates live flags.
    // Only a trusted staged link can prove the historical destination here.
    if explicit_has_no_app_dir && config.get("env") == Some(&Value::Null) && default_is_valid {
        Ok(CaskConfig::UnrecordedEnvironment(
            Sha256::digest(bytes).into(),
        ))
    } else {
        Ok(CaskConfig::Unverifiable)
    }
}

fn read_json_bytes(files: &UnixFiles, path: &Path) -> io::Result<Option<Vec<u8>>> {
    match files.read_regular(path, MAX_METADATA_BYTES) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn decode_json<T: DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    serde_json::from_slice(bytes).map_err(io::Error::other)
}

fn trusted_record_time(files: &UnixFiles, path: &Path, expected: &[u8; 32]) -> Option<SystemTime> {
    let (bytes, modified) = files
        .read_trusted_local_file(path, MAX_METADATA_BYTES)
        .ok()?;
    let observed: [u8; 32] = Sha256::digest(bytes).into();
    (&observed == expected).then_some(modified)
}

fn read_snapshot(
    files: &UnixFiles,
    metadata: &Path,
    token: &str,
    allow_staged_evidence: bool,
    cancel: &Cancellation,
) -> Result<Option<Snapshot>> {
    let versions = match files.list(metadata) {
        Ok(versions) => versions,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut remaining = MAX_METADATA_ENTRIES;
    count_metadata_entries(&mut remaining, versions.len())?;
    let mut newest: Option<PathBuf> = None;
    let mut ambiguous = false;
    // Homebrew orders its snapshots by the timestamp component across versions.
    for version in versions.into_iter().filter(|path| !hidden(path)) {
        cancel.check()?;
        let entry = files.probe_discovery_target(&version)?;
        match entry.map(|entry| entry.category) {
            Some(Category::Directory) => {}
            Some(_) => continue,
            None => return Err(invalid_metadata("unverifiable cask version entry").into()),
        }
        let snapshots = files.list(&version)?;
        count_metadata_entries(&mut remaining, snapshots.len())?;
        for snapshot in snapshots.into_iter().filter(|path| !hidden(path)) {
            cancel.check()?;
            let latest_name = newest.as_deref().and_then(Path::file_name);
            match snapshot.file_name().cmp(&latest_name) {
                std::cmp::Ordering::Greater => {
                    newest = Some(snapshot);
                    ambiguous = false;
                }
                std::cmp::Ordering::Equal => ambiguous = true,
                std::cmp::Ordering::Less => {}
            }
        }
    }
    if ambiguous {
        return Err(invalid_metadata("multiple cask snapshots share the latest timestamp").into());
    }
    let Some(directory) = newest else {
        return Ok(None);
    };
    let casks = directory.join("Casks");
    let version_folder = directory
        .parent()
        .and_then(Path::file_name)
        .and_then(OsStr::to_str);
    let install_date = directory
        .file_name()
        .and_then(OsStr::to_str)
        .and_then(installation_date);
    for (extension, internal) in [("json", false), ("internal.json", true)] {
        let path = casks.join(format!("{token}.{extension}"));
        let Some(bytes) = read_json_bytes(files, &path)? else {
            continue;
        };
        let definition = decode_json::<Definition>(&bytes)?;
        let version = definition
            .version
            .as_deref()
            .filter(|version| !version.is_empty())
            .or(version_folder)
            .map(str::to_owned);
        let staged_source = version_folder
            .filter(|folder| {
                allow_staged_evidence
                    && !internal
                    && install_date.is_some()
                    && relative_path(folder).is_some_and(|path| path.components().count() == 1)
            })
            .map(|version| StagedSnapshot {
                version: version.into(),
                definition_path: path,
                definition_digest: Sha256::digest(&bytes).into(),
            });
        return Ok(Some(Snapshot {
            version,
            staged_source,
            install_date,
            definition,
            internal,
            native_removal_shape: !internal && decode_json::<RemovalSnapshot>(&bytes).is_ok(),
        }));
    }
    let ruby_path = casks.join(format!("{token}.rb"));
    match files.probe_discovery_target(&ruby_path) {
        Ok(Some(entry)) if entry.category == Category::File => Ok(Some(Snapshot {
            version: version_folder.map(str::to_owned),
            staged_source: None,
            install_date,
            definition: Definition::default(),
            internal: false,
            native_removal_shape: false,
        })),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
        Ok(_) => Err(invalid_metadata("unverifiable cask source file").into()),
    }
}

fn count_metadata_entries(remaining: &mut usize, count: usize) -> io::Result<()> {
    *remaining = remaining
        .checked_sub(count)
        .ok_or_else(|| invalid_metadata("cask metadata entry limit reached"))?;
    Ok(())
}

fn hidden(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name.as_encoded_bytes().starts_with(b"."))
}

fn installation_date(timestamp: &str) -> Option<String> {
    let (seconds, milliseconds) = timestamp.split_once('.')?;
    if seconds.len() != 14
        || milliseconds.len() != 3
        || !seconds.bytes().all(|byte| byte.is_ascii_digit())
        || !milliseconds.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some(seconds.get(..8)?.to_owned())
}

fn invalid_metadata(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn discovery_entry_absent(files: &UnixFiles, path: &Path) -> bool {
    files.local_entry_absent(path).is_ok_and(|absent| absent)
}

struct AppPaths<'a> {
    home: &'a Path,
    home_applications: &'a Path,
    app_dir: Option<&'a str>,
}

#[derive(Clone, Copy)]
enum ArtifactFormat {
    Named,
    Internal,
}

type StagedAppTargets<'a> = BTreeMap<&'a str, StagedAppTarget<'a>>;

struct StagedAppTarget<'a> {
    target_option: Option<&'a str>,
    destination: PathBuf,
}

#[derive(Default)]
struct AppEvidence {
    targets: BTreeSet<PathBuf>,
    observed: bool,
    invalid: bool,
}

impl AppEvidence {
    fn add_definition(
        &mut self,
        definition: &Definition,
        internal: bool,
        paths: &AppPaths<'_>,
        staged_targets: &StagedAppTargets<'_>,
    ) {
        self.observed |= definition
            .artifacts
            .as_ref()
            .is_some_and(|items| !items.is_empty())
            || (internal
                && definition
                    .raw_artifacts
                    .as_ref()
                    .is_some_and(|items| !items.is_empty()));
        let staged_targets = (!staged_targets.is_empty())
            .then_some(staged_targets)
            .filter(|_| {
                // These steps can install apps outside the staged app declaration.
                !definition.artifacts.as_deref().is_some_and(|artifacts| {
                    artifacts.iter().any(|artifact| {
                        named_artifact(artifact).is_some_and(|(kind, arguments)| {
                            kind == "pkg"
                                || may_install_other_apps(
                                    kind,
                                    arguments.as_array().map(Vec::as_slice),
                                )
                        })
                    })
                })
            });
        self.add_definition_artifacts(definition, internal, paths, staged_targets);
        // Old API snapshots can include alternative OS and architecture
        // destinations. They add possible claims without proving the base
        // artifact list was present in this installation's metadata.
        for variation in definition.variations.values() {
            self.add_definition_artifacts(variation, internal, paths, None);
            if !variation.variations.is_empty() {
                self.invalid = true;
            }
        }
    }

    fn add_definition_artifacts(
        &mut self,
        definition: &Definition,
        internal: bool,
        paths: &AppPaths<'_>,
        staged_targets: Option<&StagedAppTargets<'_>>,
    ) {
        if let Some(artifacts) = &definition.artifacts {
            self.add(artifacts, ArtifactFormat::Named, paths, staged_targets);
        }
        if let Some(artifacts) = definition.raw_artifacts.as_ref().filter(|_| internal) {
            self.add(artifacts, ArtifactFormat::Internal, paths, None);
        }
        // The stored language can change the app name or destination.
        for variation in &definition.language_variations {
            if let Some(artifacts) = &variation.artifacts {
                self.add(artifacts, ArtifactFormat::Named, paths, None);
            }
            // Current snapshots store a language block's return value here.
            // Only older object-shaped values include artifact declarations.
            if let Some(artifacts) = variation.value.get("artifacts") {
                match artifacts.as_array() {
                    Some(artifacts) => self.add(artifacts, ArtifactFormat::Named, paths, None),
                    None => self.invalid = true,
                }
            }
            if let Some(artifacts) = &variation.overrides.raw_artifacts {
                self.add(artifacts, ArtifactFormat::Internal, paths, None);
            }
            if let Some(artifacts) = &variation.overrides.artifacts {
                self.add(artifacts, ArtifactFormat::Named, paths, None);
            }
            if !variation.overrides.variations.is_empty() {
                self.invalid = true;
            }
        }
    }

    fn add(
        &mut self,
        artifacts: &[Value],
        format: ArtifactFormat,
        paths: &AppPaths<'_>,
        staged_targets: Option<&StagedAppTargets<'_>>,
    ) {
        let mut used_staged_sources = BTreeSet::new();
        for artifact in artifacts {
            let staged_record = staged_targets.and_then(|targets| {
                let (source, target_option) = receipt_app_args(artifact)?;
                let recovered = targets.get(source)?;
                if !used_staged_sources.insert(source) {
                    self.invalid = true;
                    return None;
                }
                Some((target_option, recovered))
            });
            let observation = app_artifact(artifact, format, paths).or_else(|| {
                let (target_option, recovered) = staged_record?;
                // A historical snapshot can repeat the receipt's declaration
                // without an appdir. Reuse only the same verified artifact.
                if recovered.target_option != target_option {
                    return None;
                }
                if artifact.get("target").is_some_and(|target| {
                    target
                        .as_str()
                        .and_then(|text| resolve_directory(text, paths.home))
                        .as_deref()
                        != Some(recovered.destination.as_path())
                }) {
                    return None;
                }
                Some(Some(recovered.destination.clone()))
            });
            self.add_observation(artifact, observation, paths);
        }
    }

    fn add_receipt_with_staged_links<'a>(
        &mut self,
        files: &UnixFiles,
        root: &Path,
        artifacts: &'a [Value],
        paths: &AppPaths<'_>,
        cancel: &Cancellation,
    ) -> Result<StagedAppTargets<'a>> {
        let mut source_counts = BTreeMap::new();
        for artifact in artifacts {
            cancel.check()?;
            if let Some((source, _)) = receipt_app_args(artifact) {
                *source_counts.entry(source.to_lowercase()).or_insert(0usize) += 1;
            }
        }
        let mut recovered_targets = BTreeSet::new();
        let mut staged_targets = StagedAppTargets::new();
        for artifact in artifacts {
            cancel.check()?;
            let mut observation = app_artifact(artifact, ArtifactFormat::Named, paths);
            if observation.is_none() && artifact.get("target").is_none() {
                if let Some((source, target)) = receipt_app_args(artifact) {
                    if source_counts.get(&source.to_lowercase()) == Some(&1) {
                        if let Some(path) = staged_app_target(files, root, source, target, paths)? {
                            if !recovered_targets.insert(path.clone()) {
                                self.invalid = true;
                            }
                            staged_targets.insert(
                                source,
                                StagedAppTarget {
                                    target_option: target,
                                    destination: path.clone(),
                                },
                            );
                            observation = Some(Some(path));
                        }
                    }
                }
            }
            self.add_observation(artifact, observation, paths);
        }
        Ok(staged_targets)
    }

    fn add_observation(
        &mut self,
        artifact: &Value,
        observation: Option<Option<PathBuf>>,
        paths: &AppPaths<'_>,
    ) {
        match observation {
            Some(Some(target)) => {
                self.targets.insert(target);
            }
            Some(None) => {}
            None => self.invalid = true,
        }
        // Keep a snapshot's serialized destination as another possible
        // claim when it differs from the saved configuration.
        if let Some(target) = artifact.get("app").and_then(|_| artifact.get("target")) {
            match target
                .as_str()
                .and_then(|target| resolve_directory(target, paths.home))
                .and_then(|target| scoped_app_destination(target, paths))
            {
                Some(target) => {
                    self.targets.insert(target);
                }
                None => self.invalid = true,
            }
        }
    }
}

fn named_artifact(artifact: &Value) -> Option<(&str, &Value)> {
    let mut stanzas = artifact
        .as_object()?
        .iter()
        .filter(|(key, _)| key.as_str() != "target");
    let (kind, arguments) = stanzas.next()?;
    stanzas
        .next()
        .is_none()
        .then_some((kind.as_str(), arguments))
}

fn receipt_app_args(artifact: &Value) -> Option<(&str, Option<&str>)> {
    let ("app", arguments) = named_artifact(artifact)? else {
        return None;
    };
    app_args(arguments.as_array()?)
}

fn staged_app_target(
    files: &UnixFiles,
    root: &Path,
    source: &str,
    target: Option<&str>,
    paths: &AppPaths<'_>,
) -> Result<Option<PathBuf>> {
    if target.is_some_and(|target| target.starts_with(['/', '~'])) {
        // An invalid absolute or home-relative target is not an appdir gap.
        return Ok(None);
    }
    let Some(source) = relative_path(source).filter(|path| bundle::is_app(path)) else {
        return Ok(None);
    };
    let Some(relative_target) = target
        .or_else(|| source.file_name()?.to_str())
        .and_then(|target| relative_path(target.strip_prefix("$APPDIR/").unwrap_or(target)))
    else {
        return Ok(None);
    };
    let link = root.join(source);
    let Some(parent) = link.parent() else {
        return Ok(None);
    };
    if files.require_trusted_local_directory(parent).is_err() {
        return Ok(None);
    }
    let Some(link_text) = files.read_discovery_symlink(&link)? else {
        return Ok(None);
    };
    let Some(destination) = link_text
        .to_str()
        .filter(|text| text.starts_with('/'))
        .and_then(|text| resolve_directory(text, paths.home))
        .and_then(|path| scoped_app_destination(path, paths))
        .filter(|path| {
            path.as_os_str() == link_text.as_os_str() && path.ends_with(relative_target)
        })
    else {
        return Ok(None);
    };
    let identity = match files.local_directory_identity(&destination) {
        Ok(identity) => identity,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    // Inspect the literal destination independently, without opening the
    // source link as part of an access path.
    match bundle::read(files, &destination) {
        Ok(_) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory | io::ErrorKind::InvalidData
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    }
    if files.local_directory_identity(&destination)? != identity
        || files.read_discovery_symlink(&link)?.as_ref() != Some(&link_text)
    {
        return Ok(None);
    }
    Ok(Some(destination))
}

fn app_artifact(
    artifact: &Value,
    format: ArtifactFormat,
    paths: &AppPaths<'_>,
) -> Option<Option<PathBuf>> {
    let (source, target) = match format {
        ArtifactFormat::Named => {
            let (kind, arguments) = named_artifact(artifact)?;
            if kind != "app" {
                return indirect_app_evidence(kind, arguments.as_array().map(Vec::as_slice));
            }
            app_args(arguments.as_array()?)?
        }
        ArtifactFormat::Internal => {
            let (kind, arguments) = artifact.as_array()?.split_first()?;
            let kind = kind.as_str()?;
            if kind != "app" {
                return indirect_app_evidence(kind, Some(arguments));
            }
            match arguments {
                [source] => app_args(source.as_array()?)?,
                [source, options] => {
                    let [source] = source.as_array()?.as_slice() else {
                        return None;
                    };
                    (source.as_str()?, target_option(options)?)
                }
                _ => return None,
            }
        }
    };
    resolve_app_target(source, target, paths).map(Some)
}

fn indirect_app_evidence(kind: &str, arguments: Option<&[Value]>) -> Option<Option<PathBuf>> {
    // Installer packages have their own ownership check using pkg receipts.
    (!may_install_other_apps(kind, arguments)).then_some(None)
}

fn may_install_other_apps(kind: &str, arguments: Option<&[Value]>) -> bool {
    match kind {
        "artifact" | "installer" | "suite" => true,
        "preflight_steps" | "postflight_steps" => {
            // Treat opaque steps as unresolved. Permission and ownership
            // changes only operate on paths that already exist.
            let Some([options]) = arguments else {
                return true;
            };
            !options
                .get("steps")
                .and_then(Value::as_array)
                .is_some_and(|steps| {
                    steps.iter().all(|step| {
                        matches!(
                            step.get("type").and_then(Value::as_str),
                            Some("set_permissions" | "set_ownership")
                        )
                    })
                })
        }
        // Legacy serialized blocks can combine install and uninstall keys.
        _ => kind
            .split(',')
            .any(|phase| matches!(phase.trim(), "preflight" | "postflight")),
    }
}

fn app_args(arguments: &[Value]) -> Option<(&str, Option<&str>)> {
    match arguments {
        [source] => Some((source.as_str()?, None)),
        [source, options] => Some((source.as_str()?, target_option(options)?)),
        _ => None,
    }
}

fn target_option(options: &Value) -> Option<Option<&str>> {
    let options = options.as_object()?;
    if options.len() != 1 {
        return None;
    }
    match options.get("target")? {
        Value::Null => Some(None),
        Value::String(target) => Some((!target.is_empty()).then_some(target.as_str())),
        _ => None,
    }
}

fn resolve_app_target(source: &str, target: Option<&str>, paths: &AppPaths<'_>) -> Option<PathBuf> {
    // Homebrew uses the staged source basename when target is omitted.
    let source_name = relative_path(source)?.file_name()?.to_str()?;
    let target = target.unwrap_or(source_name);
    let resolved = if let Some(relative) = target.strip_prefix("$APPDIR/") {
        resolve_directory(paths.app_dir?, paths.home)?.join(relative_path(relative)?)
    } else if target.starts_with(['/', '~']) {
        resolve_directory(target, paths.home)?
    } else {
        resolve_directory(paths.app_dir?, paths.home)?.join(relative_path(target)?)
    };
    scoped_app_destination(resolved, paths)
}

fn scoped_app_destination(resolved: PathBuf, paths: &AppPaths<'_>) -> Option<PathBuf> {
    let system_applications = Path::new(SYSTEM_APPLICATIONS);
    let supported_location = resolved.starts_with(system_applications)
        || resolved.starts_with(paths.home_applications)
        || macos_portable_location(paths.home, &resolved);
    (supported_location && bundle::is_app(&resolved)).then_some(resolved)
}

fn resolve_directory(value: &str, home: &Path) -> Option<PathBuf> {
    if let Some(relative) = value
        .strip_prefix("~/")
        .or_else(|| value.strip_prefix("/$HOME/"))
    {
        return Some(home.join(relative_path(relative)?));
    }
    let relative = value.strip_prefix('/')?;
    Some(Path::new("/").join(relative_path(relative)?))
}

fn relative_path(value: &str) -> Option<&Path> {
    if value
        .chars()
        .any(|ch| ch.is_control() || matches!(ch, '\\' | '$'))
        || value.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return None;
    }
    Some(Path::new(value))
}

fn valid_token(token: &str) -> bool {
    token.len() <= 120
        && token
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && !token.contains("..")
        && token.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'@' | b'+' | b'.' | b'_')
        })
}

fn app_dir(config: &Value) -> Option<&str> {
    let config = config.as_object()?;
    for scope in ["explicit", "env", "default"] {
        match config.get(scope) {
            Some(Value::Object(options)) => {
                if let Some(value) = options.get("appdir") {
                    return value.as_str();
                }
            }
            None => {}
            Some(Value::Null) if scope != "env" => {}
            // A null env uses Homebrew's live environment. A malformed
            // scope likewise cannot prove the historical installation path.
            _ => return None,
        }
    }
    // Only infer the default when both higher-priority saved scopes are
    // present. An incomplete historical record can hide a custom appdir.
    let has_saved_overrides = matches!(config.get("explicit"), Some(Value::Object(_)))
        && matches!(config.get("env"), Some(Value::Object(_)));
    has_saved_overrides.then_some(SYSTEM_APPLICATIONS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_attributes_app_artifacts_to_scoped_paths() {
        let paths = AppPaths {
            home: Path::new("/Users/example"),
            home_applications: Path::new("/Users/example/Applications"),
            app_dir: Some(SYSTEM_APPLICATIONS),
        };
        let valid = [json!({"app": ["Foo.app", {"target": "Bar.app"}]})];
        assert_eq!(
            app_artifact(&valid[0], ArtifactFormat::Named, &paths),
            Some(Some(PathBuf::from("/Applications/Bar.app")))
        );
        for invalid in [
            json!({"app": ["../Other.app"]}),
            json!({"app": ["Other.app", {"target": "/System/Applications/Other.app"}]}),
            json!({"app": ["Other.app", {"target": "Harmless.app", "other": true}]}),
        ] {
            assert_eq!(app_artifact(&invalid, ArtifactFormat::Named, &paths), None);
        }
    }

    #[test]
    fn install_steps_prevent_an_exhaustive_application_ownership_claim() {
        let paths = AppPaths {
            home: Path::new("/Users/example"),
            home_applications: Path::new("/Users/example/Applications"),
            app_dir: Some(SYSTEM_APPLICATIONS),
        };
        let app = json!({"app": ["Example.app"]});
        for step in [
            json!({"preflight": null}),
            json!({"postflight": null}),
            json!({"preflight, uninstall_preflight": null}),
            json!({"preflight_steps": [{"steps": [{"type": "run"}]}]}),
            json!({"postflight_steps": [{"steps": [{"type": "move"}]}]}),
            json!({"postflight_steps": [{"steps": [{"type": "unrecognized"}]}]}),
            json!({"preflight_steps": null}),
        ] {
            let mut evidence = AppEvidence::default();
            evidence.add(&[app.clone(), step], ArtifactFormat::Named, &paths, None);
            assert!(evidence.invalid);
            assert!(
                evidence
                    .targets
                    .contains(Path::new("/Applications/Example.app"))
            );
        }
        assert_eq!(
            app_artifact(
                &json!(["postflight_steps", {"steps": [{"type": "move"}]}]),
                ArtifactFormat::Internal,
                &paths,
            ),
            None,
        );
        assert_eq!(
            app_artifact(
                &json!({"uninstall_postflight_steps": [{"steps": [{"type": "remove"}]}]}),
                ArtifactFormat::Named,
                &paths,
            ),
            Some(None),
        );
        assert_eq!(
            app_artifact(
                &json!({"postflight_steps": [{"steps": [
                    {"type": "set_permissions"}, {"type": "set_ownership"}
                ]}]}),
                ArtifactFormat::Named,
                &paths,
            ),
            Some(None),
        );
    }

    #[test]
    fn rejects_invalid_cask_identities() {
        for invalid in [
            "0:--zap:com.example",
            "0:../cask:com.example",
            "2:editor:com.example",
        ] {
            assert!(CaskId::parse(invalid).is_none());
        }
    }
}
