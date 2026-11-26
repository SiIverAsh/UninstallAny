//! Anchored Unix file inspection, quarantine and private audit storage.

#![cfg(any(target_os = "linux", target_os = "macos"))]

#[cfg(target_os = "macos")]
mod bundle_size;
#[cfg(target_os = "macos")]
mod directory_disposal;
#[cfg(target_os = "macos")]
mod file_disposal;
mod native;
mod store;
#[cfg(target_os = "macos")]
mod trash;

use std::ffi::OsStr;
#[cfg(target_os = "macos")]
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{self, FileType};
use serde::{Deserialize, Serialize};
#[cfg(target_os = "macos")]
use sha2::{Digest, Sha256};
use uninstallany_core::{Access, Cancellation, Category, FileStore, Inspection, RuleTarget};
#[cfg(target_os = "macos")]
use uninstallany_core::{Artifact, Journal};
use uuid::Uuid;

use crate::native::{EntryStamp, NodeId, checked_file, deny, invalid};

const MAX_DIRECTORY_ENTRIES: usize = 16_384;
const MAX_METADATA_BYTES: usize = 16 * 1024 * 1024;
const QUARANTINE_DIR: &str = "quarantine";
const AUDIT_DIR: &str = "audit";
#[cfg(target_os = "macos")]
const MAX_LAUNCH_AGENT_BYTES: usize = 262_144;

const PROTECTED_SYSTEM_TREES: &[&str] = &[
    "/System",
    "/dev",
    "/etc",
    "/proc",
    "/sys",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/boot",
    "/run",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/lib64",
    "/usr/libexec",
    "/usr/share",
    "/private/etc",
    "/Library/Apple",
    "/Library/LaunchDaemons",
    "/Library/LaunchAgents",
    "/var/lib",
    "/var/db",
];
const PROTECTED_HOME_TREES: &[&str] = &[
    "Desktop",
    "Documents",
    "Downloads",
    ".ssh",
    ".gnupg",
    ".pki",
    ".Trash",
    ".local/share/Trash",
    "Library/Keychains",
    "Library/Group Containers",
    "Library/LaunchAgents",
];

/// Provides identical file and audit guarantees to the macOS and Linux backends.
#[derive(Clone)]
pub struct UnixFiles {
    roots: Vec<PathBuf>,
    protected: Vec<PathBuf>,
    protected_nodes: Vec<NodeId>,
    state_node: Option<NodeId>,
    state: PathBuf,
    home: PathBuf,
    uid: u32,
    #[cfg(target_os = "macos")]
    application_roots: Vec<PathBuf>,
    #[cfg(target_os = "macos")]
    portable_applications: bool,
    #[cfg(target_os = "macos")]
    launch_agent_root: Option<PathBuf>,
    #[cfg(target_os = "macos")]
    cache_roots: Vec<PathBuf>,
    #[cfg(target_os = "macos")]
    saved_state_root: Option<PathBuf>,
    #[cfg(target_os = "macos")]
    sandbox_container_root: Option<PathBuf>,
    #[cfg(target_os = "macos")]
    webkit_root: Option<PathBuf>,
    #[cfg(target_os = "macos")]
    http_storage_root: Option<PathBuf>,
}

impl UnixFiles {
    /// Gives a platform backend explicit discovery roots and a private local state path.
    ///
    /// Roots may be absent until an application is installed. This constructor never creates
    /// anything, and configuration only narrows the built-in protection policy.
    pub fn new(roots: Vec<PathBuf>, protected: Vec<PathBuf>, state: PathBuf) -> io::Result<Self> {
        let uid = rustix::process::geteuid().as_raw();
        if uid == 0 || rustix::process::getuid().as_raw() != uid {
            return Err(deny(
                "run UninstallAny as an ordinary user with matching real and effective IDs",
            ));
        }
        Self::with_account(roots, protected, state, user_home()?, uid)
    }

    fn with_account(
        roots: Vec<PathBuf>,
        protected: Vec<PathBuf>,
        state: PathBuf,
        home: PathBuf,
        uid: u32,
    ) -> io::Result<Self> {
        for path in roots.iter().chain(&protected).chain([&home, &state]) {
            check_absolute(path)?;
        }
        if !state.starts_with(&home)
            || state == home
            || roots.iter().any(|path| path == Path::new("/"))
        {
            return Err(deny(
                "Unix state must be below the effective account's home and scan roots must be scoped",
            ));
        }
        let mut protected = protected;
        protected.extend(PROTECTED_SYSTEM_TREES.iter().map(PathBuf::from));
        protected.extend(PROTECTED_HOME_TREES.iter().map(|path| home.join(path)));
        if protected.iter().any(|path| is_at_or_below(&state, path)) {
            return Err(deny(
                "Unix state cannot be written inside a protected system or personal tree",
            ));
        }
        let protected_nodes = protected
            .iter()
            .filter_map(|path| native::protected_id(path).ok())
            .collect();
        let state_node = native::protected_id(&state).ok();
        protected.push(state.clone());
        Ok(Self {
            roots,
            protected,
            protected_nodes,
            state_node,
            state,
            home,
            uid,
            #[cfg(target_os = "macos")]
            application_roots: Vec::new(),
            #[cfg(target_os = "macos")]
            portable_applications: false,
            #[cfg(target_os = "macos")]
            launch_agent_root: None,
            #[cfg(target_os = "macos")]
            cache_roots: Vec::new(),
            #[cfg(target_os = "macos")]
            saved_state_root: None,
            #[cfg(target_os = "macos")]
            sandbox_container_root: None,
            #[cfg(target_os = "macos")]
            webkit_root: None,
            #[cfg(target_os = "macos")]
            http_storage_root: None,
        })
    }

    /// Allows standalone `.app` bundles only as direct children of existing discovery roots.
    ///
    /// A complete bundle is treated as one directory entry after verifying its private
    /// ownership, regular Info.plist, unchanged tree, and lack of nested mounts.
    #[cfg(target_os = "macos")]
    pub fn with_application_roots(mut self, roots: Vec<PathBuf>) -> io::Result<Self> {
        for root in &roots {
            if self.scope(root)? != root {
                return Err(deny(
                    "application roots must be configured as exact discovery roots",
                ));
            }
        }
        self.application_roots = roots;
        Ok(self)
    }

    /// Enables whole-bundle quarantine for explicitly reviewed user-home apps.
    ///
    /// The app must still pass the same ownership, mount, and directory checks.
    #[cfg(target_os = "macos")]
    pub fn with_portable_applications(mut self) -> io::Result<Self> {
        if self.scope(&self.home)? != self.home.as_path() {
            return Err(deny(
                "a portable application requires a scoped account home",
            ));
        }
        self.portable_applications = true;
        Ok(self)
    }

    /// Enables guarded moves of direct user LaunchAgent plists for a native backend.
    /// The caller must first verify ownership and prove the launchd job inactive.
    #[cfg(target_os = "macos")]
    pub fn with_user_launch_agents(mut self) -> io::Result<Self> {
        let root = self.home.join("Library/LaunchAgents");
        if self.scope(&root)? != root {
            return Err(deny(
                "the user LaunchAgents folder must be an exact discovery root",
            ));
        }
        self.protected_nodes = self
            .protected
            .iter()
            .filter(|path| *path != &root)
            .filter_map(|path| native::protected_id(path).ok())
            .collect();
        self.launch_agent_root = Some(root);
        Ok(self)
    }

    /// Supports bounded trees directly under the user's Caches and Logs folders.
    #[cfg(target_os = "macos")]
    pub fn with_macos_cache_directories(mut self) -> io::Result<Self> {
        let library = self.home.join("Library");
        let roots = [library.join("Caches"), library.join("Logs")];
        for root in &roots {
            if self.scope(root)? != root {
                return Err(deny("cache and log folders must be exact discovery roots"));
            }
        }
        self.cache_roots.extend(roots);
        Ok(self)
    }

    /// Enables guarded moves of literal application state directories.
    ///
    /// The native backend must associate each directory with a specific app.
    #[cfg(target_os = "macos")]
    pub fn with_macos_saved_state_directories(mut self) -> io::Result<Self> {
        let root = self.home.join("Library/Saved Application State");
        if self.scope(&root)? != root {
            return Err(deny(
                "the saved state folder must be an exact discovery root",
            ));
        }
        self.saved_state_root = Some(root);
        Ok(self)
    }

    /// Enables guarded moves of supported app-private directories within a sandbox.
    #[cfg(target_os = "macos")]
    pub fn with_macos_sandbox_directories(mut self) -> io::Result<Self> {
        let root = self.home.join("Library/Containers");
        if self.scope(&root)? != root {
            return Err(deny(
                "the Containers folder must be an exact discovery root",
            ));
        }
        self.sandbox_container_root = Some(root);
        Ok(self)
    }

    /// Enables guarded moves of exact third-party WebKit website data directories.
    ///
    /// The native backend must associate each directory with a specific app.
    #[cfg(target_os = "macos")]
    pub fn with_macos_webkit_website_data(mut self) -> io::Result<Self> {
        let root = self.home.join("Library/WebKit");
        if self.scope(&root)? != root {
            return Err(deny("the WebKit folder must be an exact discovery root"));
        }
        self.webkit_root = Some(root);
        Ok(self)
    }

    /// Enables guarded moves of per-app HTTP database directories as one object.
    #[cfg(target_os = "macos")]
    pub fn with_macos_http_storage(mut self) -> io::Result<Self> {
        let root = self.home.join("Library/HTTPStorages");
        if self.scope(&root)? != root {
            return Err(deny(
                "the HTTP storage folder must be an exact discovery root",
            ));
        }
        self.http_storage_root = Some(root);
        Ok(self)
    }

    /// Reads immediate names without following symlinks or crossing a nested mount.
    pub fn list(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        let fd = self.open_scoped_directory(path)?;
        let entries = fs::Dir::read_from(fd)?;
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if matches!(name, b"." | b"..") {
                continue;
            }
            if names.len() == MAX_DIRECTORY_ENTRIES {
                return Err(invalid("the discovery directory exceeds the entry limit"));
            }
            names.push(path.join(OsStr::from_bytes(name)));
        }
        names.sort_unstable();
        Ok(names)
    }

    /// Alias for listing the direct children of a discovery directory.
    pub fn children(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        self.list(path)
    }

    /// Checks that a discovery directory is reachable without links on a local volume.
    pub fn require_local_directory(&self, path: &Path) -> io::Result<()> {
        native::require_local(&self.open_scoped_directory(path)?)
    }

    /// Requires every directory component to exclude writes by other accounts.
    #[cfg(target_os = "macos")]
    pub fn require_trusted_local_directory(&self, path: &Path) -> io::Result<()> {
        self.open_trusted_local_directory(path).map(drop)
    }

    /// Holds a read-only descriptor to a trusted local directory without following links.
    #[cfg(target_os = "macos")]
    pub fn open_trusted_local_directory(&self, path: &Path) -> io::Result<OwnedFd> {
        let scoped = self.open_scoped_directory(path)?;
        let (directory, is_trusted) = native::open_trusted_path(path, self.uid, &[], None)?;
        if !is_trusted {
            return Err(deny("a directory is writable by an unrelated account"));
        }
        if native::directory_id(&scoped)? != native::directory_id(&directory)? {
            return Err(deny("the discovery directory changed during verification"));
        }
        native::require_local(&directory)?;
        Ok(directory)
    }

    /// Pins a trusted regular file for descriptor-based identity verification.
    #[cfg(target_os = "macos")]
    pub fn open_trusted_local_regular_file(&self, path: &Path) -> io::Result<File> {
        self.scope(path)?;
        let parent = self.open_trusted_local_directory(parent_path(path)?)?;
        let (file, _) = self.open_trusted_regular_at(&parent, filename(path)?)?;
        Ok(file)
    }

    /// Reads bounded discovery metadata and its modification time from one
    /// stable regular file owned by root or the current user.
    #[cfg(target_os = "macos")]
    pub fn read_trusted_local_file(
        &self,
        path: &Path,
        max_bytes: usize,
    ) -> io::Result<(Vec<u8>, std::time::SystemTime)> {
        self.scope(path)?;
        if max_bytes > MAX_METADATA_BYTES {
            return Err(invalid("metadata read exceeds the discovery byte limit"));
        }
        let parent_path = parent_path(path)?;
        let parent = self.open_trusted_local_directory(parent_path)?;
        let parent_identity = native::directory_id(&parent)?;
        let name = filename(path)?;
        let (mut file, stat) = self.open_trusted_regular_at(&parent, name)?;
        let stamp = EntryStamp::from_stat(&stat);
        let modified_at = file.metadata()?.modified()?;
        let mut bytes = Vec::new();
        (&mut file)
            .take(max_bytes as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > max_bytes {
            return Err(invalid("metadata file exceeds the requested byte limit"));
        }

        // Check both the held file and the name used by the caller. A
        // trusted descriptor alone can outlive a replacement at that name.
        let named_parent = self.open_trusted_local_directory(parent_path)?;
        let held = fs::fstat(&file)?;
        let named = native::entry_stat(&named_parent, name)?;
        let file_changed = EntryStamp::from_stat(&held) != stamp
            || EntryStamp::from_stat(&named) != stamp
            || held.st_flags != stat.st_flags
            || named.st_flags != stat.st_flags;
        if file_changed
            || native::directory_id(&named_parent)? != parent_identity
            || native::acl_allows_mutation(&file)?
        {
            return Err(deny("the trusted discovery file changed while reading it"));
        }
        Ok((bytes, modified_at))
    }

    #[cfg(target_os = "macos")]
    fn open_trusted_regular_at(
        &self,
        parent: &OwnedFd,
        name: &OsStr,
    ) -> io::Result<(File, fs::Stat)> {
        let file = checked_file(parent, name)?;
        let stat = fs::fstat(&file)?;
        if stat.st_uid != 0 && stat.st_uid != self.uid
            || stat.st_nlink != 1
            || stat.st_mode & 0o022 != 0
            || native::acl_allows_mutation(&file)?
        {
            return Err(deny("the discovery file can be changed by another account"));
        }
        Ok((file, stat))
    }

    /// Checks whether ordinary permissions allow reaching an eligible app bundle.
    ///
    /// This inventory hint checks directories and ACLs without reading the
    /// bundle tree. A move still requires full fingerprint and backup checks.
    #[cfg(target_os = "macos")]
    pub fn validate_macos_application_bundle_location(&self, path: &Path) -> io::Result<()> {
        if !self.is_application_bundle(path) {
            return Err(deny("the path is not an eligible application bundle"));
        }
        let parent = self.mutable_parent(path)?;
        let bundle = native::open_subdirectory(&parent, filename(path)?)?;
        native::reject_protected(&bundle, &self.protected_nodes)?;
        self.reject_state_alias(&bundle)?;
        native::require_current_user_directory(&bundle, self.uid)
    }

    /// Identifies a local directory without following aliases implemented as links.
    #[cfg(target_os = "macos")]
    pub fn local_directory_identity(
        &self,
        path: &Path,
    ) -> io::Result<impl Eq + std::hash::Hash + use<>> {
        let directory = self.open_scoped_directory(path)?;
        native::require_local(&directory)?;
        native::directory_id(&directory)
    }

    /// Checks one name for absence in a held local directory without following links.
    /// A missing parent remains an error so callers can verify its scope separately.
    #[cfg(target_os = "macos")]
    pub fn local_entry_absent(&self, path: &Path) -> io::Result<bool> {
        self.scope(path)?;
        let parent = parent_path(path)?;
        let directory = self.open_scoped_directory(parent)?;
        native::require_local(&directory)?;
        let identity = native::directory_id(&directory)?;
        match native::entry_stat(&directory, filename(path)?) {
            // A link or special object also occupies the name.
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        // Lookup and identity came from one open directory, so a pathname
        // replacement cannot supply the absence of an unrelated directory.
        let current = self.open_scoped_directory(parent)?;
        if native::directory_id(&current)? != identity {
            return Err(io::Error::other(
                "the containing directory changed during the absence check",
            ));
        }
        Ok(true)
    }

    /// Observes a regular entry or directory for an inventory-only reference.
    pub fn probe_discovery_target(&self, path: &Path) -> io::Result<Option<RuleTarget>> {
        self.scope(path)?;
        let parent = self.open_scoped_directory(parent_path(path)?)?;
        probe_discovery_entry(&parent, path)
    }

    /// Observes a receipt-listed system path without extending other discovery scopes.
    /// The caller supplies its receipt-specific allowlist. This method only reads
    /// metadata below the local Applications and Library directories.
    #[cfg(target_os = "macos")]
    pub fn probe_macos_installer_system_target(path: &Path) -> io::Result<Option<RuleTarget>> {
        check_absolute(path)?;
        let parent = parent_path(path)?;
        let Some(root) = [Path::new("/Applications"), Path::new("/Library")]
            .into_iter()
            .find(|root| parent.starts_with(root))
        else {
            return Ok(None);
        };
        // Start at the system directory so a nested mount cannot replace
        // one of the receipt-specific subdirectories.
        let parent = open_directory_below(root, parent)?;
        probe_discovery_entry(&parent, path)
    }

    /// Checks a discovery entry's link type without opening its destination.
    #[cfg(target_os = "macos")]
    pub fn is_discovery_symlink(&self, path: &Path) -> io::Result<bool> {
        self.scope(path)?;
        let parent = self.open_scoped_directory(parent_path(path)?)?;
        let entry = native::entry_stat(&parent, filename(path)?)?;
        Ok(FileType::from_raw_mode(entry.st_mode) == FileType::Symlink)
    }

    /// Reads one stable discovery symlink in a trusted local directory.
    ///
    /// A missing entry or a non-symlink returns `None`. The returned path is
    /// discovery evidence only and its destination is never opened here.
    #[cfg(target_os = "macos")]
    pub fn read_discovery_symlink(&self, path: &Path) -> io::Result<Option<PathBuf>> {
        self.scope(path)?;
        let parent_path = parent_path(path)?;
        let parent = match self.open_trusted_local_directory(parent_path) {
            Ok(parent) => parent,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let parent_identity = native::directory_id(&parent)?;
        let name = filename(path)?;
        let entry = match native::entry_stat(&parent, name) {
            Ok(entry) => entry,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if FileType::from_raw_mode(entry.st_mode) != FileType::Symlink {
            return Ok(None);
        }
        if entry.st_uid != 0 && entry.st_uid != self.uid
            || entry.st_nlink != 1
            || NodeId::from_stat(&entry).device != parent_identity.device
        {
            return Err(deny(
                "the discovery symlink crosses a volume boundary or has unverified ownership",
            ));
        }

        // Bound the kernel read without resolving the destination. Recheck
        // the held entry and its named parent before returning ownership evidence.
        let mut target = [0; libc::PATH_MAX as usize + 1];
        let length = fs::readlinkat_raw(&parent, name, &mut target[..])?;
        if length == 0 || length >= target.len() {
            return Err(invalid(
                "the discovery symlink has empty or oversized target text",
            ));
        }
        let current_parent = self.open_trusted_local_directory(parent_path)?;
        let observed = native::entry_stat(&current_parent, name)?;
        if native::directory_id(&current_parent)? != parent_identity
            || EntryStamp::from_stat(&entry) != EntryStamp::from_stat(&observed)
            || entry.st_flags != observed.st_flags
        {
            return Err(deny(
                "the discovery symlink changed while reading its target text",
            ));
        }
        Ok(Some(PathBuf::from(OsStr::from_bytes(&target[..length]))))
    }

    /// Reads a private user LaunchAgent and binds its bytes to the approval fingerprint.
    #[cfg(target_os = "macos")]
    pub fn read_observed_regular(
        &self,
        path: &Path,
        max_bytes: usize,
    ) -> io::Result<(Vec<u8>, Inspection)> {
        if !self.is_user_launch_agent(path) || max_bytes > MAX_LAUNCH_AGENT_BYTES {
            return Err(deny("the file is outside the supported LaunchAgent scope"));
        }
        let parent = self.mutable_parent(path)?;
        let (stamp, bytes) = self.read_private_plist(&parent, filename(path)?, max_bytes)?;
        let fingerprint = self.fingerprint(path, &parent)?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        if fingerprint.entry.metadata != stamp
            || fingerprint.entry.launch_agent_digest != Some(digest)
        {
            return Err(deny("the LaunchAgent changed during observation"));
        }
        self.validate_store_volume(fingerprint.parent, &self.store_anchor()?)?;
        Ok((
            bytes,
            Inspection {
                fingerprint: serde_json::to_string(&fingerprint).map_err(io::Error::other)?,
                access: Access::Allowed,
            },
        ))
    }

    /// Captures an approval fingerprint only for a guarded regular file.
    #[cfg(target_os = "macos")]
    pub fn inspect_macos_regular_file(&self, path: &Path) -> io::Result<Inspection> {
        let parent = self.mutable_parent(path)?;
        let fingerprint = self.fingerprint(path, &parent)?;
        let named = native::entry_stat(&parent, filename(path)?)?;
        // The generic fingerprint also supports links. Bind the regular-file
        // check to the fingerprint before offering a selectable candidate.
        if FileType::from_raw_mode(named.st_mode) != FileType::RegularFile
            || EntryStamp::from_stat(&named) != fingerprint.entry.metadata
        {
            return Err(deny("the target is not a stable regular file"));
        }
        self.validate_store_volume(fingerprint.parent, &self.store_anchor()?)?;
        Ok(Inspection {
            fingerprint: serde_json::to_string(&fingerprint).map_err(io::Error::other)?,
            access: Access::Allowed,
        })
    }

    /// Binds a bounded prefix read to the same regular file used by quarantine.
    #[cfg(target_os = "macos")]
    pub fn read_macos_observed_regular_prefix(
        &self,
        path: &Path,
        max_bytes: usize,
    ) -> io::Result<(Vec<u8>, Inspection)> {
        if max_bytes > MAX_METADATA_BYTES {
            return Err(invalid("metadata read exceeds the discovery byte limit"));
        }
        let parent = self.mutable_parent(path)?;
        let name = filename(path)?;
        let mut file = checked_file(&parent, name)?;
        let original = EntryStamp::from_stat(&fs::fstat(&file)?);
        let mut bytes = Vec::new();
        (&mut file).take(max_bytes as u64).read_to_end(&mut bytes)?;
        let fingerprint = self.fingerprint(path, &parent)?;
        let current_parent = self.mutable_parent(path)?;
        // The evidence and the approval must identify the file we opened,
        // even if the enclosing directory was renamed during the read.
        if original != fingerprint.entry.metadata
            || original != EntryStamp::from_stat(&fs::fstat(&file)?)
            || native::directory_id(&current_parent)? != fingerprint.parent
            || original != EntryStamp::from_stat(&native::entry_stat(&current_parent, name)?)
        {
            return Err(deny("the regular file changed while reading its prefix"));
        }
        self.validate_store_volume(fingerprint.parent, &self.store_anchor()?)?;
        Ok((
            bytes,
            Inspection {
                fingerprint: serde_json::to_string(&fingerprint).map_err(io::Error::other)?,
                access: Access::Allowed,
            },
        ))
    }

    /// Captures approval evidence for a guarded cache or log directory as one object.
    #[cfg(target_os = "macos")]
    pub fn inspect_macos_cache_directory(&self, path: &Path) -> io::Result<Inspection> {
        if !self.is_macos_cache_directory(path) {
            return Err(deny(
                "the path is outside the supported cache or log directory scope",
            ));
        }
        self.inspect_macos_private_tree(
            path,
            "the cache or log entry must be an ordinary directory",
        )
    }

    /// Captures a private, top-level saved state directory for approval.
    #[cfg(target_os = "macos")]
    pub fn inspect_macos_saved_state_directory(&self, path: &Path) -> io::Result<Inspection> {
        if self.macos_saved_state_bundle_id(path).is_none() {
            return Err(deny(
                "the path is outside the supported saved state directory scope",
            ));
        }
        self.inspect_macos_private_tree(path, "the saved state entry must be an ordinary directory")
    }

    /// Captures a sandbox's dedicated application support directory as one object.
    #[cfg(target_os = "macos")]
    pub fn inspect_macos_sandbox_application_support(&self, path: &Path) -> io::Result<Inspection> {
        if self
            .macos_sandbox_application_support_bundle_id(path)
            .is_none()
        {
            return Err(deny(
                "the path is outside the dedicated sandbox support scope",
            ));
        }
        self.inspect_macos_private_tree(
            path,
            "the sandbox support entry must be an ordinary directory",
        )
    }

    /// Captures private WebKit website data as one guarded directory for approval.
    #[cfg(target_os = "macos")]
    pub fn inspect_macos_webkit_website_data(&self, path: &Path) -> io::Result<Inspection> {
        if self.macos_webkit_website_data_bundle_id(path).is_none() {
            return Err(deny("the path is outside the WebKit website data scope"));
        }
        self.inspect_macos_private_tree(
            path,
            "the website data entry must be an ordinary directory",
        )
    }

    /// Captures the HTTP storage database and sidecars together for approval.
    #[cfg(target_os = "macos")]
    pub fn inspect_macos_http_storage(&self, path: &Path) -> io::Result<Inspection> {
        if self.macos_http_storage_bundle_id(path).is_none() {
            return Err(deny(
                "the path is outside the app-specific HTTP storage scope",
            ));
        }
        self.inspect_macos_private_tree(
            path,
            "the HTTP storage entry must be an ordinary directory",
        )
    }

    #[cfg(target_os = "macos")]
    fn inspect_macos_private_tree(
        &self,
        path: &Path,
        non_directory: &'static str,
    ) -> io::Result<Inspection> {
        let parent = self.mutable_parent(path)?;
        let fingerprint = self.fingerprint(path, &parent)?;
        if fingerprint.entry.bundle.is_none() {
            return Err(deny(non_directory));
        }
        self.validate_store_volume(fingerprint.parent, &self.store_anchor()?)?;
        Ok(Inspection {
            fingerprint: serde_json::to_string(&fingerprint).map_err(io::Error::other)?,
            access: Access::Allowed,
        })
    }

    /// Reads a small regular file in a discovery root or returns a size error.
    pub fn read_regular(&self, path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
        self.read_metadata(path, max_bytes, false)
    }

    /// Reads only the requested prefix of a regular file in a discovery root.
    pub fn read_prefix(&self, path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
        self.read_metadata(path, max_bytes, true)
    }

    /// Inspects bounded, unprotected rule hints without following their entries.
    pub fn probe_rule_target(&self, path: &Path) -> io::Result<Option<RuleTarget>> {
        let parent = self.mutable_parent(path)?;
        let name = filename(path)?;
        let entry = native::entry_stat(&parent, name)?;
        native::reject_protected_entry(&entry, &self.protected_nodes)?;
        native::reject_protected_entry(&entry, self.state_node.as_slice())?;
        let identity = native::directory_id(&parent)?;
        if identity.device != NodeId::from_stat(&entry).device
            || identity.mount != native::mount_id(&parent, name, fs::AtFlags::SYMLINK_NOFOLLOW)?
        {
            return Ok(None);
        }
        let category = match FileType::from_raw_mode(entry.st_mode) {
            FileType::RegularFile => Category::File,
            FileType::Directory => Category::Directory,
            _ => return Ok(None),
        };
        Ok(Some(RuleTarget {
            path: path.to_path_buf(),
            category,
        }))
    }

    fn read_metadata(&self, path: &Path, max_bytes: usize, prefix: bool) -> io::Result<Vec<u8>> {
        self.scope(path)?;
        if max_bytes > MAX_METADATA_BYTES {
            return Err(invalid("metadata read exceeds the discovery byte limit"));
        }
        let name = filename(path)?;
        let parent = self.open_scoped_directory(parent_path(path)?)?;
        let mut file = checked_file(&parent, name)?;
        let mut bytes = Vec::new();
        (&mut file)
            .take(max_bytes as u64 + u64::from(!prefix))
            .read_to_end(&mut bytes)?;
        if bytes.len() > max_bytes {
            return Err(invalid("metadata file exceeds the requested byte limit"));
        }
        Ok(bytes)
    }

    fn scope(&self, path: &Path) -> io::Result<&Path> {
        check_absolute(path)?;
        self.roots
            .iter()
            .filter(|root| path.starts_with(root))
            .max_by_key(|root| root.components().count())
            .map(PathBuf::as_path)
            .ok_or_else(|| deny("path is outside the configured discovery roots"))
    }

    fn open_scoped_directory(&self, path: &Path) -> io::Result<OwnedFd> {
        open_directory_below(self.scope(path)?, path)
    }

    fn check_mutation_path(&self, path: &Path) -> io::Result<()> {
        let _ = self.scope(path)?;
        #[cfg(target_os = "macos")]
        let launch_agent_exception = self
            .launch_agent_root
            .as_deref()
            .filter(|_| self.is_user_launch_agent(path));
        #[cfg(not(target_os = "macos"))]
        let launch_agent_exception: Option<&Path> = None;
        if self.roots.iter().any(|root| same_spelling(path, root))
            || same_spelling(path, &self.home)
            || self.protected.iter().any(|root| {
                launch_agent_exception != Some(root.as_path())
                    && (is_at_or_below(path, root) || is_at_or_below(root, path))
            })
        {
            return Err(deny(
                "protected path, its ancestor, or a discovery root must be preserved",
            ));
        }
        #[cfg(target_os = "macos")]
        if (self
            .webkit_root
            .as_deref()
            .is_some_and(|root| is_at_or_below(path, root))
            || self.macos_sandbox_webkit_location(path).is_some())
            && self.macos_webkit_website_data_bundle_id(path).is_none()
        {
            return Err(deny("only exact per-app WebKit website data is eligible"));
        }
        #[cfg(target_os = "macos")]
        if path
            .components()
            .any(|part| is_bundle_name(Path::new(part.as_os_str())))
            && !self.is_application_bundle(path)
        {
            return Err(deny(
                "application bundles and their contents must be preserved as a unit",
            ));
        }
        #[cfg(target_os = "macos")]
        if let Ok(relative) = path.strip_prefix(&self.home) {
            let mut parts = relative.components();
            if parts
                .next()
                .is_some_and(|part| part.as_os_str().eq_ignore_ascii_case("Library"))
                && parts.any(|part| part.as_os_str().to_str().is_some_and(is_apple_identifier))
            {
                return Err(deny("macOS-managed Library entries must be preserved"));
            }
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn is_application_bundle(&self, path: &Path) -> bool {
        is_bundle_name(path)
            && (self
                .application_roots
                .iter()
                .any(|root| path.parent() == Some(root.as_path()))
                || macos_suite_bundle_location(&self.application_roots, path)
                || self.portable_applications && macos_portable_location(&self.home, path))
    }

    #[cfg(target_os = "macos")]
    fn is_user_launch_agent(&self, path: &Path) -> bool {
        self.launch_agent_root
            .as_deref()
            .is_some_and(|root| path.parent() == Some(root))
            && path.extension() == Some(OsStr::new("plist"))
            && path
                .file_stem()
                .and_then(OsStr::to_str)
                .is_some_and(is_third_party_identifier)
    }

    #[cfg(target_os = "macos")]
    fn is_macos_cache_directory(&self, path: &Path) -> bool {
        path.parent()
            .is_some_and(|parent| self.cache_roots.iter().any(|root| root == parent))
            && path
                .file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| name.split('.').count() >= 3 && is_third_party_identifier(name))
    }

    /// Identifies a literal third-party app's direct user saved state path.
    ///
    /// This is a lexical check. Directory access still requires inspection.
    #[cfg(target_os = "macos")]
    pub fn macos_saved_state_bundle_id<'a>(&self, path: &'a Path) -> Option<&'a str> {
        let root = self.saved_state_root.as_deref()?;
        let name = path.file_name()?;
        let identifier = name.to_str()?.strip_suffix(".savedState")?;
        (is_third_party_identifier(identifier)
            && path.parent() == Some(root)
            && path.as_os_str() == root.join(name).as_os_str())
        .then_some(identifier)
    }

    /// Returns the Bundle ID from a literal sandbox support path.
    ///
    /// The path must repeat the same third-party ID in both directories.
    /// Native inspection still has to verify ownership and the tree.
    #[cfg(target_os = "macos")]
    pub fn macos_sandbox_application_support_bundle_id<'a>(
        &self,
        path: &'a Path,
    ) -> Option<&'a str> {
        let root = self.sandbox_container_root.as_deref()?;
        let identifier = path.file_name()?.to_str()?;
        if !path.starts_with(root) || !is_third_party_identifier(identifier) {
            return None;
        }
        let expected = root
            .join(identifier)
            .join("Data/Library/Application Support")
            .join(identifier);
        (path.as_os_str() == expected.as_os_str()).then_some(identifier)
    }

    /// Identifies the app in a literal user or sandbox WebKit default store path.
    ///
    /// This is a lexical check. Directory access still requires inspection.
    #[cfg(target_os = "macos")]
    pub fn macos_webkit_website_data_bundle_id<'a>(&self, path: &'a Path) -> Option<&'a str> {
        let root = self.webkit_root.as_deref()?;
        let parent = path.parent()?;
        let (identifier, webkit) = if parent.parent() == Some(root) {
            let identifier = parent.file_name()?;
            (identifier, root.join(identifier))
        } else {
            self.macos_sandbox_webkit_location(path)?
        };
        let identifier = identifier.to_str()?;
        // Global WebKit data and named stores may have different ownership.
        (is_third_party_identifier(identifier)
            && path.as_os_str() == webkit.join("WebsiteData").as_os_str())
        .then_some(identifier)
    }

    #[cfg(target_os = "macos")]
    fn macos_sandbox_webkit_location<'a>(&self, path: &'a Path) -> Option<(&'a OsStr, PathBuf)> {
        let root = self.sandbox_container_root.as_deref()?;
        if !is_at_or_below(path, root) {
            return None;
        }
        let identifier = path
            .components()
            .nth(root.components().count())?
            .as_os_str();
        let webkit = root.join(identifier).join("Data/Library/WebKit");
        // The namespace guard also covers spelling aliases on case-folding volumes.
        is_at_or_below(path, &webkit).then_some((identifier, webkit))
    }

    /// Identifies a literal third-party app's direct HTTP storage directory.
    /// The app backend verifies the observed spelling and app attribution.
    #[cfg(target_os = "macos")]
    pub fn macos_http_storage_bundle_id<'a>(&self, path: &'a Path) -> Option<&'a str> {
        let root = self.http_storage_root.as_deref()?;
        let identifier = path.file_name()?.to_str()?;
        (is_third_party_identifier(identifier)
            && path.parent() == Some(root)
            && path.as_os_str() == root.join(identifier).as_os_str())
        .then_some(identifier)
    }

    #[cfg(target_os = "macos")]
    fn is_macos_private_tree_directory(&self, path: &Path) -> bool {
        self.is_macos_cache_directory(path)
            || self.macos_saved_state_bundle_id(path).is_some()
            || self
                .macos_sandbox_application_support_bundle_id(path)
                .is_some()
            || self.macos_webkit_website_data_bundle_id(path).is_some()
            || self.macos_http_storage_bundle_id(path).is_some()
    }

    fn mutable_parent(&self, path: &Path) -> io::Result<OwnedFd> {
        self.check_mutation_path(path)?;
        let parent = parent_path(path)?;
        let root = self.scope(path)?;
        let (mut current, root_is_trusted) =
            native::open_trusted_path(root, self.uid, &self.protected_nodes, self.state_node)?;
        if !root_is_trusted {
            return Err(deny(
                "the discovery root is under a shared or untrusted directory",
            ));
        }
        let relative = parent.strip_prefix(root).map_err(io::Error::other)?;
        self.reject_state_alias(&current)?;
        for component in relative.components() {
            current = native::open_subdirectory(&current, component.as_os_str())?;
            native::reject_protected(&current, &self.protected_nodes)?;
            self.reject_state_alias(&current)?;
            native::require_local(&current)?;
            if !native::trusted_directory(&current, self.uid)? {
                return Err(deny("the target is under a shared or untrusted directory"));
            }
        }
        native::require_local(&current)?;
        #[cfg(target_os = "macos")]
        if self.is_application_bundle(path)
            && self.application_roots.iter().any(|root| root == parent)
            && native::is_sticky_application_directory(&current)?
        {
            // Sticky ownership protects the already-verified user-owned bundle
            // even when other administrators can add names to this directory.
            fs::accessat(
                &current,
                ".",
                fs::Access::WRITE_OK | fs::Access::EXEC_OK,
                fs::AtFlags::EACCESS,
            )?;
            return Ok(current);
        }
        native::require_current_user_directory(&current, self.uid)?;
        Ok(current)
    }

    fn reject_state_alias(&self, fd: &OwnedFd) -> io::Result<()> {
        if let Some(state_node) = self.state_node {
            native::reject_protected(fd, std::slice::from_ref(&state_node))?;
        }
        Ok(())
    }

    fn fingerprint(&self, path: &Path, parent: &OwnedFd) -> io::Result<Fingerprint> {
        let name = filename(path)?;
        let entry = native::entry_stat(parent, name)?;
        native::reject_protected_entry(&entry, &self.protected_nodes)?;
        let kind = FileType::from_raw_mode(entry.st_mode);
        #[cfg(target_os = "macos")]
        if self.is_user_launch_agent(path) && kind != FileType::RegularFile {
            return Err(deny("only regular user LaunchAgent plists are eligible"));
        }
        #[cfg(target_os = "macos")]
        if self.is_application_bundle(path) && kind != FileType::Directory {
            return Err(deny(
                "a reviewed application bundle must be an ordinary directory",
            ));
        }
        #[cfg(target_os = "macos")]
        if self.macos_webkit_website_data_bundle_id(path).is_some() && kind != FileType::Directory {
            return Err(deny("the website data entry must be an ordinary directory"));
        }
        match kind {
            FileType::RegularFile if !native::safe_user_entry(&entry, self.uid) => {
                return Err(deny(
                    "regular file is shared, does not belong to the current user, or is writable by others",
                ));
            }
            FileType::Symlink if entry.st_uid != self.uid || entry.st_nlink != 1 => {
                return Err(deny(
                    "link is shared or does not belong to the current user",
                ));
            }
            FileType::RegularFile | FileType::Symlink => {}
            #[cfg(target_os = "macos")]
            FileType::Directory
                if self.is_application_bundle(path)
                    || self.is_macos_private_tree_directory(path) => {}
            _ => {
                return Err(deny(
                    "directories and special files are not eligible for quarantine",
                ));
            }
        }
        let parent_id = native::directory_id(parent)?;
        let mount = native::mount_id(parent, name, fs::AtFlags::SYMLINK_NOFOLLOW)?;
        if parent_id.device != NodeId::from_stat(&entry).device || parent_id.mount != mount {
            return Err(deny("a mount point cannot be quarantined"));
        }
        let observed = self.observe_entry(parent, name, path)?;
        if observed.metadata != EntryStamp::from_stat(&entry) {
            return Err(deny(
                "the target changed while the ownership checks were running",
            ));
        }
        Ok(Fingerprint {
            path: path.as_os_str().as_bytes().to_vec(),
            parent: parent_id,
            entry: observed,
        })
    }

    fn observe_entry(
        &self,
        parent: &OwnedFd,
        name: &OsStr,
        _original: &Path,
    ) -> io::Result<VerifiedEntry> {
        let stat = native::entry_stat(parent, name)?;
        let metadata = EntryStamp::from_stat(&stat);
        #[cfg(target_os = "macos")]
        if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
            && native::acl_allows_mutation(&native::checked_file(parent, name)?)?
        {
            return Err(deny("the target file allows shared writes"));
        }
        #[cfg(target_os = "macos")]
        let bundle = match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory if self.macos_http_storage_bundle_id(_original).is_some() => Some(
                native::http_storage_directory_stamp(parent, name, self.uid)?,
            ),
            FileType::Directory if self.is_macos_private_tree_directory(_original) => {
                Some(native::cache_directory_stamp(parent, name, self.uid)?)
            }
            FileType::Directory => Some(native::application_stamp(parent, name, self.uid)?),
            _ => None,
        };
        #[cfg(target_os = "macos")]
        let launch_agent_digest = if self.is_user_launch_agent(_original) {
            let (observed, bytes) =
                self.read_private_plist(parent, name, MAX_LAUNCH_AGENT_BYTES)?;
            if metadata != observed {
                return Err(deny("the LaunchAgent changed during verification"));
            }
            Some(Sha256::digest(bytes).into())
        } else {
            None
        };
        Ok(VerifiedEntry {
            metadata,
            #[cfg(target_os = "macos")]
            bundle,
            #[cfg(target_os = "macos")]
            launch_agent_digest,
        })
    }

    #[cfg(target_os = "macos")]
    fn read_private_plist(
        &self,
        parent: &OwnedFd,
        name: &OsStr,
        limit: usize,
    ) -> io::Result<(EntryStamp, Vec<u8>)> {
        let mut file = checked_file(parent, name)?;
        let stat = fs::fstat(&file)?;
        if !native::safe_user_entry(&stat, self.uid) || native::acl_allows_mutation(&file)? {
            return Err(deny("the LaunchAgent is shared or belongs to another user"));
        }
        let stamp = EntryStamp::from_stat(&stat);
        let mut bytes = Vec::new();
        (&mut file).take(limit as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() > limit {
            return Err(invalid(
                "the LaunchAgent is empty or exceeds the supported size",
            ));
        }
        if EntryStamp::from_stat(&fs::fstat(&file)?) != stamp
            || EntryStamp::from_stat(&native::entry_stat(parent, name)?) != stamp
        {
            return Err(deny("the LaunchAgent changed while reading it"));
        }
        Ok((stamp, bytes))
    }

    fn validate_store_volume(&self, parent: NodeId, store: &impl AsFd) -> io::Result<()> {
        let destination = native::directory_id(store)?;
        if destination.device != parent.device || destination.mount != parent.mount {
            return Err(deny(
                "quarantine requires a private directory on the same mounted volume",
            ));
        }
        Ok(())
    }

    fn checked_target(&self, path: &Path, expected: &Fingerprint) -> io::Result<OwnedFd> {
        let parent = self.mutable_parent(path)?;
        if self.fingerprint(path, &parent)? != *expected {
            return Err(deny("the target or its directory changed after preview"));
        }
        Ok(parent)
    }

    /// Verifies that this exact macOS object was moved from its slot to its source.
    #[cfg(target_os = "macos")]
    pub fn verify_file_restored(
        &self,
        path: &Path,
        expected: &str,
        slot: Uuid,
    ) -> io::Result<bool> {
        let expected = Fingerprint::decode(expected, path)?;
        if self
            .read(slot, Artifact::QuarantinePurgeCommitted)?
            .is_some()
        {
            return Ok(false);
        }
        let parent = match self.mutable_parent(path) {
            Ok(parent) => parent,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        let observed = match self.fingerprint(path, &parent) {
            Ok(fingerprint) => fingerprint,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        if !observed.parent.same_inode(expected.parent)
            || !expected.entry.matches_moved(&observed.entry)
        {
            return Ok(false);
        }
        let quarantine = match self.open_store(QUARANTINE_DIR, false) {
            Ok(quarantine) => quarantine,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        self.validate_store_volume(observed.parent, &quarantine)?;
        let slots_absent = || -> io::Result<bool> {
            Ok(quarantine_name_absent(&quarantine, &slot.to_string())?
                && quarantine_name_absent(
                    &quarantine,
                    &directory_disposal::disposing_slot_name(slot),
                )?)
        };
        if !slots_absent()? {
            return Ok(false);
        }
        // The earlier rename might have completed before its directories
        // were synced. Make the observed state durable before logging success.
        native::sync_move(&quarantine, &parent)?;
        let current = self.mutable_parent(path)?;
        let entry = native::entry_stat(&current, filename(path)?)?;
        Ok(native::directory_id(&current)? == observed.parent
            && EntryStamp::from_stat(&entry) == observed.entry.metadata
            && slots_absent()?
            && self
                .read(slot, Artifact::QuarantinePurgeCommitted)?
                .is_none())
    }
}

impl FileStore for UnixFiles {
    fn inspect_file(&self, path: &Path) -> io::Result<Inspection> {
        self.scope(path)?;
        let result = (|| {
            let parent = self.mutable_parent(path)?;
            let fingerprint = self.fingerprint(path, &parent)?;
            self.validate_store_volume(fingerprint.parent, &self.store_anchor()?)?;
            Ok::<_, io::Error>(fingerprint)
        })();
        match result {
            Ok(fingerprint) => Ok(Inspection {
                fingerprint: serde_json::to_string(&fingerprint).map_err(io::Error::other)?,
                access: Access::Allowed,
            }),
            Err(error) => Ok(Inspection {
                fingerprint: String::new(),
                access: Access::ReadOnly(error.to_string()),
            }),
        }
    }

    fn file_backup_path(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<PathBuf> {
        let expected = Fingerprint::decode(expected, path)?;
        let _ = self.checked_target(path, &expected)?;
        self.validate_store_volume(expected.parent, &self.store_anchor()?)?;
        Ok(self.state.join(QUARANTINE_DIR).join(slot.to_string()))
    }

    fn quarantine_file(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<()> {
        self.quarantine_verified(path, expected, slot, || Ok(()))
    }

    fn quarantine_file_with_cancel(
        &self,
        path: &Path,
        expected: &str,
        slot: Uuid,
        cancel: &Cancellation,
    ) -> uninstallany_core::Result<()> {
        cancel.check()?;
        self.quarantine_verified(path, expected, slot, || cancel.check())
    }

    fn file_is_quarantined(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<bool> {
        self.check_mutation_path(path)?;
        let expected = Fingerprint::decode(expected, path)?;
        let quarantine = match self.open_store(QUARANTINE_DIR, false) {
            Ok(quarantine) => quarantine,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        let slot_name = slot.to_string();
        let name = OsStr::new(&slot_name);
        let initial = match native::entry_stat(&quarantine, name) {
            Ok(initial) => EntryStamp::from_stat(&initial),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        // Only the slot name itself proves absence. A missing file inside a
        // held bundle must leave the backup visible for review.
        let entry = self.observe_entry(&quarantine, name, path)?;
        if entry.metadata != initial || !expected.entry.matches_moved(&entry) {
            return Err(deny(
                "quarantine slot no longer contains the recorded object",
            ));
        }
        #[cfg(target_os = "macos")]
        {
            self.check_disposal_not_committed(slot)?;
            if !quarantine_name_absent(&quarantine, &directory_disposal::disposing_slot_name(slot))?
            {
                return Err(deny(
                    "both quarantine locations for this backup are occupied",
                ));
            }
        }
        Ok(true)
    }

    #[cfg(target_os = "macos")]
    fn recoverable_detached_file_backup(
        &self,
        path: &Path,
        expected: &str,
        slot: Uuid,
    ) -> io::Result<Option<PathBuf>> {
        let fingerprint = Fingerprint::decode(expected, path)?;
        if fingerprint.entry.bundle.is_some() {
            self.recoverable_detached_directory_backup(path, expected, slot)
        } else {
            self.recoverable_detached_single_file(path, expected, fingerprint, slot)
        }
    }

    fn restore_file(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<()> {
        let fingerprint = Fingerprint::decode(expected, path)?;
        #[cfg(target_os = "macos")]
        {
            if fingerprint.entry.bundle.is_some() {
                self.restore_directory_backup(path, expected, fingerprint, slot)
            } else {
                self.restore_single_file(path, expected, fingerprint, slot)
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let quarantine = self.open_store(QUARANTINE_DIR, false)?;
            self.restore_named_quarantine(
                path,
                &fingerprint,
                &quarantine,
                OsStr::new(&slot.to_string()),
            )
        }
    }

    fn can_purge_quarantined(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<bool> {
        let fingerprint = Fingerprint::decode(expected, path)?;
        #[cfg(target_os = "macos")]
        if self.is_directory_backup(path, &fingerprint) {
            return self.review_directory_disposal(path, fingerprint, slot);
        }
        Ok(self.purge_slot(path, &fingerprint, slot)?.is_some())
    }

    #[cfg(target_os = "macos")]
    fn has_pending_quarantine_purge(
        &self,
        path: &Path,
        expected: &str,
        slot: Uuid,
    ) -> io::Result<bool> {
        let fingerprint = Fingerprint::decode(expected, path)?;
        if fingerprint.entry.bundle.is_some() {
            self.pending_directory_disposal(path, expected, slot)
        } else {
            self.pending_single_file_disposal(path, expected, fingerprint, slot)
        }
    }

    fn purge_quarantined(&self, path: &Path, expected: &str, slot: Uuid) -> io::Result<()> {
        let fingerprint = Fingerprint::decode(expected, path)?;
        #[cfg(target_os = "macos")]
        {
            if self.is_directory_backup(path, &fingerprint) {
                self.purge_directory(path, expected, fingerprint, slot)
            } else {
                self.purge_single_file(path, expected, fingerprint, slot)
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let Some((directory, name, confirmed)) = self.purge_slot(path, &fingerprint, slot)?
            else {
                return Err(deny("no verified single-file quarantine slot is available"));
            };
            let name = OsStr::new(&name);
            if self.observe_entry(&directory, name, path)? != confirmed {
                return Err(deny("quarantine slot changed immediately before purge"));
            }
            // This directory is anchored and private to the current user. Never pass
            // AT_REMOVEDIR: a terminal symlink is removed as an entry, without traversal.
            fs::unlinkat(&directory, name, fs::AtFlags::empty())?;
            fs::fsync(&directory)?;
            Ok(())
        }
    }
}

impl UnixFiles {
    fn restore_named_quarantine(
        &self,
        path: &Path,
        expected: &Fingerprint,
        quarantine: &OwnedFd,
        name: &OsStr,
    ) -> io::Result<()> {
        let parent = self.mutable_parent(path)?;
        let parent_id = native::directory_id(&parent)?;
        if !parent_id.same_inode(expected.parent) {
            return Err(deny(
                "the original directory changed; the backup has been retained",
            ));
        }
        self.validate_store_volume(parent_id, quarantine)?;
        let held = self.observe_entry(quarantine, name, path)?;
        if !expected.entry.matches_moved(&held) {
            return Err(deny(
                "quarantine slot no longer contains the recorded object",
            ));
        }
        self.checked_move(
            (quarantine, name),
            (&parent, filename(path)?),
            &held,
            (path, parent_id),
            || Ok(()),
        )
    }

    fn purge_slot(
        &self,
        path: &Path,
        expected: &Fingerprint,
        slot: Uuid,
    ) -> io::Result<Option<(OwnedFd, String, VerifiedEntry)>> {
        self.check_mutation_path(path)?;
        let directory = match self.open_store(QUARANTINE_DIR, false) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let slot = slot.to_string();
        let observed = self.inspect_purge_entry(path, expected, &directory, OsStr::new(&slot))?;
        Ok(observed.map(|entry| (directory, slot, entry)))
    }

    fn inspect_purge_entry(
        &self,
        path: &Path,
        expected: &Fingerprint,
        directory: &OwnedFd,
        name: &OsStr,
    ) -> io::Result<Option<VerifiedEntry>> {
        let entry = match native::entry_stat(directory, name) {
            Ok(entry) => entry,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let safe = match FileType::from_raw_mode(entry.st_mode) {
            FileType::RegularFile => native::safe_user_entry(&entry, self.uid),
            FileType::Symlink => entry.st_uid == self.uid && entry.st_nlink == 1,
            _ => false,
        };
        if !safe {
            return Ok(None);
        }
        native::reject_protected_entry(&entry, &self.protected_nodes)?;
        let directory_id = native::directory_id(directory)?;
        if directory_id.device != expected.parent.device
            || directory_id.device != NodeId::from_stat(&entry).device
            || directory_id.mount
                != native::mount_id(directory, name, fs::AtFlags::SYMLINK_NOFOLLOW)?
        {
            return Err(deny(
                "the isolation entry is on an unexpected mounted volume",
            ));
        }
        let observed = self.observe_entry(directory, name, path)?;
        if EntryStamp::from_stat(&entry) != observed.metadata
            || !expected.entry.matches_moved(&observed)
        {
            return Err(deny(
                "quarantine slot no longer contains the recorded object",
            ));
        }
        Ok(Some(observed))
    }

    fn quarantine_verified<E: From<io::Error>>(
        &self,
        path: &Path,
        fingerprint: &str,
        slot: Uuid,
        before_rename: impl FnOnce() -> Result<(), E>,
    ) -> Result<(), E> {
        let expected = Fingerprint::decode(fingerprint, path)?;
        let quarantine = self.open_store(QUARANTINE_DIR, true)?;
        let parent = self.checked_target(path, &expected)?;
        self.validate_store_volume(expected.parent, &quarantine)?;
        let name = filename(path)?;
        let slot = slot.to_string();
        self.checked_move(
            (&parent, name),
            (&quarantine, OsStr::new(&slot)),
            &expected.entry,
            (path, expected.parent),
            before_rename,
        )
    }

    fn checked_move<E: From<io::Error>>(
        &self,
        from: (&OwnedFd, &OsStr),
        to: (&OwnedFd, &OsStr),
        expected: &VerifiedEntry,
        (original, original_parent): (&Path, NodeId),
        before_rename: impl FnOnce() -> Result<(), E>,
    ) -> Result<(), E> {
        if native::directory_id(&self.mutable_parent(original)?)? != original_parent
            || self.observe_entry(from.0, from.1, original)? != *expected
        {
            return Err(deny("the object or original directory changed before the move").into());
        }
        // Once rename starts, verification and sync must establish its outcome.
        before_rename()?;
        native::rename_exclusive(from, to)?;
        let observed = self.observe_entry(to.0, to.1, original);
        let parent_is_original = self
            .mutable_parent(original)
            .and_then(|fd| native::directory_id(&fd))
            .is_ok_and(|id| id == original_parent);
        if !observed
            .as_ref()
            .is_ok_and(|entry| expected.matches_moved(entry))
            || !parent_is_original
        {
            // Both kernels rename by directory entry, not by an expected inode. Verify the
            // destination, and reverse a raced move only when the source is still vacant.
            let observed = observed.map_err(|error| {
                uncertain_move(format!("could not verify the moved entry: {error}"))
            })?;
            let destination_unchanged = self
                .observe_entry(to.0, to.1, original)
                .is_ok_and(|entry| entry == observed);
            if !destination_unchanged {
                return Err(uncertain_move("the destination changed during the move").into());
            }
            native::rename_exclusive(to, from).map_err(|error| {
                uncertain_move(format!("could not reverse a raced move: {error}"))
            })?;
            // A reverse rename is still only a live observation until both
            // parent directories have been synced.
            native::sync_move(to.0, from.0).map_err(|error| {
                uncertain_move(format!("could not make the reverse move durable: {error}"))
            })?;
            let returned = self
                .observe_entry(from.0, from.1, original)
                .map_err(|error| {
                    uncertain_move(format!("could not verify the returned entry: {error}"))
                })?;
            let original_parent_restored = self
                .mutable_parent(original)
                .and_then(|fd| native::directory_id(&fd))
                .is_ok_and(|id| id == original_parent);
            let destination_vacant = native::entry_stat(to.0, to.1)
                .is_err_and(|error| error.kind() == io::ErrorKind::NotFound);
            if !observed.matches_moved(&returned)
                || !original_parent_restored
                || !destination_vacant
            {
                return Err(
                    uncertain_move("the file or its location changed during rollback").into(),
                );
            }
            return Err(deny(
                "the object or directory changed during the move; the move was reversed",
            )
            .into());
        }
        native::sync_move(from.0, to.0).map_err(|error| uncertain_move(error.to_string()))?;
        Ok(())
    }
}

fn uncertain_move(reason: impl Into<String>) -> io::Error {
    // FileStore also serves callers that use io::Result. Carry the native
    // outcome through that boundary without interpreting error messages.
    io::Error::other(uninstallany_core::Error::FileChangeNeedsReview(
        reason.into(),
    ))
}

#[cfg(target_os = "macos")]
fn quarantine_name_absent(parent: &OwnedFd, name: &str) -> io::Result<bool> {
    match native::entry_stat(parent, OsStr::new(name)) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error),
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct Fingerprint {
    path: Vec<u8>,
    parent: NodeId,
    entry: VerifiedEntry,
}

impl Fingerprint {
    fn decode(value: &str, path: &Path) -> io::Result<Self> {
        let expected: Self = serde_json::from_str(value).map_err(io::Error::other)?;
        if expected.path != path.as_os_str().as_bytes() {
            return Err(deny("the requested path differs from the confirmed target"));
        }
        Ok(expected)
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct VerifiedEntry {
    metadata: EntryStamp,
    #[cfg(target_os = "macos")]
    bundle: Option<[u8; 32]>,
    #[cfg(target_os = "macos")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    launch_agent_digest: Option<[u8; 32]>,
}

impl VerifiedEntry {
    fn matches_moved(&self, other: &Self) -> bool {
        #[cfg(target_os = "macos")]
        if self.bundle != other.bundle || self.launch_agent_digest != other.launch_agent_digest {
            return false;
        }
        self.metadata.matches_moved(&other.metadata)
    }
}

#[cfg(target_os = "macos")]
fn is_bundle_name(path: &Path) -> bool {
    path.extension()
        .is_some_and(|suffix| suffix.as_bytes().eq_ignore_ascii_case(b"app"))
}

/// Recognizes a literal `.app` one suite directory below an Applications root.
/// Filesystem access still requires the native no-follow and ownership guards.
#[cfg(target_os = "macos")]
pub fn macos_suite_bundle_location(application_roots: &[PathBuf], path: &Path) -> bool {
    let Some(suite) = path.parent() else {
        return false;
    };
    let Some(root) = application_roots
        .iter()
        .find(|root| root.is_absolute() && suite.parent() == Some(root.as_path()))
    else {
        return false;
    };
    let (Some(suite_name), Some(app_name)) = (suite.file_name(), path.file_name()) else {
        return false;
    };
    is_bundle_name(path)
        && !is_bundle_name(suite)
        && !application_roots.iter().any(|root| root.as_path() == suite)
        && [suite_name, app_name].into_iter().all(|part| {
            part.to_str()
                .is_some_and(|part| !part.starts_with('.') && !part.chars().any(char::is_control))
        })
        && root.join(suite_name).join(app_name).as_os_str() == path.as_os_str()
}

/// Checks the lexical scope of a manually chosen macOS application location.
///
/// The file store separately verifies ownership and identity without following links.
#[cfg(target_os = "macos")]
pub fn macos_portable_location(home: &Path, path: &Path) -> bool {
    use std::path::Component;

    if check_absolute(path).is_err() {
        return false;
    }
    let Ok(relative) = path.strip_prefix(home) else {
        return false;
    };
    let mut parts = relative.components().peekable();
    let Some(Component::Normal(root)) = parts.peek().copied() else {
        return false;
    };
    let reserved = [
        "Desktop",
        "Documents",
        "Downloads",
        "Library",
        "Movies",
        "Music",
        "Pictures",
        "Public",
    ];
    if reserved.iter().any(|part| root.eq_ignore_ascii_case(part))
        || root.eq_ignore_ascii_case("Applications") && relative.components().count() == 1
    {
        return false;
    }
    while let Some(part) = parts.next() {
        let Component::Normal(name) = part else {
            return false;
        };
        if name.as_bytes().starts_with(b".")
            || is_bundle_name(Path::new(name)) && parts.peek().is_some()
        {
            return false;
        }
    }
    true
}

#[cfg(target_os = "macos")]
fn is_third_party_identifier(value: &str) -> bool {
    !is_apple_identifier(value)
        && value.contains('.')
        && value.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
}

#[cfg(target_os = "macos")]
fn is_apple_identifier(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    normalized == "com.apple" || normalized.starts_with("com.apple.")
}

/// Gets the effective account's home from the system account database.
pub fn user_home() -> io::Result<PathBuf> {
    native::user_home()
}

fn check_absolute(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .as_os_str()
            .as_bytes()
            .split(|byte| *byte == b'/')
            .any(|part| matches!(part, b"." | b"..") || part.contains(&0))
    {
        return Err(invalid(
            "path must be absolute and may not contain traversal components",
        ));
    }
    Ok(())
}

fn is_at_or_below(path: &Path, root: &Path) -> bool {
    let mut parts = path.components();
    root.components().all(|part| {
        parts.next().is_some_and(|component| {
            component
                .as_os_str()
                .as_bytes()
                .eq_ignore_ascii_case(part.as_os_str().as_bytes())
        })
    })
}

fn same_spelling(left: &Path, right: &Path) -> bool {
    is_at_or_below(left, right) && is_at_or_below(right, left)
}

fn filename(path: &Path) -> io::Result<&OsStr> {
    path.file_name()
        .ok_or_else(|| invalid("path must have a final name"))
}

fn parent_path(path: &Path) -> io::Result<&Path> {
    path.parent()
        .ok_or_else(|| invalid("path must have a parent directory"))
}

fn open_directory_below(root: &Path, path: &Path) -> io::Result<OwnedFd> {
    let mut current = native::open_absolute(root)?;
    let relative = path.strip_prefix(root).map_err(io::Error::other)?;
    for component in relative.components() {
        current = native::open_subdirectory(&current, component.as_os_str())?;
    }
    Ok(current)
}

fn probe_discovery_entry(parent: &OwnedFd, path: &Path) -> io::Result<Option<RuleTarget>> {
    native::require_local(parent)?;
    let name = filename(path)?;
    let entry = native::entry_stat(parent, name)?;
    let parent_id = native::directory_id(parent)?;
    if parent_id.device != NodeId::from_stat(&entry).device
        || parent_id.mount != native::mount_id(parent, name, fs::AtFlags::SYMLINK_NOFOLLOW)?
    {
        return Ok(None);
    }
    let category = match FileType::from_raw_mode(entry.st_mode) {
        FileType::RegularFile => Category::File,
        FileType::Directory => Category::Directory,
        _ => return Ok(None),
    };
    Ok(Some(RuleTarget {
        path: path.to_path_buf(),
        category,
    }))
}

#[cfg(test)]
mod tests;
