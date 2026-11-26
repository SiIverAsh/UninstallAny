//! Guarded Windows filesystem access and same-volume quarantine.

pub(super) mod native;
mod security;

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::OwnedHandle;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows_sys::Wdk::Storage::FileSystem::{FILE_CREATE, FILE_OPEN, FILE_OPEN_IF};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_WRITE_DATA,
    GetTempPathW, READ_CONTROL,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::UI::Shell::{
    FOLDERID_CommonStartMenu, FOLDERID_Desktop, FOLDERID_Documents, FOLDERID_Downloads,
    FOLDERID_LocalAppData, FOLDERID_Profile, FOLDERID_ProgramData, FOLDERID_ProgramFiles,
    FOLDERID_ProgramFilesCommon, FOLDERID_ProgramFilesCommonX64, FOLDERID_ProgramFilesCommonX86,
    FOLDERID_ProgramFilesX64, FOLDERID_ProgramFilesX86, FOLDERID_Public, FOLDERID_PublicDesktop,
    FOLDERID_RoamingAppData, FOLDERID_StartMenu, FOLDERID_UserProfiles, FOLDERID_Windows,
    KF_FLAG_DONT_VERIFY, SHGetKnownFolderPath,
};
use windows_sys::core::GUID;
use windows_sys::core::PWSTR;

use crate::shortcuts::MAX_SHORTCUT_BYTES;
use native::{Identity, LocalPath, Metadata, OpenPath, OpenRequest, denied, invalid};
use security::PrivateSecurity;

const DATA_DIRECTORY: &str = "UninstallAny";
const QUARANTINE_DIRECTORY: &str = "Quarantine";
const JOURNAL_DIRECTORY: &str = "Journal";
const SHARE_DIRECTORY: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;
const MAX_ARTIFACT_BYTES: u64 = 20 * 1024 * 1024;

/// Whether a target can be addressed by the Windows file quarantine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileDisposition {
    /// A regular file with a single hard link.
    Regular,
    /// A symbolic link or recognized junction itself, with its destination unopened.
    Link,
    /// A directory whose approved children may be isolated separately.
    Directory,
    /// A protected or otherwise unsupported object.
    Protected,
}

/// Native no-follow fingerprint at discovery time, stored in quarantine entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSnapshot {
    /// The native, normalized DOS path to the object itself.
    #[serde(with = "native_path")]
    pub path: PathBuf,
    /// The observed volume, identity, metadata and parent in a comparable representation.
    pub fingerprint: String,
    /// The native action gate, which is re-evaluated before every write.
    pub disposition: FileDisposition,
    parent: Option<Identity>,
    metadata: Metadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    shortcut_digest: Option<[u8; 32]>,
}

/// Holds the owner-specific Windows directory policy and resolves authorized paths.
pub struct WindowsFiles {
    policy: Policy,
    roots: Vec<PathBuf>,
}

impl WindowsFiles {
    /// Resolves the current user's known folders and system protection roots.
    pub fn new() -> io::Result<Self> {
        let policy = Policy::read()?;
        let roots = policy.roots.iter().map(LocalPath::as_path).collect();
        Ok(Self { policy, roots })
    }

    /// Bounded scan roots from the shell and current user's temp directory API.
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    pub(crate) fn local_app_data(&self) -> PathBuf {
        self.policy.local.as_path()
    }

    pub(crate) fn roaming_app_data(&self) -> Option<PathBuf> {
        let roaming = local_folder(&FOLDERID_RoamingAppData)?;
        self.policy
            .roots
            .iter()
            .any(|root| root.same(&roaming))
            .then(|| roaming.as_path())
    }

    /// Checks policy without requiring the path to exist. This grants no write access.
    pub(super) fn allows_registration_location(&self, path: &Path) -> bool {
        LocalPath::parse(path).is_ok_and(|path| !self.policy.protects(&path))
    }

    /// Reports the current user's known Desktop and Start Menu shortcut scope.
    pub(super) fn is_user_shortcut(&self, path: &Path) -> bool {
        LocalPath::parse(path)
            .is_ok_and(|path| self.policy.is_user_shortcut(&path) && !self.policy.protects(&path))
    }

    /// Reads local Shell Link bytes tied to the exact snapshot used for attribution.
    pub(super) fn read_shortcut(&self, path: &Path) -> io::Result<(FileSnapshot, Vec<u8>)> {
        let requested = LocalPath::parse(path)?;
        if !is_shell_link(&requested)
            || !self.policy.has_shortcut_root(&requested)
            || self.policy.protects(&requested)
        {
            return Err(denied("the path is not in a known Windows shortcut folder"));
        }
        let opened = native::open(&requested, FILE_READ_DATA, FILE_SHARE_READ)?;
        opened.verify_address_under(&requested)?;
        let mut snapshot = self.policy.snapshot(&requested, &opened)?;
        let bytes = read_shortcut_bytes(opened.leaf(), &snapshot.metadata)?;
        snapshot.shortcut_digest = Some(Sha256::digest(&bytes).into());
        Ok((snapshot, bytes))
    }

    /// Opens the path by component without following links and reads the leaf identity.
    pub fn inspect(&self, path: &Path) -> io::Result<FileSnapshot> {
        let requested = LocalPath::parse(path)?;
        let opened = native::open(&requested, 0, SHARE_DIRECTORY)?;
        self.policy.snapshot(&requested, &opened)
    }

    /// Lists direct descendants without opening a reparse point or following its destination.
    pub fn children(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        let requested = LocalPath::parse(path)?;
        let opened = native::open(&requested, native::SCAN_DIRECTORY, SHARE_DIRECTORY)?;
        let canonical = native::canonical(opened.leaf())?;
        if !self.policy.discoverable(&requested) || !self.policy.discoverable(&canonical) {
            return Err(denied(
                "directory is outside the permitted Windows scan scope",
            ));
        }
        let path = canonical.as_path();
        Ok(native::list(opened.leaf(), true)?
            .into_iter()
            .map(|name| path.join(name))
            .collect())
    }

    /// Determines a quarantine destination without creating directories or files.
    pub fn quarantine_slot(&self, snapshot: &FileSnapshot, slot: &str) -> io::Result<PathBuf> {
        validate_slot(slot)?;
        require_movable(snapshot)?;
        let local = native::open(&self.policy.local, FILE_TRAVERSE, SHARE_DIRECTORY)?;
        if native::identity(local.leaf())?.volume != snapshot.metadata.identity.volume {
            return Err(denied("no verified same-volume quarantine is available"));
        }
        Ok(self.private_path(QUARANTINE_DIRECTORY).join(slot))
    }

    /// Moves a previously approved object under a unique slot, after native revalidation.
    pub fn quarantine(&self, snapshot: &FileSnapshot, slot: &str) -> io::Result<()> {
        self.quarantine_slot(snapshot, slot)?;
        let policy = self.fresh_policy()?;
        let requested = LocalPath::parse(&snapshot.path)?;
        let source = native::open(
            &requested,
            DELETE | READ_CONTROL | snapshot.content_access(),
            FILE_SHARE_READ,
        )?;
        let mut observed = policy.snapshot(&requested, &source)?;
        if is_shell_link(&requested) && snapshot.shortcut_digest.is_none() {
            return Err(denied("the shortcut has no approved content fingerprint"));
        }
        if snapshot.shortcut_digest.is_some() {
            observed.shortcut_digest = Some(
                Sha256::digest(read_shortcut_bytes(source.leaf(), &observed.metadata)?).into(),
            );
        }
        require_movable(&observed)?;
        if &observed != snapshot {
            return Err(denied(
                "the approved file or its parent changed after preview",
            ));
        }

        let security = PrivateSecurity::new()?;
        // A same-volume move may keep the original ACL. A private parent alone does not
        // prevent a user with bypass-traverse privilege from opening a known leaf name.
        security.require_safe_source(source.leaf())?;
        let destination = self.private_directory(QUARANTINE_DIRECTORY, true, &security)?;
        if native::identity(&destination.leaf)?.volume != observed.metadata.identity.volume {
            return Err(denied("the private quarantine is on a different volume"));
        }
        native::rename(source.leaf(), &destination.leaf, OsStr::new(slot))
    }

    /// Verifies whether an isolated object occupies the expected unique slot.
    pub fn quarantined(&self, snapshot: &FileSnapshot, slot: &str) -> io::Result<bool> {
        validate_slot(slot)?;
        require_movable(snapshot)?;
        let security = PrivateSecurity::new()?;
        let destination = self.private_directory(QUARANTINE_DIRECTORY, false, &security);
        let destination = match destination {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            operation => operation?,
        };
        let item = native::open_child(
            &destination.leaf,
            OsStr::new(slot),
            OpenRequest::existing(READ_CONTROL | snapshot.content_access(), FILE_SHARE_READ, 0),
        );
        match item {
            Ok(item) => {
                require_moved_object(snapshot, &item, &security)?;
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Restores the verified object into its original parent with replacement disabled.
    pub fn restore(&self, snapshot: &FileSnapshot, slot: &str) -> io::Result<()> {
        validate_slot(slot)?;
        require_movable(snapshot)?;
        let policy = self.fresh_policy()?;
        let original = LocalPath::parse(&snapshot.path)?;
        let Some((parent, name)) = original.parent().zip(original.name()) else {
            return Err(denied("a volume root has no restorable parent"));
        };
        let destination = native::open(&parent, FILE_TRAVERSE, SHARE_DIRECTORY)?;
        native::require_directory(destination.leaf())?;
        let canonical = native::canonical(destination.leaf())?.child(name)?;
        if !canonical.same(&original) || policy.protects(&original) || policy.protects(&canonical) {
            return Err(denied("the restoration destination is now protected"));
        }
        if snapshot.shortcut_digest.is_some() && !policy.is_user_shortcut(&canonical) {
            return Err(denied(
                "the original shortcut folder is outside the current user's shortcut scope",
            ));
        }
        let destination_id = native::identity(destination.leaf())?;
        if Some(&destination_id) != snapshot.parent.as_ref() {
            return Err(denied(
                "the original parent directory changed after quarantine",
            ));
        }

        let security = PrivateSecurity::new()?;
        let storage = self.private_directory(QUARANTINE_DIRECTORY, false, &security)?;
        let source = native::open_child(
            &storage.leaf,
            OsStr::new(slot),
            OpenRequest::existing(
                DELETE | READ_CONTROL | snapshot.content_access(),
                FILE_SHARE_READ,
                0,
            ),
        )?;
        require_moved_object(snapshot, &source, &security)?;
        native::rename(&source, destination.leaf(), name)
    }

    /// Checks for a verified, exclusively accessible non-directory quarantine entry.
    pub fn can_purge(&self, snapshot: &FileSnapshot, slot: &str) -> io::Result<bool> {
        Ok(self.open_purge_slot(snapshot, slot)?.is_some())
    }

    /// Deletes only the verified file or non-directory symbolic link in the private slot.
    pub fn purge(&self, snapshot: &FileSnapshot, slot: &str) -> io::Result<()> {
        let Some((directory, isolated)) = self.open_purge_slot(snapshot, slot)? else {
            return Err(denied(
                "no verified single-file quarantine slot is available",
            ));
        };
        native::delete_checked_handle(&isolated)?;
        // Without POSIX deletion semantics the link is removed when the handle closes.
        drop(isolated);
        let check = native::open_child(
            &directory.leaf,
            OsStr::new(slot),
            OpenRequest::existing(READ_CONTROL, FILE_SHARE_READ, native::EXISTING_FILE),
        );
        match check {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            _ => Err(denied(
                "the quarantine entry's removal could not be verified",
            )),
        }
    }

    fn open_purge_slot(
        &self,
        snapshot: &FileSnapshot,
        slot: &str,
    ) -> io::Result<Option<(PrivateDirectory, OwnedHandle)>> {
        validate_slot(slot)?;
        require_movable(snapshot)?;
        if snapshot.metadata.is_directory || snapshot.metadata.links != 1 {
            return Ok(None);
        }
        self.fresh_policy()?;
        let security = PrivateSecurity::new()?;
        let directory = match self.private_directory(QUARANTINE_DIRECTORY, false, &security) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if native::identity(&directory.leaf)?.volume != snapshot.metadata.identity.volume {
            return Err(denied("the private quarantine is on a different volume"));
        }
        let isolated = match native::open_child(
            &directory.leaf,
            OsStr::new(slot),
            OpenRequest::existing(
                DELETE | READ_CONTROL | snapshot.content_access(),
                0,
                native::EXISTING_FILE,
            ),
        ) {
            Ok(isolated) => isolated,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        require_moved_object(snapshot, &isolated, &security)?;
        if snapshot.metadata.is_reparse
            && !native::supported_link(&isolated, snapshot.metadata.tag)?
        {
            return Ok(None);
        }
        Ok(Some((directory, isolated)))
    }

    /// Returns the location used for an audit or backup artifact.
    /// This path is for reporting. Reads and writes go through the guarded methods.
    pub fn artifact_path(&self, name: &str) -> PathBuf {
        self.private_path(JOURNAL_DIRECTORY).join(name)
    }

    pub(super) fn check_report_path(path: &Path) -> io::Result<()> {
        let units: Vec<_> = path.as_os_str().encode_wide().collect();
        let ordinary = units.strip_prefix(&[92, 92, 63, 92]).unwrap_or(&units);
        let target = LocalPath::parse(Path::new(&OsString::from_wide(ordinary)))?;
        let parent = target
            .parent()
            .ok_or_else(|| invalid("choose a report file in an existing directory"))?;
        let opened = native::open(&parent, FILE_TRAVERSE, SHARE_DIRECTORY)?;
        native::require_directory(opened.leaf())
    }

    /// Writes and syncs a complete artifact, then publishes it without replacing an older one.
    pub fn create_artifact(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        validate_artifact(name)?;
        if bytes.len() as u64 > MAX_ARTIFACT_BYTES {
            return Err(invalid("the audit artifact exceeds its size limit"));
        }
        self.fresh_policy()?;
        let security = PrivateSecurity::new()?;
        let directory = self.private_directory(JOURNAL_DIRECTORY, true, &security)?;
        let pending = format!("{name}.pending");
        let artifact = native::open_child(
            &directory.leaf,
            OsStr::new(&pending),
            OpenRequest {
                access: FILE_WRITE_DATA | DELETE,
                share: 0,
                disposition: FILE_CREATE,
                options: native::EXISTING_FILE,
                security: security.descriptor(),
            },
        )?;
        let mut file = File::from(artifact);
        file.write_all(bytes)?;
        file.sync_all()?;
        let artifact: OwnedHandle = file.into();
        native::rename(&artifact, &directory.leaf, OsStr::new(name))?;
        File::from(artifact).sync_all()
    }

    /// Reads an audit or backup artifact without following links.
    pub fn read_artifact(&self, name: &str) -> io::Result<Vec<u8>> {
        validate_artifact(name)?;
        let security = PrivateSecurity::new()?;
        let directory = self.private_directory(JOURNAL_DIRECTORY, false, &security)?;
        let item = native::open_child(
            &directory.leaf,
            OsStr::new(name),
            OpenRequest::existing(
                FILE_READ_DATA | READ_CONTROL,
                FILE_SHARE_READ,
                native::EXISTING_FILE,
            ),
        )?;
        let metadata = native::regular(&item)?;
        security.require_private(&item)?;
        if metadata.size as u64 > MAX_ARTIFACT_BYTES {
            return Err(invalid("the audit artifact exceeds its size limit"));
        }
        let mut bytes = Vec::with_capacity(metadata.size as usize);
        File::from(item)
            .take(MAX_ARTIFACT_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_ARTIFACT_BYTES {
            return Err(invalid(
                "the audit artifact exceeded its size limit while reading",
            ));
        }
        Ok(bytes)
    }

    /// Lists published artifacts without creating the journal directory.
    pub fn artifact_names(&self) -> io::Result<Vec<String>> {
        let security = PrivateSecurity::new()?;
        let directory = match self.private_directory(JOURNAL_DIRECTORY, false, &security) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            result => result?,
        };
        Ok(native::list(&directory.leaf, false)?
            .into_iter()
            .filter_map(|name| name.into_string().ok())
            .filter(|name| validate_artifact(name).is_ok())
            .collect())
    }

    fn fresh_policy(&self) -> io::Result<Policy> {
        let policy = Policy::read()?;
        if !policy.local.same(&self.policy.local) {
            return Err(denied(
                "the current user's local data folder changed during the operation",
            ));
        }
        Ok(policy)
    }

    fn private_path(&self, directory: &str) -> PathBuf {
        self.policy
            .local
            .as_path()
            .join(DATA_DIRECTORY)
            .join(directory)
    }

    fn private_directory(
        &self,
        name: &str,
        create: bool,
        security: &PrivateSecurity,
    ) -> io::Result<PrivateDirectory> {
        let base = native::open(&self.policy.local, FILE_TRAVERSE, SHARE_DIRECTORY)?;
        native::require_directory(base.leaf())?;
        if !native::canonical(base.leaf())?.same(&self.policy.local) {
            return Err(denied(
                "the private data directory resolved through an alias",
            ));
        }
        let state = private_child(base.leaf(), DATA_DIRECTORY, create, security)?;
        let leaf = private_child(&state, name, create, security)?;
        Ok(PrivateDirectory {
            _base: base,
            _state: state,
            leaf,
        })
    }
}

struct PrivateDirectory {
    _base: OpenPath,
    _state: OwnedHandle,
    leaf: OwnedHandle,
}

fn private_child(
    parent: &OwnedHandle,
    name: &str,
    create: bool,
    security: &PrivateSecurity,
) -> io::Result<OwnedHandle> {
    let disposition = if create { FILE_OPEN_IF } else { FILE_OPEN };
    let dir = native::open_child(
        parent,
        OsStr::new(name),
        OpenRequest {
            access: native::SCAN_DIRECTORY | READ_CONTROL,
            share: SHARE_DIRECTORY,
            disposition,
            options: native::EXISTING_DIRECTORY,
            security: if create {
                security.descriptor()
            } else {
                null_mut()
            },
        },
    )?;
    native::require_directory(&dir)?;
    security.require_private(&dir)?;
    Ok(dir)
}

fn require_movable(snapshot: &FileSnapshot) -> io::Result<()> {
    match snapshot.disposition {
        FileDisposition::Regular | FileDisposition::Link => Ok(()),
        FileDisposition::Directory => Err(denied("whole-directory quarantine is unavailable")),
        FileDisposition::Protected => {
            Err(denied("the file is protected or its type is unsupported"))
        }
    }
}

impl FileSnapshot {
    fn content_access(&self) -> u32 {
        if self.shortcut_digest.is_some() {
            FILE_READ_DATA
        } else {
            0
        }
    }
}

fn read_shortcut_bytes(handle: &OwnedHandle, metadata: &Metadata) -> io::Result<Vec<u8>> {
    if !metadata.is_single_local_file() {
        return Err(denied("the shortcut is linked, remote, or offline"));
    }
    let length = u64::try_from(metadata.size)
        .ok()
        .filter(|&length| length <= MAX_SHORTCUT_BYTES)
        .and_then(|length| usize::try_from(length).ok())
        .ok_or_else(|| invalid("the shortcut length exceeds the supported limit"))?;
    // The duplicate keeps the original handle's no-write and no-delete sharing.
    let mut file = File::from(handle.try_clone()?);
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes)?;
    if native::metadata(handle)? != *metadata {
        return Err(denied("the shortcut changed while reading its target"));
    }
    Ok(bytes)
}

fn require_moved_object(
    snapshot: &FileSnapshot,
    file: &OwnedHandle,
    security: &PrivateSecurity,
) -> io::Result<()> {
    let metadata = native::metadata(file)?;
    if !metadata.same_moved_object(&snapshot.metadata) {
        return Err(denied(
            "the quarantine slot contains an unexpected or modified object",
        ));
    }
    security.require_safe_source(file)?;
    if let Some(expected) = snapshot.shortcut_digest {
        let actual = Sha256::digest(read_shortcut_bytes(file, &metadata)?);
        if <[u8; 32]>::from(actual) != expected {
            return Err(denied("the quarantined shortcut content changed"));
        }
    }
    Ok(())
}

fn validate_slot(slot: &str) -> io::Result<()> {
    if slot.len() < 16
        || slot.len() > 80
        || !slot
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(invalid("invalid quarantine slot identifier"));
    }
    Ok(())
}

fn validate_artifact(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() > 160
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        || !(name.ends_with(".json") || name.ends_with(".reg"))
    {
        return Err(invalid("invalid audit artifact name"));
    }
    Ok(())
}

struct Policy {
    local: LocalPath,
    profile: LocalPath,
    profiles_parent: LocalPath,
    public: LocalPath,
    public_desktop: Option<LocalPath>,
    roots: Vec<LocalPath>,
    exact: Vec<LocalPath>,
    trees: Vec<LocalPath>,
    managed_trees: Vec<LocalPath>,
    shortcut_roots: Vec<LocalPath>,
    user_shortcut_roots: Vec<LocalPath>,
    shared_shortcut_roots: Option<Vec<LocalPath>>,
}

impl Policy {
    fn read() -> io::Result<Self> {
        let local = required_folder(&FOLDERID_LocalAppData)?;
        let profile = required_folder(&FOLDERID_Profile)?;
        let profiles_parent = required_folder(&FOLDERID_UserProfiles)?;
        let windows = required_folder(&FOLDERID_Windows)?;
        let public = required_folder(&FOLDERID_Public)?;
        let public_desktop = optional_protected_folder(&FOLDERID_PublicDesktop)?;
        let program_data = required_folder(&FOLDERID_ProgramData)?;
        let program_files = required_folder(&FOLDERID_ProgramFiles)?;
        let mut roots = vec![local.clone(), program_data.clone(), program_files.clone()];
        extend_folders(
            &mut roots,
            &[
                FOLDERID_ProgramFilesX86,
                FOLDERID_ProgramFilesX64,
                FOLDERID_RoamingAppData,
            ],
        );
        if let Some(temp) = temp_directory().filter(|temp| {
            temp.depth() > 0
                && !profile.starts_with(temp)
                && !windows.starts_with(temp)
                && !roots.iter().any(|root| root.starts_with(temp))
        }) {
            roots.push(temp);
        }
        let mut exact = roots.clone();
        exact.extend([profile.clone(), profiles_parent.clone()]);
        exact.push(LocalPath::parse(&std::env::current_exe()?)?);
        let mut trees = vec![
            windows,
            local.child(OsStr::new(DATA_DIRECTORY))?,
            local.child(OsStr::new("Packages"))?,
            local.child(OsStr::new("Microsoft"))?,
        ];
        trees.extend(optional_protected_folder(&FOLDERID_Documents)?);
        trees.extend(optional_protected_folder(&FOLDERID_Downloads)?);
        extend_folders(
            &mut trees,
            &[
                FOLDERID_ProgramFilesCommon,
                FOLDERID_ProgramFilesCommonX64,
                FOLDERID_ProgramFilesCommonX86,
            ],
        );
        let mut user_shortcut_roots: Vec<_> = optional_protected_folder(&FOLDERID_Desktop)?
            .into_iter()
            .collect();
        extend_folders(&mut user_shortcut_roots, &[FOLDERID_StartMenu]);
        let mut declared_shared: Vec<_> = public_desktop.iter().cloned().collect();
        let common_start_menu = local_folder(&FOLDERID_CommonStartMenu);
        let shared_folders_known = public_desktop.is_some() && common_start_menu.is_some();
        if let Some(root) = common_start_menu {
            declared_shared.push(root);
        }
        let mut shortcut_roots = user_shortcut_roots.clone();
        for shared in &declared_shared {
            if !shortcut_roots.iter().any(|root| root.same(shared)) {
                shortcut_roots.push(shared.clone());
            }
        }
        // A known shared folder can use a short name for the user's canonical path.
        // If a shared root is ambiguous, no shortcut is authorized for quarantine.
        let shared_shortcut_roots = if shared_folders_known {
            declared_shared
                .iter()
                .map(canonical_shortcut_root)
                .collect::<io::Result<Vec<_>>>()
                .ok()
        } else {
            None
        };
        roots.extend(shortcut_roots.iter().cloned());
        exact.extend(shortcut_roots.iter().cloned());
        // Machine-wide installer caches and Microsoft configuration can affect unrelated apps.
        let mut managed_trees = vec![
            program_data.child(OsStr::new("Microsoft"))?,
            program_data.child(OsStr::new("Package Cache"))?,
        ];
        if let Some(roaming) = local_folder(&FOLDERID_RoamingAppData) {
            managed_trees.push(roaming.child(OsStr::new("Microsoft"))?);
        }
        let mut machine_programs = vec![program_files];
        extend_folders(
            &mut machine_programs,
            &[FOLDERID_ProgramFilesX86, FOLDERID_ProgramFilesX64],
        );
        for root in machine_programs {
            for name in [
                "Microsoft",
                "Windows Defender",
                "Windows Mail",
                "Windows Media Player",
                "Windows NT",
                "WindowsPowerShell",
                "Internet Explorer",
            ] {
                managed_trees.push(root.child(OsStr::new(name))?);
            }
        }
        Ok(Self {
            local,
            profile,
            profiles_parent,
            public,
            public_desktop,
            roots,
            exact,
            trees,
            managed_trees,
            shortcut_roots,
            user_shortcut_roots,
            shared_shortcut_roots,
        })
    }

    fn snapshot(&self, requested: &LocalPath, opened: &OpenPath) -> io::Result<FileSnapshot> {
        let canonical = native::canonical(opened.leaf())?;
        let parent = opened.parent_id()?;
        let metadata = native::metadata(opened.leaf())?;
        let protected_shortcut = (is_shell_link(requested) || is_shell_link(&canonical))
            && (!requested.same(&canonical)
                || !self.is_user_shortcut(&canonical)
                || !metadata.is_single_local_file());
        let disposition = if self.protects(requested)
            || self.protects(&canonical)
            || metadata.links != 1
            || protected_shortcut
        {
            FileDisposition::Protected
        } else if metadata.is_reparse {
            if native::supported_link(opened.leaf(), metadata.tag)? {
                FileDisposition::Link
            } else {
                FileDisposition::Protected
            }
        } else if metadata.is_directory {
            FileDisposition::Directory
        } else {
            FileDisposition::Regular
        };
        Ok(FileSnapshot {
            path: canonical.as_path(),
            fingerprint: format!("{parent:?}/{metadata:?}"),
            disposition,
            parent,
            metadata,
            shortcut_digest: None,
        })
    }

    fn protects(&self, path: &LocalPath) -> bool {
        if path.depth() == 0 || self.exact.iter().any(|exact| path.same(exact)) {
            return true;
        }
        // Do not permit portable scans to claim other profiles or arbitrary public data.
        let shortcut_name = is_shell_link(path);
        self.system_tree(path)
            || self.trees.iter().any(|root| path.starts_with(root))
            || self.managed_trees.iter().any(|root| path.starts_with(root))
            || (self.shared_profile(path) && !(shortcut_name && self.public_shortcut_tree(path)))
            || (self.is_shortcut_tree(path) && !shortcut_name)
    }

    fn discoverable(&self, path: &LocalPath) -> bool {
        if self.system_tree(path) || self.trees.iter().any(|root| path.starts_with(root)) {
            return false;
        }
        if self.shared_profile(path) {
            return self.public_shortcut_tree(path);
        }
        if self.is_shortcut_tree(path) {
            return true;
        }
        !self.protects(path) || self.roots.iter().any(|root| path.same(root))
    }

    fn is_shortcut_tree(&self, path: &LocalPath) -> bool {
        self.shortcut_roots
            .iter()
            .any(|root| path.starts_with(root))
    }

    fn has_shortcut_root(&self, path: &LocalPath) -> bool {
        self.shortcut_roots.iter().any(|root| {
            root.depth() > 0
                && !self.profile.starts_with(root)
                && path.depth() > root.depth()
                && path.starts_with(root)
        })
    }

    fn is_user_shortcut(&self, path: &LocalPath) -> bool {
        is_shell_link(path)
            && !self.shared_profile(path)
            && self.user_shortcut_roots.iter().any(|root| {
                root.depth() > 0
                    && !self.profile.starts_with(root)
                    && path.depth() > root.depth()
                    && path.starts_with(root)
            })
            && self
                .shared_shortcut_roots
                .as_ref()
                .is_some_and(|roots| !roots.iter().any(|root| path.starts_with(root)))
    }

    fn shared_profile(&self, path: &LocalPath) -> bool {
        path.starts_with(&self.public)
            || (path.starts_with(&self.profiles_parent) && !path.starts_with(&self.profile))
    }

    fn public_shortcut_tree(&self, path: &LocalPath) -> bool {
        self.public_desktop
            .as_ref()
            .is_some_and(|desktop| desktop.starts_with(&self.public) && path.starts_with(desktop))
    }

    fn system_tree(&self, path: &LocalPath) -> bool {
        let fixed_root_tree = path.first().is_some_and(|first| {
            [
                "$Recycle.Bin",
                "Boot",
                "Recovery",
                "System Volume Information",
                "Windows.old",
            ]
            .into_iter()
            .any(|name| native::equal_name(first, OsStr::new(name)))
        });
        let managed_install_tree = self.roots.iter().any(|root| {
            ["WindowsApps", "ModifiableWindowsApps", "Common Files"]
                .into_iter()
                .any(|name| {
                    root.child(OsStr::new(name))
                        .is_ok_and(|child| path.starts_with(&child))
                })
        });
        fixed_root_tree || managed_install_tree
    }
}

fn is_shell_link(path: &LocalPath) -> bool {
    path.name()
        .and_then(|name| Path::new(name).extension())
        .is_some_and(|extension| native::equal_name(extension, OsStr::new("lnk")))
}

fn canonical_shortcut_root(root: &LocalPath) -> io::Result<LocalPath> {
    match native::walk(root, 0, SHARE_DIRECTORY)? {
        native::PathWalk::Present(opened) => {
            native::require_directory(opened.leaf())?;
            native::canonical(opened.leaf())
        }
        native::PathWalk::Missing { parent, .. } => {
            parent.verify_address_under(root)?;
            Ok(root.clone())
        }
    }
}

fn required_folder(folder: &GUID) -> io::Result<LocalPath> {
    LocalPath::parse(&known_folder(folder)?)
}

fn local_folder(folder: &GUID) -> Option<LocalPath> {
    required_folder(folder).ok()
}

fn optional_protected_folder(folder: &GUID) -> io::Result<Option<LocalPath>> {
    // A known folder may redirect to a network name; its entire namespace is already denied.
    let path = known_folder(folder)?;
    if path.as_os_str().encode_wide().take(2).eq([92, 92]) {
        return Ok(None);
    }
    LocalPath::parse(&path).map(Some)
}

fn extend_folders(target: &mut Vec<LocalPath>, folders: &[GUID]) {
    for path in folders.iter().filter_map(local_folder) {
        if !target.iter().any(|existing| path.same(existing)) {
            target.push(path);
        }
    }
}

fn known_folder(folder: &GUID) -> io::Result<PathBuf> {
    let mut path: PWSTR = null_mut();
    // SAFETY: Windows reads the GUID and fills a COM-allocated path on success.
    let status =
        unsafe { SHGetKnownFolderPath(folder, KF_FLAG_DONT_VERIFY as u32, null_mut(), &mut path) };
    let _allocation = KnownFolder(path);
    if status < 0 {
        return Err(io::Error::other(format!(
            "could not query Windows known folder (HRESULT {status:#x})"
        )));
    }
    if path.is_null() {
        return Err(io::Error::other("Windows returned an empty known folder"));
    }
    let mut length = 0;
    // SAFETY: The successful call returned a terminated UTF-16 string.
    while unsafe { *path.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: The path is live and `length` is its measured UTF-16 length.
    Ok(PathBuf::from(OsString::from_wide(unsafe {
        std::slice::from_raw_parts(path, length)
    })))
}

struct KnownFolder(PWSTR);

impl Drop for KnownFolder {
    fn drop(&mut self) {
        // SAFETY: Folder paths from SHGetKnownFolderPath use the COM allocator.
        unsafe { CoTaskMemFree(self.0.cast()) };
    }
}

fn temp_directory() -> Option<LocalPath> {
    let mut units = vec![0_u16; 32_768];
    // SAFETY: The buffer is writable and the reported capacity is measured in UTF-16 units.
    let length = unsafe { GetTempPathW(units.len() as u32, units.as_mut_ptr()) } as usize;
    if length == 0 || length >= units.len() {
        return None;
    }
    LocalPath::parse(Path::new(&OsString::from_wide(&units[..length]))).ok()
}

mod native_path {
    use super::*;

    pub(super) fn serialize<S: serde::Serializer>(
        path: &Path,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        path.as_os_str()
            .encode_wide()
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<PathBuf, D::Error> {
        Vec::<u16>::deserialize(deserializer)
            .map(|units| PathBuf::from(OsString::from_wide(&units)))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use uuid::Uuid;

    use super::*;

    #[test]
    fn local_path_rejects_traversal_devices_and_nonlocal_names() {
        for name in [
            r"C:\Apps\..\Windows",
            r"C:Apps\file",
            r"\\server\share\file",
            r"\\?\C:\file",
            r"C:\Apps\A:stream",
            r"C:\Apps\con.txt",
            r"C:\Apps\LPT²",
            r"C:\Apps\private.\file",
        ] {
            assert!(LocalPath::parse(Path::new(name)).is_err(), "{name}");
        }
        assert!(LocalPath::parse(Path::new(r"C:\Apps\Test\")).is_ok());
    }

    #[test]
    fn path_ancestry_uses_components() -> io::Result<()> {
        let root = LocalPath::parse(Path::new(r"C:\Apps\Acme"))?;
        let child = LocalPath::parse(Path::new(r"c:\apps\ACME\cache.dat"))?;
        let sibling = LocalPath::parse(Path::new(r"C:\Apps\AcmeOther\cache.dat"))?;
        assert!(child.starts_with(&root));
        assert!(!sibling.starts_with(&root));
        Ok(())
    }

    #[test]
    fn artifact_and_quarantine_names_cannot_change_directory() {
        assert!(validate_artifact("evt-a1b2.json").is_ok());
        assert!(validate_artifact("backup-a1b2.reg").is_ok());
        assert!(validate_artifact("backup-a1b2.reg.pending").is_err());
        assert!(validate_artifact("../backup.json").is_err());
        assert!(validate_slot("12345678-1234-1234-1234-123456789abc").is_ok());
        assert!(validate_slot("../123456789123456789").is_err());
    }

    #[test]
    #[ignore = "run on a disposable Windows VM with fixed NTFS storage"]
    fn native_quarantine_round_trip_and_purge_preserve_a_new_target() -> io::Result<()> {
        let files = WindowsFiles::new()?;
        let name = format!("UninstallAny-test-{}", Uuid::new_v4());
        let directory = files.policy.local.as_path().join(name);
        fs::create_dir(&directory)?;
        let path = directory.join("private-fixture.txt");
        write_private_fixture(&directory, b"synthetic quarantine fixture")?;
        let snapshot = files.inspect(&path)?;
        let slot = Uuid::new_v4().to_string();
        let isolated = files.quarantine_slot(&snapshot, &slot)?;
        assert!(!isolated.try_exists()?);

        files.quarantine(&snapshot, &slot)?;
        assert!(!path.try_exists()?);
        assert!(files.quarantined(&snapshot, &slot)?);
        fs::write(&path, b"restore conflict fixture")?;
        assert!(files.restore(&snapshot, &slot).is_err());
        assert_eq!(fs::read(&path)?, b"restore conflict fixture");
        assert!(files.quarantined(&snapshot, &slot)?);

        let conflicting = directory.join("known-conflict-fixture.txt");
        fs::rename(&path, &conflicting)?;
        files.restore(&snapshot, &slot)?;
        assert!(!isolated.try_exists()?);
        assert_eq!(fs::read(&path)?, b"synthetic quarantine fixture");

        let snapshot = files.inspect(&path)?;
        let slot = Uuid::new_v4().to_string();
        let isolated = files.quarantine_slot(&snapshot, &slot)?;
        files.quarantine(&snapshot, &slot)?;
        fs::write(&path, b"purge conflict fixture")?;
        assert!(files.can_purge(&snapshot, &slot)?);
        files.purge(&snapshot, &slot)?;
        assert!(!isolated.try_exists()?);
        assert_eq!(fs::read(&path)?, b"purge conflict fixture");
        fs::remove_file(&conflicting)?;
        fs::remove_file(&path)?;
        fs::remove_dir(directory)
    }

    fn write_private_fixture(directory: &Path, contents: &[u8]) -> io::Result<()> {
        let parent = native::open(
            &LocalPath::parse(directory)?,
            FILE_TRAVERSE,
            SHARE_DIRECTORY,
        )?;
        let security = PrivateSecurity::new()?;
        let file = native::open_child(
            parent.leaf(),
            OsStr::new("private-fixture.txt"),
            OpenRequest {
                access: FILE_WRITE_DATA,
                share: 0,
                disposition: FILE_CREATE,
                options: native::EXISTING_FILE,
                security: security.descriptor(),
            },
        )?;
        File::from(file).write_all(contents)
    }
}
