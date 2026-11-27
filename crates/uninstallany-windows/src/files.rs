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
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uninstallany_core::{Cancellation, Error};
use uuid::Uuid;
use windows_sys::Wdk::Storage::FileSystem::{FILE_CREATE, FILE_OPEN, FILE_OPEN_IF};
use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ADD_FILE, FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
    FILE_WRITE_DATA, GetTempPathW, READ_CONTROL,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::UI::Shell::{
    FOLDERID_AdminTools, FOLDERID_CommonAdminTools, FOLDERID_CommonPrograms,
    FOLDERID_CommonStartMenu, FOLDERID_CommonStartup, FOLDERID_Desktop, FOLDERID_Documents,
    FOLDERID_Downloads, FOLDERID_LocalAppData, FOLDERID_Profile, FOLDERID_ProgramData,
    FOLDERID_ProgramFiles, FOLDERID_ProgramFilesCommon, FOLDERID_ProgramFilesCommonX64,
    FOLDERID_ProgramFilesCommonX86, FOLDERID_ProgramFilesX64, FOLDERID_ProgramFilesX86,
    FOLDERID_Programs, FOLDERID_Public, FOLDERID_PublicDesktop, FOLDERID_RoamingAppData,
    FOLDERID_StartMenu, FOLDERID_Startup, FOLDERID_UserProfiles, FOLDERID_UserProgramFiles,
    FOLDERID_UserProgramFilesCommon, FOLDERID_Windows, KF_FLAG_DEFAULT_PATH, KF_FLAG_DONT_VERIFY,
    KF_FLAG_NOT_PARENT_RELATIVE, SHGetKnownFolderPath,
};
use windows_sys::core::GUID;
use windows_sys::core::PWSTR;

use crate::shortcuts::{self, MAX_SHORTCUT_BYTES, ShortcutTarget};
use crate::uninstall::{ExecutableIdentity, PinnedExecutable, pin_startup_shortcut_target};
use native::{Identity, LocalPath, Metadata, OpenPath, OpenRequest, denied, invalid};
use security::PrivateSecurity;

const DATA_DIRECTORY: &str = "UninstallAny";
// These names match the machine MSI and the privileged helper's trust path.
const INSTALL_DIRECTORY: &str = "UninstallAny";
const INSTALLED_GUI_NAME: &str = "UninstallAny.exe";
const QUARANTINE_DIRECTORY: &str = "Quarantine";
const JOURNAL_DIRECTORY: &str = "Journal";
const COORDINATION_DIRECTORY: &str = "Coordination";
const MUTATION_LOCK: &str = "mutation.lock";
const SHARE_DIRECTORY: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;
const MAX_ARTIFACT_BYTES: u64 = 20 * 1024 * 1024;
// These direct AppData names serve Windows or multiple applications.
const RESERVED_APP_DATA_NAMES: &[&str] = &[
    "Comms",
    "ConnectedDevicesPlatform",
    "CrashDumps",
    "D3DSCache",
    "Desktop",
    "Diagnostics",
    "Documents",
    "ElevatedDiagnostics",
    "Favorites",
    "Microsoft",
    "Packages",
    "ProgramData",
    "Programs",
    "Publishers",
    "SquirrelTemp",
    "Temp",
    "VirtualStore",
];

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    startup_executable: Option<ExecutableIdentity>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ShortcutScope {
    Ordinary,
    Startup,
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

    /// Holds a private, no-follow exclusive file handle for one complete write operation.
    pub(super) fn lock_mutations(&self) -> io::Result<impl Sized> {
        self.fresh_policy()?;
        let security = PrivateSecurity::new()?;
        let directory = self.private_directory(COORDINATION_DIRECTORY, true, &security)?;
        // Windows releases the share reservation even after process termination.
        // Keeping the parent handles open prevents swapping the lock's directory.
        let file = native::open_child(
            &directory.leaf,
            OsStr::new(MUTATION_LOCK),
            OpenRequest {
                access: FILE_READ_DATA | FILE_WRITE_DATA | READ_CONTROL,
                share: 0,
                disposition: FILE_OPEN_IF,
                options: native::EXISTING_FILE,
                security: security.descriptor(),
            },
        )
        .map_err(|error| {
            if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "another UninstallAny operation is changing this Windows profile",
                )
            } else {
                error
            }
        })?;
        native::regular(&file)?;
        security.require_private(&file)?;
        Ok((file, directory))
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

    /// Finds existing literal-name directories under this user's default AppData roots.
    pub(super) fn app_data_directories(&self, application_name: &str) -> Vec<PathBuf> {
        let name = OsStr::new(application_name);
        if RESERVED_APP_DATA_NAMES
            .iter()
            .any(|reserved| native::equal_name(name, OsStr::new(reserved)))
        {
            return Vec::new();
        }
        let Ok(policy) = self.fresh_policy() else {
            return Vec::new();
        };
        [&FOLDERID_LocalAppData, &FOLDERID_RoamingAppData]
            .into_iter()
            .filter_map(|folder| {
                let current = local_folder(folder)?;
                let default = default_local_folder(folder)?;
                if !current.same(&default)
                    || current.depth() <= policy.profile.depth()
                    || !current.starts_with(&policy.profile)
                {
                    return None;
                }
                let candidate = current.child(name).ok()?;
                // The no-follow walk holds the root and every other ancestor.
                // The canonical name must agree with the full declared path.
                let opened = native::open(&candidate, 0, SHARE_DIRECTORY).ok()?;
                native::require_directory(opened.leaf()).ok()?;
                opened.verify_address_under(&candidate).ok()?;
                (!policy.protects(&candidate)).then(|| candidate.as_path())
            })
            .collect()
    }

    /// Checks policy without requiring the path to exist. This grants no write access.
    pub(super) fn allows_registration_location(&self, path: &Path) -> bool {
        LocalPath::parse(path).is_ok_and(|path| !self.policy.protects(&path))
    }

    pub(super) fn inferred_user_program_directory(&self, directory: &Path) -> Option<PathBuf> {
        let path = LocalPath::parse(directory).ok()?;
        let root = local_folder(&FOLDERID_UserProgramFiles)?;
        let shared = local_folder(&FOLDERID_UserProgramFilesCommon)?;
        let default_shared = default_local_folder(&FOLDERID_UserProgramFilesCommon)?;
        let canonical_shared = canonical_shortcut_root(&shared).ok()?;
        let is_direct_child = root.same(&default_local_folder(&FOLDERID_UserProgramFiles)?)
            && root.parent()?.same(&self.policy.local)
            && path.parent()?.same(&root);
        let is_shared = [&shared, &default_shared, &canonical_shared]
            .iter()
            .any(|root| path.starts_with(root));
        (is_direct_child && !is_shared && !self.policy.protects(&path)).then(|| path.as_path())
    }

    /// Reports the current user's known Desktop and Start Menu shortcut scope.
    pub(super) fn is_user_shortcut(&self, path: &Path) -> bool {
        LocalPath::parse(path)
            .is_ok_and(|path| self.policy.is_user_shortcut(&path) && !self.policy.protects(&path))
    }

    /// Returns an eligible Desktop for scanning only its immediate shortcut entries.
    pub(super) fn user_shortcut_desktop(&self) -> Option<PathBuf> {
        let desktop = local_folder(&FOLDERID_Desktop)?;
        let example = desktop.child(OsStr::new("shortcut.lnk")).ok()?;
        self.policy
            .is_user_shortcut(&example)
            .then(|| desktop.as_path())
    }

    /// Returns the verified, unredirected Desktop for ordinary shortcut discovery.
    pub(super) fn default_user_shortcut_desktop(&self) -> Option<PathBuf> {
        self.policy
            .default_shortcut_desktop()
            .map(|desktop| desktop.as_path())
    }

    /// Rechecks the narrow discovery roots independently of the link's bytes.
    pub(super) fn check_observed_ordinary_shortcut_scope(
        &self,
        path: &Path,
        program_depth_limit: usize,
    ) -> io::Result<bool> {
        let path = LocalPath::parse(path)?;
        let policy = self.fresh_policy()?;
        if !policy.is_user_shortcut(&path) || policy.protects(&path) {
            return Ok(false);
        }
        let Some(parent) = path.parent() else {
            return Ok(false);
        };
        if policy
            .default_shortcut_desktop()
            .is_some_and(|desktop| parent.same(&desktop))
        {
            return Ok(true);
        }
        Ok(policy.start_menu_programs().is_some_and(|programs| {
            programs.includes(&path)
                && parent
                    .depth()
                    .checked_sub(programs.root.depth())
                    .is_some_and(|depth| depth <= program_depth_limit)
        }))
    }

    /// Checks whether the exact user package directory remains. Its contents stay private.
    pub(super) fn remaining_package_directory(&self, family: &str) -> io::Result<Option<PathBuf>> {
        let package = self
            .policy
            .local
            .child(OsStr::new("Packages"))?
            .child(OsStr::new(family))?;
        let opened = match native::open(&package, 0, SHARE_DIRECTORY) {
            Ok(opened) => opened,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        native::require_directory(opened.leaf())?;
        opened.verify_address_under(&package)?;
        Ok(Some(package.as_path()))
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

    pub(super) fn is_startup_shortcut(&self, path: &Path) -> bool {
        LocalPath::parse(path).is_ok_and(|path| self.policy.is_startup_shortcut(&path))
    }

    pub(super) fn startup_shortcut_paths(&self) -> io::Result<Vec<PathBuf>> {
        let Some(root) = self.policy.startup_folders().writable.as_ref() else {
            return Ok(Vec::new());
        };
        let opened = native::open(root, native::SCAN_DIRECTORY, SHARE_DIRECTORY)?;
        opened.verify_address_under(root)?;
        Ok(listed_children(&opened, root)?
            .into_iter()
            .filter(|path| self.is_startup_shortcut(path))
            .collect())
    }

    /// Reads a direct shortcut and obtains a native fingerprint for its executable.
    pub(super) fn read_startup_shortcut(
        &self,
        path: &Path,
        identify: impl FnOnce(&ShortcutTarget) -> io::Result<Option<ExecutableIdentity>>,
    ) -> io::Result<Option<(FileSnapshot, PathBuf)>> {
        let path = LocalPath::parse(path)?;
        if !self.policy.is_startup_shortcut(&path) {
            return Ok(None);
        }
        let opened = native::open(&path, FILE_READ_DATA, FILE_SHARE_READ)?;
        opened.verify_address_under(&path)?;
        let mut snapshot = self
            .policy
            .snapshot_for(&path, &opened, ShortcutScope::Startup)?;
        if snapshot.disposition != FileDisposition::Regular {
            return Ok(None);
        }
        let bytes = read_shortcut_bytes(opened.leaf(), &snapshot.metadata)?;
        let Some(target) = shortcuts::startup_target(&bytes)? else {
            return Ok(None);
        };
        let Some(identity) = identify(&target)? else {
            return Ok(None);
        };
        snapshot.shortcut_digest = Some(Sha256::digest(&bytes).into());
        snapshot.startup_executable = Some(identity);
        Ok(Some((snapshot, target.path)))
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
        listed_children(&opened, &canonical)
    }

    pub(super) fn start_menu_programs(&self) -> Option<PathBuf> {
        self.policy
            .start_menu_programs()
            .map(|programs| programs.root.as_path())
    }

    pub(super) fn program_menu_children(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        let requested = LocalPath::parse(path)?;
        let Some(programs) = self.policy.start_menu_programs() else {
            return Ok(Vec::new());
        };
        if !programs.includes(&requested) || !self.policy.discoverable(&requested) {
            return Ok(Vec::new());
        }
        let opened = native::open(&requested, native::SCAN_DIRECTORY, SHARE_DIRECTORY)?;
        opened.verify_address_under(&requested)?;
        listed_children(&opened, &requested)
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
        let mut observed = policy.snapshot_for(&requested, &source, snapshot.shortcut_scope())?;
        if is_shell_link(&requested) && snapshot.shortcut_digest.is_none() {
            return Err(denied("the shortcut has no approved content fingerprint"));
        }
        let _startup_pin = if snapshot.shortcut_digest.is_some() {
            let bytes = read_shortcut_bytes(source.leaf(), &observed.metadata)?;
            observed.shortcut_digest = Some(Sha256::digest(&bytes).into());
            if observed.shortcut_digest != snapshot.shortcut_digest {
                return Err(denied(
                    "the approved shortcut contents changed after preview",
                ));
            }
            let pinned = snapshot.pin_startup_target(&bytes)?;
            observed
                .startup_executable
                .clone_from(&snapshot.startup_executable);
            pinned
        } else {
            None
        };
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
                let _ = require_moved_object(snapshot, &item, &security)?;
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
        let scope = snapshot.shortcut_scope();
        if !canonical.same(&original)
            || policy.protects_for(&original, scope)
            || policy.protects_for(&canonical, scope)
        {
            return Err(denied("the restoration destination is now protected"));
        }
        if scope == ShortcutScope::Ordinary
            && snapshot.shortcut_digest.is_some()
            && !policy.is_user_shortcut(&canonical)
        {
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
        let bytes = require_moved_object(snapshot, &source, &security)?;
        let _startup_pin = snapshot.pin_moved_startup_target(bytes.as_deref())?;
        native::rename(&source, destination.leaf(), name)
    }

    /// Reconciles a restored object after a process exited before writing its receipt.
    pub(super) fn verify_restored(&self, snapshot: &FileSnapshot, slot: &str) -> io::Result<bool> {
        validate_slot(slot)?;
        require_movable(snapshot)?;
        let policy = self.fresh_policy()?;
        let original = LocalPath::parse(&snapshot.path)?;
        // Hold the original file and its ancestors while inspecting the slot.
        // DELETE participates in share checks even for objects whose data we do not read.
        let opened = match native::open(
            &original,
            DELETE | READ_CONTROL | snapshot.content_access(),
            FILE_SHARE_READ,
        ) {
            Ok(opened) => opened,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        let observed = policy.snapshot_for(&original, &opened, snapshot.shortcut_scope())?;
        if observed.path != snapshot.path
            || observed.parent != snapshot.parent
            || observed.disposition != snapshot.disposition
        {
            return Ok(false);
        }
        let security = PrivateSecurity::new()?;
        let bytes = require_moved_object(snapshot, opened.leaf(), &security)?;
        let _startup_pin = snapshot.pin_moved_startup_target(bytes.as_deref())?;

        // An unavailable store cannot prove the recorded child is absent.
        let storage = self.private_directory(QUARANTINE_DIRECTORY, false, &security)?;
        if native::identity(&storage.leaf)?.volume != observed.metadata.identity.volume {
            return Err(denied("the private quarantine is on a different volume"));
        }
        match native::open_child(
            &storage.leaf,
            OsStr::new(slot),
            OpenRequest::existing(READ_CONTROL, FILE_SHARE_READ, 0),
        ) {
            Ok(_) => Ok(false),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error),
        }
    }

    /// Checks for an exclusively accessible file or supported link in quarantine.
    pub fn can_purge(&self, snapshot: &FileSnapshot, slot: &str) -> io::Result<bool> {
        Ok(self.open_purge_slot(snapshot, slot)?.is_some())
    }

    /// Deletes only the verified file or link object in the private slot.
    pub fn purge(&self, snapshot: &FileSnapshot, slot: &str) -> io::Result<()> {
        let Some((directory, isolated)) = self.open_purge_slot(snapshot, slot)? else {
            return Err(denied(
                "no verified file or link quarantine slot is available",
            ));
        };
        native::delete_checked_handle(&isolated)?;
        // Without POSIX deletion semantics the link is removed when the handle closes.
        drop(isolated);
        let check = native::open_child(
            &directory.leaf,
            OsStr::new(slot),
            OpenRequest::existing(READ_CONTROL, FILE_SHARE_READ, 0),
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
        let supported_kind = match snapshot.disposition {
            FileDisposition::Regular => {
                !snapshot.metadata.is_directory && !snapshot.metadata.is_reparse
            }
            FileDisposition::Link => snapshot.metadata.is_reparse,
            FileDisposition::Directory | FileDisposition::Protected => false,
        };
        // FileDispositionInfo refuses read-only objects even with DELETE access.
        if !supported_kind || snapshot.metadata.links != 1 || snapshot.metadata.is_read_only() {
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
        // A directory link must be opened as the reparse object itself. The
        // handle-relative opener never follows its destination.
        let options = if snapshot.metadata.is_directory {
            0
        } else {
            native::EXISTING_FILE
        };
        let isolated = match native::open_child(
            &directory.leaf,
            OsStr::new(slot),
            OpenRequest::existing(
                DELETE | READ_CONTROL | snapshot.content_access(),
                0,
                options,
            ),
        ) {
            Ok(isolated) => isolated,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let _ = require_moved_object(snapshot, &isolated, &security)?;
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

    pub(super) fn check_report_path(&self, path: &Path) -> io::Result<()> {
        self.report_parent(path, FILE_TRAVERSE).map(|_| ())
    }

    /// Stages and publishes the report relative to the same pinned directory.
    pub(super) fn write_audit_export(
        &self,
        path: &Path,
        cancel: &Cancellation,
        write: impl FnOnce(&mut dyn Write) -> uninstallany_core::Result<()>,
    ) -> uninstallany_core::Result<()> {
        cancel.check()?;
        let (target, parent_path, parent) =
            self.report_parent(path, FILE_TRAVERSE | FILE_ADD_FILE)?;
        let name = target
            .name()
            .ok_or_else(|| invalid("choose an audit report name"))?;
        match native::open_child(
            parent.leaf(),
            name,
            OpenRequest::existing(0, SHARE_DIRECTORY, 0),
        ) {
            Ok(_) => return Err(io::Error::from(io::ErrorKind::AlreadyExists).into()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let security = PrivateSecurity::new()?;
        let temporary = format!(".uninstallany-audit-{}.tmp", Uuid::new_v4());
        let staged = native::open_child(
            parent.leaf(),
            OsStr::new(&temporary),
            OpenRequest {
                access: FILE_WRITE_DATA | READ_CONTROL | DELETE,
                share: 0,
                disposition: FILE_CREATE,
                options: native::EXISTING_FILE,
                security: security.descriptor(),
            },
        )?;
        let security_check =
            native::regular(&staged).and_then(|_| security.require_private(&staged));
        let mut file = File::from(staged);
        let publish = (|| -> uninstallany_core::Result<()> {
            security_check?;
            write(&mut file)?;
            file.sync_all()?;
            // Recheck the DOS address while the same volume and parent chain
            // remain pinned, then publish without resolving the source by name.
            parent.verify_address_under(&parent_path)?;
            cancel.check()?;
            native::rename(&file, parent.leaf(), name)?;
            Ok(())
        })();
        if let Err(error) = publish {
            if let Err(cleanup) = native::delete_checked_handle(&file) {
                return Err(Error::Io(io::Error::other(format!(
                    "{error}. Could not discard temporary audit export {temporary}: {cleanup}"
                ))));
            }
            return Err(error);
        }
        Ok(())
    }

    fn report_parent(
        &self,
        path: &Path,
        access: u32,
    ) -> io::Result<(LocalPath, LocalPath, OpenPath)> {
        let units: Vec<_> = path.as_os_str().encode_wide().collect();
        let ordinary = units.strip_prefix(&[92, 92, 63, 92]).unwrap_or(&units);
        let target = LocalPath::parse(Path::new(&OsString::from_wide(ordinary)))?;
        if !target
            .name()
            .and_then(|name| Path::new(name).extension())
            .is_some_and(|extension| native::equal_name(extension, OsStr::new("jsonl")))
        {
            return Err(invalid("choose a .jsonl file for the audit report"));
        }
        let policy = self.fresh_policy()?;
        let internal = policy.local.child(OsStr::new(DATA_DIRECTORY))?;
        if target.starts_with(&internal)
            || target.starts_with(&required_folder(&FOLDERID_Windows)?)
            || policy.system_tree(&target)
            || policy
                .managed_trees
                .iter()
                .any(|root| target.starts_with(root))
            || policy.shared_profile(&target)
            || policy.startup_folders().excludes(&target)
        {
            return Err(denied(
                "choose an audit report outside system, shared profile, and private UninstallAny directories",
            ));
        }
        let parent = target
            .parent()
            .ok_or_else(|| invalid("choose a report file in an existing directory"))?;
        let opened = native::open(&parent, access, SHARE_DIRECTORY)?;
        native::require_directory(opened.leaf())?;
        opened.verify_address_under(&parent)?;
        Ok((target, parent, opened))
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
    if snapshot.is_startup_shortcut() && snapshot.shortcut_digest.is_none() {
        return Err(denied(
            "the startup shortcut has no approved content fingerprint",
        ));
    }
    match snapshot.disposition {
        FileDisposition::Regular | FileDisposition::Link => Ok(()),
        FileDisposition::Directory => Err(denied("whole-directory quarantine is unavailable")),
        FileDisposition::Protected => {
            Err(denied("the file is protected or its type is unsupported"))
        }
    }
}

impl FileSnapshot {
    /// Reports whether the snapshot describes a single-link regular file available offline.
    pub(super) fn is_local_regular_file(&self) -> bool {
        self.disposition == FileDisposition::Regular && self.metadata.is_single_local_file()
    }

    /// Identifies an approved file whose executable must be restored first.
    pub(super) fn is_startup_shortcut(&self) -> bool {
        self.startup_executable.is_some()
    }

    fn shortcut_scope(&self) -> ShortcutScope {
        if self.is_startup_shortcut() {
            ShortcutScope::Startup
        } else {
            ShortcutScope::Ordinary
        }
    }

    fn pin_startup_target(&self, bytes: &[u8]) -> io::Result<Option<PinnedExecutable>> {
        let Some(expected) = &self.startup_executable else {
            return Ok(None);
        };
        let target = shortcuts::startup_target(bytes)?
            .ok_or_else(|| denied("the startup shortcut no longer has one direct target"))?;
        let (pinned, current) = pin_startup_shortcut_target(&target)?;
        if &current != expected {
            return Err(denied(
                "the startup executable differs from its approved identity",
            ));
        }
        Ok(Some(pinned))
    }

    fn pin_moved_startup_target(
        &self,
        bytes: Option<&[u8]>,
    ) -> io::Result<Option<PinnedExecutable>> {
        if !self.is_startup_shortcut() {
            return Ok(None);
        }
        let bytes =
            bytes.ok_or_else(|| denied("the isolated startup shortcut has no verified bytes"))?;
        self.pin_startup_target(bytes)
    }

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
) -> io::Result<Option<Vec<u8>>> {
    let metadata = native::metadata(file)?;
    if !metadata.same_moved_object(&snapshot.metadata) {
        return Err(denied(
            "the moved object differs from its approved identity or metadata",
        ));
    }
    security.require_safe_source(file)?;
    if let Some(expected) = snapshot.shortcut_digest {
        let bytes = read_shortcut_bytes(file, &metadata)?;
        let actual = Sha256::digest(&bytes);
        if <[u8; 32]>::from(actual) != expected {
            return Err(denied("the moved shortcut content changed"));
        }
        return Ok(Some(bytes));
    }
    Ok(None)
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

fn listed_children(opened: &OpenPath, directory: &LocalPath) -> io::Result<Vec<PathBuf>> {
    let path = directory.as_path();
    Ok(native::list(opened.leaf(), true)?
        .into_iter()
        .map(|name| path.join(name))
        .collect())
}

struct StartMenuPrograms {
    root: LocalPath,
    excluded: Vec<LocalPath>,
}

struct StartupFolders {
    protected: Vec<LocalPath>,
    writable: Option<LocalPath>,
    complete: bool,
}

impl StartupFolders {
    fn read(programs: Option<&StartMenuPrograms>) -> Self {
        let configured = local_folder(&FOLDERID_Startup);
        let default = default_local_folder(&FOLDERID_Startup);
        let common = local_folder(&FOLDERID_CommonStartup);
        let common_default = default_local_folder(&FOLDERID_CommonStartup);
        let mut protected = Vec::new();
        let mut complete = true;
        let mut common_roots = Vec::new();
        for (path, shared) in [
            (configured.as_ref(), false),
            (default.as_ref(), false),
            (common.as_ref(), true),
            (common_default.as_ref(), true),
        ] {
            let Some(path) = path else {
                complete = false;
                continue;
            };
            protected.push(path.clone());
            if shared {
                common_roots.push(path.clone());
            }
            match canonical_shortcut_root(path) {
                Ok(resolved) => {
                    if shared {
                        common_roots.push(resolved.clone());
                    }
                    protected.push(resolved);
                }
                Err(_) => complete = false,
            }
        }
        let writable = configured.filter(|path| {
            complete
                && default.as_ref().is_some_and(|default| path.same(default))
                && programs.is_some_and(|programs| {
                    path.parent()
                        .is_some_and(|parent| parent.same(&programs.root))
                })
                && !common_roots
                    .iter()
                    .any(|root| path.starts_with(root) || root.starts_with(path))
        });
        Self {
            protected,
            writable,
            complete,
        }
    }

    fn excludes(&self, path: &LocalPath) -> bool {
        self.protected.iter().any(|root| path.starts_with(root))
            || (!self.complete && is_shell_link(path))
    }
}

impl StartMenuPrograms {
    fn read(profile: &LocalPath, roaming_microsoft: &LocalPath) -> Option<Self> {
        let root = local_folder(&FOLDERID_Programs)?;
        let default = default_local_folder(&FOLDERID_Programs)?;
        let menu = local_folder(&FOLDERID_StartMenu)?;
        let is_user_menu = [&menu, profile, roaming_microsoft]
            .into_iter()
            .all(|parent| root.depth() > parent.depth() && root.starts_with(parent));
        if !root.same(&default) || !is_user_menu {
            return None;
        }
        let opened = native::open(&root, 0, SHARE_DIRECTORY).ok()?;
        native::require_directory(opened.leaf()).ok()?;
        opened.verify_address_under(&root).ok()?;

        let excluded = ordinary_shortcut_exclusions()?;
        if excluded.iter().any(|folder| root.starts_with(folder)) {
            return None;
        }
        Some(Self { root, excluded })
    }

    fn includes(&self, path: &LocalPath) -> bool {
        path.starts_with(&self.root) && !self.excluded.iter().any(|root| path.starts_with(root))
    }
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
    roaming_microsoft: Option<LocalPath>,
    start_menu_programs: OnceLock<Option<StartMenuPrograms>>,
    startup_folders: OnceLock<StartupFolders>,
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
        let current_exe = LocalPath::parse(&std::env::current_exe()?)?;
        let mut trees = vec![
            windows,
            local.child(OsStr::new(DATA_DIRECTORY))?,
            local.child(OsStr::new("Packages"))?,
            local.child(OsStr::new("Microsoft"))?,
        ];
        // Only the fixed installed GUI may reserve its containing directory.
        let install_directory = program_files.child(OsStr::new(INSTALL_DIRECTORY))?;
        if current_exe.same(&install_directory.child(OsStr::new(INSTALLED_GUI_NAME))?) {
            trees.push(install_directory);
        }
        exact.push(current_exe);
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
        let roaming_microsoft = local_folder(&FOLDERID_RoamingAppData)
            .map(|roaming| roaming.child(OsStr::new("Microsoft")))
            .transpose()?;
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
            roaming_microsoft,
            start_menu_programs: OnceLock::new(),
            startup_folders: OnceLock::new(),
            shortcut_roots,
            user_shortcut_roots,
            shared_shortcut_roots,
        })
    }

    fn start_menu_programs(&self) -> Option<&StartMenuPrograms> {
        self.start_menu_programs
            .get_or_init(|| {
                StartMenuPrograms::read(&self.profile, self.roaming_microsoft.as_ref()?)
            })
            .as_ref()
    }

    fn startup_folders(&self) -> &StartupFolders {
        self.startup_folders
            .get_or_init(|| StartupFolders::read(self.start_menu_programs()))
    }

    fn default_shortcut_desktop(&self) -> Option<LocalPath> {
        let desktop = local_folder(&FOLDERID_Desktop)?;
        if !desktop.same(&default_local_folder(&FOLDERID_Desktop)?)
            || !desktop.parent()?.same(&self.profile)
        {
            return None;
        }
        let child = desktop.child(OsStr::new("shortcut.lnk")).ok()?;
        if !self.is_user_shortcut(&child)
            || self.protects(&child)
            || ordinary_shortcut_exclusions()?
                .iter()
                .any(|folder| desktop.starts_with(folder))
        {
            return None;
        }
        let opened = native::open(&desktop, 0, SHARE_DIRECTORY).ok()?;
        native::require_directory(opened.leaf()).ok()?;
        opened.verify_address_under(&desktop).ok()?;
        Some(desktop)
    }

    fn is_startup_shortcut(&self, path: &LocalPath) -> bool {
        is_shell_link(path)
            && self
                .startup_folders()
                .writable
                .as_ref()
                .is_some_and(|root| path.parent().is_some_and(|parent| parent.same(root)))
    }

    fn snapshot(&self, requested: &LocalPath, opened: &OpenPath) -> io::Result<FileSnapshot> {
        self.snapshot_for(requested, opened, ShortcutScope::Ordinary)
    }

    fn snapshot_for(
        &self,
        requested: &LocalPath,
        opened: &OpenPath,
        scope: ShortcutScope,
    ) -> io::Result<FileSnapshot> {
        let canonical = native::canonical(opened.leaf())?;
        let ancestors = opened.ancestor_ids()?;
        let parent = ancestors.last().cloned();
        let metadata = native::metadata(opened.leaf())?;
        let in_shortcut_scope = match scope {
            ShortcutScope::Ordinary => self.is_user_shortcut(&canonical),
            ShortcutScope::Startup => self.is_startup_shortcut(&canonical),
        };
        let protected_shortcut = (is_shell_link(requested) || is_shell_link(&canonical))
            && (!requested.same(&canonical)
                || !in_shortcut_scope
                || !metadata.is_single_local_file());
        let disposition = if self.protects_for(requested, scope)
            || self.protects_for(&canonical, scope)
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
            // A substituted higher directory can retain both the original leaf
            // and its immediate parent. Bind the full chain to the approved move.
            fingerprint: format!("{ancestors:?}/{metadata:?}"),
            disposition,
            parent,
            metadata,
            shortcut_digest: None,
            startup_executable: None,
        })
    }

    fn protects(&self, path: &LocalPath) -> bool {
        self.protects_for(path, ShortcutScope::Ordinary)
    }

    fn protects_for(&self, path: &LocalPath, scope: ShortcutScope) -> bool {
        if path.depth() == 0 || self.exact.iter().any(|exact| path.same(exact)) {
            return true;
        }
        let startup = scope == ShortcutScope::Startup && self.is_startup_shortcut(path);
        // Generic file and link workflows must keep even redirected Startup
        // paths protected. Only a verified direct Startup link gets an exception.
        if (scope == ShortcutScope::Startup && !startup)
            || (!startup && self.startup_folders().excludes(path))
        {
            return true;
        }
        // Do not permit portable scans to claim other profiles or arbitrary public data.
        let shortcut_name = is_shell_link(path);
        let in_roaming_microsoft = self
            .roaming_microsoft
            .as_ref()
            .is_some_and(|root| path.starts_with(root));
        // The verified default Programs subtree is an exception only for .lnk files.
        let protected_roaming = !startup
            && in_roaming_microsoft
            && !(shortcut_name
                && self
                    .start_menu_programs()
                    .is_some_and(|programs| programs.includes(path)));
        self.system_tree(path)
            || self.trees.iter().any(|root| path.starts_with(root))
            || self.managed_trees.iter().any(|root| path.starts_with(root))
            || protected_roaming
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

fn ordinary_shortcut_exclusions() -> Option<Vec<LocalPath>> {
    // Preserve configured, default and canonical locations so a folder
    // relocation cannot make startup, tools or common links writable.
    let mut excluded: Vec<LocalPath> = Vec::new();
    for folder in [
        FOLDERID_Startup,
        FOLDERID_CommonStartup,
        FOLDERID_AdminTools,
        FOLDERID_CommonAdminTools,
        FOLDERID_CommonPrograms,
    ] {
        for path in [local_folder(&folder)?, default_local_folder(&folder)?] {
            if excluded.iter().any(|known| known.same(&path)) {
                continue;
            }
            let canonical = canonical_shortcut_root(&path).ok()?;
            excluded.push(path);
            if !excluded.iter().any(|known| known.same(&canonical)) {
                excluded.push(canonical);
            }
        }
    }
    Some(excluded)
}

fn required_folder(folder: &GUID) -> io::Result<LocalPath> {
    LocalPath::parse(&known_folder(folder)?)
}

fn local_folder(folder: &GUID) -> Option<LocalPath> {
    required_folder(folder).ok()
}

fn default_local_folder(folder: &GUID) -> Option<LocalPath> {
    let flags = (KF_FLAG_DONT_VERIFY | KF_FLAG_DEFAULT_PATH | KF_FLAG_NOT_PARENT_RELATIVE) as u32;
    LocalPath::parse(&known_folder_with_flags(folder, flags).ok()?).ok()
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
    known_folder_with_flags(folder, KF_FLAG_DONT_VERIFY as u32)
}

fn known_folder_with_flags(folder: &GUID, flags: u32) -> io::Result<PathBuf> {
    let mut path: PWSTR = null_mut();
    // SAFETY: Windows reads the GUID and fills a COM-allocated path on success.
    let status = unsafe { SHGetKnownFolderPath(folder, flags, null_mut(), &mut path) };
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
    fn program_menu_scope_excludes_startup_and_nearby_folders() -> io::Result<()> {
        let root = LocalPath::parse(Path::new(r"C:\Profile\Start Menu\Programs"))?;
        let startup = root.child(OsStr::new("Startup"))?;
        let application = root.child(OsStr::new("Example Editor"))?;
        let programs = StartMenuPrograms {
            root,
            excluded: vec![startup.clone()],
        };
        assert!(programs.includes(&application.child(OsStr::new("Example Editor.lnk"))?));
        assert!(!programs.includes(&startup.child(OsStr::new("Example Editor.lnk"))?));
        let sibling = LocalPath::parse(Path::new(r"C:\Profile\Start Menu\Programs Old"))?;
        assert!(!programs.includes(&sibling.child(OsStr::new("Example Editor.lnk"))?));
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
    fn native_audit_export_preserves_late_conflicts_and_discards_cancelled_staging()
    -> uninstallany_core::Result<()> {
        let files = WindowsFiles::new()?;
        let directory = tempfile::tempdir_in(files.local_app_data())?;
        let path = directory.path().join("audit.jsonl");
        let cancel = Cancellation::default();

        let cancelled = files.write_audit_export(&path, &cancel, |output| {
            output.write_all(b"unfinished report\n")?;
            cancel.cancel();
            Ok(())
        });
        assert!(matches!(cancelled, Err(Error::Cancelled)));
        assert!(fs::read_dir(directory.path())?.next().is_none());

        let cancel = Cancellation::default();
        let conflicted = files.write_audit_export(&path, &cancel, |output| {
            output.write_all(b"unpublished report\n")?;
            fs::write(&path, b"independent file\n")?;
            Ok(())
        });
        assert!(
            matches!(conflicted, Err(Error::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists)
        );
        assert_eq!(fs::read(&path)?, b"independent file\n");
        assert_eq!(fs::read_dir(directory.path())?.count(), 1);

        let new_report = directory.path().join("new-report.jsonl");
        files.write_audit_export(&new_report, &cancel, |output| {
            output.write_all(b"{}\n")?;
            Ok(())
        })?;
        assert_eq!(fs::read(new_report)?, b"{}\n");
        Ok(())
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
        assert!(!files.verify_restored(&snapshot, &slot)?);
        fs::write(&path, b"restore conflict fixture")?;
        assert!(files.restore(&snapshot, &slot).is_err());
        assert_eq!(fs::read(&path)?, b"restore conflict fixture");
        assert!(files.quarantined(&snapshot, &slot)?);

        let conflicting = directory.join("known-conflict-fixture.txt");
        fs::rename(&path, &conflicting)?;
        files.restore(&snapshot, &slot)?;
        assert!(!isolated.try_exists()?);
        assert_eq!(fs::read(&path)?, b"synthetic quarantine fixture");
        assert!(files.verify_restored(&snapshot, &slot)?);
        fs::write(&isolated, b"unrelated slot fixture")?;
        assert!(!files.verify_restored(&snapshot, &slot)?);
        fs::remove_file(&isolated)?;

        let snapshot = files.inspect(&path)?;
        let slot = Uuid::new_v4().to_string();
        let isolated = files.quarantine_slot(&snapshot, &slot)?;
        files.quarantine(&snapshot, &slot)?;
        fs::write(&path, b"purge conflict fixture")?;
        assert!(files.can_purge(&snapshot, &slot)?);
        files.purge(&snapshot, &slot)?;
        assert!(!isolated.try_exists()?);
        assert_eq!(fs::read(&path)?, b"purge conflict fixture");
        assert!(!matches!(files.verify_restored(&snapshot, &slot), Ok(true)));
        fs::remove_file(&conflicting)?;
        fs::remove_file(&path)?;
        fs::remove_dir(directory)
    }

    #[test]
    #[ignore = "run on a disposable Windows VM with Developer Mode for directory symlinks"]
    fn native_expiry_removes_directory_symlink_without_touching_its_target() -> io::Result<()> {
        let files = WindowsFiles::new()?;
        let directory = tempfile::tempdir_in(files.local_app_data())?;
        let target = directory.path().join("link-target");
        fs::create_dir(&target)?;
        let marker = target.join("marker.txt");
        fs::write(&marker, b"target remains")?;
        let link = directory.path().join("directory-link");
        std::os::windows::fs::symlink_dir(&target, &link)?;
        let snapshot = files.inspect(&link)?;
        assert_eq!(snapshot.disposition, FileDisposition::Link);
        assert!(snapshot.metadata.is_directory);

        let slot = Uuid::new_v4().to_string();
        let isolated = files.quarantine_slot(&snapshot, &slot)?;
        files.quarantine(&snapshot, &slot)?;
        fs::create_dir(&link)?;
        let replacement = link.join("replacement.txt");
        fs::write(&replacement, b"replacement remains")?;
        assert!(files.can_purge(&snapshot, &slot)?);
        files.purge(&snapshot, &slot)?;
        let missing = fs::symlink_metadata(isolated).expect_err("the isolated link should be gone");
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
        assert_eq!(fs::read(marker)?, b"target remains");
        assert_eq!(fs::read(replacement)?, b"replacement remains");
        Ok(())
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
