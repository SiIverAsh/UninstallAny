use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use rustix::fd::OwnedFd;
use rustix::fs::{self, Mode, OFlags};
use uninstallany_core::{Artifact, Journal};
#[cfg(target_os = "macos")]
use uninstallany_core::{Cancellation, Error, Result};
use uuid::Uuid;

use super::{AUDIT_DIR, UnixFiles};
use crate::native::{self, DIRECTORY_FLAGS, deny, invalid};

const MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;
const PRIVATE_DIR: Mode = Mode::RWXU;
const PRIVATE_RECORD: Mode = Mode::RUSR.union(Mode::WUSR);

impl UnixFiles {
    pub(super) fn store_anchor(&self) -> io::Result<OwnedFd> {
        self.state_directory(false, true)
    }

    pub(super) fn open_store(&self, name: &str, create: bool) -> io::Result<OwnedFd> {
        let state = self.state_directory(create, false)?;
        let fd = open_or_create(&state, OsStr::new(name), create)?;
        native::require_local(&fd)?;
        native::require_private(&fd, self.uid)?;
        self.validate_store_volume(native::directory_id(&state)?, &fd)?;
        Ok(fd)
    }

    #[cfg(target_os = "macos")]
    fn audit_export_parent(&self, path: &Path) -> io::Result<OwnedFd> {
        super::check_absolute(path)?;
        let parent = super::parent_path(path)?;
        if !path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("jsonl"))
        {
            return Err(invalid("choose a .jsonl file for the audit report"));
        }
        // These personal folders remain protected from cleanup. Creating a new
        // private report there does not need permission to alter their contents.
        let export_folders = ["Desktop", "Documents", "Downloads"].map(|name| self.home.join(name));
        let protected = self.protected.iter().filter(|path| {
            !export_folders
                .iter()
                .any(|allowed| super::same_spelling(path, allowed))
        });
        let mut blocked = Vec::new();
        for root in protected {
            if super::is_at_or_below(parent, root) {
                return Err(deny(
                    "choose an audit report directory outside protected and private state folders",
                ));
            }
            if let Ok(id) = native::protected_id(root) {
                blocked.push(id);
            }
        }
        let (directory, trusted) =
            native::open_trusted_path(parent, self.uid, &blocked, self.state_node)?;
        if !trusted {
            return Err(deny(
                "choose a local report directory without shared writes",
            ));
        }
        native::require_current_user_directory(&directory, self.uid)?;
        native::require_local(&directory)?;
        Ok(directory)
    }

    fn state_directory(&self, create: bool, accept_missing: bool) -> io::Result<OwnedFd> {
        let (mut fd, trusted) =
            native::open_trusted_path(&self.home, self.uid, &self.protected_nodes, None)?;
        if !trusted {
            return Err(deny(
                "the home path is under a shared or untrusted directory",
            ));
        }
        native::require_current_user_directory(&fd, self.uid)?;
        native::require_local(&fd)?;
        let relative = self
            .state
            .strip_prefix(&self.home)
            .map_err(io::Error::other)?;
        for part in relative.components() {
            let child = match open_or_create(&fd, part.as_os_str(), create) {
                Ok(child) => child,
                Err(error) if accept_missing && error.kind() == io::ErrorKind::NotFound => {
                    return Ok(fd);
                }
                Err(error) => return Err(error),
            };
            native::reject_protected(&child, &self.protected_nodes)?;
            native::require_current_user_directory(&child, self.uid)?;
            native::require_local(&child)?;
            fd = child;
        }
        native::require_private(&fd, self.uid)?;
        Ok(fd)
    }
}

impl Journal for UnixFiles {
    fn create(&self, id: Uuid, artifact: Artifact, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err(invalid("the audit record exceeds the storage limit"));
        }
        let parent = self.open_store(AUDIT_DIR, true)?;
        let name = artifact.file_name(id);
        let staged = format!(".pending-{}", Uuid::new_v4());
        let flags =
            OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::CREATE | OFlags::EXCL;
        let fd = fs::openat(&parent, staged.as_str(), flags, PRIVATE_RECORD)?;
        native::require_private(&fd, self.uid)?;
        let mut output = File::from(fd);
        output.write_all(bytes)?;
        output.sync_all()?;
        native::rename_exclusive((&parent, OsStr::new(&staged)), (&parent, OsStr::new(&name)))?;
        fs::fsync(&parent)?;
        Ok(())
    }

    fn read(&self, id: Uuid, artifact: Artifact) -> io::Result<Option<Vec<u8>>> {
        let parent = match self.open_store(AUDIT_DIR, false) {
            Ok(parent) => parent,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let file = match native::checked_file(&parent, OsStr::new(&artifact.file_name(id))) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        native::require_private(&file, self.uid)?;
        let stat = fs::fstat(&file)?;
        if stat.st_nlink != 1 {
            return Err(deny("audit artifact unexpectedly has another hard link"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err(invalid("the audit record exceeds the storage limit"));
        }
        Ok(Some(bytes))
    }

    fn list(&self, artifact: Artifact) -> io::Result<Vec<Uuid>> {
        let parent = match self.open_store(AUDIT_DIR, false) {
            Ok(parent) => parent,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let mut ids = Vec::new();
        for entry in fs::Dir::read_from(parent)? {
            let entry = entry?;
            if let Some(id) = entry
                .file_name()
                .to_str()
                .ok()
                .and_then(|name| artifact.id(name))
            {
                ids.push(id);
            }
        }
        ids.sort_unstable();
        Ok(ids)
    }

    fn location(&self, id: Uuid, artifact: Artifact) -> PathBuf {
        self.state.join(AUDIT_DIR).join(artifact.file_name(id))
    }

    #[cfg(not(target_os = "macos"))]
    fn check_export_path(&self, path: &Path) -> io::Result<()> {
        super::check_absolute(path)?;
        let parent = super::parent_path(path)?;
        let (directory, trusted) = native::open_trusted_path(parent, self.uid, &[], None)?;
        if !trusted {
            return Err(deny(
                "choose a local report directory without shared writes",
            ));
        }
        native::require_local(&directory)
    }

    #[cfg(target_os = "macos")]
    fn check_export_path(&self, path: &Path) -> io::Result<()> {
        self.audit_export_parent(path).map(|_| ())
    }

    #[cfg(target_os = "macos")]
    fn write_audit_export(
        &self,
        path: &Path,
        cancel: &Cancellation,
        write: impl FnOnce(&mut dyn Write) -> Result<()>,
    ) -> Result<()> {
        cancel.check()?;
        let parent = self.audit_export_parent(path)?;
        let name = super::filename(path)?;
        match native::entry_stat(&parent, name) {
            Ok(_) => return Err(io::Error::from(io::ErrorKind::AlreadyExists).into()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }

        let staged = format!(".uninstallany-audit-{}.tmp", Uuid::new_v4());
        let staged = OsStr::new(&staged);
        let flags =
            OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::CREATE | OFlags::EXCL;
        let fd = fs::openat(&parent, staged, flags, PRIVATE_RECORD).map_err(io::Error::from)?;
        let mut output = File::from(fd);
        let publish = (|| -> Result<()> {
            // A mode-0600 file can still inherit an ACL on macOS.
            native::require_private(&output, self.uid)?;
            write(&mut output)?;
            output.sync_all()?;
            let current = self.audit_export_parent(path)?;
            if native::directory_id(&current)? != native::directory_id(&parent)? {
                return Err(deny("the audit report directory changed before publication").into());
            }
            native::require_private(&output, self.uid)?;
            let held = fs::fstat(&output).map_err(io::Error::from)?;
            let named = native::entry_stat(&parent, staged)?;
            if held.st_nlink != 1
                || native::EntryStamp::from_stat(&held) != native::EntryStamp::from_stat(&named)
            {
                return Err(deny("the staged audit report changed before publication").into());
            }
            cancel.check()?;
            native::rename_exclusive((&parent, staged), (&parent, name))?;
            Ok(())
        })();
        if let Err(error) = publish {
            discard_report_stage(&parent, staged, &output).map_err(|cleanup| {
                Error::Io(io::Error::other(format!(
                    "{error}. Could not discard temporary audit export {}: {cleanup}",
                    staged.to_string_lossy(),
                )))
            })?;
            return Err(error);
        }
        fs::fsync(&parent).map_err(|error| {
            io::Error::other(format!(
                "the report was published but its directory could not be synchronized: {error}"
            ))
        })?;
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn discard_report_stage(parent: &OwnedFd, name: &OsStr, file: &File) -> io::Result<()> {
    let named = match native::entry_stat(parent, name) {
        Ok(named) => named,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let held = native::NodeId::from_stat(&fs::fstat(file)?);
    if !held.same_inode(native::NodeId::from_stat(&named)) {
        return Err(deny("the temporary audit name was replaced"));
    }
    fs::unlinkat(parent, name, fs::AtFlags::empty())?;
    Ok(())
}

fn open_or_create(parent: &OwnedFd, name: &OsStr, create: bool) -> io::Result<OwnedFd> {
    let child = match fs::openat(parent, name, DIRECTORY_FLAGS, Mode::empty()) {
        Ok(child) => child,
        Err(rustix::io::Errno::NOENT) if create => {
            match fs::mkdirat(parent, name, PRIVATE_DIR) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
            fs::openat(parent, name, DIRECTORY_FLAGS, Mode::empty())?
        }
        Err(error) => return Err(error.into()),
    };
    if create {
        // A retry may open a directory left visible by an interrupted mkdir.
        // Before publishing state in it, make its name durable as well.
        fs::fsync(parent)?;
    }
    Ok(child)
}
