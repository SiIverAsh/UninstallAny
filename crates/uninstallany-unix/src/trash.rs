use std::{
    ffi::OsStr,
    fs::File,
    io,
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
};

use rustix::{fd::AsFd, fs};

use crate::{EntryStamp, UnixFiles, check_absolute, deny, filename, invalid, native, parent_path};

impl UnixFiles {
    /// Verifies that a held application and its executable still occupy a
    /// trusted position beneath the current user's native Trash directory.
    pub fn is_bundle_in_macos_trash(
        &self,
        trash: &Path,
        bundle: &File,
        executable: &File,
        executable_suffix: &Path,
    ) -> io::Result<bool> {
        if !executable_suffix
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
        {
            return Err(invalid("the executable suffix must stay inside its bundle"));
        }
        let root = self.open_trusted_local_directory(trash)?;
        native::require_current_user_directory(&root, self.uid)?;
        let root_path = descriptor_path(&root)?;
        let location = descriptor_path(bundle)?;
        let Ok(relative) = location.strip_prefix(&root_path) else {
            return Ok(false);
        };
        if relative.as_os_str().is_empty() {
            return Ok(false);
        }

        // The kernel path selects a candidate only. The trusted, no-follow
        // walk must reach both held objects on the same local volume.
        let root_id = native::directory_id(&root)?;
        let bundle_id = native::directory_id(bundle)?;
        if root_id.device != bundle_id.device {
            return Ok(false);
        }
        let candidate = trash.join(relative);
        let mut parent = self.open_trusted_local_directory(&candidate)?;
        if native::directory_id(&parent)? != bundle_id {
            return Ok(false);
        }
        for part in parent_path(executable_suffix)?.components() {
            parent = native::open_subdirectory(&parent, part.as_os_str())?;
            if !native::trusted_directory(&parent, self.uid)? {
                return Err(deny(
                    "a directory inside the moved bundle allows shared writes",
                ));
            }
        }
        let (_, named) = self.open_trusted_regular_at(&parent, filename(executable_suffix)?)?;
        let held = fs::fstat(executable)?;
        if EntryStamp::from_stat(&held) != EntryStamp::from_stat(&named)
            || held.st_flags != named.st_flags
        {
            return Ok(false);
        }

        let current_root = self.open_trusted_local_directory(trash)?;
        native::require_current_user_directory(&current_root, self.uid)?;
        let current_bundle = self.open_trusted_local_directory(&candidate)?;
        Ok(native::directory_id(&current_root)? == root_id
            && native::directory_id(&current_bundle)? == bundle_id
            && descriptor_path(&current_root)? == root_path
            && descriptor_path(bundle)? == location)
    }
}

fn descriptor_path(fd: impl AsFd) -> io::Result<PathBuf> {
    let path = fs::getpath(fd)?;
    let path = PathBuf::from(OsStr::from_bytes(path.as_bytes()));
    check_absolute(&path)?;
    Ok(path)
}
