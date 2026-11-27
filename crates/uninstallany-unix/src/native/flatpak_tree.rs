use std::ffi::{OsStr, OsString};
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use rustix::fd::OwnedFd;
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};
use sha2::{Digest, Sha256};

use super::{
    EntryStamp, NodeId, deny, directory_id, entry_stat, invalid, mount_id, open_subdirectory,
    reject_protected_entry, require_current_user_directory, safe_user_entry,
};

const MAX_DEPTH: u64 = 48;

pub(crate) fn stamp(
    parent: &OwnedFd,
    name: &OsStr,
    uid: u32,
    expected: &EntryStamp,
    protected: &[NodeId],
) -> io::Result<([u8; 32], OwnedFd)> {
    let directory = open_subdirectory(parent, name)?;
    require_held_entry(parent, name, &directory, expected)?;
    let mut tree = TreeStamp {
        digest: Sha256::new(),
        remaining: crate::MAX_DIRECTORY_ENTRIES,
        uid,
        protected,
    };
    tree.visit(&directory, expected, 0)?;
    require_held_entry(parent, name, &directory, expected)?;
    // The root has a new name and ctime after rename. Its other metadata is
    // checked by the caller, and every descendant must have the same stamp.
    Ok((tree.digest.finalize().into(), directory))
}

struct TreeStamp<'a> {
    digest: Sha256,
    remaining: usize,
    uid: u32,
    protected: &'a [NodeId],
}

impl TreeStamp<'_> {
    fn visit(&mut self, directory: &OwnedFd, expected: &EntryStamp, depth: u64) -> io::Result<()> {
        if depth > MAX_DEPTH {
            return Err(invalid("the Flatpak data tree exceeds the depth limit"));
        }
        require_current_user_directory(directory, self.uid)?;
        let mut names = Vec::new();
        for entry in fs::Dir::read_from(directory)? {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if matches!(name, b"." | b"..") {
                continue;
            }
            self.remaining = self
                .remaining
                .checked_sub(1)
                .ok_or_else(|| invalid("the Flatpak data tree exceeds the entry limit"))?;
            names.push(OsString::from_vec(name.to_vec()));
        }
        names.sort_unstable();
        for name in names {
            self.visit_entry(directory, &name, depth)?;
        }
        if EntryStamp::from_stat(&fs::fstat(directory)?) != *expected {
            return Err(deny(
                "the Flatpak data directory changed during verification",
            ));
        }
        Ok(())
    }

    fn visit_entry(&mut self, directory: &OwnedFd, name: &OsStr, depth: u64) -> io::Result<()> {
        let stat = entry_stat(directory, name)?;
        reject_protected_entry(&stat, self.protected)?;
        let expected = EntryStamp::from_stat(&stat);
        let kind = FileType::from_raw_mode(stat.st_mode);
        let is_directory = kind == FileType::Directory;
        let private_leaf = match kind {
            FileType::RegularFile => safe_user_entry(&stat, self.uid),
            FileType::Symlink => stat.st_uid == self.uid && stat.st_nlink == 1,
            _ => false,
        };
        let held = if is_directory {
            open_subdirectory(directory, name)?
        } else if private_leaf {
            // A metadata-only handle cannot open a FIFO or device after a
            // name exchange. Symlinks are pinned without opening their targets.
            let flags = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            fs::openat(directory, name, flags, Mode::empty())?
        } else {
            return Err(deny(
                "the Flatpak data tree contains shared or special entries",
            ));
        };
        require_held_entry(directory, name, &held, &expected)?;

        let encoded = serde_json::to_vec(&expected).map_err(io::Error::other)?;
        let name_len = u64::try_from(name.as_bytes().len()).map_err(io::Error::other)?;
        let stamp_len = u64::try_from(encoded.len()).map_err(io::Error::other)?;
        self.digest.update(depth.to_le_bytes());
        self.digest.update(name_len.to_le_bytes());
        self.digest.update(name.as_bytes());
        self.digest.update(stamp_len.to_le_bytes());
        self.digest.update(encoded);
        if is_directory {
            self.visit(&held, &expected, depth + 1)?;
            require_held_entry(directory, name, &held, &expected)?;
        }
        Ok(())
    }
}

fn require_held_entry(
    parent: &OwnedFd,
    name: &OsStr,
    held: &OwnedFd,
    expected: &EntryStamp,
) -> io::Result<()> {
    let parent_id = directory_id(parent)?;
    let held_id = directory_id(held)?;
    if held_id.device != parent_id.device
        || held_id.mount != parent_id.mount
        || mount_id(parent, name, AtFlags::SYMLINK_NOFOLLOW)? != parent_id.mount
        || EntryStamp::from_stat(&fs::fstat(held)?) != *expected
        || EntryStamp::from_stat(&entry_stat(parent, name)?) != *expected
    {
        return Err(deny(
            "a Flatpak data entry changed or crosses a mount boundary",
        ));
    }
    Ok(())
}
