use std::{io, os::unix::ffi::OsStrExt, path::Path, time::Instant};

use rustix::{
    fd::OwnedFd,
    fs::{self, FileType},
};
use uninstallany_core::{Cancellation, Result};

use crate::{
    UnixFiles, is_bundle_name,
    native::{self, EntryStamp, deny, invalid},
};

const MAX_ENTRIES_PER_BUNDLE: usize = 40_000;
const MAX_DEPTH: usize = 64;

impl UnixFiles {
    /// Estimates a local app bundle's logical size for inventory display.
    ///
    /// Each regular-file pathname contributes its length at observation time.
    /// Symbolic links are skipped and their destinations are never opened.
    /// Limits yield no estimate, and the call debits observed entries from the
    /// caller's shared budget even if it cannot finish the bundle.
    pub fn measure_macos_bundle_size(
        &self,
        path: &Path,
        remaining_entries: &mut usize,
        deadline: Instant,
        cancel: &Cancellation,
    ) -> Result<Option<u64>> {
        cancel.check()?;
        if !is_bundle_name(path) {
            return Err(invalid("bundle size requires an application directory").into());
        }
        if *remaining_entries == 0 || Instant::now() >= deadline {
            return Ok(None);
        }
        let directory = self.open_scoped_directory(path)?;
        native::require_local(&directory)?;
        let original = fs::fstat(&directory).map_err(io::Error::from)?;
        let mut budget = WalkBudget {
            shared_entries: remaining_entries,
            bundle_entries: MAX_ENTRIES_PER_BUNDLE,
            deadline,
            cancel,
        };
        let Some(bytes) = measure_directory(&directory, &original, &mut budget, 0)? else {
            return Ok(None);
        };
        if !budget.has_time()? {
            return Ok(None);
        }
        // The pinned descriptor may survive a rename. Reopen the inventory
        // path so the estimate still identifies the selected bundle.
        let current = self.open_scoped_directory(path)?;
        let current = fs::fstat(&current).map_err(io::Error::from)?;
        if EntryStamp::from_stat(&current) != EntryStamp::from_stat(&original) {
            return Err(deny("the app bundle changed during size discovery").into());
        }
        Ok(budget.has_time()?.then_some(bytes))
    }
}

struct WalkBudget<'a> {
    shared_entries: &'a mut usize,
    bundle_entries: usize,
    deadline: Instant,
    cancel: &'a Cancellation,
}

impl WalkBudget<'_> {
    fn has_time(&self) -> Result<bool> {
        self.cancel.check()?;
        Ok(Instant::now() < self.deadline)
    }

    fn observe_entry(&mut self) -> Result<bool> {
        if !self.has_time()? || self.bundle_entries == 0 || *self.shared_entries == 0 {
            return Ok(false);
        }
        self.bundle_entries -= 1;
        *self.shared_entries -= 1;
        Ok(true)
    }
}

fn measure_directory(
    directory: &OwnedFd,
    original: &fs::Stat,
    budget: &mut WalkBudget<'_>,
    depth: usize,
) -> Result<Option<u64>> {
    if depth >= MAX_DEPTH || !budget.has_time()? {
        return Ok(None);
    }
    let mut bytes = 0u64;
    for entry in fs::Dir::read_from(directory).map_err(io::Error::from)? {
        let entry = entry.map_err(io::Error::from)?;
        let name = entry.file_name().to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        if !budget.observe_entry()? {
            return Ok(None);
        }
        let name = std::ffi::OsStr::from_bytes(name);
        let stat = native::entry_stat(directory, name)?;
        if stat.st_dev != original.st_dev {
            return Err(deny("a nested volume prevents measuring the app bundle").into());
        }
        let size = match FileType::from_raw_mode(stat.st_mode) {
            FileType::RegularFile => u64::try_from(stat.st_size)
                .map_err(|_| invalid("an app bundle file reported an invalid length"))?,
            FileType::Directory => {
                let child = native::open_subdirectory(directory, name)?;
                let expected = EntryStamp::from_stat(&stat);
                let opened = fs::fstat(&child).map_err(io::Error::from)?;
                if EntryStamp::from_stat(&opened) != expected {
                    return Err(deny("an app bundle directory changed before measurement").into());
                }
                let Some(size) = measure_directory(&child, &opened, budget, depth + 1)? else {
                    return Ok(None);
                };
                if EntryStamp::from_stat(&native::entry_stat(directory, name)?) != expected {
                    return Err(deny("an app bundle directory moved during measurement").into());
                }
                size
            }
            FileType::Symlink => continue,
            _ => return Err(deny("the app bundle contains an unsupported object").into()),
        };
        bytes = bytes
            .checked_add(size)
            .ok_or_else(|| invalid("the app bundle exceeds the supported logical size"))?;
    }
    let current = fs::fstat(directory).map_err(io::Error::from)?;
    if EntryStamp::from_stat(original) != EntryStamp::from_stat(&current) {
        return Err(deny("an app bundle directory changed during measurement").into());
    }
    Ok(budget.has_time()?.then_some(bytes))
}
