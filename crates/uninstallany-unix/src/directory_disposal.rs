//! Durable authorization for expiry of a complete quarantined macOS directory.

use std::{
    ffi::OsStr,
    fs::File,
    io,
    path::{Path, PathBuf},
};

use rustix::{fd::OwnedFd, fs};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uninstallany_core::{Artifact, Journal};
use uuid::Uuid;

use super::{AUDIT_DIR, Fingerprint, QUARANTINE_DIR, UnixFiles};
use crate::native::{self, DirectoryExpiryFingerprint, DirectoryExpiryTree, EntryStamp, deny};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DisposalPlan {
    fingerprint: [u8; 32],
    tree: DirectoryExpiryTree,
}

struct StoredPlan {
    digest: [u8; 32],
    contents: DisposalPlan,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CommittedDisposal {
    fingerprint: [u8; 32],
    plan: [u8; 32],
}

#[derive(Clone, Copy)]
pub(super) enum SlotState {
    Held,
    Disposing,
    Absent,
}

pub(super) struct DisposalSlot<'a> {
    pub(super) parent: OwnedFd,
    id: Uuid,
    pub(super) held: String,
    pub(super) disposing: String,
    path: &'a Path,
    pub(super) fingerprint: Fingerprint,
}

impl<'a> DisposalSlot<'a> {
    pub(super) fn open(
        files: &UnixFiles,
        path: &'a Path,
        fingerprint: Fingerprint,
        id: Uuid,
    ) -> io::Result<Self> {
        files.check_mutation_path(path)?;
        let parent = files.open_store(QUARANTINE_DIR, false)?;
        files.validate_store_volume(fingerprint.parent, &parent)?;
        Ok(Self {
            parent,
            id,
            held: id.to_string(),
            disposing: disposing_slot_name(id),
            path,
            fingerprint,
        })
    }

    pub(super) fn lock(&self, uid: u32) -> io::Result<File> {
        let lock_name = format!(".disposal-lock-{}", self.id);
        let name = OsStr::new(&lock_name);
        let flags = fs::OFlags::RDWR
            | fs::OFlags::CREATE
            | fs::OFlags::EXCL
            | fs::OFlags::NOFOLLOW
            | fs::OFlags::CLOEXEC;
        let lock = match fs::openat(&self.parent, name, flags, fs::Mode::RUSR | fs::Mode::WUSR) {
            Ok(lock) => File::from(lock),
            Err(rustix::io::Errno::EXIST) => native::checked_file(&self.parent, name)?,
            Err(error) => return Err(error.into()),
        };
        native::require_private(&lock, uid)?;
        match fs::flock(&lock, fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {}
            Err(rustix::io::Errno::WOULDBLOCK) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "another operation is using this quarantine backup",
                ));
            }
            Err(error) => return Err(error.into()),
        }
        let held = fs::fstat(&lock)?;
        if held.st_nlink != 1
            || EntryStamp::from_stat(&held)
                != EntryStamp::from_stat(&native::entry_stat(&self.parent, name)?)
        {
            return Err(deny("the quarantine backup lock changed"));
        }
        // Keep the same lock name across operations. Unlinking it on release
        // could leave two callers locking different files for the same slot.
        Ok(lock)
    }

    pub(super) fn state(&self) -> io::Result<SlotState> {
        let exists = |name: &str| match native::entry_stat(&self.parent, OsStr::new(name)) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        };
        match (exists(&self.held)?, exists(&self.disposing)?) {
            (true, false) => Ok(SlotState::Held),
            (false, true) => Ok(SlotState::Disposing),
            (false, false) => Ok(SlotState::Absent),
            (true, true) => Err(deny(
                "both quarantine locations for this backup are occupied",
            )),
        }
    }

    fn verify_intact(&self, files: &UnixFiles, name: &str) -> io::Result<()> {
        let observed = files.observe_entry(&self.parent, OsStr::new(name), self.path)?;
        if !self.fingerprint.entry.matches_moved(&observed) {
            return Err(deny(
                "the quarantined directory differs from its recorded identity",
            ));
        }
        Ok(())
    }
}

pub(super) fn disposing_slot_name(id: Uuid) -> String {
    format!(".disposing-{id}")
}

impl UnixFiles {
    pub(super) fn is_directory_backup(&self, path: &Path, fingerprint: &Fingerprint) -> bool {
        fingerprint.entry.bundle.is_some()
            && (self.is_application_bundle(path) || self.is_macos_private_tree_directory(path))
    }

    pub(super) fn check_disposal_not_committed(&self, id: Uuid) -> io::Result<()> {
        if self.read(id, Artifact::QuarantinePurgeCommitted)?.is_some() {
            return Err(deny("disposal has already been committed for this backup"));
        }
        Ok(())
    }

    pub(super) fn review_directory_disposal(
        &self,
        path: &Path,
        fingerprint: Fingerprint,
        id: Uuid,
    ) -> io::Result<bool> {
        let slot = DisposalSlot::open(self, path, fingerprint, id)?;
        native::require_apfs(&slot.parent)?;
        if !matches!(slot.state()?, SlotState::Held) {
            return Ok(false);
        }
        if self.read(id, Artifact::QuarantinePurgeCommitted)?.is_some() {
            return Err(deny(
                "a committed disposal unexpectedly has a restorable slot",
            ));
        }
        self.capture_disposal_tree(&slot)?;
        Ok(true)
    }

    pub(super) fn recoverable_detached_directory_backup(
        &self,
        path: &Path,
        reviewed: &str,
        id: Uuid,
    ) -> io::Result<Option<PathBuf>> {
        let fingerprint = Fingerprint::decode(reviewed, path)?;
        if !self.is_directory_backup(path, &fingerprint) {
            return Ok(None);
        }
        let slot = match DisposalSlot::open(self, path, fingerprint, id) {
            Ok(slot) => slot,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if !matches!(slot.state()?, SlotState::Disposing)
            || !self.detached_directory_is_restorable(&slot, reviewed)?
        {
            return Ok(None);
        }
        Ok(Some(self.state.join(QUARANTINE_DIR).join(slot.disposing)))
    }

    fn detached_directory_is_restorable(
        &self,
        slot: &DisposalSlot<'_>,
        reviewed: &str,
    ) -> io::Result<bool> {
        native::require_apfs(&slot.parent)?;
        let digest = Sha256::digest(reviewed.as_bytes()).into();
        let (plan, committed) = self.read_disposal_authority(slot.id, digest)?;
        if committed {
            return Ok(false);
        }
        let plan = plan.ok_or_else(|| deny("the detached backup has no matching disposal plan"))?;
        slot.verify_intact(self, &slot.disposing)?;
        plan.contents.tree.verify_remaining(
            &slot.parent,
            OsStr::new(&slot.disposing),
            self.uid,
            &self.protected_nodes,
        )?;
        Ok(true)
    }

    pub(super) fn restore_directory_backup(
        &self,
        path: &Path,
        reviewed: &str,
        fingerprint: Fingerprint,
        id: Uuid,
    ) -> io::Result<()> {
        let slot = DisposalSlot::open(self, path, fingerprint, id)?;
        let _lock = slot.lock(self.uid)?;
        let name = match slot.state()? {
            SlotState::Held => {
                self.check_disposal_not_committed(id)?;
                &slot.held
            }
            SlotState::Disposing if self.detached_directory_is_restorable(&slot, reviewed)? => {
                &slot.disposing
            }
            SlotState::Disposing => {
                return Err(deny(
                    "directory disposal has already been committed for this backup",
                ));
            }
            SlotState::Absent => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "the directory backup is missing",
                ));
            }
        };
        self.restore_named_quarantine(path, &slot.fingerprint, &slot.parent, OsStr::new(name))
    }

    pub(super) fn pending_directory_disposal(
        &self,
        path: &Path,
        reviewed: &str,
        id: Uuid,
    ) -> io::Result<bool> {
        let fingerprint = Fingerprint::decode(reviewed, path)?;
        if !self.is_directory_backup(path, &fingerprint) {
            return Ok(false);
        }
        let digest = Sha256::digest(reviewed.as_bytes()).into();
        let (plan, committed) = self.read_disposal_authority(id, digest)?;
        if plan.is_none() && !committed {
            return Ok(false);
        }
        let slot = DisposalSlot::open(self, path, fingerprint, id)?;
        native::require_apfs(&slot.parent)?;
        match slot.state()? {
            SlotState::Held if committed => Err(deny(
                "the original slot reappeared after directory disposal was committed",
            )),
            SlotState::Held => Ok(false),
            SlotState::Absent => Ok(committed),
            SlotState::Disposing => {
                let plan =
                    plan.ok_or_else(|| deny("the pending directory has no disposal plan"))?;
                if !committed {
                    slot.verify_intact(self, &slot.disposing)?;
                }
                plan.contents.tree.verify_remaining(
                    &slot.parent,
                    OsStr::new(&slot.disposing),
                    self.uid,
                    &self.protected_nodes,
                )?;
                Ok(true)
            }
        }
    }

    pub(super) fn purge_directory(
        &self,
        path: &Path,
        reviewed: &str,
        fingerprint: Fingerprint,
        id: Uuid,
    ) -> io::Result<()> {
        let digest = Sha256::digest(reviewed.as_bytes()).into();
        let slot = DisposalSlot::open(self, path, fingerprint, id)?;
        native::require_apfs(&slot.parent)?;
        let _lock = slot.lock(self.uid)?;
        let (mut plan, committed) = self.read_disposal_authority(id, digest)?;
        match slot.state()? {
            SlotState::Held if !committed => {
                slot.verify_intact(self, &slot.held)?;
                if plan.is_none() {
                    plan = Some(self.record_disposal_plan(&slot, digest)?);
                }
                let tree = &plan
                    .as_ref()
                    .ok_or_else(|| deny("missing disposal plan"))?
                    .contents
                    .tree;
                tree.verify_remaining(
                    &slot.parent,
                    OsStr::new(&slot.held),
                    self.uid,
                    &self.protected_nodes,
                )?;
                slot.verify_intact(self, &slot.held)?;
                native::rename_exclusive(
                    (&slot.parent, OsStr::new(&slot.held)),
                    (&slot.parent, OsStr::new(&slot.disposing)),
                )?;
            }
            SlotState::Disposing => {}
            SlotState::Absent if committed => return self.finish_directory_disposal(&slot),
            _ => {
                return Err(deny(
                    "the directory location conflicts with the disposal record",
                ));
            }
        }
        let plan = plan.ok_or_else(|| deny("the pending directory has no disposal plan"))?;
        if !committed {
            slot.verify_intact(self, &slot.disposing)?;
            // The original slot must be durably detached before the first
            // unlink. A saved plan alone does not prove that detachment.
            fs::fsync(&slot.parent)?;
            self.create(
                id,
                Artifact::QuarantinePurgeCommitted,
                &serde_json::to_vec(&CommittedDisposal {
                    fingerprint: digest,
                    plan: plan.digest,
                })
                .map_err(io::Error::other)?,
            )?;
        } else {
            // A previous attempt can publish the commitment and fail while
            // syncing its directory. Make that name durable before unlinking.
            fs::fsync(self.open_store(AUDIT_DIR, false)?)?;
        }
        plan.contents
            .tree
            .remove_remaining(
                &slot.parent,
                OsStr::new(&slot.disposing),
                self.uid,
                &self.protected_nodes,
            )
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "directory disposal {} can be reviewed again: {error}",
                        slot.id
                    ),
                )
            })?;
        self.finish_directory_disposal(&slot)
    }

    fn record_disposal_plan(
        &self,
        slot: &DisposalSlot<'_>,
        fingerprint: [u8; 32],
    ) -> io::Result<StoredPlan> {
        let tree = self.capture_disposal_tree(slot)?;
        let contents = DisposalPlan { fingerprint, tree };
        let bytes = serde_json::to_vec(&contents).map_err(io::Error::other)?;
        self.create(slot.id, Artifact::QuarantinePurgePlan, &bytes)?;
        Ok(StoredPlan {
            digest: Sha256::digest(&bytes).into(),
            contents,
        })
    }

    fn capture_disposal_tree(&self, slot: &DisposalSlot<'_>) -> io::Result<DirectoryExpiryTree> {
        let digest = slot
            .fingerprint
            .entry
            .bundle
            .ok_or_else(|| deny("missing directory fingerprint"))?;
        let scope = if self.is_macos_private_tree_directory(slot.path) {
            DirectoryExpiryFingerprint::Cache(digest)
        } else {
            DirectoryExpiryFingerprint::Bundle(digest)
        };
        let tree = DirectoryExpiryTree::capture(
            &slot.parent,
            OsStr::new(&slot.held),
            self.uid,
            scope,
            &self.protected_nodes,
        )?;
        if !tree.matches_root(&slot.fingerprint.entry.metadata) {
            return Err(deny(
                "the captured directory does not match the quarantined root",
            ));
        }
        Ok(tree)
    }

    fn read_disposal_authority(
        &self,
        id: Uuid,
        fingerprint: [u8; 32],
    ) -> io::Result<(Option<StoredPlan>, bool)> {
        let plan = self
            .read(id, Artifact::QuarantinePurgePlan)?
            .map(|bytes| {
                let contents: DisposalPlan =
                    serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                if contents.fingerprint != fingerprint {
                    return Err(deny(
                        "the disposal plan refers to a different quarantine backup",
                    ));
                }
                Ok(StoredPlan {
                    digest: Sha256::digest(&bytes).into(),
                    contents,
                })
            })
            .transpose()?;
        let Some(bytes) = self.read(id, Artifact::QuarantinePurgeCommitted)? else {
            return Ok((plan, false));
        };
        let commit: CommittedDisposal = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        if commit.fingerprint != fingerprint
            || plan.as_ref().is_some_and(|plan| plan.digest != commit.plan)
        {
            return Err(deny(
                "the committed disposal does not match the reviewed backup",
            ));
        }
        Ok((plan, true))
    }

    fn finish_directory_disposal(&self, slot: &DisposalSlot<'_>) -> io::Result<()> {
        if !matches!(slot.state()?, SlotState::Absent) {
            return Err(deny(
                "the quarantine directory is still present after disposal",
            ));
        }
        fs::fsync(&slot.parent)?;
        // Leave the small commitment until the core writes its outcome.
        // The larger entry set is no longer needed after the directory is gone.
        let audit = self.open_store(AUDIT_DIR, false)?;
        let plan_name = Artifact::QuarantinePurgePlan.file_name(slot.id);
        match fs::unlinkat(&audit, plan_name.as_str(), fs::AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => fs::fsync(&audit)?,
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::Fixture;
    use uninstallany_core::{Access, FileStore};

    #[test]
    fn only_intact_uncommitted_detached_directories_can_be_restored() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let files = fixture
            .guard
            .with_application_roots(vec![fixture.scope.clone()])?;
        if native::require_apfs(&files.store_anchor()?).is_err() {
            return Ok(());
        }
        for (name, committed) in [("Uncommitted.app", false), ("Committed.app", true)] {
            let original = fixture.scope.join(name);
            let plist = original.join("Contents/Info.plist");
            std::fs::create_dir_all(original.join("Contents"))?;
            std::fs::write(&plist, b"fixture metadata")?;
            let inspection = files.inspect_file(&original)?;
            assert_eq!(inspection.access, Access::Allowed);
            let reviewed = &inspection.fingerprint;
            let id = Uuid::new_v4();
            files.quarantine_file(&original, reviewed, id)?;
            let fingerprint = Fingerprint::decode(reviewed, &original)?;
            let slot = DisposalSlot::open(&files, &original, fingerprint, id)?;
            let digest = Sha256::digest(reviewed.as_bytes()).into();
            let plan = files.record_disposal_plan(&slot, digest)?;
            native::rename_exclusive(
                (&slot.parent, OsStr::new(&slot.held)),
                (&slot.parent, OsStr::new(&slot.disposing)),
            )?;
            let detached = fixture.state.join(QUARANTINE_DIR).join(&slot.disposing);
            if committed {
                let receipt = CommittedDisposal {
                    fingerprint: digest,
                    plan: plan.digest,
                };
                files.create(
                    id,
                    Artifact::QuarantinePurgeCommitted,
                    &serde_json::to_vec(&receipt).map_err(io::Error::other)?,
                )?;
                assert!(
                    files
                        .recoverable_detached_file_backup(&original, reviewed, id)?
                        .is_none()
                );
                assert!(files.restore_file(&original, reviewed, id).is_err());
                assert!(detached.is_dir());
                continue;
            }

            assert_eq!(
                files.recoverable_detached_file_backup(&original, reviewed, id)?,
                Some(detached.clone())
            );
            assert!(files.has_pending_quarantine_purge(&original, reviewed, id)?);
            let first_lock = slot.lock(files.uid)?;
            let blocked = files.restore_file(&original, reviewed, id);
            assert!(blocked.is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock));
            drop(first_lock);

            std::fs::write(&original, b"occupant")?;
            assert!(files.restore_file(&original, reviewed, id).is_err());
            assert_eq!(std::fs::read(&original)?, b"occupant");
            std::fs::rename(&original, fixture.scope.join("occupant"))?;
            files.restore_file(&original, reviewed, id)?;
            assert!(files.verify_file_restored(&original, reviewed, id)?);
            assert!(!detached.exists());
            assert_eq!(std::fs::read(&plist)?, b"fixture metadata");
        }
        Ok(())
    }
}
