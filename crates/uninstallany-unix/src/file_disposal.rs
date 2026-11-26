//! Recoverable expiry of one quarantined macOS file or terminal link.

use std::{
    ffi::OsStr,
    io,
    path::{Path, PathBuf},
};

use rustix::fs;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uninstallany_core::{Artifact, Journal};
use uuid::Uuid;

use super::{AUDIT_DIR, Fingerprint, QUARANTINE_DIR, UnixFiles, VerifiedEntry};
use crate::directory_disposal::{DisposalSlot, SlotState};
use crate::native::{self, NodeId, deny};

const FILE_DISPOSAL_VERSION: u8 = 1;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CommittedFileDisposal {
    version: u8,
    id: Uuid,
    fingerprint: [u8; 32],
    quarantine: NodeId,
    entry: VerifiedEntry,
}

impl UnixFiles {
    pub(super) fn recoverable_detached_single_file(
        &self,
        path: &Path,
        reviewed: &str,
        fingerprint: Fingerprint,
        id: Uuid,
    ) -> io::Result<Option<PathBuf>> {
        let slot = match DisposalSlot::open(self, path, fingerprint, id) {
            Ok(slot) => slot,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if !matches!(slot.state()?, SlotState::Disposing)
            || self
                .read_file_disposal_commit(&slot, reviewed, id)?
                .is_some()
        {
            return Ok(None);
        }
        self.disposal_file_entry(&slot, path, &slot.disposing)?;
        Ok(Some(self.state.join(QUARANTINE_DIR).join(slot.disposing)))
    }

    pub(super) fn restore_single_file(
        &self,
        path: &Path,
        reviewed: &str,
        fingerprint: Fingerprint,
        id: Uuid,
    ) -> io::Result<()> {
        let slot = DisposalSlot::open(self, path, fingerprint, id)?;
        let _lock = slot.lock(self.uid)?;
        if self
            .read_file_disposal_commit(&slot, reviewed, id)?
            .is_some()
        {
            return Err(deny(
                "file disposal has already been committed for this backup",
            ));
        }
        let name = match slot.state()? {
            SlotState::Held => &slot.held,
            SlotState::Disposing => &slot.disposing,
            SlotState::Absent => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "the file backup is missing",
                ));
            }
        };
        self.restore_named_quarantine(path, &slot.fingerprint, &slot.parent, OsStr::new(name))
    }

    pub(super) fn pending_single_file_disposal(
        &self,
        path: &Path,
        reviewed: &str,
        fingerprint: Fingerprint,
        id: Uuid,
    ) -> io::Result<bool> {
        let slot = match DisposalSlot::open(self, path, fingerprint, id) {
            Ok(slot) => slot,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        let commit = self.read_file_disposal_commit(&slot, reviewed, id)?;
        match slot.state()? {
            SlotState::Held if commit.is_some() => Err(deny(
                "the ordinary slot reappeared after file disposal was committed",
            )),
            SlotState::Held => Ok(false),
            SlotState::Absent => Ok(commit.is_some()),
            SlotState::Disposing => {
                let entry = self.disposal_file_entry(&slot, path, &slot.disposing)?;
                if commit.is_some_and(|commit| commit.entry != entry) {
                    return Err(deny("the committed file disposal object changed"));
                }
                Ok(true)
            }
        }
    }

    pub(super) fn purge_single_file(
        &self,
        path: &Path,
        reviewed: &str,
        fingerprint: Fingerprint,
        id: Uuid,
    ) -> io::Result<()> {
        let slot = DisposalSlot::open(self, path, fingerprint, id)?;
        let _lock = slot.lock(self.uid)?;
        let commit = match self.read_file_disposal_commit(&slot, reviewed, id)? {
            Some(commit) => {
                // A failed sync can leave the marker visible but not durable.
                fs::fsync(self.open_store(AUDIT_DIR, false)?)?;
                commit
            }
            None => self.commit_single_file_disposal(&slot, path, reviewed, id)?,
        };

        match slot.state()? {
            SlotState::Disposing => {
                if self.disposal_file_entry(&slot, path, &slot.disposing)? != commit.entry {
                    return Err(deny("the committed file disposal object changed"));
                }
                // Unlink only the verified terminal name, including links.
                fs::unlinkat(
                    &slot.parent,
                    OsStr::new(&slot.disposing),
                    fs::AtFlags::empty(),
                )?;
            }
            SlotState::Absent => {}
            SlotState::Held => {
                return Err(deny(
                    "the ordinary slot reappeared after file disposal was committed",
                ));
            }
        }
        fs::fsync(&slot.parent)?;
        Ok(())
    }

    fn commit_single_file_disposal(
        &self,
        slot: &DisposalSlot<'_>,
        path: &Path,
        reviewed: &str,
        id: Uuid,
    ) -> io::Result<CommittedFileDisposal> {
        let detached = match slot.state()? {
            SlotState::Held => {
                let held = self.disposal_file_entry(slot, path, &slot.held)?;
                native::rename_exclusive(
                    (&slot.parent, OsStr::new(&slot.held)),
                    (&slot.parent, OsStr::new(&slot.disposing)),
                )?;
                let detached = self.disposal_file_entry(slot, path, &slot.disposing)?;
                if !held.matches_moved(&detached) {
                    return Err(deny("the file changed while being detached for disposal"));
                }
                detached
            }
            SlotState::Disposing => self.disposal_file_entry(slot, path, &slot.disposing)?,
            SlotState::Absent => return Err(deny("no verified file quarantine slot is available")),
        };
        // A durable detachment must precede the first irreversible deletion.
        fs::fsync(&slot.parent)?;
        let commit = CommittedFileDisposal {
            version: FILE_DISPOSAL_VERSION,
            id,
            fingerprint: Sha256::digest(reviewed.as_bytes()).into(),
            quarantine: native::directory_id(&slot.parent)?,
            entry: detached,
        };
        let bytes = serde_json::to_vec(&commit).map_err(io::Error::other)?;
        self.create(id, Artifact::QuarantinePurgeCommitted, &bytes)?;
        Ok(commit)
    }

    fn read_file_disposal_commit(
        &self,
        slot: &DisposalSlot<'_>,
        reviewed: &str,
        id: Uuid,
    ) -> io::Result<Option<CommittedFileDisposal>> {
        let Some(bytes) = self.read(id, Artifact::QuarantinePurgeCommitted)? else {
            return Ok(None);
        };
        let commit: CommittedFileDisposal =
            serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        let fingerprint: [u8; 32] = Sha256::digest(reviewed.as_bytes()).into();
        if commit.version != FILE_DISPOSAL_VERSION
            || commit.id != id
            || commit.fingerprint != fingerprint
            || commit.quarantine != native::directory_id(&slot.parent)?
            || !slot.fingerprint.entry.matches_moved(&commit.entry)
        {
            return Err(deny(
                "the file disposal commitment does not match the quarantine backup",
            ));
        }
        Ok(Some(commit))
    }

    fn disposal_file_entry(
        &self,
        slot: &DisposalSlot<'_>,
        path: &Path,
        name: &str,
    ) -> io::Result<VerifiedEntry> {
        self.inspect_purge_entry(path, &slot.fingerprint, &slot.parent, OsStr::new(name))?
            .ok_or_else(|| deny("the file disposal entry is absent or cannot be verified"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::Fixture;
    use uninstallany_core::{Access, FileStore};

    #[test]
    fn detached_file_can_be_restored_before_disposal_is_committed() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let files = &fixture.guard;
        let original = fixture.scope.join("candidate");
        std::fs::write(&original, b"restore me")?;
        let reviewed = files.inspect_file(&original)?;
        assert_eq!(reviewed.access, Access::Allowed);
        let id = Uuid::new_v4();
        files.quarantine_file(&original, &reviewed.fingerprint, id)?;
        let fingerprint = Fingerprint::decode(&reviewed.fingerprint, &original)?;
        let slot = DisposalSlot::open(files, &original, fingerprint, id)?;
        native::rename_exclusive(
            (&slot.parent, OsStr::new(&slot.held)),
            (&slot.parent, OsStr::new(&slot.disposing)),
        )?;

        assert!(
            files
                .recoverable_detached_file_backup(&original, &reviewed.fingerprint, id)?
                .is_some()
        );
        assert!(files.has_pending_quarantine_purge(&original, &reviewed.fingerprint, id)?);
        files.restore_file(&original, &reviewed.fingerprint, id)?;
        assert_eq!(std::fs::read(&original)?, b"restore me");
        assert!(files.verify_file_restored(&original, &reviewed.fingerprint, id)?);
        Ok(())
    }

    #[test]
    fn committed_link_disposal_retries_without_touching_the_link_destination() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let files = &fixture.guard;
        let original = fixture.scope.join("link");
        let destination = fixture.scope.join("kept");
        std::fs::write(&destination, b"keep me")?;
        std::os::unix::fs::symlink(&destination, &original)?;
        let reviewed = files.inspect_file(&original)?;
        assert_eq!(reviewed.access, Access::Allowed);
        let id = Uuid::new_v4();
        files.quarantine_file(&original, &reviewed.fingerprint, id)?;
        let fingerprint = Fingerprint::decode(&reviewed.fingerprint, &original)?;
        let slot = DisposalSlot::open(files, &original, fingerprint, id)?;
        let lock = slot.lock(files.uid)?;
        files.commit_single_file_disposal(&slot, &original, &reviewed.fingerprint, id)?;
        drop(lock);

        assert!(
            files
                .recoverable_detached_file_backup(&original, &reviewed.fingerprint, id)?
                .is_none()
        );
        assert!(
            files
                .restore_file(&original, &reviewed.fingerprint, id)
                .is_err()
        );
        assert!(files.has_pending_quarantine_purge(&original, &reviewed.fingerprint, id)?);
        files.purge_quarantined(&original, &reviewed.fingerprint, id)?;
        assert!(files.has_pending_quarantine_purge(&original, &reviewed.fingerprint, id)?);
        files.purge_quarantined(&original, &reviewed.fingerprint, id)?;
        assert_eq!(std::fs::read(&destination)?, b"keep me");
        assert!(matches!(slot.state()?, SlotState::Absent));
        Ok(())
    }
}
