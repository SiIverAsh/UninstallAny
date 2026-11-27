use std::{io, num::NonZeroU64};

use uninstallany_core::{Artifact, AuditEvent, Cancellation, Journal, Result};
use uuid::Uuid;

use crate::inventory::valid_snap_instance;

const ACTION: &str = "snap_snapshot";
const SAVED: &str = "succeeded";
const BACKUP_PREFIX: &str = "snapd://snapshot/";

/// Reference to a Snap data snapshot recorded during an uninstall.
#[derive(Debug)]
pub struct SnapSnapshot {
    /// Set identifier allocated by snapd at the time of the save.
    pub set_id: NonZeroU64,
    /// Exact Snap instance included in the save.
    pub instance: String,
    time_unix_ms: u64,
}

/// Local snapshot references and any records that could not be read.
#[derive(Debug, Default)]
pub struct SnapSnapshotHistory {
    /// Valid records, newest first.
    pub snapshots: Vec<SnapSnapshot>,
    /// Diagnostics for records omitted from the list.
    pub warnings: Vec<String>,
}

pub(crate) fn record(journal: &impl Journal, instance: &str, set_id: NonZeroU64) -> Result<()> {
    let id = Uuid::new_v4();
    let mut event = AuditEvent::new(instance.into(), ACTION, SAVED);
    event.operation_id = Some(id);
    event.backup = Some(format!("{BACKUP_PREFIX}{set_id}"));
    journal.create(id, Artifact::SnapSnapshot, &serde_json::to_vec(&event)?)?;
    Ok(())
}

pub(crate) fn history(
    journal: &impl Journal,
    cancel: &Cancellation,
) -> Result<SnapSnapshotHistory> {
    cancel.check()?;
    let mut history = SnapSnapshotHistory::default();
    for id in journal.list(Artifact::SnapSnapshot)? {
        cancel.check()?;
        match read_snapshot(journal, id) {
            Ok(snapshot) => history.snapshots.push(snapshot),
            Err(error) => history
                .warnings
                .push(format!("Could not read Snap snapshot record {id}: {error}")),
        }
    }
    history.snapshots.sort_unstable_by_key(|snapshot| {
        std::cmp::Reverse((snapshot.time_unix_ms, snapshot.set_id))
    });
    Ok(history)
}

fn read_snapshot(journal: &impl Journal, id: Uuid) -> Result<SnapSnapshot> {
    let bytes = journal
        .read(id, Artifact::SnapSnapshot)?
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    let event: AuditEvent = serde_json::from_slice(&bytes)?;
    let set_id = event
        .backup
        .as_deref()
        .and_then(|backup| backup.strip_prefix(BACKUP_PREFIX))
        .and_then(|set| set.parse::<NonZeroU64>().ok())
        .filter(|_| {
            event.operation_id == Some(id)
                && event.action == ACTION
                && event.result == SAVED
                && valid_snap_instance(&event.object)
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Snap snapshot reference",
            )
        })?;
    Ok(SnapSnapshot {
        set_id,
        instance: event.object,
        time_unix_ms: event.time_unix_ms,
    })
}

pub(crate) struct SavedSet<'a> {
    pub id: NonZeroU64,
    pub revision: Option<&'a str>,
}

pub(crate) fn parse_saved_set<'a>(output: &'a str, instance: &str) -> Option<SavedSet<'a>> {
    let mut rows = output.lines().filter_map(|line| {
        let mut columns = line.split_whitespace();
        let set_id = columns.next()?.parse::<NonZeroU64>().ok()?;
        let snap = columns.next();
        // The native table puts Age and Version before Rev.
        let revision = columns.nth(2).filter(|value| valid_revision(value));
        Some((
            snap,
            SavedSet {
                id: set_id,
                revision,
            },
        ))
    });
    let (snap, set) = rows.next()?;
    // The command requested exactly one instance. Other numeric rows would
    // make the set printed by this save ambiguous.
    (snap == Some(instance) && rows.next().is_none()).then_some(set)
}

pub(crate) fn matches_installed_revision(output: &str, instance: &str, revision: &str) -> bool {
    let mut rows = output.lines().filter_map(|line| {
        let mut columns = line.split_whitespace();
        let name = columns.next()?;
        // The native list table starts with Name, Version and Rev.
        (name != "Name").then(|| (name, columns.nth(1)))
    });
    rows.next() == Some((instance, Some(revision))) && rows.next().is_none()
}

fn valid_revision(value: &str) -> bool {
    value
        .strip_prefix('x')
        .unwrap_or(value)
        .parse::<NonZeroU64>()
        .is_ok()
}
