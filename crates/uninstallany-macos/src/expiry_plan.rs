//! Shared review and execution of local and signed-helper backup expiry.

#[cfg(feature = "privileged-inspection")]
use std::{
    cell::Cell,
    collections::{HashMap, HashSet},
};

#[cfg(feature = "privileged-inspection")]
use uninstallany_core::{AuditEvent, ChangeResult, Error};
use uninstallany_core::{
    BackupSummary, Cancellation, ChangeReport, Engine, ExpiryCleanupPlan, Journal, PlatformBackend,
    Result,
};
use uuid::Uuid;

#[cfg(feature = "privileged-inspection")]
use crate::{
    read_system_backups,
    system_backup_expiry::{SystemExpiryReview, prepare_system_expiry},
};

/// A dry-run of eligible backups with the authority for each reviewed object.
pub struct MacExpiryPlan {
    local: ExpiryCleanupPlan,
    items: Vec<BackupSummary>,
    warnings: Vec<String>,
    #[cfg(feature = "privileged-inspection")]
    system: HashMap<Uuid, SystemExpiryReview>,
}

impl MacExpiryPlan {
    /// Reviews expired backups without disposing of any objects.
    pub fn prepare<P: PlatformBackend, J: Journal>(
        engine: &Engine<P, J>,
        cancel: &Cancellation,
    ) -> Result<Self> {
        let local = engine.prepare_expiry_cleanup(cancel)?;
        let plan = Self {
            items: local.items().cloned().collect(),
            warnings: local.warnings().to_vec(),
            local,
            #[cfg(feature = "privileged-inspection")]
            system: HashMap::new(),
        };
        #[cfg(feature = "privileged-inspection")]
        let plan = plan.with_system_backups(engine, cancel)?;
        Ok(plan)
    }

    /// Lists the exact backups available for selection.
    pub fn items(&self) -> &[BackupSummary] {
        &self.items
    }

    /// Returns diagnostics from the local and system backup reviews.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Consumes this review and applies only the approved backup IDs.
    pub fn apply<P: PlatformBackend, J: Journal>(
        self,
        engine: &Engine<P, J>,
        batch_id: Uuid,
        selected: Vec<Uuid>,
        cancel: &Cancellation,
    ) -> Result<ChangeReport> {
        #[cfg(feature = "privileged-inspection")]
        {
            self.apply_mixed(engine, batch_id, selected, cancel)
        }
        #[cfg(not(feature = "privileged-inspection"))]
        {
            let _ = batch_id;
            engine.apply_expiry_cleanup(self.local.confirm(&selected)?, cancel)
        }
    }

    #[cfg(feature = "privileged-inspection")]
    fn with_system_backups<P: PlatformBackend, J: Journal>(
        mut self,
        engine: &Engine<P, J>,
        cancel: &Cancellation,
    ) -> Result<Self> {
        let catalog = read_system_backups(cancel)?;
        self.warnings.extend(catalog.inventory.warnings);
        if catalog.expiry_ids.is_empty() {
            return Ok(self);
        }
        let local = engine.backups();
        cancel.check()?;
        let local_ids = match local {
            Ok(local) => backup_namespace(self.items.iter().chain(&local.items)),
            Err(error) => {
                self.warnings.push(format!(
                    "Could not separate local and system backup IDs: {error}"
                ));
                return Ok(self);
            }
        };
        for operation in catalog.expiry_ids {
            cancel.check()?;
            if local_ids.contains(&operation) {
                self.warnings.push(format!(
                    "System backup {operation} shares an identifier with a local backup and was omitted."
                ));
                continue;
            }
            let review = prepare_system_expiry(operation)
                .map_err(Error::from)
                .and_then(|review| {
                    cancel.check()?;
                    engine.record_external_audit_event(&review.audit_preview())?;
                    Ok(review)
                });
            match review {
                Ok(review) => {
                    self.items.push(review.summary().clone());
                    self.system.insert(operation, review);
                }
                Err(Error::Cancelled) => return Err(Error::Cancelled),
                Err(error) => self.warnings.push(format!(
                    "Could not review system backup {operation}: {error}"
                )),
            }
        }
        cancel.check()?;
        if !self.system.is_empty() {
            self.warnings.push(
                "Removing a system backup requires a separate macOS administrator approval.".into(),
            );
            self.items.sort_unstable_by(|left, right| {
                (&left.target, left.id).cmp(&(&right.target, right.id))
            });
        }
        Ok(self)
    }

    #[cfg(feature = "privileged-inspection")]
    fn apply_mixed<P: PlatformBackend, J: Journal>(
        self,
        engine: &Engine<P, J>,
        batch_id: Uuid,
        selected: Vec<Uuid>,
        cancel: &Cancellation,
    ) -> Result<ChangeReport> {
        let Self {
            local, mut system, ..
        } = self;
        let unique: HashSet<_> = selected.iter().copied().collect();
        if unique.is_empty() || unique.len() != selected.len() {
            return Err(Error::Rejected("select distinct expired backups".into()));
        }
        let local_available: HashSet<_> = local.items().map(|entry| entry.id).collect();
        let mut local_ids = Vec::new();
        let mut system_reviews = Vec::new();
        for id in selected {
            match (local_available.contains(&id), system.remove(&id)) {
                (true, None) => local_ids.push(id),
                (false, Some(review)) => system_reviews.push(review),
                _ => {
                    return Err(Error::Rejected(
                        "a selected backup does not identify exactly one reviewed item".into(),
                    ));
                }
            }
        }
        let confirmed_local = if local_ids.is_empty() {
            None
        } else {
            Some(local.confirm(&local_ids)?)
        };
        cancel.check()?;
        if !system_reviews.is_empty() {
            let local = engine.backups()?;
            let local_ids = backup_namespace(&local.items);
            if system_reviews
                .iter()
                .any(|review| local_ids.contains(&review.summary().id))
            {
                return Err(Error::Rejected(
                    "a selected system backup conflicts with a local backup ID".into(),
                ));
            }
        }

        let audit_error = Cell::new(None);
        let record = |event: &AuditEvent| {
            let result = engine.record_external_audit_event(event);
            if let Err(error) = &result {
                audit_error.set(Some(error.to_string()));
            }
            result
        };
        let mut confirmed_system = Vec::with_capacity(system_reviews.len());
        for review in system_reviews {
            cancel.check()?;
            confirmed_system.push(review.confirm(&record));
            if let Some(error) = audit_error.take() {
                return Err(Error::Rejected(format!(
                    "Could not record system backup expiry confirmation: {error}"
                )));
            }
        }

        cancel.check()?;
        let (mut report, mut can_continue) = if let Some(confirmed) = confirmed_local {
            let outcome = engine.apply_expiry_cleanup_with_status(confirmed, cancel)?;
            (outcome.report, outcome.can_continue)
        } else {
            (
                ChangeReport {
                    batch_id,
                    items: Vec::new(),
                },
                true,
            )
        };
        for review in confirmed_system {
            let item = match review {
                Ok(confirmed) if can_continue => confirmed.run(cancel, &record),
                Ok(confirmed) => confirmed.skip_after_unresolved_change(report.batch_id, &record),
                Err(skipped) => skipped,
            };
            can_continue &= audit_error.take().is_none()
                && !matches!(&item.result, ChangeResult::NeedsReview(_));
            report.items.push(item);
        }
        Ok(report)
    }
}

#[cfg(feature = "privileged-inspection")]
fn backup_namespace<'a>(entries: impl IntoIterator<Item = &'a BackupSummary>) -> HashSet<Uuid> {
    entries
        .into_iter()
        .flat_map(|entry| [entry.id, entry.batch_id])
        .collect()
}
