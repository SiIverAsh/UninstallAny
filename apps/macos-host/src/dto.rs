//! Read-only responses for the Tauri IPC contract.

use serde::Serialize;
use uninstallany_core::{
    Access, AppId, AppRecord, BackupInventory, BackupSummary, Candidate, Category, ChangeReport,
    ChangeResult, CleanupPlan, Confidence, Inventory, ItemResult, LoadedPreferences, MatchKind,
    OfficialIntent, OfficialOutcome, RecoveryState, RestorePlan, Risk, ScanMode,
};
use uuid::Uuid;

/// Application metadata and diagnostics for the application list.
#[derive(Serialize)]
pub(crate) struct InventoryPayload {
    applications: Vec<AppRecordPayload>,
    warnings: Vec<String>,
}

impl From<Inventory> for InventoryPayload {
    fn from(inventory: Inventory) -> Self {
        Self {
            applications: inventory.applications.into_iter().map(Into::into).collect(),
            warnings: inventory.warnings,
        }
    }
}

#[derive(Serialize)]
struct AppRecordPayload {
    id: AppId,
    name: String,
    publisher: Option<String>,
    version: Option<String>,
    install_location: Option<String>,
    size_bytes: Option<u64>,
    install_date: Option<String>,
    system_component: bool,
    official_uninstall_available: bool,
}

impl From<AppRecord> for AppRecordPayload {
    fn from(app: AppRecord) -> Self {
        Self {
            id: app.id,
            name: app.name,
            publisher: app.publisher,
            version: app.version,
            install_location: app.install_location.map(|path| path.display().to_string()),
            size_bytes: app.size_bytes,
            install_date: app.install_date,
            system_component: app.system_component,
            official_uninstall_available: app.official_uninstall_available,
        }
    }
}

/// Display fields from a cleanup plan held in the backend session.
#[derive(Serialize)]
pub(crate) struct CleanupPreview {
    id: Uuid,
    candidates: Vec<CandidatePayload>,
    mode: &'static str,
    warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<String>,
}

impl CleanupPreview {
    /// Projects a live plan into the frontend's review shape.
    pub(crate) fn new(plan: &CleanupPlan, subject: Option<String>) -> Self {
        let mode = match plan.mode() {
            ScanMode::Leftovers => "Leftovers",
            ScanMode::ForceRemoval => "ForceRemoval",
            ScanMode::AfterOfficialUninstall => "AfterOfficialUninstall",
        };
        Self {
            id: plan.id(),
            candidates: plan.candidates().map(Into::into).collect(),
            mode,
            warnings: plan.warnings().to_vec(),
            subject,
        }
    }
}

#[derive(Serialize)]
struct CandidatePayload {
    id: usize,
    target_display: String,
    category: Category,
    confidence: Confidence,
    evidence: MatchKind,
    reason: String,
    risk: Risk,
    access: Access,
}

impl From<&Candidate> for CandidatePayload {
    fn from(candidate: &Candidate) -> Self {
        Self {
            id: candidate.id,
            target_display: candidate.target.display(),
            category: candidate.category,
            confidence: candidate.confidence,
            evidence: candidate.evidence,
            reason: candidate.reason.clone(),
            risk: candidate.risk,
            access: candidate.access.clone(),
        }
    }
}

/// A ticket and the actions shown on the uninstall confirmation screen.
#[derive(Serialize)]
pub(crate) struct UninstallReviewPayload {
    ticket: Uuid,
    intents: Vec<OfficialIntentPayload>,
    warnings: Vec<String>,
}

impl UninstallReviewPayload {
    /// Copies the display fields from the reviewed intents.
    pub(crate) fn new<'a>(
        ticket: Uuid,
        intents: impl IntoIterator<Item = &'a OfficialIntent>,
        warnings: Vec<String>,
    ) -> Self {
        Self {
            ticket,
            intents: intents.into_iter().map(Into::into).collect(),
            warnings,
        }
    }
}

#[derive(Serialize)]
struct OfficialIntentPayload {
    application: String,
    method: String,
    quiet: bool,
    notice: String,
}

impl From<&OfficialIntent> for OfficialIntentPayload {
    fn from(intent: &OfficialIntent) -> Self {
        Self {
            application: intent.application.clone(),
            method: intent.method.clone(),
            quiet: intent.quiet,
            notice: intent.notice.clone(),
        }
    }
}

/// One uninstall result and its optional residual cleanup preview.
#[derive(Serialize)]
pub(crate) struct OfficialRow {
    application: String,
    outcome: Result<OfficialOutcome, String>,
    cleanup: Option<CleanupPreview>,
    warnings: Vec<String>,
}

impl OfficialRow {
    /// Builds a result row with the frontend's tagged outcome.
    pub(crate) fn new(
        application: String,
        outcome: Result<OfficialOutcome, String>,
        cleanup: Option<CleanupPreview>,
        warnings: Vec<String>,
    ) -> Self {
        Self {
            application,
            outcome,
            cleanup,
            warnings,
        }
    }
}

/// Quarantine entries and diagnostics for the recovery view.
#[derive(Serialize)]
pub(crate) struct BackupInventoryPayload {
    items: Vec<BackupSummaryPayload>,
    warnings: Vec<String>,
}

impl From<BackupInventory> for BackupInventoryPayload {
    fn from(inventory: BackupInventory) -> Self {
        Self {
            items: inventory.items.into_iter().map(Into::into).collect(),
            warnings: inventory.warnings,
        }
    }
}

/// A restore ticket and the entries shown before confirmation.
#[derive(Serialize)]
pub(crate) struct RestoreReviewPayload {
    ticket: Uuid,
    entries: Vec<BackupSummaryPayload>,
    warnings: Vec<String>,
}

impl RestoreReviewPayload {
    /// Projects a live restore plan into the frontend's review shape.
    pub(crate) fn new(ticket: Uuid, plan: &RestorePlan) -> Self {
        Self::from_entries(ticket, plan.entries().cloned(), plan.warnings().to_vec())
    }

    /// Projects independently verified backup summaries without exposing authority.
    pub(crate) fn from_entries(
        ticket: Uuid,
        entries: impl IntoIterator<Item = BackupSummary>,
        warnings: Vec<String>,
    ) -> Self {
        Self {
            ticket,
            entries: entries.into_iter().map(Into::into).collect(),
            warnings,
        }
    }
}

/// The backups eligible for one expiry confirmation.
#[derive(Serialize)]
pub(crate) struct ExpiryReviewPayload {
    ticket: Uuid,
    entries: Vec<BackupSummaryPayload>,
    warnings: Vec<String>,
}

impl ExpiryReviewPayload {
    /// Projects an expiry review without exposing its prepared operations.
    pub(crate) fn new(ticket: Uuid, entries: &[BackupSummary], warnings: &[String]) -> Self {
        Self {
            ticket,
            entries: entries.iter().cloned().map(Into::into).collect(),
            warnings: warnings.to_vec(),
        }
    }
}

#[derive(Serialize)]
struct BackupSummaryPayload {
    id: Uuid,
    batch_id: Uuid,
    target: String,
    backup: String,
    expires_unix_ms: u64,
    state: &'static str,
}

impl From<BackupSummary> for BackupSummaryPayload {
    fn from(summary: BackupSummary) -> Self {
        let state = match summary.state {
            RecoveryState::Staged => "Staged",
            RecoveryState::Applied => "Applied",
            RecoveryState::Restored => "Restored",
            RecoveryState::Purged => "Purged",
            RecoveryState::NeedsReview => "NeedsReview",
        };
        Self {
            id: summary.id,
            batch_id: summary.batch_id,
            target: summary.target,
            backup: summary.backup,
            expires_unix_ms: summary.expires_unix_ms,
            state,
        }
    }
}

/// Independent cleanup results and their review batch ID.
#[derive(Serialize)]
pub(crate) struct ChangeReportPayload {
    batch_id: Uuid,
    items: Vec<ItemResultPayload>,
}

impl From<ChangeReport> for ChangeReportPayload {
    fn from(report: ChangeReport) -> Self {
        Self {
            batch_id: report.batch_id,
            items: report.items.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Serialize)]
struct ItemResultPayload {
    target: String,
    backup_id: Option<Uuid>,
    result: ChangeResultPayload,
}

impl From<ItemResult> for ItemResultPayload {
    fn from(item: ItemResult) -> Self {
        let result = match item.result {
            ChangeResult::Applied => ChangeResultPayload::Applied,
            ChangeResult::Restored => ChangeResultPayload::Restored,
            ChangeResult::Purged => ChangeResultPayload::Purged,
            ChangeResult::Skipped(reason) => ChangeResultPayload::Skipped(reason),
            ChangeResult::NeedsReview(reason) => ChangeResultPayload::NeedsReview(reason),
        };
        Self {
            target: item.target,
            backup_id: item.backup_id,
            result,
        }
    }
}

#[derive(Serialize)]
enum ChangeResultPayload {
    Applied,
    Restored,
    Purged,
    Skipped(String),
    NeedsReview(String),
}

/// Saved preferences and diagnostics shown when the frontend starts.
#[derive(Serialize)]
pub(crate) struct LoadedPreferencesPayload {
    retention_days: u16,
    custom_rules: String,
    warnings: Vec<String>,
}

impl From<&LoadedPreferences> for LoadedPreferencesPayload {
    fn from(preferences: &LoadedPreferences) -> Self {
        Self {
            retention_days: preferences.retention_days.get(),
            custom_rules: preferences.custom_rules.clone(),
            warnings: preferences.warnings.clone(),
        }
    }
}
