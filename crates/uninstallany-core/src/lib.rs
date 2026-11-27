//! UI-independent discovery, confirmation, cleanup, and restore.
#![forbid(unsafe_code)]

mod audit;
mod backend;
mod engine;
mod model;
mod policy;
mod preferences;
mod rules;
mod state;
#[cfg(test)]
mod tests;

pub use audit::AuditExport;
pub use backend::*;
pub use engine::*;
pub use model::*;
pub use policy::{
    is_current_user_app_path_default_target, is_protected_registry_target, match_name,
};
pub use preferences::LoadedPreferences;
pub use rules::{MAX_RULE_FILE_BYTES, RuleRoot, RuleTarget, validate_custom_rules};
pub use state::{Artifact, AuditEvent, BackupInventory, BackupSummary, Journal, RecoveryState};
