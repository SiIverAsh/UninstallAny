use std::num::NonZeroU16;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    Artifact, Engine, Error, Journal, PlatformBackend, Result,
    engine::DEFAULT_RETENTION_DAYS,
    state::{put_json, read_json},
};

const PREFERENCES_VERSION: u8 = 1;
const MAX_PREFERENCE_WARNINGS: usize = 16;

/// Valid settings loaded from the private application journal.
pub struct LoadedPreferences {
    pub retention_days: NonZeroU16,
    pub custom_rules: String,
    pub warnings: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    revision: u64,
    setting: Setting,
}

#[derive(Deserialize, Serialize)]
enum Setting {
    RetentionDays(NonZeroU16),
    CustomRules(String),
}

struct History {
    latest_revision: u64,
    retention: Option<((u64, Uuid), NonZeroU16)>,
    rules: Option<((u64, Uuid), String)>,
    warnings: Vec<String>,
}

impl<P: PlatformBackend, J: Journal> Engine<P, J> {
    /// Loads valid settings at startup and applies their settings to this process.
    pub fn restore_preferences(&mut self) -> Result<LoadedPreferences> {
        let history = read_history(&self.journal)?;
        let retention_days = history
            .retention
            .map_or(DEFAULT_RETENTION_DAYS, |(_, days)| days);
        let custom_rules = history.rules.map_or_else(String::new, |(_, text)| text);
        self.set_retention(retention_days);
        self.use_rules(&custom_rules)?;
        Ok(LoadedPreferences {
            retention_days,
            custom_rules,
            warnings: history.warnings,
        })
    }

    /// Saves retention for future backups, without altering existing backups.
    pub fn persist_retention(&mut self, days: NonZeroU16) -> Result<()> {
        self.save_preference(Setting::RetentionDays(days))?;
        self.set_retention(days);
        Ok(())
    }

    /// Validates and saves the user's rule text. Blank text clears the custom rules.
    pub fn persist_custom_rules(&mut self, text: String) -> Result<usize> {
        let count = validate(&text)?;
        let text = if text.trim().is_empty() {
            String::new()
        } else {
            text
        };
        self.save_preference(Setting::CustomRules(text.clone()))?;
        self.use_rules(&text)?;
        Ok(count)
    }

    fn use_rules(&mut self, text: &str) -> Result<()> {
        if text.is_empty() {
            self.clear_custom_rules();
        } else {
            self.load_custom_rules(text.as_bytes())?;
        }
        Ok(())
    }

    fn save_preference(&self, setting: Setting) -> Result<()> {
        let revision = read_history(&self.journal)?
            .latest_revision
            .checked_add(1)
            .ok_or_else(|| Error::Rejected("preference history revision is exhausted".into()))?;
        // One immutable entry per setting keeps simultaneous edits to different
        // preferences independent and avoids replacing an arbitrary profile file.
        let record = Record {
            version: PREFERENCES_VERSION,
            revision,
            setting,
        };
        put_json(
            &self.journal,
            Uuid::new_v4(),
            Artifact::Preferences,
            &record,
        )
    }
}

fn validate(text: &str) -> Result<usize> {
    if text.len() > crate::MAX_RULE_FILE_BYTES {
        return Err(Error::Rejected(
            "custom rules exceed the supported file size".into(),
        ));
    }
    if text.trim().is_empty() {
        return Ok(0);
    }
    crate::validate_custom_rules(text.as_bytes())
}

fn read_history(journal: &impl Journal) -> Result<History> {
    let mut history = History {
        latest_revision: 0,
        retention: None,
        rules: None,
        warnings: Vec::new(),
    };
    let mut errors = 0;
    for id in journal.list(Artifact::Preferences)? {
        let result = read_json(journal, id, Artifact::Preferences)
            .and_then(|record| {
                record.ok_or_else(|| Error::Rejected("settings record is unavailable".into()))
            })
            .and_then(|record| record_preference(&mut history, id, record));
        if let Err(error) = result {
            errors += 1;
            if history.warnings.len() < MAX_PREFERENCE_WARNINGS {
                history.warnings.push(format!("Preference {id}: {error}"));
            }
        }
    }
    if errors > MAX_PREFERENCE_WARNINGS {
        history.warnings.push(format!(
            "{} additional settings records could not be loaded",
            errors - MAX_PREFERENCE_WARNINGS
        ));
    }
    Ok(history)
}

fn record_preference(history: &mut History, id: Uuid, record: Record) -> Result<()> {
    if record.version != PREFERENCES_VERSION || record.revision == 0 {
        return Err(Error::Rejected(
            "settings record version or revision is unsupported".into(),
        ));
    }
    let order = (record.revision, id);
    match record.setting {
        Setting::RetentionDays(days) => {
            if history
                .retention
                .as_ref()
                .is_none_or(|(previous, _)| order > *previous)
            {
                history.retention = Some((order, days));
            }
        }
        Setting::CustomRules(text) => {
            if history
                .rules
                .as_ref()
                .is_none_or(|(previous, _)| order > *previous)
            {
                validate(&text)?;
                history.rules = Some((order, text));
            }
        }
    }
    history.latest_revision = history.latest_revision.max(record.revision);
    Ok(())
}
