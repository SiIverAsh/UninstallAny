use std::{
    collections::HashSet,
    io::{self, Read},
    path::PathBuf,
    str,
};

use serde::Deserialize;
use uuid::Uuid;

use crate::{
    Access, AppId, AppRecord, Cancellation, Category, Error, MatchKind, PlatformBackend, Proposal,
    Result, Risk, Scan, Target, match_name, policy::valid_file_address,
};

/// Maximum size of a custom rules document in bytes.
pub const MAX_RULE_FILE_BYTES: usize = 64 * 1024;
const RULE_VERSION: u8 = 1;
const MAX_RULES: usize = 128;
const MAX_COMPONENTS: usize = 12;
const MAX_RELATIVE_PATH_BYTES: usize = 384;
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_EVIDENCE_BYTES: usize = 320;
const BUILTIN: &[u8] = include_bytes!("rules/builtin.toml");

/// A platform-owned per-user directory, never a path supplied by a rule.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RuleRoot {
    WindowsRoamingAppData,
    WindowsLocalAppData,
    MacosApplicationSupport,
    MacosCaches,
    MacosPreferences,
    LinuxConfig,
    LinuxData,
    LinuxCache,
}

impl RuleRoot {
    fn scope(self) -> Scope {
        match self {
            Self::WindowsRoamingAppData | Self::WindowsLocalAppData => Scope::Windows,
            Self::MacosApplicationSupport | Self::MacosCaches | Self::MacosPreferences => {
                Scope::Macos
            }
            Self::LinuxConfig | Self::LinuxData | Self::LinuxCache => Scope::Linux,
        }
    }
}

/// Existing rule target identified by a no-follow platform probe.
#[derive(Debug)]
pub struct RuleTarget {
    pub path: PathBuf,
    pub category: Category,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Scope {
    Windows,
    Macos,
    Linux,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u8,
    rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    id: String,
    scope: Scope,
    app_match: AppMatch,
    root_id: RuleRoot,
    relative_path: String,
    evidence: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum AppMatch {
    WindowsUninstallCode { code: String },
    WindowsPackage { full_name: String },
    MacosBundle { id: String },
    LinuxPackage { manager: String, id: String },
    PublisherAndName { publisher: String, name: String },
}

impl AppMatch {
    fn valid_in(&self, scope: Scope) -> bool {
        match self {
            Self::WindowsUninstallCode { code } => {
                scope == Scope::Windows && Uuid::parse_str(code).is_ok()
            }
            Self::WindowsPackage { full_name } => scope == Scope::Windows && identifier(full_name),
            Self::MacosBundle { id } => {
                scope == Scope::Macos
                    && identifier(id)
                    && id.contains('.')
                    && id.split('.').all(|label| {
                        !label.is_empty()
                            && label
                                .bytes()
                                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    })
            }
            Self::LinuxPackage { manager, id } => {
                scope == Scope::Linux
                    && matches!(
                        manager.as_str(),
                        "dpkg" | "rpm" | "pacman" | "flatpak-user" | "flatpak-system" | "snap"
                    )
                    && identifier(id)
            }
            Self::PublisherAndName { publisher, name } => {
                valid_text(publisher, MAX_IDENTIFIER_BYTES)
                    && valid_text(name, MAX_IDENTIFIER_BYTES)
                    && match_name(name, Some(publisher), name, Some(publisher))
                        == Some(MatchKind::PublisherAndApp)
            }
        }
    }

    fn matches(&self, app: &AppRecord) -> bool {
        match (self, &app.id) {
            (Self::WindowsUninstallCode { code }, AppId::WindowsRegistry(address)) => {
                let observed = address
                    .key
                    .rsplit('\\')
                    .next()
                    .and_then(|name| Uuid::parse_str(name).ok());
                observed.is_some() && observed == Uuid::parse_str(code).ok()
            }
            (Self::WindowsPackage { full_name }, AppId::WindowsPackage(observed)) => {
                full_name.eq_ignore_ascii_case(observed)
            }
            (
                Self::MacosBundle { id },
                AppId::Package {
                    manager,
                    id: observed,
                },
            ) => macos_bundle_id(manager, observed)
                .is_some_and(|value| id.eq_ignore_ascii_case(value)),
            (
                Self::LinuxPackage { manager, id },
                AppId::Package {
                    manager: source,
                    id: observed,
                },
            ) => manager == source && id == observed,
            (Self::PublisherAndName { publisher, name }, _) => {
                match_name(name, Some(publisher), &app.name, app.publisher.as_deref())
                    == Some(MatchKind::PublisherAndApp)
            }
            _ => false,
        }
    }
}

fn macos_bundle_id<'a>(manager: &str, observed: &'a str) -> Option<&'a str> {
    match manager {
        "macos-bundle" => observed.split_once(':').map(|(bundle, _)| bundle),
        "homebrew-cask" => observed.splitn(3, ':').nth(2).filter(|id| !id.is_empty()),
        _ => None,
    }
}

pub(crate) struct RuleBook {
    builtin: Vec<Rule>,
    custom: Vec<Rule>,
}

impl RuleBook {
    pub(crate) fn new() -> Self {
        Self {
            builtin: parse(BUILTIN).expect("the embedded rule document is validated by unit tests"),
            custom: Vec::new(),
        }
    }

    pub(crate) fn load_custom(&mut self, reader: impl Read) -> Result<usize> {
        self.custom = parse(reader)?;
        Ok(self.custom.len())
    }

    pub(crate) fn clear_custom(&mut self) {
        self.custom.clear();
    }

    pub(crate) fn suggest(
        &self,
        platform: &impl PlatformBackend,
        app: &AppRecord,
        scan: &mut Scan,
        cancel: &Cancellation,
    ) -> Result<()> {
        let mut rules = self
            .builtin
            .iter()
            .map(|rule| ("Built-in", rule))
            .chain(self.custom.iter().map(|rule| ("Custom", rule)))
            .filter(|(_, rule)| rule.app_match.matches(app))
            .peekable();
        if rules.peek().is_none() {
            return Ok(());
        }
        let mut seen: HashSet<_> = scan
            .proposals
            .iter()
            .map(|proposal| proposal.target.clone())
            .collect();
        for (source, rule) in rules {
            cancel.check()?;
            let Some(root) = platform.rule_root(rule.root_id) else {
                continue;
            };
            let path = rule
                .relative_path
                .split('/')
                .fold(root, |directory, component| directory.join(component));
            if !valid_file_address(&path) || seen.contains(&Target::File(path.clone())) {
                continue;
            }
            let found = match platform.probe_rule_target(&path) {
                Ok(Some(found)) => found,
                Ok(None) => continue,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    scan.warnings.push(format!("Rule {}: {error}", rule.id));
                    continue;
                }
            };
            let target = Target::File(found.path);
            if !seen.insert(target.clone()) {
                continue;
            }
            // Matching the application identifies a useful place to inspect.
            // The rule cannot establish ownership of this particular object.
            scan.proposals.push(Proposal {
                target,
                category: found.category,
                evidence: MatchKind::RuleHint,
                reason: format!("{source} rule {}: {}", rule.id, rule.evidence),
                risk: Risk::High,
                access: Access::ReadOnly(
                    "A rule is a hint. Platform ownership verification is required for cleanup."
                        .into(),
                ),
            });
        }
        Ok(())
    }
}

/// Validates a bounded custom TOML document without changing the active rules.
pub fn validate_custom_rules(reader: impl Read) -> Result<usize> {
    parse(reader).map(|rules| rules.len())
}

fn parse(reader: impl Read) -> Result<Vec<Rule>> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_RULE_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_RULE_FILE_BYTES {
        return Err(rejected("Rule document exceeds 64 KiB."));
    }
    let contents = str::from_utf8(&bytes).map_err(|_| rejected("Rule document must be UTF-8."))?;
    let document: Document = toml::from_str(contents)
        .map_err(|error| rejected(&format!("Invalid TOML rules: {}", error.message())))?;
    if document.version != RULE_VERSION {
        return Err(rejected("Unsupported rule schema version."));
    }
    if document.rules.len() > MAX_RULES {
        return Err(rejected("Rule document contains more than 128 rules."));
    }
    let mut seen = HashSet::new();
    for (index, rule) in document.rules.iter().enumerate() {
        if !rule_id(&rule.id) || !seen.insert(rule.id.as_str()) {
            return Err(rejected(&format!(
                "Rule {} needs a unique, literal identifier.",
                index + 1
            )));
        }
        if rule.root_id.scope() != rule.scope || !rule.app_match.valid_in(rule.scope) {
            return Err(rejected(&format!(
                "Rule {} has an invalid root or app match for its scope.",
                rule.id
            )));
        }
        if !relative_path(&rule.relative_path) || !valid_text(&rule.evidence, MAX_EVIDENCE_BYTES) {
            return Err(rejected(&format!(
                "Rule {} has an invalid relative path or evidence description.",
                rule.id
            )));
        }
    }
    Ok(document.rules)
}

fn rule_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn valid_text(text: &str, limit: usize) -> bool {
    !text.is_empty()
        && text.trim() == text
        && text.len() <= limit
        && !text.chars().any(char::is_control)
        && !text.contains("://")
}

fn identifier(text: &str) -> bool {
    valid_text(text, MAX_IDENTIFIER_BYTES)
        && text.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'.' | b'-' | b'_' | b'~' | b'+' | b'=' | b':' | b'/' | b'@'
                )
        })
}

fn relative_path(path: &str) -> bool {
    if path.len() > MAX_RELATIVE_PATH_BYTES {
        return false;
    }
    let parts: Vec<_> = path.split('/').collect();
    parts.len() <= MAX_COMPONENTS
        && parts.into_iter().all(|component| {
            valid_text(component, 120)
                && !component.ends_with('.')
                && !component.contains([
                    '\\', ':', '*', '?', '[', ']', '<', '>', '|', '"', '$', '%', '~', '\u{0060}',
                ])
                && !reserved_device_name(component)
        })
}

fn reserved_device_name(component: &str) -> bool {
    let first = component.split('.').next().unwrap_or_default().trim_end();
    let upper = first.to_ascii_uppercase();
    if matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$") {
        return true;
    }
    let digit = upper
        .strip_prefix("COM")
        .or_else(|| upper.strip_prefix("LPT"));
    digit.is_some_and(|value| {
        matches!(
            value,
            "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
        )
    })
}

fn rejected(message: &str) -> Error {
    Error::Rejected(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE_HEADER: &str = r#"[[rules]]
id = "sample-tool-cache"
scope = "windows"
app_match = { kind = "publisher_and_name", publisher = "Example Studio", name = "Example Tool" }
root_id = "windows_local_app_data"
"#;

    fn single_rule(path: &str) -> String {
        format!("version = 1\n{RULE_HEADER}relative_path = {path:?}\nevidence = \"Test folder\"\n")
    }

    #[test]
    fn accepts_builtins_and_a_literal_scoped_document() -> Result<()> {
        assert!(validate_custom_rules(BUILTIN)? > 0);
        assert_eq!(
            validate_custom_rules(single_rule("Example Studio/Cache").as_bytes())?,
            1
        );
        Ok(())
    }

    #[test]
    fn rejects_traversal_device_names_and_expansions() {
        for path in [
            "",
            ".",
            "..",
            "kid/../secrets",
            "/absolute/folder",
            "mixed\\slashes",
            "kid//cache",
            "kid/cache/",
            "C:/data",
            "file:stream",
            "folder/*.png",
            "profiles/[abc]",
            "%LOCALAPPDATA%/foo",
            "$HOME/private",
            "foo/PRN.txt",
            "foo/COM¹",
            "folder/Cache.",
            "folder/Cache ",
        ] {
            assert!(
                validate_custom_rules(single_rule(path).as_bytes()).is_err(),
                "{path}"
            );
        }
    }

    #[test]
    fn rejects_unknown_actions_versions_or_scope_mismatches() {
        let good = single_rule("Example Studio/Cache");
        for text in [
            format!("{good}command = \"remove anything\"\n"),
            good.replace(
                "name = \"Example Tool\" }",
                "name = \"Example Tool\", confidence = \"high\" }",
            ),
            good.replace("version = 1", "version = 2"),
            good.replace("windows_local_app_data", "linux_cache"),
            good.replace("Example Studio", "Microsoft"),
            good.replace("Example Tool", "Update"),
            good.replace("Test folder", "https://example.org"),
        ] {
            assert!(validate_custom_rules(text.as_bytes()).is_err(), "{text}");
        }
    }

    #[test]
    fn rejects_duplicate_ids_and_unbounded_input() {
        let rule = single_rule("Example Studio/Cache");
        assert!(
            validate_custom_rules(format!("{rule}{}", &rule["version = 1\n".len()..]).as_bytes())
                .is_err()
        );
        assert!(validate_custom_rules(vec![b'x'; MAX_RULE_FILE_BYTES + 1].as_slice()).is_err());
        assert!(validate_custom_rules([0xFF].as_slice()).is_err());
    }
}
