use std::path::{Component, Path};

use crate::{MatchKind, RegistryHive, RegistryTarget, RegistryView};

const APP_PATHS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\App Paths";
const PROTECTED_APP_PATH_PROGRAMS: &[&str] = &[
    "calc",
    "cmd",
    "command",
    "control",
    "cscript",
    "explorer",
    "hh",
    "mmc",
    "mshta",
    "msiexec",
    "notepad",
    "powershell",
    "pwsh",
    "reg",
    "regasm",
    "regedit",
    "regsvr32",
    "rundll32",
    "schtasks",
    "svchost",
    "taskmgr",
    "winlogon",
    "wmic",
    "wscript",
];

const GENERIC_TERMS: &[&str] = &[
    "app",
    "application",
    "apps",
    "cache",
    "common",
    "data",
    "files",
    "installer",
    "local",
    "microsoft",
    "program",
    "programs",
    "settings",
    "shared",
    "software",
    "temp",
    "update",
    "updater",
    "windows",
];

// Match evidence by complete normalized components. This normalization is
// never used to decide the identity of a file or a registry key.
fn normalized_name(name: &str) -> String {
    name.split(|character: char| !character.is_alphanumeric())
        .filter(|term| !term.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn is_specific(name: &str) -> bool {
    let length = name
        .chars()
        .filter(|character| !character.is_whitespace())
        .count();
    let minimum = if name.is_ascii() { 4 } else { 3 };
    length >= minimum
        && name
            .split_whitespace()
            .any(|term| !GENERIC_TERMS.contains(&term))
}

/// Scores a candidate's name, using publisher evidence only if it is also specific.
pub fn match_name(
    application: &str,
    application_publisher: Option<&str>,
    candidate: &str,
    candidate_publisher: Option<&str>,
) -> Option<MatchKind> {
    let application = normalized_name(application);
    let candidate = normalized_name(candidate);
    if !is_specific(&application) || !is_specific(&candidate) {
        return None;
    }
    if application == candidate {
        let same_publisher = application_publisher
            .zip(candidate_publisher)
            .map(|(expected, observed)| (normalized_name(expected), normalized_name(observed)))
            .is_some_and(|(expected, observed)| is_specific(&expected) && expected == observed);
        return Some(if same_publisher {
            MatchKind::PublisherAndApp
        } else {
            MatchKind::AppName
        });
    }
    let is_prefix = candidate
        .strip_prefix(&application)
        .is_some_and(|tail| tail.starts_with(' '));
    let is_suffix = candidate
        .strip_suffix(&application)
        .is_some_and(|head| head.ends_with(' '));
    (is_prefix || is_suffix).then_some(MatchKind::FuzzyName)
}

/// Identifies an eligible App Paths default-value address in the current user view.
///
/// A native backend must still establish ownership and verify the registered executable.
pub fn is_current_user_app_path_default_target(target: &RegistryTarget) -> bool {
    if target.hive != RegistryHive::CurrentUser
        || target.view != RegistryView::Native
        || target.value.as_deref() != Some("")
    {
        return false;
    }
    let Some((parent, leaf)) = target.key.rsplit_once('\\') else {
        return false;
    };
    let Some((stem, extension)) = leaf.rsplit_once('.') else {
        return false;
    };
    if !parent.eq_ignore_ascii_case(APP_PATHS_KEY)
        || !extension.eq_ignore_ascii_case("exe")
        || stem.trim() != stem
        || stem.starts_with('.')
        || stem.ends_with('.')
        || stem.chars().any(|character| {
            character.is_control()
                || matches!(
                    character,
                    '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '[' | ']' | '%'
                )
        })
    {
        return false;
    }
    let normalized = normalized_name(stem);
    is_specific(&normalized)
        && !is_builtin(stem)
        && !normalized.starts_with("microsoft")
        && !normalized.starts_with("windows")
        && !PROTECTED_APP_PATH_PROGRAMS.contains(&normalized.as_str())
}

/// Rejects protected or noncanonical registry targets before a platform can write.
pub fn is_protected_registry_target(target: &RegistryTarget) -> bool {
    let canonical = target.key.to_lowercase();
    let segments: Vec<&str> = canonical.split('\\').collect();
    if segments
        .iter()
        .any(|part| part.is_empty() || part.trim() != *part || part.contains('\0'))
    {
        return true;
    }
    if let Some(value) = &target.value {
        if value.contains('\0') {
            return true;
        }
    }
    match segments.as_slice() {
        [
            "software",
            "microsoft",
            "windows",
            "currentversion",
            "uninstall",
            leaf,
        ] => target.value.is_some() || is_builtin(leaf),
        [
            "software",
            "microsoft",
            "windows",
            "currentversion",
            "app paths",
            ..,
        ] => !is_current_user_app_path_default_target(target),
        [
            "software",
            "microsoft",
            "windows",
            "currentversion",
            "run" | "runonce",
        ] => target
            .value
            .as_deref()
            .is_none_or(|name| is_builtin(&name.to_lowercase())),
        ["software", vendor, rest @ ..] => {
            rest.is_empty() && target.value.is_none()
                || is_builtin(vendor)
                || rest.iter().any(|part| is_builtin(part))
        }
        _ => true,
    }
}

fn is_builtin(name: &str) -> bool {
    let normalized = normalized_name(name);
    normalized.is_empty()
        || normalized
            .split_whitespace()
            .any(|term| matches!(term, "microsoft" | "windows"))
        || matches!(normalized.as_str(), "classes" | "policies" | "wow6432node")
}

pub(crate) fn valid_file_address(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    let mut has_leaf = false;
    for component in path.components() {
        match component {
            Component::ParentDir | Component::CurDir => return false,
            Component::Normal(_) => has_leaf = true,
            Component::Prefix(_) | Component::RootDir => {}
        }
    }
    has_leaf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_ignores_short_and_generic_names_and_scores_evidence() {
        for name in ["abc", "Microsoft", "Common", "Update", "Common Data"] {
            assert_eq!(match_name(name, None, name, None), None);
        }
        assert_eq!(
            match_name(
                "Example Tool",
                Some("Studio Eight"),
                "EXAMPLE-tool",
                Some("studio eight")
            ),
            Some(MatchKind::PublisherAndApp)
        );
        assert_eq!(
            match_name("Example Tool", None, "Example Tool", None),
            Some(MatchKind::AppName)
        );
        assert_eq!(
            match_name("Example Tool", None, "Example Tool Cache", None),
            Some(MatchKind::FuzzyName)
        );
        assert_eq!(
            match_name("Example Tool", None, "OtherExample Tool", None),
            None
        );
    }

    #[test]
    fn paths_reject_root_relative_and_traversal_addresses() {
        #[cfg(windows)]
        let addresses = [
            r"C:\",
            r"Example\sample",
            r"C:\Example\..\sample",
            r"C:\Example\sample",
        ];
        #[cfg(unix)]
        let addresses = [
            "/",
            "Example/sample",
            "/Example/../sample",
            "/Example/sample",
        ];
        assert!(
            addresses[..3]
                .iter()
                .all(|p| !valid_file_address(Path::new(p)))
        );
        assert!(valid_file_address(Path::new(addresses[3])));
    }

    #[test]
    fn registry_policy_rejects_protected_hives_and_containers() {
        let target = |key: &str, value: Option<&str>| RegistryTarget {
            hive: RegistryHive::LocalMachine,
            view: RegistryView::Registry64,
            key: key.into(),
            value: value.map(str::to_owned),
        };
        let uninstall = r"Software\Microsoft\Windows\CurrentVersion\Uninstall";
        assert!(is_protected_registry_target(&target(r"SYSTEM\Setup", None)));
        assert!(is_protected_registry_target(&target(
            r"Software\Microsoft\Office",
            None
        )));
        assert!(is_protected_registry_target(&target(uninstall, None)));
        assert!(is_protected_registry_target(&target(
            &format!("{uninstall}\\Microsoft Tool"),
            None
        )));
        assert!(!is_protected_registry_target(&target(
            &format!("{uninstall}\\Example Tool"),
            None
        )));
        assert!(!is_protected_registry_target(&target(
            r"Software\Studio Eight\Example Tool",
            None
        )));
        assert!(is_protected_registry_target(&target(
            r"Software\Studio Eight",
            None
        )));
    }

    #[test]
    fn app_paths_policy_only_allows_the_current_user_native_executable_default() {
        let allowed = RegistryTarget {
            hive: RegistryHive::CurrentUser,
            view: RegistryView::Native,
            key: format!(r"{APP_PATHS_KEY}\Scope Sample.EXE"),
            value: Some(String::new()),
        };
        assert!(is_current_user_app_path_default_target(&allowed));
        assert!(!is_protected_registry_target(&allowed));

        for rejected in [
            RegistryTarget {
                hive: RegistryHive::LocalMachine,
                ..allowed.clone()
            },
            RegistryTarget {
                view: RegistryView::Registry32,
                ..allowed.clone()
            },
            RegistryTarget {
                view: RegistryView::Registry64,
                ..allowed.clone()
            },
            RegistryTarget {
                value: None,
                ..allowed.clone()
            },
            RegistryTarget {
                value: Some("Path".into()),
                ..allowed.clone()
            },
            RegistryTarget {
                key: APP_PATHS_KEY.into(),
                ..allowed.clone()
            },
        ] {
            assert!(
                !is_current_user_app_path_default_target(&rejected),
                "{rejected:?}"
            );
            assert!(is_protected_registry_target(&rejected), "{rejected:?}");
        }

        for leaf in [
            r"Nested\Scope Sample.exe",
            "Scope Sample.dll",
            "Scope/Sample.exe",
            "Scope]Sample.exe",
            "Scope Sample.exe ",
            "Scope Sample .exe",
            "Common.exe",
            "powershell.exe",
            "MicrosoftEdge.exe",
            "Windows Terminal.exe",
        ] {
            let rejected = RegistryTarget {
                key: format!(r"{APP_PATHS_KEY}\{leaf}"),
                ..allowed.clone()
            };
            assert!(
                !is_current_user_app_path_default_target(&rejected),
                "{leaf}"
            );
            assert!(is_protected_registry_target(&rejected), "{leaf}");
        }
    }
}
