use std::{collections::HashSet, path::Path};

const LAUNCH_KEYS: &[&str] = &[
    "Name",
    "Type",
    "Exec",
    "TryExec",
    "DBusActivatable",
    "Hidden",
    "Actions",
    "X-Flatpak",
    "X-SnapInstanceName",
];

/// Recognizes an unambiguous desktop entry directly launching this AppImage.
pub(crate) fn targets_appimage(contents: &[u8], image: &Path) -> bool {
    let Ok(contents) = std::str::from_utf8(contents) else {
        return false;
    };
    let Some(image) = image.to_str().filter(|_| image.is_absolute()) else {
        return false;
    };
    let mut main_group = false;
    let mut seen = HashSet::new();
    for line in contents.lines() {
        if line.trim_matches(' ').is_empty() || line.starts_with('#') {
            continue;
        }
        if line.trim_start_matches(' ').starts_with('[') {
            if main_group || line != "[Desktop Entry]" {
                return false;
            }
            main_group = true;
            continue;
        }
        if !main_group || line.chars().any(char::is_control) {
            return false;
        }
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        let key = key.trim_matches(' ');
        let base = key.split_once('[').map_or(key, |(key, _)| key);
        if base.is_empty()
            || !base
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return false;
        }
        let localized_name = base == "Name" && key != base;
        if localized_name || !LAUNCH_KEYS.contains(&base) {
            continue;
        }
        if key != base || !seen.insert(key) {
            return false;
        }
        let value = value.trim_matches(' ');
        let matches = match key {
            "Name" => !value.is_empty(),
            "Type" => value == "Application",
            "Exec" => direct_exec(value, image),
            "TryExec" => value == image,
            "DBusActivatable" | "Hidden" => value == "false",
            "Actions" => value.is_empty(),
            // A package-manager marker is independent evidence of ownership.
            _ => false,
        };
        if !matches {
            return false;
        }
    }
    seen.contains("Name") && seen.contains("Type") && seen.contains("Exec")
}

fn direct_exec(value: &str, image: &str) -> bool {
    let (executable, arguments) = if let Some(quoted) = value.strip_prefix('"') {
        let Some((literal, suffix)) = quoted.split_once('"') else {
            return false;
        };
        if !suffix.is_empty() && !suffix.starts_with(' ') {
            return false;
        }
        (literal, suffix)
    } else {
        value.split_once(' ').unwrap_or((value, ""))
    };
    // Exec is an ASCII string. Recognize the literal subset without decoding
    // string escapes, shell metacharacters or field codes in the executable.
    executable == image
        && executable.is_ascii()
        && !executable.contains([
            '"', '\'', '\\', '>', '<', '~', '|', '&', ';', '$', '*', '?', '#', '(', ')', '\x60',
            '%', '=',
        ])
        && matches!(arguments.trim_matches(' '), "" | "%f" | "%F" | "%u" | "%U")
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE: &str = "/home/example/Applications/Editor.AppImage";
    const ENTRY: &str = "[Desktop Entry]\nType=Application\nName=Editor\n";

    #[test]
    fn exact_launcher_allows_quoted_spaces_and_one_file_field() {
        let image = "/home/example/Applications/Example Editor.AppImage";
        let contents = format!(
            "{ENTRY}Name[zh]=编辑器\nExec=\"{image}\"   %U\nTryExec={image}\nDBusActivatable=false\n"
        );
        assert!(targets_appimage(contents.as_bytes(), Path::new(image)));
        assert!(targets_appimage(
            format!("{ENTRY}Exec={IMAGE}\n").as_bytes(),
            Path::new(IMAGE),
        ));
    }

    #[test]
    fn launcher_rejects_wrappers_nonliteral_paths_and_extra_arguments() {
        for command in [
            format!("/usr/bin/env {IMAGE}"),
            format!("/bin/sh -c \"{IMAGE}\""),
            format!("\"{IMAGE}\"%U"),
            format!("{IMAGE} %f %u"),
            format!("{IMAGE} --extra"),
            format!("{IMAGE}\t%f"),
            IMAGE.replace("Editor", "Edit\\sor"),
            IMAGE.replace("Applications", "Applications/."),
        ] {
            let contents = format!("{ENTRY}Exec={command}\n");
            assert!(!targets_appimage(contents.as_bytes(), Path::new(IMAGE)));
        }
    }

    #[test]
    fn launcher_rejects_other_activation_paths_and_duplicate_fields() {
        for alternative in [
            "Name=Another Editor",
            "DBusActivatable=true",
            "Hidden=true",
            "TryExec=/usr/bin/editor",
            "Actions=NewWindow;",
            "[Desktop Action NewWindow]\nExec=/usr/bin/editor",
            "[Desktop Entry]\nType=Application",
            "Exec=/usr/bin/editor",
            "Exec[en]=/usr/bin/editor",
            "X-Flatpak=org.example.Editor",
        ] {
            let contents = format!("{ENTRY}Exec={IMAGE}\n{alternative}\n");
            assert!(!targets_appimage(contents.as_bytes(), Path::new(IMAGE)));
        }
        let missing_name = format!("[Desktop Entry]\nType=Application\nExec={IMAGE}\n");
        assert!(!targets_appimage(missing_name.as_bytes(), Path::new(IMAGE)));
    }
}
