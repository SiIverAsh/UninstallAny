use std::{
    collections::HashSet,
    ffi::OsStr,
    io,
    path::{Path, PathBuf},
};

use uninstallany_core::{AppRecord, Cancellation, Inventory, Result};
use uninstallany_unix::UnixFiles;

use crate::{
    inventory::{Source, app_id_from_ref, record, valid_snap_instance},
    paths::LinuxPaths,
};

const DESKTOP_MAX_BYTES: usize = 128 * 1024;
const MAX_ENTRIES_PER_SOURCE: usize = 5_000;
const ELF_HEADER: &[u8] = b"\x7fELF";
const APPIMAGE_HEADER_SIZE: usize = 11;

#[derive(Debug)]
pub(crate) struct Launcher {
    pub name: String,
    pub flatpak_id: Option<String>,
    pub snap_id: Option<String>,
    pub no_display: bool,
}

pub(crate) fn augment(
    inventory: &mut Inventory,
    files: &UnixFiles,
    paths: &LinuxPaths,
    cancel: &Cancellation,
) -> Result<()> {
    let appimages = read_appimages(files, paths, cancel)?;
    inventory.applications.extend(appimages.applications);
    inventory.warnings.extend(appimages.warnings);
    let managed = known_exports(&inventory.applications);
    let desktops = read_desktops(files, paths, managed, cancel)?;
    inventory.applications.extend(desktops.applications);
    inventory.warnings.extend(desktops.warnings);
    Ok(())
}

fn read_appimages(
    files: &UnixFiles,
    paths: &LinuxPaths,
    cancel: &Cancellation,
) -> Result<Inventory> {
    let mut inventory = Inventory::default();
    let mut seen = HashSet::new();
    for directory in &paths.appimages {
        let children = children(files, directory, &mut inventory);
        for path in children.into_iter().take(MAX_ENTRIES_PER_SOURCE) {
            cancel.check()?;
            if !appimage_name(&path) || !seen.insert(path.clone()) {
                continue;
            }
            let header = match files.read_prefix(&path, APPIMAGE_HEADER_SIZE) {
                Ok(header) => header,
                Err(error) => {
                    inventory
                        .warnings
                        .push(format!("could not inspect {}: {error}", path.display()));
                    continue;
                }
            };
            if !has_appimage_magic(&header) {
                inventory.warnings.push(format!(
                    "{} does not contain an AppImage header",
                    path.display()
                ));
                continue;
            }
            let Some((identity, name)) =
                path.to_str().zip(path.file_stem().and_then(OsStr::to_str))
            else {
                inventory.warnings.push(format!(
                    "AppImage identity is not valid Unicode: {}",
                    path.display()
                ));
                continue;
            };
            inventory.applications.push(AppRecord {
                install_location: Some(path.clone()),
                ..record(Source::AppImage, identity, name)
            });
        }
    }
    Ok(inventory)
}

pub(crate) fn appimage_name(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|extension| extension.eq_ignore_ascii_case("AppImage"))
}

pub(crate) fn has_appimage_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(ELF_HEADER) && matches!(bytes.get(8..11), Some(b"AI\x01" | b"AI\x02"))
}

fn read_desktops(
    files: &UnixFiles,
    paths: &LinuxPaths,
    exports: (HashSet<String>, HashSet<String>),
    cancel: &Cancellation,
) -> Result<Inventory> {
    let mut inventory = Inventory::default();
    let mut seen = HashSet::new();
    for directory in &paths.desktop_dirs {
        let children = children(files, directory, &mut inventory);
        for path in children.into_iter().take(MAX_ENTRIES_PER_SOURCE) {
            cancel.check()?;
            let Some(filename) = path
                .file_name()
                .filter(|_| path.extension() == Some(OsStr::new("desktop")))
            else {
                continue;
            };
            if !seen.insert(filename.to_os_string()) {
                continue;
            }
            let launcher = match read_launcher(files, &path) {
                Ok(Some(launcher)) => launcher,
                Ok(None) => continue,
                Err(error) => {
                    inventory
                        .warnings
                        .push(format!("could not read {}: {error}", path.display()));
                    continue;
                }
            };
            if launcher
                .flatpak_id
                .as_ref()
                .is_some_and(|id| exports.0.contains(id))
                || launcher
                    .snap_id
                    .as_ref()
                    .is_some_and(|id| exports.1.contains(id))
            {
                continue;
            }
            let Some(identity) = path.to_str() else {
                inventory.warnings.push(format!(
                    "launcher identity is not valid Unicode: {}",
                    path.display()
                ));
                continue;
            };
            inventory.applications.push(AppRecord {
                install_location: Some(path.clone()),
                system_component: launcher.no_display,
                ..record(Source::Desktop, identity, &launcher.name)
            });
        }
    }
    Ok(inventory)
}

fn known_exports(applications: &[AppRecord]) -> (HashSet<String>, HashSet<String>) {
    let mut known = (HashSet::new(), HashSet::new());
    for app in applications {
        match Source::identify(&app.id) {
            Some((Source::FlatpakUser | Source::FlatpakSystem, reference)) => {
                if let Some(id) = app_id_from_ref(reference) {
                    known.0.insert(id.into());
                }
            }
            Some((Source::Snap, name)) => {
                known.1.insert(name.into());
            }
            _ => {}
        }
    }
    known
}

fn children(files: &UnixFiles, path: &Path, inventory: &mut Inventory) -> Vec<PathBuf> {
    match files.list(path) {
        Ok(children) => children,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => {
            inventory
                .warnings
                .push(format!("could not list {}: {error}", path.display()));
            Vec::new()
        }
    }
}

pub(crate) fn read_launcher(files: &UnixFiles, path: &Path) -> io::Result<Option<Launcher>> {
    let bytes = files.read_regular(path, DESKTOP_MAX_BYTES)?;
    let content = std::str::from_utf8(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "desktop entry is not UTF-8"))?;
    Ok(parse_desktop(content))
}

fn parse_desktop(content: &str) -> Option<Launcher> {
    let mut active = false;
    let mut name = None;
    let mut application = false;
    let mut hidden = false;
    let mut no_display = false;
    let mut flatpak_id = None;
    let mut snap_id = None;
    for line in content.lines().map(str::trim) {
        if line.starts_with('[') {
            if active {
                break;
            }
            active = line == "[Desktop Entry]";
        }
        if !active || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "Type" => application = value == "Application",
            "Hidden" => hidden = value == "true",
            "NoDisplay" => no_display = value == "true",
            "Name" if !value.is_empty() => name = decode_label(value),
            "X-Flatpak" if app_id_from_ref(&format!("app/{value}/unknown/stable")).is_some() => {
                flatpak_id = Some(value.into());
            }
            "X-SnapInstanceName" if valid_snap_instance(value) => snap_id = Some(value.into()),
            // Exec and TryExec can contain executable paths and field codes.
            // They are neither evaluated nor used to authorize file cleanup.
            _ => {}
        }
    }
    if !application || hidden {
        return None;
    }
    Some(Launcher {
        name: name?,
        flatpak_id,
        snap_id,
        no_display,
    })
}

fn decode_label(value: &str) -> Option<String> {
    let mut characters = value.chars();
    let mut label = String::with_capacity(value.len());
    while let Some(character) = characters.next() {
        let decoded = if character == '\\' {
            match characters.next()? {
                's' => ' ',
                'n' | 'r' | 't' => ' ',
                '\\' => '\\',
                _ => return None,
            }
        } else if character.is_control() {
            return None;
        } else {
            character
        };
        label.push(decoded);
    }
    (!label.trim().is_empty()).then_some(label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_parser_does_not_use_exec_or_other_sections() -> io::Result<()> {
        let entry = parse_desktop("[Desktop Entry]\nType=Application\nName=Example\\sEditor\nExec=sh -c 'ignored'\nX-Flatpak=org.example.Editor\n[Desktop Action Thing]\nName=Wrong\n")
            .ok_or_else(|| io::Error::other("test launcher did not parse"))?;
        assert_eq!(entry.name, "Example Editor");
        assert_eq!(entry.flatpak_id.as_deref(), Some("org.example.Editor"));
        assert!(
            parse_desktop("[Desktop Entry]\nType=Application\nName=Hidden\nHidden=true").is_none()
        );
        assert!(parse_desktop("[Desktop Entry]\nType=Link\nName=Link").is_none());
        Ok(())
    }

    #[test]
    fn appimage_requires_the_elf_and_appimage_markers() {
        assert!(has_appimage_magic(b"\x7fELF\x02\x01\x01\0AI\x02"));
        assert!(!has_appimage_magic(b"\x7fELF\x02\x01\x01\0AI\x03"));
        assert!(!has_appimage_magic(b"not an image"));
    }
}
