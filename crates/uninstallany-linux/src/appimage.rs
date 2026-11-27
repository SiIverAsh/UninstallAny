use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{self, File},
    io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use uninstallany_core::{Access, AppId, Cancellation, Error, Result};
use uninstallany_unix::UnixFiles;

use crate::{
    appimage_launcher::targets_appimage,
    desktop::{APPIMAGE_HEADER_SIZE, DESKTOP_MAX_BYTES, appimage_name, has_appimage_magic},
    inventory::Source,
    paths::LinuxPaths,
};

const MAX_LAUNCHER_WARNINGS: usize = 8;

pub(crate) fn path_for_id<'a>(app: &'a AppId, paths: &LinuxPaths) -> Result<&'a Path> {
    let Some((Source::AppImage, id)) = Source::identify(app) else {
        return Err(Error::Rejected("the application is not an AppImage".into()));
    };
    let path = Path::new(id);
    if !path.is_absolute()
        || !appimage_name(path)
        || !paths
            .appimages
            .iter()
            .any(|root| path.parent() == Some(root.as_path()))
    {
        return Err(Error::Rejected(
            "the AppImage path is outside the configured discovery directories".into(),
        ));
    }
    Ok(path)
}

/// Validates the original AppImage and returns the identity for the core move.
pub(crate) fn inspect(files: &UnixFiles, path: &Path, cancel: &Cancellation) -> Result<String> {
    cancel.check()?;
    let (inspection, header) = files.inspect_regular_with_prefix(path, APPIMAGE_HEADER_SIZE)?;
    if let Access::ReadOnly(reason) = inspection.access {
        return Err(Error::Rejected(reason));
    }
    if !has_appimage_magic(&header) {
        return Err(Error::Rejected(
            "the file no longer has an AppImage header".into(),
        ));
    }
    reject_running_image(path, cancel)?;
    Ok(inspection.fingerprint)
}

pub(crate) fn observe_launchers(
    files: &UnixFiles,
    menu: &Path,
    image: &Path,
    observed: &mut HashMap<PathBuf, String>,
    cancel: &Cancellation,
) -> Result<Vec<String>> {
    let entries = match files.list(menu) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Ok(vec![format!("{}: {error}", menu.display())]),
    };
    let mut warnings = Vec::new();
    for path in entries {
        cancel.check()?;
        match pin_launcher(files, menu, image, &path) {
            Ok(Some((fingerprint, _))) => {
                observed.insert(path, fingerprint);
            }
            Ok(None) => {}
            // A launcher rejected by the filesystem guard may still appear as
            // a read-only hint in the ordinary residual scan.
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                ) => {}
            Err(error) if warnings.len() < MAX_LAUNCHER_WARNINGS => {
                warnings.push(format!("{}: {error}", path.display()));
            }
            Err(_) => {}
        }
    }
    Ok(warnings)
}

/// Returns the file used for attribution so the caller can hold it through a move.
pub(crate) fn pin_launcher(
    files: &UnixFiles,
    menu: &Path,
    image: &Path,
    launcher: &Path,
) -> io::Result<Option<(String, File)>> {
    if launcher.parent() != Some(menu) || launcher.extension() != Some(OsStr::new("desktop")) {
        return Ok(None);
    }
    let (inspection, bytes, file) =
        files.pin_regular_with_prefix(launcher, DESKTOP_MAX_BYTES + 1)?;
    // A bounded prefix must not authorize a file with unreviewed trailing entries.
    if inspection.access != Access::Allowed
        || bytes.len() > DESKTOP_MAX_BYTES
        || !targets_appimage(&bytes, image)
    {
        return Ok(None);
    }
    Ok(Some((inspection.fingerprint, file)))
}

fn reject_running_image(path: &Path, cancel: &Cancellation) -> Result<()> {
    let image = fs::symlink_metadata(path)?;
    if !image.is_file() {
        return Err(Error::Rejected(
            "the AppImage is no longer a regular file".into(),
        ));
    }
    let uid = rustix::process::geteuid().as_raw();
    for entry in fs::read_dir("/proc")? {
        cancel.check()?;
        let Some(entry) = process_entry(entry)? else {
            continue;
        };
        if !entry
            .file_name()
            .as_encoded_bytes()
            .iter()
            .all(u8::is_ascii_digit)
        {
            continue;
        }
        let process = entry.path();
        let Some(owner) = process_entry(process.symlink_metadata())? else {
            continue;
        };
        if owner.uid() != uid {
            continue;
        }
        // The kernel's exe reference gives an inode even when its path is renamed.
        // It detects a directly running image; a separately launched payload may
        // have a different executable. This check never authorizes data cleanup.
        if let Some(executable) = process_entry(process.join("exe").metadata())?
            && executable.dev() == image.dev()
            && executable.ino() == image.ino()
        {
            return Err(Error::Rejected(
                "close the running AppImage before uninstalling".into(),
            ));
        }
    }
    Ok(())
}

fn process_entry<T>(entry: io::Result<T>) -> io::Result<Option<T>> {
    match entry {
        Ok(entry) => Ok(Some(entry)),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appimage_identity_requires_a_direct_file_in_a_discovery_root() -> Result<()> {
        let paths = LinuxPaths::from_home("/home/example".into());
        let image = AppId::Package {
            manager: "appimage".into(),
            id: "/home/example/Applications/Example.AppImage".into(),
        };
        assert_eq!(
            path_for_id(&image, &paths)?,
            Path::new("/home/example/Applications/Example.AppImage")
        );
        for id in [
            "Applications/Example.AppImage",
            "/home/example/Applications/inner/Example.AppImage",
            "/home/example/Downloads/Example.AppImage",
            "/home/example/Applications/Example.bin",
        ] {
            let candidate = AppId::Package {
                manager: "appimage".into(),
                id: id.into(),
            };
            assert!(path_for_id(&candidate, &paths).is_err(), "{id}");
        }
        Ok(())
    }
}
