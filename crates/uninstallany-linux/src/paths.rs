use std::{
    env, io,
    path::{Component, Path, PathBuf},
};

use uninstallany_unix::UnixFiles;

const SYSTEM_ROOTS: &[&str] = &[
    "/bin",
    "/sbin",
    "/boot",
    "/dev",
    "/etc",
    "/lib",
    "/lib32",
    "/lib64",
    "/opt",
    "/proc",
    "/root",
    "/run",
    "/sys",
    "/usr",
    "/var/lib",
    "/var/cache",
    "/var/snap",
];
const USER_DOCUMENT_ROOTS: &[&str] = &["Desktop", "Documents", "Download", "Downloads"];
const PROTECTED_USER_DIR_KEYS: &[&str] =
    &["XDG_DESKTOP_DIR", "XDG_DOCUMENTS_DIR", "XDG_DOWNLOAD_DIR"];
const USER_DIRS_LIMIT: usize = 32 * 1024;

pub(crate) struct LinuxPaths {
    pub home: PathBuf,
    pub config: PathBuf,
    pub data: PathBuf,
    pub cache: PathBuf,
    pub state: PathBuf,
    pub flatpak_data: PathBuf,
    pub snap_data: PathBuf,
    pub appimages: Vec<PathBuf>,
    pub desktop_dirs: Vec<PathBuf>,
    pub autostart_dirs: Vec<PathBuf>,
    pub service_dirs: Vec<PathBuf>,
    pub system_settings_dirs: Vec<PathBuf>,
}

impl LinuxPaths {
    pub(crate) fn from_home(home: PathBuf) -> Self {
        let config = xdg_directory(&home, "XDG_CONFIG_HOME", ".config");
        let data = xdg_directory(&home, "XDG_DATA_HOME", ".local/share");
        let cache = xdg_directory(&home, "XDG_CACHE_HOME", ".cache");
        let state = xdg_directory(&home, "XDG_STATE_HOME", ".local/state").join("UninstallAny");
        let user_data_dirs = xdg_search("XDG_DATA_DIRS", "/usr/local/share:/usr/share");
        let user_config_dirs = xdg_search("XDG_CONFIG_DIRS", "/etc/xdg");
        let mut desktop_dirs = vec![data.join("applications")];
        desktop_dirs.extend(
            user_data_dirs
                .into_iter()
                .map(|root| root.join("applications")),
        );
        let mut autostart_dirs = vec![config.join("autostart")];
        autostart_dirs.extend(
            user_config_dirs
                .into_iter()
                .map(|root| root.join("autostart")),
        );
        let service_dirs = vec![
            config.join("systemd/user"),
            data.join("systemd/user"),
            "/etc/systemd/user".into(),
            "/etc/systemd/system".into(),
            "/usr/local/lib/systemd/user".into(),
            "/usr/lib/systemd/user".into(),
            "/usr/local/lib/systemd/system".into(),
            "/usr/lib/systemd/system".into(),
        ];
        Self {
            appimages: vec![
                home.join("Applications"),
                home.join("AppImages"),
                data.join("appimages"),
            ],
            flatpak_data: home.join(".var/app"),
            snap_data: home.join("snap"),
            home,
            config,
            cache,
            data,
            state,
            desktop_dirs,
            autostart_dirs,
            service_dirs,
            system_settings_dirs: vec!["/etc".into(), "/opt".into()],
        }
    }

    pub(crate) fn files(&self) -> io::Result<UnixFiles> {
        if !self.state.starts_with(&self.home) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "use a private XDG_STATE_HOME within your home directory",
            ));
        }
        let mut roots = vec![
            self.home.clone(),
            self.config.clone(),
            self.data.clone(),
            self.cache.clone(),
            self.flatpak_data.clone(),
            self.snap_data.clone(),
        ];
        roots.extend(
            self.appimages
                .iter()
                .chain(&self.desktop_dirs)
                .chain(&self.autostart_dirs)
                .chain(&self.service_dirs)
                .chain(&self.system_settings_dirs)
                .cloned(),
        );
        let mut protected: Vec<_> = SYSTEM_ROOTS.iter().map(PathBuf::from).collect();
        protected.extend(USER_DOCUMENT_ROOTS.iter().map(|name| self.home.join(name)));
        protected.extend(
            roots
                .iter()
                .filter(|path| !path.starts_with(&self.home))
                .cloned(),
        );
        protected.push(self.snap_data.clone());
        protected.push(self.data.join("flatpak"));
        roots.sort_unstable();
        roots.dedup();
        let discovery = UnixFiles::new(roots.clone(), protected.clone(), self.state.clone())?;
        let settings = self.config.join("user-dirs.dirs");
        match discovery.read_regular(&settings, USER_DIRS_LIMIT) {
            Ok(bytes) => match std::str::from_utf8(&bytes)
                .ok()
                .and_then(|text| protected_user_dirs(&self.home, text))
            {
                Some(directories) => protected.extend(directories),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "could not safely read redirected user directories",
                    ));
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("could not safely open {}: {error}", settings.display()),
                ));
            }
        }
        UnixFiles::new(roots, protected, self.state.clone())
    }
}

fn xdg_directory(home: &Path, key: &str, fallback: &str) -> PathBuf {
    env::var_os(key)
        .map(PathBuf::from)
        .filter(|path| usable_absolute(path) && path != home)
        .unwrap_or_else(|| home.join(fallback))
}

fn xdg_search(key: &str, fallback: &str) -> Vec<PathBuf> {
    env::split_paths(
        &env::var_os(key)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| fallback.into()),
    )
    .filter(|path| usable_absolute(path))
    .take(20)
    .collect()
}

fn usable_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path.parent().is_some()
        && !path
            .components()
            .any(|item| matches!(item, Component::ParentDir | Component::CurDir))
}

fn protected_user_dirs(home: &Path, contents: &str) -> Option<Vec<PathBuf>> {
    let mut output = Vec::new();
    for line in contents.lines() {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        if !PROTECTED_USER_DIR_KEYS.contains(&key.trim()) {
            continue;
        }
        let value = value.trim().strip_prefix('"')?.strip_suffix('"')?;
        // user-dirs.dirs is executable shell syntax in some desktops. Parse a
        // narrow data subset and refuse unresolved expansions or escapes.
        if value.contains(['"', '\\', '`', '\n', '\r', '\0']) {
            return None;
        }
        let path = match value {
            "$HOME" | "$HOME/" => continue,
            _ if value.starts_with("$HOME/") && !value[6..].contains('$') => home.join(&value[6..]),
            _ if value.starts_with('/') && !value.contains('$') => PathBuf::from(value),
            _ => return None,
        };
        if !usable_absolute(&path) {
            return None;
        }
        if path != home {
            output.push(path);
        }
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirected_user_directories_are_protected_without_evaluation() -> io::Result<()> {
        let home = Path::new("/home/test");
        let input = "# generated\nXDG_DESKTOP_DIR=\"$HOME/Desktop files\"\nXDG_DOCUMENTS_DIR=\"/data/work\"\nXDG_DOWNLOAD_DIR=\"$HOME/\"\n";
        let directories = protected_user_dirs(home, input)
            .ok_or_else(|| io::Error::other("fixture had invalid user directories"))?;
        assert_eq!(
            directories,
            [
                PathBuf::from("/home/test/Desktop files"),
                PathBuf::from("/data/work")
            ]
        );
        assert!(protected_user_dirs(home, "XDG_DESKTOP_DIR=\"$(echo here)\"").is_none());
        assert!(protected_user_dirs(home, "XDG_DESKTOP_DIR=\"$HOME/../other\"").is_none());
        Ok(())
    }
}
