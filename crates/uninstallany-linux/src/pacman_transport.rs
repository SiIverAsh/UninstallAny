use std::{
    ffi::OsString,
    fs::{File, Metadata},
    io::{self, Read},
    num::NonZeroU64,
    os::unix::fs::MetadataExt,
    path::Path,
};

use rustix::fs::{self, Mode, OFlags};
use uninstallany_core::{Cancellation, Result};

use crate::{
    command::{Program, query_strict, trusted_regular_file},
    inventory::{pacman_name, pacman_version},
    system_helper::SystemHelper,
};

const PACMAN: &str = "/usr/bin/pacman";
const DATABASE: &str = "/var/lib/pacman";
const DATABASE_VERSION: &str = "/var/lib/pacman/local/ALPM_DB_VERSION";
const MAX_DESC_BYTES: u64 = 1024 * 1024;
const QUERY: &[&str] = &["--dbpath", DATABASE, "--query", "--color", "never"];

pub(crate) const HELPER: SystemHelper = SystemHelper {
    executable: "/usr/libexec/uninstallany-pacman-helper",
    policy_path: "/usr/share/polkit-1/actions/io.github.siiverash.uninstallany.pacman.policy",
    policy: include_bytes!(
        "../../../packaging/arch-pacman-helper/io.github.siiverash.uninstallany.pacman.policy"
    ),
};

pub(crate) fn launcher() -> io::Result<(Program, Program)> {
    trusted_regular_file(Path::new(DATABASE_VERSION))?;
    Program::fixed(Path::new(PACMAN))?;
    HELPER.launcher()
}

pub(crate) fn removal_arguments(name: &str, version: &str) -> io::Result<Vec<OsString>> {
    if !pacman_name(name) || !pacman_version(version) {
        return Err(invalid("the reviewed pacman package identity is invalid"));
    }
    let path = Path::new(DATABASE)
        .join("local")
        .join(format!("{name}-{version}"))
        .join("desc");
    let named = trusted_regular_file(&path)?;
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = fs::open(&path, flags, Mode::empty()).map_err(io::Error::from)?;
    let mut file = File::from(fd);
    let held = file.metadata()?;
    let stamp = RecordStamp::from(&held);
    if !held.is_file()
        || held.uid() != 0
        || held.mode() & 0o022 != 0
        || stamp != RecordStamp::from(&named)
        || stamp.changed_seconds <= 0
        || !(0..1_000_000_000).contains(&stamp.changed_nanoseconds)
    {
        return Err(invalid(
            "the pacman installation record changed or is unsafe",
        ));
    }
    let mut contents = String::new();
    (&mut file)
        .take(MAX_DESC_BYTES + 1)
        .read_to_string(&mut contents)?;
    if contents.len() as u64 > MAX_DESC_BYTES {
        return Err(invalid(
            "the pacman installation record exceeds the read limit",
        ));
    }
    if stamp != RecordStamp::from(&file.metadata()?) {
        return Err(invalid(
            "the pacman installation record changed during review",
        ));
    }
    let installed = parse_installation(&contents, name, version)?;
    Ok(vec![
        name.into(),
        version.into(),
        installed.to_string().into(),
        stamp.device.to_string().into(),
        stamp.inode.to_string().into(),
        stamp.changed_seconds.to_string().into(),
        stamp.changed_nanoseconds.to_string().into(),
    ])
}

#[derive(Eq, PartialEq)]
struct RecordStamp {
    device: u64,
    inode: u64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl From<&Metadata> for RecordStamp {
    fn from(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

/// Rechecks the system package database independently of the privileged process.
pub(crate) fn verify_removed(name: &str, cancel: &Cancellation) -> Result<bool> {
    trusted_regular_file(Path::new(DATABASE_VERSION))?;
    let program = Program::fixed(Path::new(PACMAN))?;
    let root = Path::new("/");
    let output = query_strict(&program, root, root, QUERY, cancel)?;
    Ok(!contains_package(&output, name)?)
}

fn parse_installation(contents: &str, name: &str, version: &str) -> io::Result<NonZeroU64> {
    let mut package = None;
    let mut package_version = None;
    let mut install_date = None;
    let mut reason = None;
    for section in contents.split("\n\n") {
        let Some((field, value)) = section.trim_end_matches('\n').split_once('\n') else {
            continue;
        };
        let entry = match field {
            "%NAME%" => &mut package,
            "%VERSION%" => &mut package_version,
            "%INSTALLDATE%" => &mut install_date,
            "%REASON%" => &mut reason,
            _ => continue,
        };
        if entry.replace(value).is_some() {
            return Err(invalid(
                "the pacman installation record contains duplicate fields",
            ));
        }
    }
    if !contents.ends_with('\n')
        || contents.contains('\0')
        || package != Some(name)
        || package_version != Some(version)
        || !matches!(reason, None | Some("0"))
    {
        return Err(invalid(
            "the selected pacman package changed or is a dependency",
        ));
    }
    install_date
        .and_then(|text| {
            text.parse::<NonZeroU64>()
                .ok()
                .filter(|number| number.to_string() == text && i64::try_from(number.get()).is_ok())
        })
        .ok_or_else(|| invalid("the pacman installation time could not be verified"))
}

fn contains_package(output: &str, name: &str) -> io::Result<bool> {
    let malformed = || invalid("malformed pacman package listing");
    if !output.is_empty() && !output.ends_with('\n') {
        return Err(malformed());
    }
    let mut present = false;
    for line in output.split_terminator('\n') {
        let (package, version) = line.split_once(' ').ok_or_else(malformed)?;
        if !pacman_name(package) || !pacman_version(version) {
            return Err(malformed());
        }
        present |= package == name;
    }
    Ok(present)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_dependency_duplicate_identity_and_stale_version() -> io::Result<()> {
        let entry = "%NAME%\neditor\n\n%VERSION%\n2:1.2-1\n\n%INSTALLDATE%\n1700000000\n\n";
        assert_eq!(
            parse_installation(entry, "editor", "2:1.2-1")?.get(),
            1700000000
        );
        assert!(parse_installation(entry, "editor", "2:1.2-2").is_err());
        assert!(
            parse_installation(&format!("{entry}%REASON%\n1\n\n"), "editor", "2:1.2-1").is_err()
        );
        assert!(
            parse_installation(&format!("{entry}%NAME%\neditor\n\n"), "editor", "2:1.2-1").is_err()
        );
        assert!(contains_package("editor 2:1.2-2\n", "editor")?);
        assert!(!contains_package("editor-sibling 1.2-1\n", "editor")?);
        Ok(())
    }
}
