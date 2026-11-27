use std::{
    env, io,
    path::{Component, Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use nix::{
    fcntl::{FcntlArg, fcntl},
    libc,
};
use rustix::{
    fd::OwnedFd,
    fs::{self, AtFlags, FileType, Mode, OFlags, Stat},
};
use uninstallany_core::{Cancellation, Error, Result};

use crate::command::{Program, query_strict};

const ALTERNATE_DIRECTORIES: &[&str] = &[
    "FLATPAK_USER_DIR",
    "FLATPAK_SYSTEM_DIR",
    "FLATPAK_CONFIG_DIR",
    "FLATPAK_DATA_DIR",
    "FLATPAK_RUN_DIR",
];
const OPEN_DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::DIRECTORY);
const INSTANCE_START_GRACE: Duration = Duration::from_secs(3);

/// Checks whether the Flatpak data can be observed while its app is inactive.
pub(crate) fn require_inactive(app_id: &str, cancel: &Cancellation) -> Result<()> {
    cancel.check()?;
    check_context(app_id)?;
    check_runtime(cancel)
}

/// Checks all configured installations and the current Flatpak runtime session.
pub(crate) fn require_absent_and_inactive(
    program: &Program,
    home: &Path,
    data: &Path,
    app_id: &str,
    cancel: &Cancellation,
) -> Result<()> {
    cancel.check()?;
    check_context(app_id)?;
    // With no scope options, Flatpak includes the user, default system, and
    // named system installations, regardless of the original ref's scope.
    let output = query_strict(
        program,
        home,
        data,
        &["list", "--app", "--columns=application:full"],
        cancel,
    )?;
    require_empty_installations(&output, app_id)?;
    check_runtime(cancel)
}

fn require_empty_installations(output: &str, app_id: &str) -> Result<()> {
    let Some(listed_id) = rows(output, "Flatpak installation list")?.next() else {
        return Ok(());
    };
    if !valid_application_id(listed_id) {
        return Err(incomplete("Flatpak installation list"));
    }
    if listed_id == app_id {
        return Err(Error::Rejected(format!(
            "Flatpak application {app_id} is still installed."
        )));
    }
    // Flatpak can give a renamed app access to directories of older IDs.
    // The installation list does not report those historical IDs.
    Err(Error::Rejected(
        "Other Flatpak apps are installed and may still use this data directory.".into(),
    ))
}

/// Requires an exact app ID and the same environment as the native command.
pub(crate) fn check_context(app_id: &str) -> Result<()> {
    if !valid_application_id(app_id) {
        return Err(Error::Rejected("Invalid Flatpak application ID.".into()));
    }
    // The sanitized subprocess would use a different set of installations.
    if let Some(variable) = ALTERNATE_DIRECTORIES
        .iter()
        .find(|variable| env::var_os(variable).is_some())
    {
        return Err(Error::Rejected(format!(
            "Flatpak cannot be checked while {variable} selects alternate directories."
        )));
    }
    Ok(())
}

fn check_runtime(cancel: &Cancellation) -> Result<()> {
    cancel.check()?;
    let uid = rustix::process::getuid().as_raw();
    let runtime = runtime_directory(uid)?;
    let base = match fs::openat(&runtime, ".flatpak", OPEN_DIRECTORY, Mode::empty()) {
        Ok(directory) => directory,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(error) => return Err(io::Error::from(error).into()),
    };
    let original = fs::fstat(&base).map_err(io::Error::from)?;
    if original.st_uid != uid || original.st_mode & 0o022 != 0 {
        return Err(incomplete("Flatpak instance directory"));
    }
    // `flatpak ps` garbage collects stale runtime trees. Only query the
    // native instance lock here so reviewing an uninstall cannot do that.
    for entry in fs::Dir::read_from(&base).map_err(io::Error::from)? {
        cancel.check()?;
        let entry = entry.map_err(io::Error::from)?;
        let name = entry.file_name();
        let bytes = name.to_bytes();
        if !bytes.is_empty() && bytes.iter().all(u8::is_ascii_digit) {
            let instance =
                fs::openat(&base, name, OPEN_DIRECTORY, Mode::empty()).map_err(io::Error::from)?;
            check_instance(&instance, uid)?;
        }
    }
    let current =
        fs::statat(&runtime, ".flatpak", AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
    if !same_entry(&original, &current) {
        return Err(incomplete("Flatpak instance directory"));
    }
    Ok(())
}

fn runtime_directory(uid: u32) -> Result<OwnedFd> {
    let path = env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .filter(|path| !path.components().any(|part| part == Component::ParentDir))
        .ok_or_else(|| incomplete("Flatpak runtime directory"))?;
    let mut directory = fs::open("/", OPEN_DIRECTORY, Mode::empty()).map_err(io::Error::from)?;
    for part in path.components().skip(1) {
        directory = fs::openat(&directory, part.as_os_str(), OPEN_DIRECTORY, Mode::empty())
            .map_err(io::Error::from)?;
        let metadata = fs::fstat(&directory).map_err(io::Error::from)?;
        let trusted_owner = metadata.st_uid == 0 || metadata.st_uid == uid;
        let system_sticky = metadata.st_uid == 0 && metadata.st_mode & 0o1000 != 0;
        if !trusted_owner || (metadata.st_mode & 0o022 != 0 && !system_sticky) {
            return Err(incomplete("Flatpak runtime directory"));
        }
    }
    let metadata = fs::fstat(&directory).map_err(io::Error::from)?;
    if metadata.st_uid != uid || metadata.st_mode & 0o077 != 0 {
        return Err(incomplete("Flatpak runtime directory"));
    }
    Ok(directory)
}

fn check_instance(instance: &OwnedFd, uid: u32) -> Result<()> {
    const SUBJECT: &str = "Flatpak instance lock";
    let directory = fs::fstat(instance).map_err(io::Error::from)?;
    let observed =
        fs::statat(instance, ".ref", AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
    if directory.st_uid != uid
        || directory.st_mode & 0o022 != 0
        || FileType::from_raw_mode(observed.st_mode) != FileType::RegularFile
        || observed.st_uid != uid
        || observed.st_nlink != 1
        || observed.st_mode & 0o022 != 0
    {
        return Err(incomplete(SUBJECT));
    }
    let flags =
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOCTTY;
    let file = fs::openat(instance, ".ref", flags, Mode::empty()).map_err(io::Error::from)?;
    let held = fs::fstat(&file).map_err(io::Error::from)?;
    if !same_entry(&observed, &held) {
        return Err(incomplete(SUBJECT));
    }
    let cutoff = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|now| now.checked_sub(INSTANCE_START_GRACE))
        .ok_or_else(|| incomplete(SUBJECT))?;
    let seconds = u64::try_from(held.st_ctime).map_err(|_| incomplete(SUBJECT))?;
    let nanos = u32::try_from(held.st_ctime_nsec).map_err(|_| incomplete(SUBJECT))?;
    let mut lock = libc::flock {
        l_type: i16::try_from(libc::F_WRLCK).map_err(|_| incomplete(SUBJECT))?,
        l_whence: i16::try_from(libc::SEEK_SET).map_err(|_| incomplete(SUBJECT))?,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    };
    fcntl(&file, FcntlArg::F_GETLK(&mut lock)).map_err(io::Error::from)?;
    if Duration::new(seconds, nanos) > cutoff || i32::from(lock.l_type) != libc::F_UNLCK {
        return Err(Error::Rejected(
            "Close all Flatpak instances and wait for them to exit before continuing.".into(),
        ));
    }
    let current =
        fs::statat(instance, ".ref", AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
    if !same_entry(&held, &current) {
        return Err(incomplete(SUBJECT));
    }
    Ok(())
}

fn same_entry(before: &Stat, after: &Stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode
        && before.st_uid == after.st_uid
        && before.st_nlink == after.st_nlink
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
}

fn rows<'a>(output: &'a str, subject: &str) -> Result<impl Iterator<Item = &'a str>> {
    if !output.is_empty() && !output.ends_with('\n') {
        return Err(incomplete(subject));
    }
    Ok(output.lines())
}

fn valid_application_id(value: &str) -> bool {
    const MAX_APP_ID_LENGTH: usize = 255;

    let segments = value.split('.');
    let count = segments.clone().count();
    value.len() <= MAX_APP_ID_LENGTH
        && count >= 3
        && segments.enumerate().all(|(index, segment)| {
            let last = index + 1 == count;
            let initial =
                |byte: u8| byte.is_ascii_alphabetic() || byte == b'_' || (last && byte == b'-');
            let mut bytes = segment.bytes();
            bytes.next().is_some_and(initial)
                && bytes.all(|byte| initial(byte) || byte.is_ascii_digit())
        })
}

fn incomplete(subject: &str) -> Error {
    Error::Rejected(format!("Could not verify the complete {subject}."))
}

#[cfg(test)]
mod tests {
    use super::{require_empty_installations, valid_application_id};

    #[test]
    fn a_remaining_flatpak_app_blocks_cleanup_of_an_old_id() {
        let old = "org.example.Editor";
        assert!(require_empty_installations("", old).is_ok());
        assert!(require_empty_installations("org.example.Editor\n", old).is_err());
        assert!(require_empty_installations("org.example.NewEditor\n", old).is_err());
    }

    #[test]
    fn application_id_rejects_non_native_segments() {
        assert!(valid_application_id("org.Example.Foo-bar2"));
        assert!(!valid_application_id("org.Ex-ample.Foo"));
        assert!(!valid_application_id("org..Foo"));
        assert!(!valid_application_id("org.example.2Foo"));
        assert!(!valid_application_id("org.example.Fóo"));
    }
}
