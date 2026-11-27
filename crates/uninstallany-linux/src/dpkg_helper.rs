use std::{
    env,
    ffi::CStr,
    fs::File,
    io::{self, Read},
    process::{Command, Stdio},
    thread,
};

use rustix::{
    fd::OwnedFd,
    fs::{self, AtFlags, Dir, FileType, FlockOperation, Mode, OFlags, Stat},
    io::Errno,
    process::{geteuid, getuid},
};

use crate::dpkg::{DPKG_ADMIN_DIR, DPKG_QUERY_BIN, DPKG_VERIFICATION_ARGUMENTS, DpkgRequest};

const DPKG: &str = "/usr/bin/dpkg";
const FRONTEND_LOCK: &str = "lock-frontend";
const SYSTEM_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_CONFIG_FILES: usize = 128;
const MAX_CONFIG_LINE_BYTES: usize = 1022;
const MAX_QUERY_BYTES: u64 = 8 * 1024 * 1024;
const MAX_DIAGNOSTIC_BYTES: u64 = 8 * 1024;
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const READ_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);

/// Executes one authorized dpkg removal and verifies its final status.
/// Returns an error if identity, configuration, locking, or completion
/// cannot be verified.
pub fn run(arguments: &[String]) -> io::Result<()> {
    require_pkexec_root()?;
    let [action, id, version] = arguments else {
        return Err(invalid(
            "expected remove, a package name:architecture, and a version",
        ));
    };
    if action != "remove" {
        return Err(invalid("unsupported dpkg helper action"));
    }
    let request = DpkgRequest::parse(id, version)?;
    let database = open_trusted_directory(&["var", "lib", "dpkg"])?;
    let _frontend_lock = lock_frontend(&database)?;
    require_native_tools()?;
    require_safe_config()?;
    request.require_installed(&query_packages()?)?;
    remove(id, true)?;
    remove(id, false)?;
    request.require_removed(&query_packages()?)
}

fn require_pkexec_root() -> io::Result<()> {
    // pkexec sets this identity for its root child. The executable itself
    // must be installed by the system and must not grant privileges.
    let invoking_uid = env::var("PKEXEC_UID").ok().and_then(|value| {
        value
            .parse::<u32>()
            .ok()
            .filter(|uid| uid.to_string() == value)
    });
    if !getuid().is_root() || !geteuid().is_root() || !invoking_uid.is_some_and(|uid| uid != 0) {
        return Err(deny(
            "invoke the dpkg helper through administrator authorization",
        ));
    }
    Ok(())
}

fn open_trusted_directory(components: &[&str]) -> io::Result<OwnedFd> {
    let mut directory = fs::open("/", DIRECTORY_FLAGS, Mode::empty())?;
    require_root_entry(&fs::fstat(&directory)?, FileType::Directory)?;
    for component in components {
        directory = fs::openat(&directory, *component, DIRECTORY_FLAGS, Mode::empty())?;
        require_root_entry(&fs::fstat(&directory)?, FileType::Directory)?;
    }
    Ok(directory)
}

fn require_root_entry(stat: &Stat, file_type: FileType) -> io::Result<()> {
    if stat.st_uid != 0
        || stat.st_mode & 0o022 != 0
        || FileType::from_raw_mode(stat.st_mode) != file_type
    {
        return Err(deny("a dpkg path is not a trusted root-owned entry"));
    }
    Ok(())
}

fn require_native_tools() -> io::Result<()> {
    let bin = open_trusted_directory(&["usr", "bin"])?;
    for name in ["dpkg", "dpkg-query"] {
        let stat = fs::statat(&bin, name, AtFlags::SYMLINK_NOFOLLOW)?;
        require_root_entry(&stat, FileType::RegularFile)?;
        if stat.st_mode & 0o100 == 0 {
            return Err(deny("a trusted dpkg command is not executable"));
        }
    }
    Ok(())
}

fn lock_frontend(database: &OwnedFd) -> io::Result<OwnedFd> {
    let named = fs::statat(database, FRONTEND_LOCK, AtFlags::SYMLINK_NOFOLLOW)?;
    require_root_entry(&named, FileType::RegularFile)?;
    let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let lock = fs::openat(database, FRONTEND_LOCK, flags, Mode::empty())?;
    let held = fs::fstat(&lock)?;
    require_root_entry(&held, FileType::RegularFile)?;
    if held.st_dev != named.st_dev || held.st_ino != named.st_ino || held.st_nlink != 1 {
        return Err(deny("the dpkg frontend lock changed while opening it"));
    }
    // dpkg and APT use POSIX record locks. Keep this descriptor in the
    // helper process until the dpkg child exits and its status is checked.
    match fs::fcntl_lock(&lock, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {}
        Err(Errno::ACCESS | Errno::AGAIN) => {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "another package manager holds the dpkg frontend lock",
            ));
        }
        Err(error) => return Err(error.into()),
    }
    let named = fs::statat(database, FRONTEND_LOCK, AtFlags::SYMLINK_NOFOLLOW)?;
    require_root_entry(&named, FileType::RegularFile)?;
    if named.st_dev != held.st_dev || named.st_ino != held.st_ino || named.st_nlink != 1 {
        return Err(deny("the dpkg frontend lock changed while opening it"));
    }
    Ok(lock)
}

fn require_safe_config() -> io::Result<()> {
    let config = open_trusted_directory(&["etc", "dpkg"])?;
    let directory = match fs::openat(&config, "dpkg.cfg.d", DIRECTORY_FLAGS, Mode::empty()) {
        Ok(directory) => Some(directory),
        Err(Errno::NOENT) => None,
        Err(error) => return Err(error.into()),
    };
    if let Some(directory) = directory {
        require_root_entry(&fs::fstat(&directory)?, FileType::Directory)?;
        for (index, entry) in Dir::read_from(&directory)?
            .filter_map(|entry| match entry {
                Ok(entry) if !config_file_name(entry.file_name()) => None,
                entry => Some(entry),
            })
            .enumerate()
        {
            if index >= MAX_CONFIG_FILES {
                return Err(invalid("too many dpkg configuration files to verify"));
            }
            require_safe_config_file(&directory, entry?.file_name())?;
        }
    }
    match require_safe_config_file(&config, c"dpkg.cfg") {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

fn config_file_name(name: &CStr) -> bool {
    let bytes = name.to_bytes();
    // dpkg ignores dotfiles and names outside this exact ASCII set.
    !bytes.is_empty()
        && bytes
            .iter()
            .all(|&byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn require_safe_config_file(directory: &OwnedFd, name: &CStr) -> io::Result<()> {
    let entry = fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)?;
    require_root_entry(&entry, FileType::RegularFile)?;
    let file = fs::openat(directory, name, READ_FLAGS, Mode::empty())?;
    let held = fs::fstat(&file)?;
    require_root_entry(&held, FileType::RegularFile)?;
    if held.st_dev != entry.st_dev || held.st_ino != entry.st_ino {
        return Err(deny("dpkg configuration changed while opening it"));
    }
    let bytes = read_bounded(File::from(file), MAX_CONFIG_BYTES)?;
    let text = std::str::from_utf8(&bytes).map_err(io::Error::other)?;
    for (index, line) in text.lines().enumerate() {
        if !is_safe_config_line(line) {
            return Err(deny(format!(
                "cannot safely use dpkg configuration {} at line {}",
                name.to_string_lossy(),
                index + 1
            )));
        }
    }
    Ok(())
}

fn is_safe_config_line(line: &str) -> bool {
    // dpkg parses configuration with a fixed-size fgets buffer. A long
    // comment could otherwise make it see a directive we never checked.
    if line.len() > MAX_CONFIG_LINE_BYTES || line.contains('\0') {
        return false;
    }
    let line = line.trim_ascii_end();
    if line.is_empty()
        || line.starts_with('#')
        || matches!(line, "no-debsig" | "force-unsafe-io" | "no-force-unsafe-io")
    {
        return true;
    }
    line.split_once(|character: char| character == '=' || character.is_ascii_whitespace())
        .is_some_and(|(option, argument)| {
            option == "log" && argument.trim_ascii() == "/var/log/dpkg.log"
        })
}

fn trusted_command(program: &str) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("PATH", SYSTEM_PATH)
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(Stdio::null());
    command
}

fn query_packages() -> io::Result<String> {
    let mut child = trusted_command(DPKG_QUERY_BIN)
        .args(DPKG_VERIFICATION_ARGUMENTS)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("dpkg-query stdout is unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("dpkg-query stderr is unavailable"))?;
    let (status, output, diagnostics) = thread::scope(|scope| {
        let stdout = scope.spawn(move || read_bounded(stdout, MAX_QUERY_BYTES));
        let stderr = scope.spawn(move || read_bounded(stderr, MAX_DIAGNOSTIC_BYTES));
        let status = child.wait();
        Ok::<_, io::Error>((status?, join_reader(stdout)?, join_reader(stderr)?))
    })?;
    if !status.success() || !diagnostics.is_empty() {
        return Err(io::Error::other(format!(
            "could not verify the dpkg database ({status}): {}",
            String::from_utf8_lossy(&diagnostics).trim()
        )));
    }
    String::from_utf8(output).map_err(io::Error::other)
}

fn read_bounded(reader: impl Read, limit: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid("dpkg input exceeds the verification size limit"));
    }
    Ok(bytes)
}

fn join_reader(reader: thread::ScopedJoinHandle<'_, io::Result<Vec<u8>>>) -> io::Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| io::Error::other("dpkg-query output reader stopped"))?
}

fn remove(id: &str, dry_run: bool) -> io::Result<()> {
    let mut command = trusted_command(DPKG);
    command
        .env("DPKG_FRONTEND_LOCKED", "1")
        .args(["--root=/", DPKG_ADMIN_DIR, "--no-force-all"]);
    if dry_run {
        command.arg("--no-act");
    }
    let status = command.args(["--remove", "--", id]).status()?;
    if !status.success() {
        let step = if dry_run {
            "removal preflight"
        } else {
            "removal"
        };
        return Err(io::Error::other(format!("dpkg {step} failed ({status})")));
    }
    Ok(())
}

fn deny(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.into())
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::is_safe_config_line;

    #[test]
    fn default_logging_is_allowed_but_scope_changing_options_are_rejected() {
        assert!(is_safe_config_line("log /var/log/dpkg.log"));
        assert!(is_safe_config_line("log=/var/log/dpkg.log"));
        assert!(!is_safe_config_line("log /tmp/user-file"));
        assert!(!is_safe_config_line("ignore-depends=example"));
        assert!(!is_safe_config_line("pre-invoke=example"));
        assert!(!is_safe_config_line("pending"));
        assert!(!is_safe_config_line(&format!("#{}", "a".repeat(1024))));
    }
}
