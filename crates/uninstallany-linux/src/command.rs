use std::{
    env,
    ffi::{OsStr, OsString},
    fs,
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use uninstallany_core::{Cancellation, Error, Result};

const SYSTEM_SEARCH: &str = "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin";
const MAX_QUERY_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ERROR_BYTES: u64 = 8 * 1024;
const QUERY_TIMEOUT: Duration = Duration::from_secs(12);
const POLL_INTERVAL: Duration = Duration::from_millis(20);
const SESSION_ENV: &[&str] = &[
    "USER",
    "LOGNAME",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
];

#[derive(Clone, Debug, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
}

#[derive(Clone, Debug)]
pub(crate) struct Program {
    path: PathBuf,
    identity: Identity,
}

impl Program {
    pub(crate) fn find(name: &str) -> Option<Self> {
        let path = env::var_os("PATH").unwrap_or_default();
        env::split_paths(&path)
            .chain(env::split_paths(OsStr::new(SYSTEM_SEARCH)))
            .filter(|directory| directory.is_absolute())
            .find_map(|directory| Self::resolve(&directory.join(name)).ok())
    }

    fn resolve(path: &Path) -> io::Result<Self> {
        // Executables are external system programs, not cleanup targets. Accept
        // common /bin aliases only after resolving and checking every ancestor.
        let path = fs::canonicalize(path)?;
        let identity = trusted_identity(&path)?;
        Ok(Self { path, identity })
    }

    pub(crate) fn command(&self, home: &Path, data: &Path) -> io::Result<Command> {
        if trusted_identity(&self.path)? != self.identity {
            return Err(io::Error::other("the package-manager executable changed"));
        }
        let mut command = Command::new(&self.path);
        command
            .env_clear()
            .env("PATH", SYSTEM_SEARCH)
            .env("HOME", home)
            .env("XDG_DATA_HOME", data)
            .env("LC_ALL", "C")
            .current_dir("/");
        for key in SESSION_ENV {
            if let Some(value) = env::var_os(key) {
                command.env(key, value);
            }
        }
        Ok(command)
    }
}

fn trusted_identity(path: &Path) -> io::Result<Identity> {
    let denied = || {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "untrusted package-manager executable",
        )
    };
    for directory in path.ancestors().skip(1) {
        let entry = fs::symlink_metadata(directory)?;
        if !entry.is_dir() || entry.uid() != 0 || entry.mode() & 0o022 != 0 {
            return Err(denied());
        }
    }
    let entry = fs::symlink_metadata(path)?;
    if !entry.is_file()
        || entry.uid() != 0
        || entry.mode() & 0o022 != 0
        || entry.mode() & 0o111 == 0
    {
        return Err(denied());
    }
    Ok(Identity {
        device: entry.dev(),
        inode: entry.ino(),
        size: entry.size(),
        modified: (entry.mtime(), entry.mtime_nsec()),
    })
}

pub(crate) fn query(
    program: &Program,
    home: &Path,
    data: &Path,
    args: &[&str],
    cancel: &Cancellation,
) -> Result<String> {
    let mut command = program.command(home, data)?;
    command.args(args);
    let (status, output, diagnostics) = capture(&mut command, Some(cancel))?;
    if !status.success() {
        return Err(Error::Rejected(format!(
            "package query exited with {status}: {}",
            diagnostics.trim()
        )));
    }
    String::from_utf8(output)
        .map_err(|_| Error::Rejected("package query returned invalid UTF-8".into()))
}

pub(crate) fn run_confirmed(
    program: Program,
    home: &Path,
    data: &Path,
    args: Vec<OsString>,
) -> Result<NativeResult> {
    let mut command = program.command(home, data)?;
    command.args(args);
    let (status, output, diagnostics) = capture(&mut command, None)?;
    if !status.success() && !diagnostics.trim().is_empty() {
        return Err(Error::Rejected(format!(
            "package removal exited with {status}: {}",
            diagnostics.trim()
        )));
    }
    Ok(NativeResult {
        status,
        output: String::from_utf8_lossy(&output).into_owned(),
    })
}

pub(crate) struct NativeResult {
    pub status: ExitStatus,
    pub output: String,
}

fn capture(
    command: &mut Command,
    cancel: Option<&Cancellation>,
) -> Result<(ExitStatus, Vec<u8>, String)> {
    if let Some(cancel) = cancel {
        cancel.check()?;
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("package-manager stdout is unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("package-manager stderr is unavailable"))?;
    thread::scope(|scope| {
        let output_reader = scope.spawn(move || read_pipe(stdout, MAX_QUERY_BYTES));
        let diagnostics_reader = scope.spawn(move || read_pipe(stderr, MAX_ERROR_BYTES));
        let result = wait(&mut child, cancel);
        let output = output_reader
            .join()
            .map_err(|_| io::Error::other("package-manager output reader stopped"))?;
        let diagnostics = diagnostics_reader
            .join()
            .map_err(|_| io::Error::other("package-manager diagnostics reader stopped"))?;
        let status = result?;
        let output = output?;
        if output.len() as u64 > MAX_QUERY_BYTES {
            return Err(Error::Rejected(
                "package-manager output exceeded the scan limit".into(),
            ));
        }
        let diagnostics = diagnostics?;
        let diagnostics = String::from_utf8_lossy(
            &diagnostics[..diagnostics.len().min(MAX_ERROR_BYTES as usize)],
        );
        Ok((status, output, diagnostics.into_owned()))
    })
}

fn read_pipe(mut pipe: impl Read, limit: u64) -> io::Result<Vec<u8>> {
    let mut result = Vec::new();
    (&mut pipe).take(limit + 1).read_to_end(&mut result)?;
    // Continue to drain excessive output so a confirmed native transaction
    // never fails because we prematurely closed its output streams.
    io::copy(&mut pipe, &mut io::sink())?;
    Ok(result)
}

fn wait(child: &mut std::process::Child, cancel: Option<&Cancellation>) -> Result<ExitStatus> {
    let Some(cancel) = cancel else {
        // User approved the official command. Do not interrupt a live package
        // transaction when the desktop cancels the rest of its queue.
        return Ok(child.wait()?);
    };
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        let status = if cancel.check().is_err() {
            Some(Error::Cancelled)
        } else if started.elapsed() >= QUERY_TIMEOUT {
            Some(Error::Rejected("installed-package query timed out".into()))
        } else {
            None
        };
        if let Some(error) = status {
            // This child is always a read-only inventory query.
            if let Err(kill_error) = child.kill() {
                if child.try_wait()?.is_none() {
                    return Err(kill_error.into());
                }
            }
            child.wait()?;
            return Err(error);
        }
        thread::sleep(POLL_INTERVAL);
    }
}
