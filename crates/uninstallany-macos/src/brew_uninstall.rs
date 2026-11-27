//! Runs Homebrew's installer against one reviewed cask inside a write sandbox.

use std::{
    collections::HashMap,
    ffi::OsString,
    fs::{self, DirBuilder, File, Metadata, OpenOptions},
    io::{self, Read, Seek},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use sha2::{Digest, Sha256};
use uninstallany_core::{
    AppId, AppRecord, Artifact, Cancellation, Category, Error, Journal, OfficialExecution,
    OfficialIntent, OfficialOutcome, Result,
};
use uninstallany_unix::UnixFiles;
use uuid::Uuid;

use crate::{activity, brew};

const SANDBOX: &str = "/usr/bin/sandbox-exec";
const SYSTEM_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
const SYSTEM_BREW_CONFIG: &str = "/etc/homebrew/brew.env";
const MAX_RUNTIME_FILE_BYTES: usize = 64 * 1024 * 1024;
const MAX_DIAGNOSTIC_BYTES: u64 = 4_096;
const MAX_CASKROOM_ENTRIES: usize = 1_024;
const MAX_RECEIPT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_ALL_RECEIPTS_BYTES: u64 = 64 * 1024 * 1024;
const RUNTIME_FILES: [&str; 15] = [
    "bin/brew",
    "Library/Homebrew/brew.sh",
    "Library/Homebrew/brew.rb",
    "Library/Homebrew/global.rb",
    "Library/Homebrew/dev-cmd/ruby.rb",
    "Library/Homebrew/cask/cask_loader.rb",
    "Library/Homebrew/cask/installer.rb",
    "Library/Homebrew/cask/artifact/moved.rb",
    "Library/Homebrew/cask/artifact/relocated.rb",
    "Library/Homebrew/cask/cask.rb",
    "Library/Homebrew/cask/caskroom.rb",
    "Library/Homebrew/cask/config.rb",
    "Library/Homebrew/cask/tab.rb",
    "Library/Homebrew/cask/utils.rb",
    "Library/Homebrew/extend/os/mac/cask/artifact/moved.rb",
];

// Keep native writes bounded even if Homebrew changes behavior between releases.
// A successful execution of sandbox-exec is mandatory for native removal.
const PROFILE: &str = r#"
(version 1)
(deny network*)
(deny mach-lookup)
(allow mach-lookup
  (global-name "com.apple.bsd.dirhelper")
  (global-name "com.apple.system.opendirectoryd.libinfo")
  (global-name "com.apple.system.opendirectoryd.membership"))
(deny lsopen)
(deny appleevent-send)
(deny file-read-data
  (literal "/private/etc/homebrew/brew.env")
  (literal (param "UA_BREW_CONFIG")))
(deny process-exec
  (literal "/usr/bin/sudo")
  (literal "/usr/bin/su")
  (literal "/usr/bin/open")
  (literal "/bin/launchctl")
  (subpath (param "UA_APP"))
  (subpath (param "UA_CASK"))
  (subpath (param "UA_TEMP")))
(allow file-write*
  (subpath (param "UA_APP"))
  (subpath (param "UA_CASK"))
  (subpath (param "UA_TEMP"))
  (literal "/dev/null")
  (literal "/dev/dtracehelper"))
(allow file-write-mode
  (subpath (param "UA_APP"))
  (subpath (param "UA_CASK"))
  (subpath (param "UA_TEMP")))
(deny file-write*)
(deny file-write-mode)
(deny file-write-setugid)
(allow default)
"#;

// Feed the verified JSON bytes to the Homebrew loader. Its
// path loader can fall through to Ruby evaluation after replacing a file.
const ADAPTER: &str = r#"
require "digest"
require "json"
require "pathname"
require "rbconfig"
require "cask/cask_loader"
require "cask/installer"
require "cask/artifact/app"

prefix, token, cask_dir, snapshot, app_path, app_dir, staged_app, version, ruby,
  snapshot_digest, receipt_digest, config_digest, app_device, app_inode,
  stage_device, stage_inode, cask_device, cask_inode, appdir_device, appdir_inode = ARGV

def check_directory(path, device = nil, inode = nil)
  stat = File.lstat(path)
  if !stat.directory? || File.realpath(path) != path ||
     (device && [stat.dev.to_s, stat.ino.to_s] != [device, inode])
    abort "A reviewed cask directory changed."
  end
end

def read_record(path, digest)
  abort "A reviewed cask record changed." unless File.realpath(path) == path
  File.open(path, File::RDONLY | File::NOFOLLOW) do |file|
    stat = file.stat
    unless stat.file? && stat.nlink == 1 && stat.uid == Process.euid && (stat.mode & 022).zero?
      abort "A reviewed cask record is invalid."
    end
    bytes = file.read(2 * 1024 * 1024 + 1) || ""
    abort "A reviewed cask record changed." unless Digest::SHA256.hexdigest(bytes) == digest
    bytes
  end
end

def check_dependents(room, selected)
  valid_name = /\A[A-Za-z0-9][A-Za-z0-9.@_+\-]{0,119}\z/
  count = 0
  total = 0
  Dir.each_child(room) do |name|
    count += 1
    abort "Too many Homebrew casks to check dependencies." if count > 1024
    next if name == selected

    path = File.join(room, name)
    stat = File.lstat(path)
    if stat.symlink?
      to = File.readlink(path)
      target = File.basename(to)
      unless valid_name.match?(target) && !target.include?("..") &&
             [target, File.join(room, target)].include?(to) && !target.casecmp?(selected)
        abort "A Homebrew alias prevents verifying cask dependencies."
      end
      next
    end
    next if stat.file?
    abort "Unknown Homebrew Caskroom entry." unless stat.directory? && valid_name.match?(name) && !name.include?("..")

    check_directory(path)
    receipt = File.join(path, ".metadata", "INSTALL_RECEIPT.json")
    abort "A cask dependency receipt is missing or linked." unless File.realpath(receipt) == receipt
    deps = File.open(receipt, File::RDONLY | File::NOFOLLOW) do |file|
      stat = file.stat
      unless stat.file? && stat.nlink == 1 && [0, Process.euid].include?(stat.uid) && (stat.mode & 022).zero?
        abort "A cask dependency receipt is untrusted."
      end
      bytes = file.read(2 * 1024 * 1024 + 1) || ""
      total += bytes.bytesize
      abort "Cask dependency receipts exceed the review limit." if bytes.bytesize > 2 * 1024 * 1024 || total > 64 * 1024 * 1024
      JSON.parse(bytes).fetch("runtime_dependencies")
    end
    next if deps.nil? || deps == []
    abort "A cask dependency receipt is invalid." unless deps.is_a?(Hash)
    casks = deps["cask"]
    next if casks.nil?
    abort "A cask dependency receipt is invalid." unless casks.is_a?(Array)

    casks.each do |dependency|
      parts = dependency.fetch("full_name").split("/", -1)
      unless [1, 3].include?(parts.length) && parts.all? { |part| valid_name.match?(part) && !part.include?("..") }
        abort "A cask dependency name is invalid."
      end
      abort "An installed Homebrew cask depends on the selected application." if parts.last.casecmp?(selected)
    end
  end
end

abort "Homebrew is running under a different account." unless Process.uid == Process.euid && Process.uid != 0
abort "Homebrew used a different Ruby runtime." unless File.realpath(RbConfig.ruby) == ruby
abort "Homebrew prefix changed." unless HOMEBREW_PREFIX.to_s == prefix
abort "Homebrew Caskroom changed." unless Cask::Caskroom.path.join(token).to_s == cask_dir

metadata = File.join(cask_dir, ".metadata")
receipt_path = File.join(metadata, "INSTALL_RECEIPT.json")
config_path = File.join(metadata, "config.json")

verify_paths = lambda do
  check_directory(cask_dir, cask_device, cask_inode)
  check_directory(app_dir, appdir_device, appdir_inode)
  check_directory(app_path, app_device, app_inode)
  check_directory(File.dirname(staged_app))
  unless [cask_dir, app_path, File.dirname(staged_app)].all? { |path|
    stat = File.lstat(path)
    stat.uid == Process.euid && (stat.mode & 022).zero?
  }
    abort "The reviewed installation owner changed."
  end
  stage = File.lstat(staged_app)
  unless stage.symlink? && stage.uid == Process.euid &&
         [stage.dev.to_s, stage.ino.to_s] == [stage_device, stage_inode] &&
         File.expand_path(File.readlink(staged_app), File.dirname(staged_app)) == app_path
    abort "The reviewed Homebrew staging link changed."
  end
end

verify_paths.call
snapshot_bytes = read_record(snapshot, snapshot_digest)
receipt_bytes = read_record(receipt_path, receipt_digest)
config_bytes = read_record(config_path, config_digest)
saved = JSON.parse(snapshot_bytes)
receipt = JSON.parse(receipt_bytes)
abort "The installed cask version changed." unless receipt.fetch("source").fetch("version") == version
abort "The installed cask has uninstall hooks." unless receipt["uninstall_flight_blocks"] == false
app_artifacts = receipt.fetch("uninstall_artifacts").select { |artifact| artifact.keys == ["app"] }
abort "The installed cask must have one app." unless app_artifacts.length == 1
saved["version"] ||= version
saved["artifacts"] = app_artifacts

loader = Cask::CaskLoader::FromAPILoader.new(
  token, from_json: saved, path: Pathname(snapshot), from_installed_caskfile: true, api_fallback: false
)
cask = loader.load(config: Cask::Config.from_json(config_bytes))
artifacts = cask.artifacts.to_a
artifact = artifacts.first
unless cask.token == token && cask.version.to_s == version &&
       cask.caskroom_path.to_s == cask_dir && cask.config_path.to_s == config_path &&
       cask.config.appdir.to_s == app_dir &&
       cask.metadata_versioned_path.to_s == File.join(metadata, version) &&
       cask.staged_path.to_s == File.join(cask_dir, version) &&
       cask.tab.tabfile.to_s == receipt_path &&
       artifacts.length == 1 && artifact.instance_of?(Cask::Artifact::App) &&
       artifact.source.to_s == staged_app && artifact.target.to_s == app_path &&
       !cask.uninstall_flight_blocks? && !cask.pinned?
  abort "Homebrew resolved a different installation or an unsupported effect."
end

# The original methods reload/migrate definitions and inspect aliases belonging
# to other casks. This private adapter instance removes one reviewed install.
class ReviewedInstaller < Cask::Installer
  def load_installed_caskfile!
  end

  def remove_broken_caskroom_symlinks
  end
end

installer = ReviewedInstaller.new(cask, force: false, binaries: false, zap: false, skip_cask_deps: true)
check_dependents(File.dirname(cask_dir), token)
verify_paths.call
read_record(snapshot, snapshot_digest)
read_record(receipt_path, receipt_digest)
read_record(config_path, config_digest)
installer.uninstall
"#;

/// Binds a reviewed installed cask and the native runtime to confirmation.
pub(super) struct Prepared {
    app: AppRecord,
    evidence: brew::UninstallEvidence,
    runtime: Runtime,
}

impl Prepared {
    /// Exact bundle used to collect evidence for the later leftovers scan.
    pub(super) fn application_path(&self) -> &Path {
        &self.evidence.app_path
    }

    /// Bundle identity used to collect evidence before launching Homebrew.
    pub(super) fn bundle_identifier(&self) -> &str {
        &self.evidence.bundle_id
    }
}

#[derive(Eq, PartialEq)]
struct Runtime {
    launcher: PathBuf,
    ruby: PathBuf,
    files: Vec<([u8; 32], FileIdentity)>,
}

#[derive(Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl From<Metadata> for FileIdentity {
    fn from(metadata: Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

/// Cheap availability check for showing the option in the inventory.
pub(super) fn available(app: &AppRecord) -> bool {
    cask_directory(app)
        .and_then(|cask| cask.parent()?.parent().map(Path::to_owned))
        .is_some_and(|prefix| {
            fs::symlink_metadata(repository(&prefix).join("bin/brew"))
                .is_ok_and(|metadata| metadata.is_file())
        })
        && fs::symlink_metadata(SANDBOX).is_ok_and(|metadata| metadata.is_file())
}

/// Describes the native package operation before the user confirms it.
pub(super) fn prepare(
    files: &UnixFiles,
    home: &Path,
    app: &AppRecord,
    cancel: &Cancellation,
) -> Result<(OfficialIntent, Prepared)> {
    let evidence = brew::prepare_uninstall_evidence(files, home, app, cancel)?;
    require_closed(files, &evidence)?;
    check_dependents(files, &evidence, cancel)?;
    let runtime = read_runtime(files, Path::new(evidence.prefix), cancel)?;
    let intent = OfficialIntent {
        application: app.name.clone(),
        method: "Homebrew Cask".into(),
        quiet: true,
        notice: format!(
            "Homebrew permanently removes the selected app at {} and its own installation at {}. Any suggested leftovers are reviewed separately before quarantine.",
            evidence.app_path.display(),
            evidence.cask_dir.display(),
        ),
    };
    Ok((
        intent,
        Prepared {
            app: app.clone(),
            evidence,
            runtime,
        },
    ))
}

/// Runs the reviewed package removal without write access to other apps.
pub(super) fn uninstall(
    files: &UnixFiles,
    home: &Path,
    prepared: Prepared,
    cancel: &Cancellation,
) -> Result<OfficialExecution> {
    let evidence = &prepared.evidence;
    if read_runtime(files, Path::new(evidence.prefix), cancel)? != prepared.runtime {
        return Err(rejected(
            "the Homebrew runtime changed after confirmation; review the uninstall again",
        ));
    }
    let work = RuntimeDirectory::create(files)?;
    let diagnostic_path = work.path.join("diagnostic");
    let mut diagnostic = OpenOptions::new()
        .create_new(true)
        .read(true)
        .append(true)
        .mode(0o600)
        .open(&diagnostic_path)?;

    if brew::prepare_uninstall_evidence(files, home, &prepared.app, cancel)? != *evidence {
        return Err(rejected(
            "the Homebrew cask changed after confirmation; review the uninstall again",
        ));
    }
    let [cask, app, app_dir] = evidence.directory_identities();
    let stage = evidence.staged_link_identity();
    let mut command = native_command(evidence, &prepared.runtime, home, &work.path);
    for (device, inode) in [app, stage, cask, app_dir] {
        command.arg(device.to_string()).arg(inode.to_string());
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(diagnostic.try_clone()?))
        .process_group(0);
    require_closed(files, evidence)?;
    cancel.check()?;
    let mut child = command.spawn().map_err(|error| {
        rejected(format!(
            "could not start Homebrew in the macOS sandbox: {error}"
        ))
    })?;
    let (outcome, mut warnings) = match child.wait() {
        Ok(status) if status.success() => {
            match verify_absent(files, &prepared.app, &Cancellation::default()) {
                Ok(true) => (OfficialOutcome::Completed, Vec::new()),
                Ok(false) => unverified(
                    0,
                    "Homebrew did not remove both the selected app and its cask records",
                ),
                Err(error) => unverified(
                    0,
                    format!("could not verify the Homebrew uninstall: {error}"),
                ),
            }
        }
        Ok(status) => unverified(
            status
                .code()
                .and_then(|code| u32::try_from(code).ok())
                .unwrap_or(1),
            "Homebrew did not complete the reviewed uninstall",
        ),
        Err(error) => unverified(1, format!("could not wait for Homebrew: {error}")),
    };
    if outcome != OfficialOutcome::Completed {
        if let Some(message) = diagnostic_message(&mut diagnostic) {
            warnings.push(message);
        }
    }
    if let Err(error) = work.remove() {
        warnings.push(format!(
            "could not remove Homebrew's private working directory: {error}"
        ));
    }
    Ok(OfficialExecution {
        outcome,
        warnings,
        read_only_residuals: Vec::new(),
        observed_files: HashMap::new(),
        post_uninstall_check: None,
    })
}

/// Independently confirms absence of the bundle and the exact cask record.
pub(super) fn verify_absent(
    files: &UnixFiles,
    app: &AppRecord,
    cancel: &Cancellation,
) -> Result<bool> {
    cancel.check()?;
    let cask = cask_directory(app).ok_or_else(|| rejected("invalid Homebrew cask identity"))?;
    let bundle = app
        .install_location
        .as_deref()
        .ok_or_else(|| rejected("the Homebrew cask has no verified bundle location"))?;
    Ok(entry_absent(files, &cask)? && entry_absent(files, bundle)?)
}

fn cask_directory(app: &AppRecord) -> Option<PathBuf> {
    let AppId::Package { manager, id } = &app.id else {
        return None;
    };
    if manager != brew::MANAGER || app.system_component || app.install_location.is_none() {
        return None;
    }
    let id = brew::CaskId::parse(id)?;
    id.bundle_id()?;
    Some(id.install_dir())
}

fn entry_absent(files: &UnixFiles, path: &Path) -> io::Result<bool> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("installation path has no parent"))?;
    let identity = files.local_directory_identity(parent)?;
    let absent = match files.probe_discovery_target(path) {
        Ok(_) => false,
        Err(error) if error.kind() == io::ErrorKind::NotFound => true,
        Err(error) => return Err(error),
    };
    Ok(absent && files.local_directory_identity(parent)? == identity)
}

fn check_dependents(
    files: &UnixFiles,
    evidence: &brew::UninstallEvidence,
    cancel: &Cancellation,
) -> Result<()> {
    let room = evidence
        .cask_dir
        .parent()
        .ok_or_else(|| rejected("invalid Homebrew Caskroom"))?;
    let paths = files.list(room)?;
    if paths.len() > MAX_CASKROOM_ENTRIES {
        return Err(rejected("too many Homebrew casks to check dependencies"));
    }
    let mut total = 0;
    for path in paths
        .into_iter()
        .filter(|entry| entry != &evidence.cask_dir)
    {
        cancel.check()?;
        match files.probe_discovery_target(&path)? {
            Some(entry) if entry.category == Category::File => continue,
            Some(entry) if entry.category == Category::Directory => {}
            None => {
                let Some((target, _)) = files.read_macos_homebrew_symlink(&path)? else {
                    return Err(rejected(
                        "an unknown Caskroom entry prevents checking dependencies",
                    ));
                };
                let Some(name) = target.file_name().and_then(|name| name.to_str()) else {
                    return Err(rejected(
                        "an unverified Homebrew alias prevents checking dependencies",
                    ));
                };
                if !valid_dependency_part(name)
                    || (target != Path::new(name) && target != room.join(name))
                    || name.eq_ignore_ascii_case(&evidence.token)
                {
                    return Err(rejected(
                        "an unverified Homebrew alias prevents checking dependencies",
                    ));
                }
                continue;
            }
            Some(_) => {
                return Err(rejected(
                    "an unverified Caskroom entry prevents checking dependencies",
                ));
            }
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| valid_dependency_part(name))
            .ok_or_else(|| rejected("an unverified cask name prevents checking dependencies"))?;
        let receipt = path.join(".metadata/INSTALL_RECEIPT.json");
        let mut bytes = Vec::new();
        files
            .open_macos_homebrew_regular_file(&receipt)
            .map_err(|error| {
                rejected(format!(
                    "could not verify dependencies of Homebrew cask {name}: {error}"
                ))
            })?
            .take(MAX_RECEIPT_BYTES + 1)
            .read_to_end(&mut bytes)?;
        let byte_count = u64::try_from(bytes.len())
            .map_err(|_| rejected("Homebrew dependency receipt exceeds the review limit"))?;
        total += byte_count;
        if byte_count > MAX_RECEIPT_BYTES || total > MAX_ALL_RECEIPTS_BYTES {
            return Err(rejected(
                "Homebrew dependency receipts exceed the review limit",
            ));
        }
        let record: serde_json::Value = serde_json::from_slice(&bytes)?;
        let dependencies = record.get("runtime_dependencies").ok_or_else(|| {
            rejected(format!(
                "Homebrew cask {name} lacks installed dependency information"
            ))
        })?;
        if dependencies.is_null() || dependencies.as_array().is_some_and(Vec::is_empty) {
            continue;
        }
        let dependencies = dependencies
            .as_object()
            .ok_or_else(|| rejected("invalid installed Homebrew dependency information"))?;
        let Some(casks) = dependencies.get("cask").filter(|casks| !casks.is_null()) else {
            continue;
        };
        let casks = casks
            .as_array()
            .ok_or_else(|| rejected("invalid installed Homebrew cask dependency information"))?;
        for dependency in casks {
            let name_parts = dependency
                .get("full_name")
                .and_then(serde_json::Value::as_str)
                .and_then(|name| {
                    let parts = name.split('/').collect::<Vec<_>>();
                    (matches!(parts.len(), 1 | 3)
                        && parts.iter().all(|part| valid_dependency_part(part)))
                    .then_some(parts)
                })
                .ok_or_else(|| rejected("an installed Homebrew cask dependency name is invalid"))?;
            if name_parts
                .last()
                .is_some_and(|dependency| dependency.eq_ignore_ascii_case(&evidence.token))
            {
                return Err(rejected(format!(
                    "Homebrew cask {name} depends on the selected application"
                )));
            }
        }
    }
    Ok(())
}

fn valid_dependency_part(part: &str) -> bool {
    part.len() <= 120
        && !part.contains("..")
        && part
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && part
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".@_+-".contains(&byte))
}

fn repository(prefix: &Path) -> PathBuf {
    if prefix == Path::new("/usr/local") {
        prefix.join("Homebrew")
    } else {
        prefix.to_owned()
    }
}

fn read_runtime(files: &UnixFiles, prefix: &Path, cancel: &Cancellation) -> Result<Runtime> {
    if !fs::symlink_metadata(SANDBOX)?.is_file() {
        return Err(rejected("the macOS sandbox is unavailable"));
    }
    for config in [
        PathBuf::from(SYSTEM_BREW_CONFIG),
        prefix.join("etc/homebrew/brew.env"),
    ] {
        match fs::symlink_metadata(config) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(rejected(
                    "this Homebrew installation has external startup configuration",
                ));
            }
        }
    }
    let root = repository(prefix);
    let portable = root.join("Library/Homebrew/vendor/portable-ruby");
    files.require_trusted_local_directory(&portable)?;
    let current = fs::read_link(portable.join("current"))?;
    if !matches!(
        current.components().collect::<Vec<_>>().as_slice(),
        [std::path::Component::Normal(_)]
    ) {
        return Err(rejected(
            "Homebrew's installed Ruby runtime is not a local version",
        ));
    }
    let ruby = portable.join(current).join("bin/ruby");
    let mut fingerprints = Vec::new();
    for path in RUNTIME_FILES
        .into_iter()
        .map(|path| root.join(path))
        .chain([ruby.clone()])
    {
        cancel.check()?;
        fingerprints.push(runtime_file(files, &path)?);
    }
    Ok(Runtime {
        launcher: root.join("bin/brew"),
        ruby,
        files: fingerprints,
    })
}

fn runtime_file(files: &UnixFiles, path: &Path) -> io::Result<([u8; 32], FileIdentity)> {
    let mut file = files.open_macos_homebrew_regular_file(path)?;
    let before = file.metadata()?;
    if before.len() > MAX_RUNTIME_FILE_BYTES as u64 {
        return Err(io::Error::other(
            "a Homebrew runtime file exceeds the review limit",
        ));
    }
    let mut hasher = Sha256::new();
    let read = io::copy(
        &mut (&mut file).take(MAX_RUNTIME_FILE_BYTES as u64 + 1),
        &mut hasher,
    )?;
    let after = files.open_macos_homebrew_regular_file(path)?.metadata()?;
    if read != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(io::Error::other(
            "a Homebrew runtime file changed during review",
        ));
    }
    Ok((hasher.finalize().into(), after.into()))
}

fn native_command(
    evidence: &brew::UninstallEvidence,
    runtime: &Runtime,
    home: &Path,
    directory: &Path,
) -> Command {
    let mut command = Command::new(SANDBOX);
    command
        .env_clear()
        .env("PATH", SYSTEM_PATH)
        .env("HOME", home)
        .env("TMPDIR", directory)
        .env("HOMEBREW_TEMP", directory)
        .env("HOMEBREW_CACHE", directory)
        .env("XDG_CONFIG_HOME", directory)
        .env("HOMEBREW_DEV_CMD_RUN", "1")
        .env("HOMEBREW_FORCE_VENDOR_RUBY", "1")
        .env("HOMEBREW_NO_ANALYTICS", "1")
        .env("HOMEBREW_NO_AUTO_UPDATE", "1")
        .env("HOMEBREW_NO_AUTOREMOVE", "1")
        .env("HOMEBREW_NO_INSTALL_FROM_API", "1")
        .env("HOMEBREW_NO_SUDO", "1")
        .current_dir(directory)
        .args(["-p", PROFILE]);
    let startup_config = Path::new(evidence.prefix).join("etc/homebrew/brew.env");
    for (name, path) in [
        ("UA_APP", evidence.app_path.as_path()),
        ("UA_CASK", &evidence.cask_dir),
        ("UA_TEMP", directory),
        ("UA_BREW_CONFIG", &startup_config),
    ] {
        let mut definition = OsString::from(name);
        definition.push("=");
        definition.push(path);
        command.arg("-D").arg(definition);
    }
    command
        .arg(&runtime.launcher)
        .args([
            "ruby",
            "--",
            "-e",
            ADAPTER,
            "--",
            evidence.prefix,
            &evidence.token,
        ])
        .arg(&evidence.cask_dir)
        .arg(&evidence.snapshot_path)
        .arg(&evidence.app_path)
        .arg(&evidence.app_dir)
        .arg(&evidence.staged_app)
        .arg(&evidence.version)
        .arg(&runtime.ruby)
        .arg(hex_digest(&evidence.snapshot_digest))
        .arg(hex_digest(&evidence.receipt_digest))
        .arg(hex_digest(&evidence.config_digest));
    command
}

fn hex_digest(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut result = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(result, "{byte:02x}");
    }
    result
}

fn require_closed(files: &UnixFiles, evidence: &brew::UninstallEvidence) -> Result<()> {
    if activity::at_location(files, Some(&evidence.app_path), &evidence.bundle_id) {
        return Err(rejected(
            "close the selected app before letting Homebrew remove it",
        ));
    }
    Ok(())
}

fn rejected(reason: impl Into<String>) -> Error {
    Error::Rejected(reason.into())
}

fn unverified(code: u32, reason: impl Into<String>) -> (OfficialOutcome, Vec<String>) {
    (OfficialOutcome::Unverified(code), vec![reason.into()])
}

fn diagnostic_message(file: &mut File) -> Option<String> {
    let mut bytes = Vec::new();
    file.rewind().ok()?;
    file.take(MAX_DIAGNOSTIC_BYTES)
        .read_to_end(&mut bytes)
        .ok()?;
    let message: String = String::from_utf8_lossy(&bytes)
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    (!message.trim().is_empty()).then(|| message.trim().to_owned())
}

struct RuntimeDirectory {
    path: PathBuf,
    identity: FileIdentity,
}

impl RuntimeDirectory {
    fn create(files: &UnixFiles) -> io::Result<Self> {
        let audit_file = files.location(Uuid::nil(), Artifact::Event);
        let state = audit_file
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| io::Error::other("audit storage does not have a state directory"))?;
        files.require_trusted_local_directory(state)?;
        let path = state.join(format!("brew-native-{}", Uuid::new_v4()));
        DirBuilder::new().mode(0o700).create(&path)?;
        let working = Self {
            identity: fs::symlink_metadata(&path)?.into(),
            path,
        };
        files.require_trusted_local_directory(&working.path)?;
        Ok(working)
    }

    fn remove(&self) -> io::Result<()> {
        match fs::symlink_metadata(&self.path) {
            Ok(metadata)
                if metadata.is_dir() && FileIdentity::from(metadata.clone()) == self.identity =>
            {
                fs::remove_dir_all(&self.path)
            }
            Ok(_) => Err(io::Error::other(
                "the private Homebrew working directory changed",
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

impl Drop for RuntimeDirectory {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}
