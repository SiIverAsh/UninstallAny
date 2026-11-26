//! Bounded discovery and confirmation for vendor-signed macOS uninstallers.

use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{self, File, Metadata},
    io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    ptr, thread,
    time::{Duration, Instant},
};

use core_foundation::{
    ConcreteCFType,
    base::{CFType, CFTypeRef, TCFType},
    data::CFData,
    dictionary::{CFDictionary, CFDictionaryRef},
    string::{CFString, CFStringRef},
    url::{CFURL, CFURLRef},
};
use objc2::rc::autoreleasepool;
use objc2_foundation::{NSFileManager, NSSearchPathDirectory, NSSearchPathDomainMask};
use uninstallany_core::{
    AppId, AppRecord, Cancellation, Error, OfficialIntent, OfficialOutcome, PostUninstallCheck,
    Result,
};
use uninstallany_unix::{UnixFiles, macos_suite_bundle_location};

use crate::{
    app_groups,
    app_signature::DEVELOPER_ID_REQUIREMENT,
    bundle::{self, Bundle},
    launch_agents, plist, receipt,
};

const OPEN: &str = "/usr/bin/open";
const OPEN_POLL_INTERVAL: Duration = Duration::from_millis(50);
const POST_EXIT_VERIFICATION_WINDOW: Duration = Duration::from_secs(2);
const WAIT_CANCELLED: &str = "Stopped waiting for the vendor uninstaller. It may still be running.";
const MAX_INFO_BYTES: usize = 2 * 1024 * 1024;
const MAX_APP_STEM_BYTES: usize = 220;
const SUITE_UNINSTALLER_NAMES: [&str; 2] = ["Uninstall.app", "Uninstaller.app"];
// SecStaticCode.h and CSCommon.h define these flags. In particular, the
// no-network flag disables online revocation and notarization queries.
const NO_NETWORK_ACCESS: u32 = 1 << 29;
const DO_NOT_VALIDATE_RESOURCES: u32 = 1 << 2;
const SIGNING_PREFLIGHT_FLAGS: u32 = NO_NETWORK_ACCESS | DO_NOT_VALIDATE_RESOURCES;
const VALIDATE_FLAGS: u32 = (1 << 0) | (1 << 3) | (1 << 4) | (1 << 7) | NO_NETWORK_ACCESS;
const SIGNING_INFORMATION: u32 = 1 << 1;
// Explicit negative results from Security.framework's CSCommon.h.
const CODE_UNSIGNED: i32 = -67062;
const SIGNATURE_FAILED: i32 = -67061;
const REQUIREMENT_FAILED: i32 = -67050;
const BAD_BUNDLE_FORMAT: i32 = -67028;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecStaticCodeCreateWithPath(path: CFURLRef, flags: u32, code: *mut CFTypeRef) -> i32;
    #[cfg(feature = "privileged-inspection")]
    fn SecCodeCopySelf(flags: u32, code: *mut CFTypeRef) -> i32;
    #[cfg(feature = "privileged-inspection")]
    fn SecCodeCheckValidity(code: CFTypeRef, flags: u32, requirement: CFTypeRef) -> i32;
    fn SecStaticCodeCheckValidity(code: CFTypeRef, flags: u32, requirement: CFTypeRef) -> i32;
    fn SecRequirementCreateWithString(
        text: CFStringRef,
        flags: u32,
        requirement: *mut CFTypeRef,
    ) -> i32;
    fn SecCodeCopySigningInformation(
        code: CFTypeRef,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> i32;
    static kSecCodeInfoIdentifier: CFStringRef;
    static kSecCodeInfoMainExecutable: CFStringRef;
    static kSecCodeInfoTeamIdentifier: CFStringRef;
    static kSecCodeInfoUnique: CFStringRef;
}

/// An uninstaller and its target, bound to both signed specimens on disk.
pub(super) struct Prepared {
    app: AppRecord,
    proof: PairProof,
}

/// A verified vendor action, or a confirmed reason it cannot be used.
#[derive(Default)]
pub(super) struct Review {
    pub(super) prepared: Option<Prepared>,
    pub(super) unavailable: Option<String>,
}

pub(super) struct VendorExecution {
    pub(super) outcome: OfficialOutcome,
    pub(super) warnings: Vec<String>,
    pub(super) app_groups: Vec<String>,
    pub(super) receipt_payloads: Vec<receipt::VendorPayload>,
    pub(super) observed_files: HashMap<PathBuf, String>,
    pub(super) incomplete_application: Option<(AppRecord, String)>,
    pub(super) post_uninstall_check: Option<PostUninstallCheck>,
}

impl VendorExecution {
    fn unverified(warning: impl Into<String>) -> Self {
        Self {
            outcome: OfficialOutcome::Unverified(0),
            warnings: vec![warning.into()],
            app_groups: Vec::new(),
            receipt_payloads: Vec::new(),
            observed_files: HashMap::new(),
            incomplete_application: None,
            post_uninstall_check: None,
        }
    }
}

impl Prepared {
    pub(super) fn application_path(&self) -> &Path {
        &self.proof.installed.path
    }

    /// Describes the exact verified vendor action before confirmation.
    pub(super) fn intent(&self) -> OfficialIntent {
        OfficialIntent {
            application: self.app.name.clone(),
            method: format!("Vendor uninstaller ({})", self.proof.uninstaller.path.display()),
            quiet: false,
            notice: "The signed vendor uninstaller runs interactively as your account. Review its prompts. The vendor uninstaller may continue after you stop waiting. UninstallAny can restore only leftovers it quarantines.".into(),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct PairProof {
    installed: SignedBundle,
    uninstaller: SignedBundle,
}

#[derive(Debug, Eq, PartialEq)]
struct SignedBundle {
    path: PathBuf,
    identifier: String,
    team: String,
    code_directory_hash: Vec<u8>,
    directory: Stamp,
    executable: Stamp,
    executable_path: PathBuf,
}

#[derive(Debug, Eq, PartialEq)]
struct Stamp {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl From<Metadata> for Stamp {
    fn from(value: Metadata) -> Self {
        Self {
            device: value.dev(),
            inode: value.ino(),
            owner: value.uid(),
            mode: value.mode(),
            size: value.size(),
            modified: (value.mtime(), value.mtime_nsec()),
            changed: (value.ctime(), value.ctime_nsec()),
        }
    }
}

/// Lists an official action only for one proven pairing of standalone bundles.
pub(super) fn available(files: &UnixFiles, app: &AppRecord, application_roots: &[PathBuf]) -> bool {
    review(files, app, application_roots).is_ok_and(|review| review.prepared.is_some())
}

/// Revalidates both bundles before allowing the system to launch the uninstaller.
pub(super) fn uninstall(
    files: &UnixFiles,
    home: &Path,
    prepared: Prepared,
    application_roots: &[PathBuf],
    cancel: &Cancellation,
) -> Result<VendorExecution> {
    cancel.check()?;
    let installed = &prepared.proof.installed;
    let mut warnings = Vec::new();
    // Capture the signed declarations while the reviewed app still exists.
    let app_groups = match app_groups::read(
        files,
        &installed.path,
        &installed.identifier,
        Some(installed.code_directory_hash.as_slice()),
        cancel,
    ) {
        Ok(groups) => groups,
        Err(Error::Cancelled) => return Err(Error::Cancelled),
        Err(error) => {
            warnings.push(format!(
                "Could not capture signed App Groups before uninstall: {error}"
            ));
            Vec::new()
        }
    };
    // Once the bundle is absent, a surviving plist must still match evidence
    // captured against its original executable and exact application identity.
    let observed_files = match launch_agents::capture_before_uninstall(
        files,
        home,
        &installed.path,
        &installed.identifier,
        cancel,
    ) {
        Ok(observations) => observations,
        Err(Error::Cancelled) => return Err(Error::Cancelled),
        Err(error) => {
            warnings.push(format!(
                "Could not verify user LaunchAgents before uninstall: {error}"
            ));
            HashMap::new()
        }
    };
    let receipt_payloads = match receipt::capture_vendor_payloads(
        &installed.path,
        &installed.executable_path,
        cancel,
        &mut warnings,
    ) {
        Ok(payloads) => payloads,
        Err(error) => {
            cancel.check()?;
            warnings.push(format!(
                "Could not inspect Installer ownership before uninstall: {error}"
            ));
            Vec::new()
        }
    };
    cancel.check()?;
    let fresh = review(files, &prepared.app, application_roots);
    cancel.check()?;
    if fresh?.prepared.as_ref().map(|action| &action.proof) != Some(&prepared.proof) {
        return Err(rejected("the application or vendor uninstaller changed after preview").into());
    }
    if crate::activity::at_location(
        files,
        Some(&prepared.proof.uninstaller.path),
        &prepared.proof.uninstaller.identifier,
    ) {
        return Err(rejected("the vendor uninstaller is already running").into());
    }
    // An uninstaller can rename or move its target. The launcher and the
    // original path alone cannot tell whether the reviewed code was removed.
    let original_bundle = File::from(files.open_trusted_local_directory(&installed.path)?);
    let original_executable = files.open_trusted_local_regular_file(&installed.executable_path)?;
    if Stamp::from(original_bundle.metadata()?) != installed.directory
        || Stamp::from(original_executable.metadata()?) != installed.executable
    {
        return Err(rejected("the installed application changed after verification").into());
    }
    let executable_suffix = installed
        .executable_path
        .strip_prefix(&installed.path)
        .map_err(io::Error::other)?
        .to_path_buf();
    let mut command = Command::new(OPEN);
    command
        // Select the approved app explicitly so Launch Services does not
        // resolve the supplied path through a default document handler.
        .args(["-n", "-W", "-a"])
        .arg(&prepared.proof.uninstaller.path)
        .current_dir("/")
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cancel.check()?;
    let child = command.spawn()?;
    let status = match wait_for_open(child, cancel) {
        Ok(status) => status,
        Err(warning) => return Ok(VendorExecution::unverified(warning)),
    };
    if !status.success() {
        return Ok(
            match status.code().and_then(|code| u32::try_from(code).ok()) {
                Some(code) => VendorExecution {
                    outcome: OfficialOutcome::Failed(code),
                    warnings,
                    app_groups: Vec::new(),
                    receipt_payloads: Vec::new(),
                    observed_files: HashMap::new(),
                    incomplete_application: None,
                    post_uninstall_check: None,
                },
                None => VendorExecution::unverified(
                    "The macOS launcher stopped without reporting completion. The vendor uninstaller may still be running.",
                ),
            },
        );
    }
    let verification = verify_removal_after_exit(
        || {
            if !bundle::original_bundle_absent(files, &installed.path, application_roots)? {
                return Ok(RemovalObservation::OriginalLocationOccupied);
            }
            observe_original_removal(
                files,
                &original_bundle,
                &original_executable,
                &executable_suffix,
            )
        },
        cancel,
    );
    let post_uninstall_check = match verification {
        Ok(trash) => trash.map(|trash| {
            trash_recheck(
                files,
                trash,
                original_bundle,
                original_executable,
                executable_suffix,
            )
        }),
        Err(error) => {
            warnings.push(format!(
                "Could not verify removal after the vendor uninstaller exited: {error}"
            ));
            return Ok(VendorExecution {
                outcome: OfficialOutcome::Unverified(0),
                warnings,
                app_groups,
                receipt_payloads: Vec::new(),
                observed_files: HashMap::new(),
                incomplete_application: Some((prepared.app, prepared.proof.installed.identifier)),
                post_uninstall_check: None,
            });
        }
    };
    Ok(VendorExecution {
        outcome: OfficialOutcome::Completed,
        warnings,
        app_groups,
        receipt_payloads,
        observed_files,
        incomplete_application: None,
        post_uninstall_check,
    })
}

enum RemovalObservation {
    OriginalLocationOccupied,
    ExecutableStillLinked,
    ExecutableUnlinked,
    InTrash(PathBuf),
}

// The vendor app can exit before a delegated removal finishes. Record any
// already-complete removal even if cancellation coincides with a normal exit.
fn verify_removal_after_exit(
    observe: impl Fn() -> io::Result<RemovalObservation>,
    cancel: &Cancellation,
) -> io::Result<Option<PathBuf>> {
    let deadline = Instant::now() + POST_EXIT_VERIFICATION_WINDOW;
    loop {
        let pending = match observe()? {
            RemovalObservation::ExecutableUnlinked => return Ok(None),
            RemovalObservation::InTrash(path) => return Ok(Some(path)),
            RemovalObservation::OriginalLocationOccupied => {
                "the original application location is still occupied"
            }
            RemovalObservation::ExecutableStillLinked => {
                "the original executable still has a link and could not be verified in your Trash"
            }
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(rejected(pending));
        }
        let check_cancelled = || {
            cancel.check().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::Interrupted,
                    format!("stopped waiting for removal: {pending}"),
                )
            })
        };
        check_cancelled()?;
        thread::sleep(OPEN_POLL_INTERVAL.min(remaining));
        check_cancelled()?;
    }
}

fn observe_original_removal(
    files: &UnixFiles,
    bundle: &File,
    executable: &File,
    executable_suffix: &Path,
) -> io::Result<RemovalObservation> {
    if executable.metadata()?.nlink() == 0 {
        return Ok(RemovalObservation::ExecutableUnlinked);
    }
    let trash = current_user_trash()?;
    match files.is_bundle_in_macos_trash(&trash, bundle, executable, executable_suffix) {
        Ok(true) => Ok(RemovalObservation::InTrash(trash)),
        Ok(false) => Ok(RemovalObservation::ExecutableStillLinked),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // A missing Trash directory or a removal in progress gives no
            // proof yet. A held executable can still become unlinked.
            Ok(RemovalObservation::ExecutableStillLinked)
        }
        Err(error) => Err(error),
    }
}

fn trash_recheck(
    files: &UnixFiles,
    trash: PathBuf,
    bundle: File,
    executable: File,
    executable_suffix: PathBuf,
) -> PostUninstallCheck {
    // Restoring from Trash can make the app usable at a different path.
    // Keep the held identities with the plan so this evidence can expire.
    let files = files.clone();
    Box::new(move |cancel| {
        cancel.check()?;
        // Emptying Trash can remove the last link to the same held executable.
        if executable.metadata()?.nlink() == 0 {
            return Ok(());
        }
        let observation =
            files.is_bundle_in_macos_trash(&trash, &bundle, &executable, &executable_suffix);
        // The Trash lookup can itself race with emptying it. The pinned
        // executable's last link disappearing establishes the same result.
        if !matches!(observation, Ok(true)) && executable.metadata()?.nlink() == 0 {
            return Ok(());
        }
        match observation {
            Ok(true) => Ok(()),
            Ok(false) => Err(Error::Rejected(
                "The original application is no longer verified in your Trash.".into(),
            )),
            Err(error) => Err(Error::Rejected(format!(
                "Could not recheck the original application in your Trash: {error}"
            ))),
        }
    })
}

fn current_user_trash() -> io::Result<PathBuf> {
    autoreleasepool(|_| {
        let url = NSFileManager::defaultManager()
            .URLForDirectory_inDomain_appropriateForURL_create_error(
                NSSearchPathDirectory::TrashDirectory,
                NSSearchPathDomainMask::UserDomainMask,
                None,
                false,
            )
            .map_err(|error| {
                io::Error::other(format!(
                    "could not locate your Trash: {}",
                    error.localizedDescription()
                ))
            })?;
        if !url.isFileURL() {
            return Err(rejected("macOS did not return a local Trash directory"));
        }
        url.to_file_path()
            .ok_or_else(|| rejected("macOS returned an invalid Trash path"))
    })
}

fn wait_for_open(
    mut child: Child,
    cancel: &Cancellation,
) -> std::result::Result<ExitStatus, String> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if cancel.check().is_err() => return stop_open(child),
            Ok(None) => thread::sleep(OPEN_POLL_INTERVAL),
            Err(error) => {
                let warning = format!(
                    "Could not observe the macOS launcher: {error}. The vendor uninstaller may still be running."
                );
                return Err(reap_in_background(child, warning));
            }
        }
    }
}

fn stop_open(mut child: Child) -> std::result::Result<ExitStatus, String> {
    // Signal only our launcher. Launch Services owns the vendor process.
    if let Err(error) = child.kill() {
        let mut warning = format!("{WAIT_CANCELLED} Could not stop the macOS launcher: {error}.");
        match child.try_wait() {
            Ok(Some(status)) if status.code().is_some() => return Ok(status),
            Ok(Some(_)) => return Err(warning),
            Ok(None) => {}
            Err(error) => warning.push_str(&format!(" Could not check its exit: {error}.")),
        }
        return Err(reap_in_background(child, warning));
    }
    match child.wait() {
        // SIGKILL cannot produce a normal exit code. A normal code means
        // the launcher exited on its own before the signal took effect.
        Ok(status) if status.code().is_some() => Ok(status),
        Ok(_) => Err(WAIT_CANCELLED.into()),
        Err(error) => Err(reap_in_background(
            child,
            format!("{WAIT_CANCELLED} Could not reap the macOS launcher: {error}."),
        )),
    }
}

fn reap_in_background(mut child: Child, mut warning: String) -> String {
    // A launcher that could not be stopped must not keep the queue waiting.
    match thread::Builder::new()
        .name("uninstallany-open-reaper".into())
        .spawn(move || child.wait())
    {
        Ok(reaper) => drop(reaper),
        Err(error) => warning.push_str(&format!(" Could not start a launcher reaper: {error}.")),
    }
    warning
}

/// Reviews a vendor action without launching anything or widening quarantine permissions.
pub(super) fn review(
    files: &UnixFiles,
    app: &AppRecord,
    application_roots: &[PathBuf],
) -> io::Result<Review> {
    let AppId::Package { manager, id } = &app.id else {
        return Ok(Review::default());
    };
    if manager != bundle::MANAGER || app.system_component {
        return Ok(Review::default());
    }
    let Some(identifier) = bundle::identifier_from_app_id(id) else {
        return Ok(Review::default());
    };
    let Some(path) = app.install_location.as_deref() else {
        return Ok(Review::default());
    };
    let mut candidates = Vec::new();
    let mut unavailable = None;
    for candidate in vendor_paths(path, application_roots) {
        match bundle::read(files, &candidate) {
            Ok(helper) if is_paired_identifier(identifier, &helper.identifier) => {
                candidates.push(helper);
            }
            Ok(_) => {}
            Err(error)
                if error.kind() == io::ErrorKind::InvalidData && candidate.starts_with(path) =>
            {
                files.require_trusted_local_directory(&candidate)?;
                unavailable.get_or_insert_with(|| {
                    format!(
                        "The embedded uninstaller candidate at {} has invalid bundle metadata.",
                        candidate.display(),
                    )
                });
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) => {}
            Err(error) => return Err(error),
        }
    }
    if candidates.is_empty() {
        return Ok(Review {
            prepared: None,
            unavailable,
        });
    }
    let installed = bundle::read(files, path)?;
    if installed.is_system()
        || installed.record().id != app.id
        || installed.version != app.version
        || installed.name != app.name
    {
        return Err(rejected(
            "the installed application changed during vendor review",
        ));
    }
    let mut signed_helpers = Vec::with_capacity(candidates.len());
    for helper in candidates {
        match signed_bundle(files, &helper)? {
            Ok(candidate) => signed_helpers.push(candidate),
            Err(reason) => {
                unavailable.get_or_insert_with(|| {
                    format!(
                        "The vendor uninstaller at {} cannot be used. {reason}",
                        helper.path.display(),
                    )
                });
            }
        }
    }
    if signed_helpers.is_empty() {
        // An embedded broken uninstaller can also break the outer bundle's
        // signature seal. No vendor action uses that seal in this case.
        return Ok(Review {
            prepared: None,
            unavailable,
        });
    }
    let installed = match signed_bundle(files, &installed)? {
        Ok(installed) => installed,
        Err(reason) => {
            return Ok(Review {
                prepared: None,
                unavailable: Some(format!(
                    "The installed application cannot be paired with a vendor uninstaller. {reason}"
                )),
            });
        }
    };
    let mut uninstaller = None;
    for candidate in signed_helpers {
        if installed.directory.owner != candidate.directory.owner
            || installed.directory.device != candidate.directory.device
            || installed.team != candidate.team
            || installed.code_directory_hash == candidate.code_directory_hash
        {
            unavailable.get_or_insert_with(|| format!(
                "The vendor uninstaller at {} could not be paired with the selected application.",
                candidate.path.display(),
            ));
            continue;
        }
        // A plist can claim a matching identifier. Only independently
        // verified companions can make launching the action ambiguous.
        if let Some(previous) = &uninstaller {
            if previous != &candidate {
                return Err(rejected(
                    "more than one vendor uninstaller passed verification",
                ));
            }
            continue;
        }
        uninstaller = Some(candidate);
    }
    match uninstaller {
        Some(uninstaller) => Ok(Review {
            prepared: Some(Prepared {
                app: app.clone(),
                proof: PairProof {
                    installed,
                    uninstaller,
                },
            }),
            unavailable: None,
        }),
        None => Ok(Review {
            prepared: None,
            unavailable,
        }),
    }
}

fn vendor_paths(bundle: &Path, application_roots: &[PathBuf]) -> Vec<PathBuf> {
    let Some(parent) = bundle.parent() else {
        return Vec::new();
    };
    let Some(stem) = bundle.file_stem().and_then(OsStr::to_str) else {
        return Vec::new();
    };
    if !bundle::is_app(bundle)
        || stem.is_empty()
        || stem.len() > MAX_APP_STEM_BYTES
        || stem.starts_with('.')
        || stem.chars().any(char::is_control)
    {
        return Vec::new();
    }
    let names = [
        format!("Uninstall {stem}.app"),
        format!("{stem} Uninstaller.app"),
    ];
    let helpers = bundle.join("Contents/Helpers");
    let resources = bundle.join("Contents/Resources");
    let mut paths: Vec<_> = [parent, helpers.as_path(), resources.as_path()]
        .into_iter()
        .flat_map(|directory| names.iter().map(move |name| directory.join(name)))
        .collect();
    paths.extend([
        helpers.join("Uninstaller.app"),
        resources.join("Uninstaller.app"),
    ]);
    // A generic name is plausible only in the application's own suite. The
    // paired identifier and both signatures are still checked independently.
    if macos_suite_bundle_location(application_roots, bundle) {
        paths.extend(SUITE_UNINSTALLER_NAMES.map(|name| parent.join(name)));
    }
    paths
}

fn is_paired_identifier(application: &str, uninstaller: &str) -> bool {
    [".uninstall", ".uninstaller"]
        .into_iter()
        .any(|suffix| uninstaller.strip_suffix(suffix) == Some(application))
}

type SignedBundleReview = std::result::Result<SignedBundle, &'static str>;

fn signed_bundle(files: &UnixFiles, bundle: &Bundle) -> io::Result<SignedBundleReview> {
    files.require_trusted_local_directory(&bundle.path)?;
    let root = fs::symlink_metadata(&bundle.path)?;
    if !root.is_dir() || root.mode() & 0o022 != 0 || fs::canonicalize(&bundle.path)? != bundle.path
    {
        return Err(rejected(
            "the bundle directory or permissions could not be verified",
        ));
    }
    let directory = Stamp::from(root);
    let Some(executable_path) = executable_path(files, bundle)? else {
        require_unchanged_bundle(&bundle.path, &directory)?;
        return Ok(Err(
            "Its main executable declaration is missing or invalid.",
        ));
    };
    let executable_parent = executable_path
        .parent()
        .ok_or_else(|| rejected("missing bundle executable directory"))?;
    let binary = match files
        .require_trusted_local_directory(executable_parent)
        .and_then(|()| fs::symlink_metadata(&executable_path))
    {
        Ok(binary) => binary,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            require_unchanged_bundle(&bundle.path, &directory)?;
            return Ok(Err("Its declared main executable is missing."));
        }
        Err(error) => return Err(error),
    };
    let can_verify_executable = binary.is_file()
        && binary.uid() == directory.owner
        && binary.dev() == directory.device
        && binary.nlink() == 1
        && binary.mode() & 0o111 != 0
        && binary.mode() & 0o6022 == 0
        && fs::canonicalize(&executable_path)? == executable_path
        && is_macho(&files.read_prefix(&executable_path, 4)?);
    let executable = Stamp::from(binary);
    let identity = if can_verify_executable {
        signed_identity(bundle, &executable_path)?
    } else {
        None
    };
    require_unchanged_bundle(&bundle.path, &directory)?;
    if Stamp::from(fs::symlink_metadata(&executable_path)?) != executable {
        return Err(rejected(
            "the bundle executable changed during verification",
        ));
    }
    let Some((team, code_directory_hash)) = identity else {
        let reason = if can_verify_executable {
            "Its Developer ID signature could not be verified."
        } else {
            "Its main executable does not meet the vendor launch requirements."
        };
        return Ok(Err(reason));
    };
    Ok(Ok(SignedBundle {
        path: bundle.path.clone(),
        identifier: bundle.identifier.clone(),
        team,
        code_directory_hash,
        directory,
        executable,
        executable_path,
    }))
}

fn require_unchanged_bundle(path: &Path, expected: &Stamp) -> io::Result<()> {
    if &Stamp::from(fs::symlink_metadata(path)?) == expected {
        Ok(())
    } else {
        Err(rejected("the bundle changed during verification"))
    }
}

fn executable_path(files: &UnixFiles, bundle: &Bundle) -> io::Result<Option<PathBuf>> {
    let info = files.read_regular(&bundle.path.join("Contents/Info.plist"), MAX_INFO_BYTES)?;
    let dictionary = plist::dictionary(&info)?;
    if plist::string(&dictionary, "CFBundleIdentifier").as_deref()
        != Some(bundle.identifier.as_str())
    {
        return Err(rejected(
            "the bundle identifier changed during verification",
        ));
    }
    let Some(name) = plist::string(&dictionary, "CFBundleExecutable") else {
        return Ok(None);
    };
    let name_path = Path::new(&name);
    if name_path.file_name() != Some(OsStr::new(&name))
        || name.starts_with('.')
        || name.chars().any(char::is_control)
    {
        return Ok(None);
    }
    Ok(Some(bundle.path.join("Contents/MacOS").join(name_path)))
}

fn is_macho(bytes: &[u8]) -> bool {
    matches!(
        bytes,
        [0xfe, 0xed, 0xfa, 0xce | 0xcf]
            | [0xce | 0xcf, 0xfa, 0xed, 0xfe]
            | [0xca, 0xfe, 0xba, 0xbe | 0xbf]
            | [0xbe | 0xbf, 0xba, 0xfe, 0xca]
    )
}

fn signed_identity(bundle: &Bundle, executable: &Path) -> io::Result<Option<(String, Vec<u8>)>> {
    let url = CFURL::from_path(&bundle.path, true)
        .ok_or_else(|| rejected("could not form a local code-signing URL"))?;
    let mut code = ptr::null();
    // SAFETY: URL and output pointer are live, and the non-null result is retained.
    let status = unsafe { SecStaticCodeCreateWithPath(url.as_concrete_TypeRef(), 0, &mut code) };
    if !code_signing_passed(status, "open the bundle for signature verification")? {
        return Ok(None);
    }
    if code.is_null() {
        return Err(io::Error::other(
            "signature verification returned no code object",
        ));
    }
    // SAFETY: A successful create call returned an owned Core Foundation reference.
    let code = unsafe { CFType::wrap_under_create_rule(code) };
    let requirement = compile_developer_id_requirement(&bundle.identifier, None)?;
    // Signing information can evaluate certificates. Configure the same
    // static code object for offline validation before querying it.
    // SAFETY: Both retained Security objects are live for this validation.
    let status = unsafe {
        SecStaticCodeCheckValidity(
            code.as_CFTypeRef(),
            SIGNING_PREFLIGHT_FLAGS,
            requirement.as_CFTypeRef(),
        )
    };
    if !code_signing_passed(status, "check the bundle's Developer ID requirement")? {
        return Ok(None);
    }

    let mut information = ptr::null();
    // SAFETY: the static code reference is valid, and the output pointer is writable.
    let status = unsafe {
        SecCodeCopySigningInformation(code.as_CFTypeRef(), SIGNING_INFORMATION, &mut information)
    };
    if !code_signing_passed(status, "read the bundle's signing information")? {
        return Ok(None);
    }
    if information.is_null() {
        return Err(io::Error::other(
            "signature verification returned no signing information",
        ));
    }
    // SAFETY: The Security framework returned a retained dictionary and process-lifetime keys.
    let (information, team_key, id_key, path_key, hash_key) = unsafe {
        (CFDictionary::<*const std::ffi::c_void, *const std::ffi::c_void>::wrap_under_create_rule(information),
        kSecCodeInfoTeamIdentifier, kSecCodeInfoIdentifier, kSecCodeInfoMainExecutable, kSecCodeInfoUnique)
    };
    let Some(team) = value::<CFString>(&information, team_key).map(|team| team.to_string()) else {
        return Ok(None);
    };
    let Some(id) = value::<CFString>(&information, id_key).map(|id| id.to_string()) else {
        return Ok(None);
    };
    let Some(hash) = value::<CFData>(&information, hash_key) else {
        return Ok(None);
    };
    let Some(signed_path) = value::<CFURL>(&information, path_key).and_then(|url| url.to_path())
    else {
        return Ok(None);
    };
    if !valid_signing_team(&team)
        || id != bundle.identifier
        || signed_path != executable
        || hash.bytes().is_empty()
    {
        return Ok(None);
    }
    let requirement = compile_developer_id_requirement(&id, Some(&team))?;
    // SAFETY: Code and requirement remain live. The flags enable strict offline validation.
    let status = unsafe {
        SecStaticCodeCheckValidity(
            code.as_CFTypeRef(),
            VALIDATE_FLAGS,
            requirement.as_CFTypeRef(),
        )
    };
    if !code_signing_passed(status, "validate the bundle's offline signature")? {
        return Ok(None);
    }
    Ok(Some((team, hash.bytes().to_vec())))
}

fn code_signing_passed(status: i32, operation: &str) -> io::Result<bool> {
    match status {
        0 => Ok(true),
        CODE_UNSIGNED | SIGNATURE_FAILED | REQUIREMENT_FAILED | BAD_BUNDLE_FORMAT => Ok(false),
        // Unknown failures can be permission, I/O or changed-object errors.
        // They cannot authorize switching to a different uninstall method.
        _ => Err(io::Error::other(format!(
            "could not {operation} (macOS status {status})"
        ))),
    }
}

fn valid_signing_team(team: &str) -> bool {
    team.len() == 10
        && team
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn compile_developer_id_requirement(identifier: &str, team: Option<&str>) -> io::Result<CFType> {
    if !bundle::valid_identifier(identifier) || team.is_some_and(|team| !valid_signing_team(team)) {
        return Err(rejected(
            "invalid Developer ID signing requirement identity",
        ));
    }
    let mut requirement = format!("{DEVELOPER_ID_REQUIREMENT} and identifier \"{identifier}\"");
    if let Some(team) = team {
        requirement.push_str(&format!(" and certificate leaf[subject.OU] = \"{team}\""));
    }
    let requirement = CFString::new(&requirement);
    let mut compiled = ptr::null();
    // SAFETY: The requirement is live and interpolated fields contain only bounded identifier characters.
    if unsafe {
        SecRequirementCreateWithString(requirement.as_concrete_TypeRef(), 0, &mut compiled)
    } != 0
        || compiled.is_null()
    {
        return Err(rejected(
            "could not compile the Developer ID signing requirement",
        ));
    }
    // SAFETY: Successful compilation yields a retained Core Foundation object.
    Ok(unsafe { CFType::wrap_under_create_rule(compiled) })
}

fn value<T: ConcreteCFType>(dictionary: &CFDictionary, key: CFStringRef) -> Option<T> {
    if key.is_null() {
        return None;
    }
    let found = dictionary.find(key.cast::<std::ffi::c_void>())?;
    // SAFETY: The dictionary retains this value, and the dynamic type is checked.
    unsafe { CFType::wrap_under_get_rule(*found) }.downcast_into::<T>()
}

#[cfg(feature = "privileged-inspection")]
pub(super) fn current_signing_team(expected_identifier: &str) -> Option<String> {
    let mut code = ptr::null();
    // SAFETY: The output pointer is writable and the call uses default flags.
    if unsafe { SecCodeCopySelf(0, &mut code) } != 0 || code.is_null() {
        return None;
    }
    // SAFETY: A successful copy gives an owned Security object.
    let code = unsafe { CFType::wrap_under_create_rule(code) };
    let requirement = compile_developer_id_requirement(expected_identifier, None).ok()?;
    // The dynamic check sets no-network validation on the static object
    // that the subsequent signing-information query obtains from this code.
    // SAFETY: The current code and its exact requirement remain live.
    if unsafe {
        SecCodeCheckValidity(
            code.as_CFTypeRef(),
            NO_NETWORK_ACCESS,
            requirement.as_CFTypeRef(),
        )
    } != 0
    {
        return None;
    }
    let mut info = ptr::null();
    // SAFETY: The code object is live and the output pointer is writable.
    if unsafe { SecCodeCopySigningInformation(code.as_CFTypeRef(), SIGNING_INFORMATION, &mut info) }
        != 0
        || info.is_null()
    {
        return None;
    }
    // SAFETY: Security returns an owned dictionary and constant field keys.
    let (info, id_key, team_key) = unsafe {
        (
            CFDictionary::wrap_under_create_rule(info),
            kSecCodeInfoIdentifier,
            kSecCodeInfoTeamIdentifier,
        )
    };
    if std::borrow::Cow::from(&value::<CFString>(&info, id_key)?).as_ref() != expected_identifier {
        return None;
    }
    let team = value::<CFString>(&info, team_key)?.to_string();
    valid_signing_team(&team).then_some(team)
}

fn rejected(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}
