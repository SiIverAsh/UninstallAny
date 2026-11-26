use std::{
    collections::{BTreeMap, HashSet},
    ffi::{OsStr, c_void},
    io::{self, BufRead, BufReader, Read},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Child, ChildStdout, Command, ExitStatus, Stdio},
    ptr, thread,
    time::{Duration, Instant},
};

use core_foundation::{
    array::CFArray,
    base::{CFAllocatorRef, CFOptionFlags, CFType, CFTypeRef, TCFType},
    data::CFData,
    date::{CFDate, CFDateRef},
    dictionary::CFDictionary,
    propertylist::{CFPropertyList, create_with_data, kCFPropertyListImmutable},
    string::{CFString, CFStringRef},
    timezone::CFTimeZone,
};
use sha2::{Digest, Sha256};
use uninstallany_core::{
    Access, AppId, AppRecord, Cancellation, Category, Error, Inventory, MatchKind, Proposal,
    Result, Risk, Scan, Target,
};
use uninstallany_unix::{UnixFiles, user_home};

use crate::{blessed_helpers, bundle, plist, scan};

pub(super) const MANAGER: &str = "apple-pkg-receipt";
pub(super) const DIRECTORY: &str = "/private/var/db/receipts";
const PKGUTIL: &str = "/usr/sbin/pkgutil";
const STARTUP: &str = "/";
const HOME_RECEIPT_PREFIX: &str = "home:";
const STARTUP_DATA: &str = "/System/Volumes/Data";
const MAX_RECEIPTS: usize = 4_096;
const MAX_RECEIPT_BYTES: usize = 1_048_576;
const MAX_BUNDLE_PLIST_BYTES: usize = 2 * 1024 * 1024;
const MAX_PAYLOAD_PROBES: usize = 8_192;
const MAX_PAYLOAD_CANDIDATES: usize = 1_024;
const MAX_PAYLOAD_PREVIEW_BYTES: usize = 1_048_576;
const MAX_BOM_QUERY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_BOM_LINE_BYTES: u64 = 4_097;
const MAX_QUERY_PACKAGES: usize = 48;
const MAX_VENDOR_FILE_CLAIMS: usize = 32;
const MAX_VENDOR_RECEIPTS: usize = 4;
const RECEIPT_QUERY_TIMEOUT: Duration = Duration::from_secs(12);
const BUNDLE_CHECK_TIMEOUT: Duration = Duration::from_secs(30);
const VENDOR_RECEIPT_TIMEOUT: Duration = Duration::from_secs(5);
const QUERY_POLL_INTERVAL: Duration = Duration::from_millis(20);
const SYSTEM_PAYLOAD_ROOTS: &[&str] = &[
    bundle::APPLICATIONS,
    blessed_helpers::HELPER_ROOT,
    "/Library/Audio/Plug-Ins",
    "/Library/Frameworks",
    "/Library/Java/JavaVirtualMachines",
    "/Library/PreferencePanes",
];

// CFDateFormatter.h defines the ISO year, month, and day option bits.
const ISO_COMPACT_DATE: CFOptionFlags = (1 << 0) | (1 << 1) | (1 << 4);
type CFDateFormatterRef = *mut c_void;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFDateFormatterCreateISO8601Formatter(
        allocator: CFAllocatorRef,
        options: CFOptionFlags,
    ) -> CFDateFormatterRef;
    fn CFDateFormatterCreateStringWithDate(
        allocator: CFAllocatorRef,
        formatter: CFDateFormatterRef,
        date: CFDateRef,
    ) -> CFStringRef;
    fn CFDateFormatterSetProperty(
        formatter: CFDateFormatterRef,
        key: CFStringRef,
        value: CFTypeRef,
    );
    static kCFDateFormatterTimeZone: CFStringRef;
}

pub(super) fn inventory(
    files: &UnixFiles,
    home: &Path,
    cancel: &Cancellation,
) -> Result<Inventory> {
    let mut warnings = Vec::new();
    let mut applications = startup_inventory(files, cancel, &mut warnings)?;
    match home_receipt_ids(home, cancel) {
        Ok(ids) => applications.extend(
            ids.iter()
                .map(|id| receipt_record(ReceiptScope::Home, id, None, None)),
        ),
        Err(error) => {
            cancel.check()?;
            warnings.push(format!(
                "could not read current-user installer receipts: {error}"
            ));
        }
    }
    Ok(Inventory {
        applications,
        warnings,
    })
}

/// Resolves a receipt within its own bounded catalog for a single-app action.
pub(super) fn lookup(
    files: &UnixFiles,
    home: &Path,
    id: &str,
    cancel: &Cancellation,
) -> Result<Option<AppRecord>> {
    let (scope, id) = ReceiptScope::decode(id);
    if !valid_identifier(id) {
        return Ok(None);
    }
    let present = match scope {
        ReceiptScope::Startup => startup_listing(cancel).map(|listing| {
            startup_ids(&listing)
                .take(MAX_RECEIPTS)
                .any(|listed| listed == id)
        }),
        ReceiptScope::Home => {
            home_receipt_ids(home, cancel).map(|ids| ids.iter().any(|listed| listed == id))
        }
    };
    cancel.check()?;
    let present = present.map_err(|error| {
        Error::Rejected(format!("could not look up installer receipt {id}: {error}"))
    })?;
    if !present {
        return Ok(None);
    }
    // The full inventory reports optional metadata warnings. A lookup
    // still returns the receipt when only that enrichment is unavailable.
    let mut warnings = Vec::new();
    let record = match scope {
        ReceiptScope::Startup => {
            startup_record(files, id, receipt_date_formatter().as_ref(), &mut warnings)
        }
        ReceiptScope::Home => receipt_record(scope, id, None, None),
    };
    cancel.check()?;
    Ok(Some(record))
}

#[derive(Clone, Copy)]
enum ReceiptScope {
    Startup,
    Home,
}

impl ReceiptScope {
    fn decode(id: &str) -> (Self, &str) {
        match id.strip_prefix(HOME_RECEIPT_PREFIX) {
            Some(id) => (Self::Home, id),
            None => (Self::Startup, id),
        }
    }

    fn volume(self, home: &Path) -> &Path {
        match self {
            Self::Startup => Path::new(STARTUP),
            Self::Home => home,
        }
    }
}

fn startup_inventory(
    files: &UnixFiles,
    cancel: &Cancellation,
    warnings: &mut Vec<String>,
) -> Result<Vec<AppRecord>> {
    cancel.check()?;
    let listing = match startup_listing(cancel) {
        Ok(listing) => listing,
        Err(error) => {
            cancel.check()?;
            warnings.push(format!(
                "could not read startup-volume installer receipts: {error}"
            ));
            return Ok(Vec::new());
        }
    };
    // Reuse a formatter for the whole inventory. ISO formatting keeps the
    // sortable date independent of the user's language and calendar.
    let date_formatter = receipt_date_formatter();
    let mut packages = Vec::new();
    for id in startup_ids(&listing) {
        cancel.check()?;
        if packages.len() == MAX_RECEIPTS {
            warnings.push("installer receipt enumeration reached its entry limit".into());
            break;
        }
        packages.push(startup_record(files, id, date_formatter.as_ref(), warnings));
    }
    Ok(packages)
}

fn startup_listing(cancel: &Cancellation) -> io::Result<String> {
    let listing = pkgutil(
        &[
            OsStr::new("--volume"),
            OsStr::new(STARTUP),
            OsStr::new("--pkgs"),
        ],
        cancel,
    )?;
    String::from_utf8(listing).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn startup_ids(listing: &str) -> impl Iterator<Item = &str> {
    listing.lines().filter(|id| valid_identifier(id))
}

fn home_receipt_ids(home: &Path, cancel: &Cancellation) -> io::Result<Vec<String>> {
    package_ids(home, cancel, Instant::now() + RECEIPT_QUERY_TIMEOUT)
}

fn startup_record(
    files: &UnixFiles,
    id: &str,
    date_formatter: Option<&CFType>,
    warnings: &mut Vec<String>,
) -> AppRecord {
    let path = Path::new(DIRECTORY).join(format!("{id}.plist"));
    let metadata = files
        .read_regular(&path, MAX_RECEIPT_BYTES)
        .and_then(|bytes| plist::dictionary(&bytes));
    let (version, install_date) = match metadata {
        Ok(record) if plist::string(&record, "PackageIdentifier").as_deref() == Some(id) => (
            plist::string(&record, "PackageVersion"),
            date_formatter.and_then(|formatter| receipt_install_date(&record, formatter)),
        ),
        Ok(_) => {
            warnings.push(format!("installer receipt identifier did not match {id}"));
            (None, None)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => (None, None),
        Err(error) => {
            warnings.push(format!(
                "could not read installer receipt metadata for {id}: {error}"
            ));
            (None, None)
        }
    };
    receipt_record(ReceiptScope::Startup, id, version, install_date)
}

fn receipt_record(
    scope: ReceiptScope,
    id: &str,
    version: Option<String>,
    install_date: Option<String>,
) -> AppRecord {
    // A package ID can exist in both catalogs. Keep startup-volume IDs
    // compatible and distinguish home receipts without encoding a path.
    let (record_id, name) = match scope {
        ReceiptScope::Startup => (id.to_owned(), id.to_owned()),
        ReceiptScope::Home => (format!("{HOME_RECEIPT_PREFIX}{id}"), format!("{id} (~)")),
    };
    AppRecord {
        id: AppId::Package {
            manager: MANAGER.into(),
            id: record_id,
        },
        name,
        publisher: None,
        version,
        install_location: None,
        size_bytes: None,
        install_date,
        system_component: id.to_ascii_lowercase().starts_with("com.apple."),
        official_uninstall_available: false,
    }
}

fn receipt_date_formatter() -> Option<CFType> {
    // SAFETY: A null allocator requests the system default. The documented
    // flags select year, month, and day in the formatter.
    let formatter = unsafe { CFDateFormatterCreateISO8601Formatter(ptr::null(), ISO_COMPACT_DATE) };
    if formatter.is_null() {
        return None;
    }
    let utc = CFTimeZone::new(0.0);
    // SAFETY: The formatter and UTC zone are live. The framework property
    // key expects a CFTimeZone value.
    unsafe {
        CFDateFormatterSetProperty(formatter, kCFDateFormatterTimeZone, utc.as_CFTypeRef());
    }
    // SAFETY: The create rule gives ownership of the non-null CF object.
    Some(unsafe { CFType::wrap_under_create_rule(formatter.cast_const()) })
}

fn receipt_install_date(record: &CFDictionary, formatter: &CFType) -> Option<String> {
    let key = CFString::new("InstallDate");
    let value = record.find(key.as_CFTypeRef())?;
    // SAFETY: The live property list retains the borrowed dictionary value.
    let value = unsafe { CFType::wrap_under_get_rule(*value) };
    let date = value.downcast_into::<CFDate>()?;
    if !date.abs_time().is_finite() {
        return None;
    }
    // SAFETY: The formatter was created by Core Foundation and both objects
    // remain live. A null allocator requests the system default.
    let formatted = unsafe {
        CFDateFormatterCreateStringWithDate(
            ptr::null(),
            formatter.as_CFTypeRef().cast_mut(),
            date.as_concrete_TypeRef(),
        )
    };
    if formatted.is_null() {
        return None;
    }
    // SAFETY: Core Foundation returned an owned, non-null CFString.
    let formatted = unsafe { CFString::wrap_under_create_rule(formatted) }.to_string();
    (formatted.len() == 8 && formatted.bytes().all(|byte| byte.is_ascii_digit()))
        .then_some(formatted)
}

/// Returns receipt-listed paths as references to existing guarded filesystem objects.
pub(super) fn scan(
    files: &UnixFiles,
    home: &Path,
    app: &AppRecord,
    cancel: &Cancellation,
) -> Result<Scan> {
    let AppId::Package { manager, id } = &app.id else {
        return Err(Error::Rejected(
            "expected an Apple Installer receipt".into(),
        ));
    };
    let (scope, id) = ReceiptScope::decode(id);
    if manager != MANAGER
        || !valid_identifier(id)
        || app.system_component
        || id.to_ascii_lowercase().starts_with("com.apple.")
    {
        return Err(Error::Rejected(
            "protected or invalid Apple Installer receipt".into(),
        ));
    }

    let mut scan = Scan::new(
        Vec::new(),
        vec!["Installer receipts describe payloads. Use the vendor's uninstaller for package-managed files.".into()],
    );
    let volume = scope.volume(home);
    let base = match install_base(app, volume, id, cancel) {
        Ok(base) => base,
        Err(error) => {
            cancel.check()?;
            scan.warnings
                .push(format!("could not verify installer receipt {id}: {error}"));
            return Ok(scan);
        }
    };
    let entries = match query_receipt(volume, "--files", id, cancel, read_payload_preview) {
        Ok(entries) => entries,
        Err(error) => {
            cancel.check()?;
            scan.warnings
                .push(format!("could not read receipt payload for {id}: {error}"));
            return Ok(scan);
        }
    };

    let PayloadPreview {
        paths,
        mut omitted,
        mut limited,
    } = entries;
    let mut seen = HashSet::new();
    let mut warned_about_system_probe = false;
    for relative in &paths {
        cancel.check()?;
        if scan.proposals.len() == MAX_PAYLOAD_CANDIDATES {
            limited = true;
            break;
        }
        if !seen.insert(relative) {
            continue;
        }
        let path = base.join(relative);
        let in_system_tree = path.starts_with(bundle::APPLICATIONS) || path.starts_with("/Library");
        let result = if in_system_tree {
            if !is_system_payload_path(&path) {
                omitted += 1;
                continue;
            }
            UnixFiles::probe_macos_installer_system_target(&path)
        } else {
            files.probe_discovery_target(&path)
        };
        let target = match result {
            Ok(Some(target)) => target,
            Err(error)
                if in_system_tree
                    && !warned_about_system_probe
                    && !matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                    ) =>
            {
                scan.warnings.push(format!(
                    "Could not inspect system payload path {} for receipt {id}: {error}",
                    path.display()
                ));
                warned_about_system_probe = true;
                omitted += 1;
                continue;
            }
            _ => {
                omitted += 1;
                continue;
            }
        };
        scan.proposals.push(Proposal {
            target: Target::File(target.path),
            category: target.category,
            evidence: MatchKind::ExactIdentity,
            reason: format!("this path is listed in Installer receipt {id}"),
            risk: Risk::High,
            access: Access::ReadOnly("Installer receipt entries remain package-managed".into()),
        });
    }
    if limited {
        scan.warnings.push(format!(
            "receipt payload discovery reached its limit for {id}"
        ));
    }
    if omitted > 0 {
        scan.warnings.push(format!(
            "{omitted} receipt payload paths were unavailable, unsupported, or outside the preview scope"
        ));
    }
    Ok(scan)
}

fn is_system_payload_path(path: &Path) -> bool {
    SYSTEM_PAYLOAD_ROOTS.iter().any(|root| {
        path.strip_prefix(root)
            .is_ok_and(|relative| !relative.as_os_str().is_empty())
    }) || scan::is_system_library_residual_path(path)
}

struct PayloadPreview {
    paths: Vec<PathBuf>,
    omitted: usize,
    limited: bool,
}

/// A bounded Installer payload associated with the original vendor app.
pub(super) struct VendorPayload {
    id: String,
    base: PathBuf,
    entries: PayloadPreview,
}

/// Captures startup-volume receipts that explicitly list both app anchors.
pub(super) fn capture_vendor_payloads(
    application: &Path,
    executable: &Path,
    cancel: &Cancellation,
    warnings: &mut Vec<String>,
) -> io::Result<Vec<VendorPayload>> {
    require_startup_data(application)?;
    let deadline = Instant::now() + VENDOR_RECEIPT_TIMEOUT;
    let info = application.join("Contents/Info.plist");
    let metadata_claims = vendor_file_claims(&info, cancel, deadline)?;
    if metadata_claims.is_empty() {
        return Ok(Vec::new());
    }
    let executable_claims = vendor_file_claims(executable, cancel, deadline)?;
    let mut shared = metadata_claims
        .into_iter()
        .filter(|(id, version)| executable_claims.get(id) == Some(version));
    let mut payloads = Vec::new();
    for (id, version) in shared.by_ref().take(MAX_VENDOR_RECEIPTS) {
        cancel.check().map_err(io::Error::other)?;
        match capture_vendor_payload(&id, &version, [&info, executable], cancel, deadline) {
            Ok(payload) => payloads.push(payload),
            Err(error) => warnings.push(format!(
                "Could not capture Installer receipt {id} before uninstall: {error}"
            )),
        }
    }
    if shared.next().is_some() {
        warnings.push("Associated Installer receipt discovery reached its entry limit.".into());
    }
    Ok(payloads)
}

fn vendor_file_claims(
    path: &Path,
    cancel: &Cancellation,
    deadline: Instant,
) -> io::Result<BTreeMap<String, String>> {
    let bytes = run_query(
        &[
            OsStr::new("--volume"),
            OsStr::new(STARTUP),
            OsStr::new("--file-info-plist"),
            path.as_os_str(),
        ],
        cancel,
        deadline,
        read_query_bytes,
    )?;
    parse_vendor_file_claims(&bytes, path)
}

fn parse_vendor_file_claims(data: &[u8], path: &Path) -> io::Result<BTreeMap<String, String>> {
    let entries = anchor_path_info(data, path)?;
    if usize::try_from(entries.len()).map_or(true, |len| len > MAX_VENDOR_FILE_CLAIMS) {
        return Err(invalid(
            "installer path info exceeds the receipt claim limit",
        ));
    }
    let mut claims = BTreeMap::new();
    for entry in &entries {
        // SAFETY: The array retains this property-list value while we read it.
        let entry = unsafe { CFType::wrap_under_get_rule(*entry) };
        let entry = entry
            .downcast_into::<CFDictionary>()
            .ok_or_else(|| invalid("invalid installer path claim"))?;
        let id = plist::string(&entry, "pkgid")
            .filter(|id| valid_identifier(id))
            .ok_or_else(|| invalid("invalid package identifier in installer path info"))?;
        let normalized = id.to_ascii_lowercase();
        if normalized == "com.apple" || normalized.starts_with("com.apple.") {
            continue;
        }
        // A dash is pkgutil's sentinel when the receipt has no version.
        let Some(version) =
            plist::string(&entry, "pkg-version").filter(|value| !value.is_empty() && value != "-")
        else {
            continue;
        };
        if claims.insert(id, version).is_some() {
            return Err(invalid("ambiguous duplicate installer path claim"));
        }
    }
    Ok(claims)
}

fn capture_vendor_payload(
    id: &str,
    version: &str,
    anchors: [&Path; 2],
    cancel: &Cancellation,
    deadline: Instant,
) -> io::Result<VendorPayload> {
    let volume = Path::new(STARTUP);
    let info_args = grouped_query(volume, "--pkg-info", &[id]);
    let info = run_query(&info_args, cancel, deadline, read_query_bytes)?;
    let text = std::str::from_utf8(&info).map_err(|_| invalid("invalid receipt metadata"))?;
    let base = parse_install_base(Some(version), id, volume, text)?;
    let entries = run_query(
        &grouped_query(volume, "--files", &[id]),
        cancel,
        deadline,
        read_payload_preview,
    )?;
    if !anchors.iter().all(|anchor| {
        anchor
            .strip_prefix(&base)
            .is_ok_and(|relative| entries.paths.iter().any(|path| path == relative))
    }) {
        return Err(invalid(
            "the bounded payload did not list both application anchors",
        ));
    }
    // Re-read full scope metadata, including install time, around the BOM query.
    // The stored paths are a historical reference even if the vendor forgets the receipt.
    if run_query(&info_args, cancel, deadline, read_query_bytes)? != info {
        return Err(invalid("the receipt metadata changed during capture"));
    }
    Ok(VendorPayload {
        id: id.into(),
        base,
        entries,
    })
}

/// Displays surviving system-wide paths from the pre-uninstall payloads.
pub(super) fn vendor_payload_residuals(
    payloads: Vec<VendorPayload>,
    cancel: &Cancellation,
) -> Result<Scan> {
    let mut scan = Scan::default();
    let mut seen = HashSet::new();
    for payload in payloads {
        let PayloadPreview { paths, limited, .. } = payload.entries;
        let mut warned_about_probe_failure = false;
        if limited {
            scan.warnings.push(format!(
                "Pre-uninstall payload discovery reached its limit for receipt {}.",
                payload.id
            ));
        }
        for relative in paths {
            cancel.check()?;
            let path = payload.base.join(relative);
            // This supplements the existing application scan with system-wide
            // receipt references. User Library data has its own ownership checks.
            if !is_system_payload_path(&path) {
                continue;
            }
            if seen.contains(&path) {
                continue;
            }
            if seen.len() == MAX_PAYLOAD_PROBES || scan.proposals.len() == MAX_PAYLOAD_CANDIDATES {
                scan.warnings
                    .push("Associated Installer residual preview reached its entry limit.".into());
                return Ok(scan);
            }
            let probe = UnixFiles::probe_macos_installer_system_target(&path);
            seen.insert(path);
            let target = match probe {
                Ok(Some(target)) => target,
                Ok(None) => continue,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                    ) =>
                {
                    continue;
                }
                Err(error) => {
                    if !warned_about_probe_failure {
                        scan.warnings.push(format!(
                            "Some paths in pre-uninstall Installer receipt {} could not be inspected: {error}",
                            payload.id
                        ));
                        warned_about_probe_failure = true;
                    }
                    continue;
                }
            };
            scan.proposals.push(Proposal {
                target: Target::File(target.path),
                category: target.category,
                evidence: MatchKind::ExactIdentity,
                reason: format!(
                    "the path was listed in pre-uninstall Installer receipt {}",
                    payload.id
                ),
                risk: Risk::High,
                access: Access::ReadOnly(
                    "the receipt does not establish current exclusive ownership".into(),
                ),
            });
        }
    }
    Ok(scan)
}

fn read_payload_preview(stdout: impl Read) -> io::Result<PayloadPreview> {
    let mut stdout = BufReader::new(stdout).take(MAX_BOM_QUERY_BYTES + 1);
    let mut preview = PayloadPreview {
        paths: Vec::new(),
        omitted: 0,
        limited: false,
    };
    let mut bytes_kept = 0;
    let mut line = Vec::new();
    for _ in 0..MAX_PAYLOAD_PROBES {
        line.clear();
        let count = (&mut stdout)
            .take(MAX_BOM_LINE_BYTES)
            .read_until(b'\n', &mut line)?;
        if count == 0 {
            break;
        }
        let Some(entry) = line.strip_suffix(b"\n") else {
            // Drain the remaining bytes of an oversized line before
            // interpreting anything else as a path.
            stdout.skip_until(b'\n')?;
            preview.omitted += 1;
            continue;
        };
        let entry = entry.strip_suffix(b"\r").unwrap_or(entry);
        if entry == b"." {
            continue;
        }
        let relative = std::str::from_utf8(entry)
            .ok()
            .and_then(|entry| payload_path(entry.strip_prefix("./").unwrap_or(entry)));
        let Some(relative) = relative else {
            preview.omitted += 1;
            continue;
        };
        bytes_kept += relative.as_os_str().as_encoded_bytes().len();
        if bytes_kept > MAX_PAYLOAD_PREVIEW_BYTES {
            preview.limited = true;
            break;
        }
        preview.paths.push(relative.to_path_buf());
    }
    // Drain the rest within the transport limit so pkgutil can exit normally
    // even when its listing is larger than this read-only preview.
    preview.limited |= io::copy(&mut stdout, &mut io::sink())? > 0;
    if stdout.limit() == 0 {
        return Err(invalid("installer file listing exceeded its byte limit"));
    }
    Ok(preview)
}

fn install_base(
    app: &AppRecord,
    volume: &Path,
    id: &str,
    cancel: &Cancellation,
) -> io::Result<PathBuf> {
    // The documented plist output has varied between OS versions. The textual
    // record's volume, identity and location fields are explicit.
    let info = query_receipt(volume, "--pkg-info", id, cancel, read_query_bytes)?;
    let info = String::from_utf8(info)
        .map_err(|_| invalid("installer receipt data is not valid UTF-8"))?;
    parse_install_base(app.version.as_deref(), id, volume, &info)
}

fn parse_install_base(
    expected_version: Option<&str>,
    id: &str,
    scope: &Path,
    info: &str,
) -> io::Result<PathBuf> {
    let (mut package, mut volume, mut location, mut version) = (None, None, None, None);
    for line in info.lines() {
        if line.is_empty() {
            continue;
        }
        let (field, value) = line
            .split_once(": ")
            .ok_or_else(|| invalid("invalid receipt metadata field"))?;
        let slot = match field {
            "package-id" => &mut package,
            "volume" => &mut volume,
            "location" => &mut location,
            "version" => &mut version,
            _ => continue,
        };
        if slot.replace(value).is_some() {
            return Err(invalid("the installer receipt contains duplicate metadata"));
        }
    }
    let volume = volume.ok_or_else(|| invalid("the installer receipt has no volume"))?;
    if package != Some(id)
        || Path::new(volume) != scope
        || expected_version.is_some_and(|expected| version != Some(expected))
    {
        return Err(invalid(
            "the receipt identity or query volume could not be verified",
        ));
    }
    let location =
        location.ok_or_else(|| invalid("the installer receipt has no install location"))?;
    if matches!(location, "." | "/") {
        return Ok(scope.to_path_buf());
    }
    let location = location.strip_suffix('/').unwrap_or(location);
    let relative = location.strip_prefix('/').unwrap_or(location);
    let relative =
        payload_path(relative).ok_or_else(|| invalid("invalid receipt install location"))?;
    if scope != Path::new(STARTUP) && Path::new(STARTUP).join(relative).starts_with(scope) {
        // A home receipt that repeats its volume in the install location
        // could describe either of two trees. Disallow the bundle move.
        return Err(invalid(
            "the home receipt has an ambiguous install location",
        ));
    }
    Ok(scope.join(relative))
}

fn payload_path(path: &str) -> Option<&Path> {
    (path.len() <= 4_096
        && !path.chars().any(char::is_control)
        && path.split('/').all(|part| !matches!(part, "" | "." | "..")))
    .then(|| Path::new(path))
}

fn query_receipt<T: Send>(
    volume: &Path,
    operation: &str,
    id: &str,
    cancel: &Cancellation,
    reader: impl FnOnce(ChildStdout) -> io::Result<T> + Send,
) -> io::Result<T> {
    let args = [
        OsStr::new("--volume"),
        volume.as_os_str(),
        OsStr::new(operation),
        OsStr::new(id),
    ];
    run_query(
        &args,
        cancel,
        Instant::now() + RECEIPT_QUERY_TIMEOUT,
        reader,
    )
}

/// Checks the bundle anchors and the relevant Installer receipt scopes.
pub(super) fn has_no_claim(
    files: &UnixFiles,
    path: &Path,
    cancel: &Cancellation,
) -> io::Result<bool> {
    let deadline = Instant::now() + BUNDLE_CHECK_TIMEOUT;
    let info_path = path.join("Contents/Info.plist");
    require_anchor(files, path, Category::Directory)?;
    require_startup_data(path)?;
    require_anchor(files, &info_path, Category::File)?;
    let dictionary = plist::dictionary(&files.read_regular(&info_path, MAX_BUNDLE_PLIST_BYTES)?)?;
    let executable = plist::string(&dictionary, "CFBundleExecutable")
        .filter(|name| valid_executable_name(name))
        .ok_or_else(|| invalid("missing or invalid bundle executable name"))?;
    let executable_path = path.join("Contents/MacOS").join(executable);
    require_anchor(files, &executable_path, Category::File)?;

    let anchors = [path, info_path.as_path(), executable_path.as_path()];
    let home = user_home()?;
    let home_scope = path.starts_with(&home).then_some(home.as_path());
    let Some(first) = claim_snapshot(path, anchors, home_scope, cancel, deadline)? else {
        return Ok(false);
    };
    let Some(second) = claim_snapshot(path, anchors, home_scope, cancel, deadline)? else {
        return Ok(false);
    };
    // Installer can replace a receipt without changing its package ID.
    if first != second {
        return Err(invalid(
            "installer receipt evidence changed during the bundle check",
        ));
    }
    Ok(true)
}

fn claim_snapshot(
    path: &Path,
    anchors: [&Path; 3],
    home_scope: Option<&Path>,
    cancel: &Cancellation,
    deadline: Instant,
) -> io::Result<Option<[u8; 32]>> {
    let mut evidence = Sha256::new();
    for item in anchors {
        let data = run_query(
            &[
                OsStr::new("--volume"),
                OsStr::new(STARTUP),
                OsStr::new("--file-info-plist"),
                item.as_os_str(),
            ],
            cancel,
            deadline,
            read_query_bytes,
        )?;
        if anchor_has_claim(&data, item)? {
            return Ok(None);
        }
        hash_evidence(&mut evidence, &data);
    }
    for volume in [Some(Path::new(STARTUP)), home_scope].into_iter().flatten() {
        if has_bom_claim(path, volume, cancel, deadline, &mut evidence)? {
            return Ok(None);
        }
    }
    Ok(Some(evidence.finalize().into()))
}

fn hash_evidence(evidence: &mut Sha256, bytes: &[u8]) {
    evidence.update(bytes.len().to_le_bytes());
    evidence.update(bytes);
}

fn anchor_has_claim(data: &[u8], path: &Path) -> io::Result<bool> {
    Ok(!anchor_path_info(data, path)?.is_empty())
}

fn anchor_path_info(data: &[u8], path: &Path) -> io::Result<CFArray> {
    let record = plist::dictionary(data)?;
    let path_field = plist::string(&record, "path");
    if path_field.as_deref().map(Path::new) != Some(path) {
        return Err(invalid("receipt file query returned another path"));
    }
    let key = CFString::new("path-info");
    let array = record
        .find(key.as_CFTypeRef())
        .ok_or_else(|| invalid("missing receipt path info"))?;
    // SAFETY: The dictionary retains this untyped CF value. The array's
    // runtime type is checked before it is read.
    let array = unsafe { CFType::wrap_under_get_rule(*array) };
    array
        .downcast_into::<CFArray>()
        .ok_or_else(|| invalid("invalid receipt path info"))
}

fn require_startup_data(path: &Path) -> io::Result<()> {
    let data = std::fs::symlink_metadata(STARTUP_DATA)?;
    let target = std::fs::symlink_metadata(path)?;
    if !data.is_dir() || !target.is_dir() || data.dev() != target.dev() {
        return Err(invalid(
            "installer receipt checks require the startup data volume",
        ));
    }
    Ok(())
}

fn has_bom_claim(
    path: &Path,
    volume: &Path,
    cancel: &Cancellation,
    deadline: Instant,
    evidence: &mut Sha256,
) -> io::Result<bool> {
    let target = volume_relative_parts(path)?;
    let listing = package_ids(volume, cancel, deadline)?;
    let packages: Vec<_> = listing.iter().map(String::as_str).collect();
    hash_evidence(evidence, volume.as_os_str().as_encoded_bytes());
    hash_evidence(evidence, &packages.len().to_le_bytes());
    for id in &listing {
        hash_evidence(evidence, id.as_bytes());
    }

    // Every package in a group uses an install location at the same depth.
    // Its relative paths therefore share the same candidate suffix, regardless
    // of the order in which pkgutil emits the grouped file lists.
    let mut sharing_prefix: BTreeMap<usize, Vec<&str>> = BTreeMap::new();
    for batch in packages.chunks(MAX_QUERY_PACKAGES) {
        let args = grouped_query(volume, "--pkg-info", batch);
        let info = run_query(&args, cancel, deadline, read_query_bytes)?;
        hash_evidence(evidence, &info);
        let info = std::str::from_utf8(&info).map_err(|_| invalid("invalid receipt metadata"))?;
        let mut metadata = info.split_inclusive('\n').peekable();
        for id in batch {
            let mut record = metadata
                .next()
                .filter(|line| {
                    line.strip_prefix("package-id: ")
                        .is_some_and(|value| value.trim_end() == *id)
                })
                .ok_or_else(|| invalid("receipt metadata did not match the requested package"))?
                .to_owned();
            while metadata
                .peek()
                .is_some_and(|line| !line.starts_with("package-id: "))
            {
                if let Some(line) = metadata.next() {
                    record.push_str(line);
                }
            }
            let base = parse_install_base(None, id, volume, &record)?;
            let base = volume_relative_parts(&base)?;
            if might_have_prefix(base.iter().copied(), &target) {
                return Ok(true);
            }
            if might_have_prefix(target.iter().copied(), &base) {
                sharing_prefix.entry(base.len()).or_default().push(id);
            }
        }
        if metadata.next().is_some() {
            return Err(invalid("pkgutil returned unexpected receipt metadata"));
        }
    }

    for (depth, packages) in sharing_prefix {
        let suffix = &target[depth..];
        for batch in packages.chunks(MAX_QUERY_PACKAGES) {
            let args = grouped_query(volume, "--files", batch);
            let (claimed, digest) = run_query(&args, cancel, deadline, |stdout| {
                contains_relative_path(stdout, suffix)
            })?;
            if claimed {
                return Ok(true);
            }
            hash_evidence(evidence, &digest);
        }
    }
    if package_ids(volume, cancel, deadline)? != listing {
        return Err(invalid(
            "installer receipts changed during the bundle check",
        ));
    }
    Ok(false)
}

fn package_ids(volume: &Path, cancel: &Cancellation, deadline: Instant) -> io::Result<Vec<String>> {
    let listing = run_query(
        &[
            OsStr::new("--volume"),
            volume.as_os_str(),
            OsStr::new("--pkgs-plist"),
        ],
        cancel,
        deadline,
        read_query_bytes,
    )?;
    let (raw, _) = create_with_data(CFData::from_buffer(&listing), kCFPropertyListImmutable)
        .map_err(|_| invalid("invalid receipt inventory property list"))?;
    // SAFETY: A successful property-list decode gives an owned non-null value.
    let property = unsafe { CFPropertyList::wrap_under_create_rule(raw) };
    let entries = property
        .downcast_into::<CFArray>()
        .ok_or_else(|| invalid("the receipt inventory is not an array"))?;
    if usize::try_from(entries.len()).map_or(true, |len| len > MAX_RECEIPTS) {
        return Err(invalid("the receipt inventory exceeds the entry limit"));
    }
    let mut ids = Vec::new();
    for entry in &entries {
        // SAFETY: The array retains a property-list value at this index.
        let value = unsafe { CFType::wrap_under_get_rule(*entry) };
        let id = value
            .downcast_into::<CFString>()
            .ok_or_else(|| invalid("invalid receipt inventory identifier type"))?
            .to_string();
        if !valid_identifier(&id) {
            return Err(invalid("invalid receipt inventory identifier"));
        }
        ids.push(id);
    }
    ids.sort_unstable();
    if ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid(
            "the receipt inventory contains duplicate identifiers",
        ));
    }
    Ok(ids)
}

fn grouped_query<'a>(volume: &'a Path, operation: &'a str, packages: &[&'a str]) -> Vec<&'a OsStr> {
    let mut args = vec![OsStr::new("--volume"), volume.as_os_str()];
    for &id in packages {
        args.extend([OsStr::new(operation), OsStr::new(id)]);
    }
    args
}

fn volume_relative_parts(path: &Path) -> io::Result<Vec<&str>> {
    let absolute = path
        .to_str()
        .ok_or_else(|| invalid("receipt path is not valid UTF-8"))?;
    let relative = absolute
        .strip_prefix('/')
        .ok_or_else(|| invalid("receipt path is not absolute"))?;
    let relative = without_startup_alias(relative);
    if relative.is_empty() {
        return Ok(Vec::new());
    }
    payload_path(relative).ok_or_else(|| invalid("invalid startup volume path"))?;
    Ok(relative.split('/').collect())
}

fn without_startup_alias(path: &str) -> &str {
    let alias = &STARTUP_DATA[1..];
    if path
        .get(..alias.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(alias))
    {
        let tail = &path[alias.len()..];
        if tail.is_empty() {
            return tail;
        }
        if let Some(relative) = tail.strip_prefix('/') {
            return relative;
        }
    }
    path
}

fn might_have_prefix<'a>(mut path: impl Iterator<Item = &'a str>, prefix: &[&str]) -> bool {
    prefix.iter().all(|expected| {
        path.next().is_some_and(|part| {
            // Case and Unicode normalization differ between APFS volumes.
            // Uncertain spellings may block a move, never permit one.
            part.eq_ignore_ascii_case(expected) || !part.is_ascii() || !expected.is_ascii()
        })
    })
}

fn contains_relative_path(stdout: impl Read, suffix: &[&str]) -> io::Result<(bool, [u8; 32])> {
    let mut stdout = BufReader::new(stdout).take(MAX_BOM_QUERY_BYTES + 1);
    let mut claimed = false;
    let mut evidence = Sha256::new();
    let mut line = String::new();
    loop {
        line.clear();
        let bytes = (&mut stdout)
            .take(MAX_BOM_LINE_BYTES)
            .read_line(&mut line)?;
        if bytes == 0 {
            return Ok((claimed, evidence.finalize().into()));
        }
        if stdout.limit() == 0 || !line.ends_with('\n') {
            return Err(invalid(
                "installer file listing exceeded its byte or line limit",
            ));
        }
        evidence.update(line.as_bytes());
        let entry = line.trim_end_matches('\n');
        if entry == "." {
            continue;
        }
        let relative = entry.strip_prefix("./").unwrap_or(entry);
        payload_path(relative).ok_or_else(|| invalid("invalid receipt payload path"))?;
        let canonical = without_startup_alias(relative);
        claimed |= might_have_prefix(relative.split('/'), suffix)
            || might_have_prefix(canonical.split('/'), suffix);
    }
}

fn require_anchor(files: &UnixFiles, path: &Path, category: Category) -> io::Result<()> {
    if files
        .probe_discovery_target(path)?
        .is_some_and(|target| target.category == category)
    {
        Ok(())
    } else {
        Err(invalid(
            "bundle receipt anchor is linked, mounted, or not of the expected kind",
        ))
    }
}

fn valid_executable_name(name: &str) -> bool {
    name.len() <= 255
        && !matches!(name, "." | "..")
        && !name.contains('/')
        && !name.chars().any(char::is_control)
}

fn pkgutil(args: &[&OsStr], cancel: &Cancellation) -> io::Result<Vec<u8>> {
    run_query(
        args,
        cancel,
        Instant::now() + RECEIPT_QUERY_TIMEOUT,
        read_query_bytes,
    )
}

fn read_query_bytes(stdout: ChildStdout) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    stdout
        .take(MAX_RECEIPT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_RECEIPT_BYTES {
        return Err(invalid("pkgutil output exceeds the receipt byte limit"));
    }
    Ok(bytes)
}

fn run_query<T: Send>(
    args: &[&OsStr],
    cancel: &Cancellation,
    deadline: Instant,
    read_stdout: impl FnOnce(ChildStdout) -> io::Result<T> + Send,
) -> io::Result<T> {
    cancel.check().map_err(io::Error::other)?;
    let deadline = deadline.min(Instant::now() + RECEIPT_QUERY_TIMEOUT);
    if Instant::now() >= deadline {
        return Err(receipt_timeout());
    }
    let mut child = Command::new(PKGUTIL)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing pkgutil output pipe"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("missing pkgutil diagnostics pipe"))?;
    thread::scope(|scope| {
        let output = scope.spawn(move || read_stdout(stdout));
        let diagnostics = scope.spawn(move || stderr.take(1).read(&mut [0; 1]));
        let status = wait_for_pkgutil(&mut child, cancel, deadline)?;
        let output = output
            .join()
            .map_err(|_| io::Error::other("installer receipt reader stopped"))??;
        let diagnostic_bytes = diagnostics
            .join()
            .map_err(|_| io::Error::other("installer receipt diagnostics reader stopped"))??;
        cancel.check().map_err(io::Error::other)?;
        if Instant::now() >= deadline {
            return Err(receipt_timeout());
        }
        if !status.success() {
            return Err(io::Error::other(format!("pkgutil returned {status}")));
        }
        if diagnostic_bytes != 0 {
            return Err(invalid(
                "pkgutil reported diagnostics instead of an unambiguous receipt result",
            ));
        }
        Ok(output)
    })
}

fn wait_for_pkgutil(
    child: &mut Child,
    cancel: &Cancellation,
    deadline: Instant,
) -> io::Result<ExitStatus> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        let error = if matches!(cancel.check(), Err(Error::Cancelled)) {
            Some(io::Error::new(
                io::ErrorKind::Interrupted,
                "installer receipt query cancelled",
            ))
        } else if Instant::now() >= deadline {
            Some(receipt_timeout())
        } else {
            None
        };
        if let Some(error) = error {
            if let Err(kill_error) = child.kill() {
                if child.try_wait()?.is_none() {
                    return Err(kill_error);
                }
            }
            child.wait()?;
            return Err(error);
        }
        thread::sleep(QUERY_POLL_INTERVAL);
    }
}

fn receipt_timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "installer receipt query timed out")
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn valid_identifier(id: &str) -> bool {
    id.len() <= 255
        && id.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && id.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_payload_preview_only_admits_descendants_of_known_directories() {
        for path in [
            "/Applications/Example.app",
            "/Library/Application Support/Example/config",
            "/Library/LaunchDaemons/org.example.service.plist",
            "/Library/Frameworks/Example.framework",
            "/Library/Audio/Plug-Ins/Components/Example.component",
            "/Library/Java/JavaVirtualMachines/example.jdk",
            "/Library/PreferencePanes/Example.prefPane",
            "/Library/PrivilegedHelperTools/org.example.helper",
        ] {
            assert!(is_system_payload_path(Path::new(path)), "{path}");
        }
        for path in [
            "/Applications",
            "/Library",
            "/Library/Frameworks",
            "/Library/FrameworksBackup/file",
            "/Library/Audio/Plug-Ins",
            "/Library/Audio/Sounds/example",
            "/Library/Keychains/example",
            "/System/Library/Frameworks/Example.framework",
            "/Users/example/Library/Frameworks/Example.framework",
        ] {
            assert!(!is_system_payload_path(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn vendor_file_claims_require_the_exact_anchor_and_unambiguous_package() -> io::Result<()> {
        let output = br#"<?xml version="1.0"?>
<plist version="1.0"><dict>
<key>path</key><string>/Applications/Example.app/Contents/Info.plist</string>
<key>path-info</key><array>
<dict><key>pkgid</key><string>org.example.package</string>
<key>pkg-version</key><string>1.2</string></dict>
<dict><key>pkgid</key><string>com.apple.example</string>
<key>pkg-version</key><string>2.0</string></dict>
</array></dict></plist>"#;
        let anchor = Path::new("/Applications/Example.app/Contents/Info.plist");
        assert_eq!(
            parse_vendor_file_claims(output, anchor)?,
            BTreeMap::from([("org.example.package".into(), "1.2".into())])
        );
        assert!(parse_vendor_file_claims(output, Path::new("/different/path")).is_err());

        let duplicate =
            String::from_utf8_lossy(output).replace("com.apple.example", "org.example.package");
        assert!(parse_vendor_file_claims(duplicate.as_bytes(), anchor).is_err());
        assert!(anchor_has_claim(duplicate.as_bytes(), anchor)?);
        Ok(())
    }

    #[test]
    fn receipt_names_cannot_escape_the_receipt_root() {
        assert!(valid_identifier("org.example.package_name"));
        for invalid in [
            "",
            "..",
            "../receipt",
            "some/path",
            ".private",
            "org..example",
            "a\0b",
        ] {
            assert!(!valid_identifier(invalid), "{invalid:?}");
        }
    }
}
