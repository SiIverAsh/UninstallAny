//! Bounded, offline signing evidence for a selected local app bundle.

use std::{borrow::Cow, fs, io, os::unix::fs::MetadataExt, path::Path, ptr};

use core_foundation::{
    ConcreteCFType,
    array::CFArray,
    base::{CFGetTypeID, CFType, CFTypeID, CFTypeRef, TCFType},
    data::CFData,
    dictionary::{CFDictionary, CFDictionaryRef},
    string::{CFString, CFStringRef},
    url::{CFURL, CFURLRef},
};
use uninstallany_core::{Cancellation, Category, Result};
use uninstallany_unix::UnixFiles;

use crate::{bundle, plist};

const MAX_INFO_BYTES: usize = 2 * 1024 * 1024;
const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_EXECUTABLE_NAME_BYTES: usize = 255;
const MAX_PUBLISHER_BYTES: usize = 255;
const DEVELOPER_ID_LABEL: &str = "Developer ID Application: ";
pub(super) const DEVELOPER_ID_REQUIREMENT: &str = concat!(
    "anchor apple generic and ",
    "certificate 1[field.1.2.840.113635.100.6.2.6] exists and ",
    "certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
);
const SIGNING_INFORMATION: u32 = 1 << 1;
// Preserve validation of the main executable while skipping resource
// traversal and network requests (SecStaticCode.h, CSCommon.h).
const VALIDATE_FLAGS: u32 = (1 << 2) | (1 << 29);
const UNSIGNED: i32 = -67062;
const REQUIREMENT_FAILED: i32 = -67050;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecStaticCodeCreateWithPath(path: CFURLRef, flags: u32, code: *mut CFTypeRef) -> i32;
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
    fn SecCertificateGetTypeID() -> CFTypeID;
    fn SecCertificateCopyCommonName(certificate: CFTypeRef, common_name: *mut CFStringRef) -> i32;
    static kSecCodeInfoIdentifier: CFStringRef;
    static kSecCodeInfoMainExecutable: CFStringRef;
    static kSecCodeInfoTeamIdentifier: CFStringRef;
    static kSecCodeInfoUnique: CFStringRef;
    static kSecCodeInfoEntitlementsDict: CFStringRef;
    static kSecCodeInfoCertificates: CFStringRef;
}

#[derive(Clone, Copy)]
enum Signer {
    AppleAnchored,
    DeveloperIdApplication,
}

struct AppIdentity<'a> {
    path: &'a Path,
    bundle_id: &'a str,
}

pub(super) struct VerifiedSignature<'a> {
    code: CFType,
    information: CFDictionary,
    bundle_id: &'a str,
    signer: Signer,
}

impl VerifiedSignature<'_> {
    pub(super) fn team_identifier(&self) -> Option<String> {
        // SAFETY: Security exports this immutable process-lifetime key.
        value::<CFString>(&self.information, unsafe { kSecCodeInfoTeamIdentifier })
            .filter(|team| team.char_len() == 10)
            .map(|team| team.to_string())
            .filter(|team| valid_team_identifier(team))
    }

    pub(super) fn verify_team(&self, team: &str, cancel: &Cancellation) -> Result<bool> {
        if !valid_team_identifier(team) {
            return Ok(false);
        }
        cancel.check()?;
        let valid = validate(&self.code, self.bundle_id, self.signer, Some(team))?;
        cancel.check()?;
        Ok(valid)
    }

    pub(super) fn matches_code_hash(&self, expected: &[u8]) -> bool {
        // SAFETY: Security exports this immutable process-lifetime key.
        value::<CFData>(&self.information, unsafe { kSecCodeInfoUnique })
            .is_some_and(|hash| hash.bytes() == expected)
    }

    pub(super) fn array_entitlement(&self, key: &str) -> Option<CFArray> {
        // SAFETY: Security exports this immutable process-lifetime key.
        let entitlements =
            value::<CFDictionary>(&self.information, unsafe { kSecCodeInfoEntitlementsDict })?;
        let key = CFString::new(key);
        value::<CFArray>(&entitlements, key.as_concrete_TypeRef())
    }
}

/// Reads displayable publisher text from the selected Developer ID signer.
pub(super) fn read_publisher(
    files: &UnixFiles,
    path: &Path,
    bundle_id: &str,
    cancel: &Cancellation,
) -> Result<Option<String>> {
    read_signature(
        files,
        AppIdentity { path, bundle_id },
        Signer::DeveloperIdApplication,
        cancel,
        |signature| {
            let Some(team) = signature.team_identifier() else {
                return Ok(None);
            };
            if !signature.verify_team(&team, cancel)? {
                return Ok(None);
            }
            let Some(common_name) = leaf_common_name(&signature.information)? else {
                return Ok(None);
            };
            let suffix = format!(" ({team})");
            let publisher = common_name
                .strip_prefix(DEVELOPER_ID_LABEL)
                .and_then(|name| name.strip_suffix(suffix.as_str()))
                .filter(|name| {
                    !name.is_empty()
                        && name.len() <= MAX_PUBLISHER_BYTES
                        && name.trim() == *name
                        && !name.chars().any(char::is_control)
                });
            Ok(publisher.map(str::to_owned))
        },
    )
}

pub(super) fn with_apple_signature<T>(
    files: &UnixFiles,
    path: &Path,
    bundle_id: &str,
    cancel: &Cancellation,
    read: impl FnOnce(&VerifiedSignature<'_>) -> Result<Option<T>>,
) -> Result<Option<T>> {
    read_signature(
        files,
        AppIdentity { path, bundle_id },
        Signer::AppleAnchored,
        cancel,
        read,
    )
}

fn read_signature<T>(
    files: &UnixFiles,
    app: AppIdentity<'_>,
    signer: Signer,
    cancel: &Cancellation,
    read: impl FnOnce(&VerifiedSignature<'_>) -> Result<Option<T>>,
) -> Result<Option<T>> {
    cancel.check()?;
    if !bundle::is_app(app.path) || !bundle::valid_identifier(app.bundle_id) {
        return Ok(None);
    }
    let directory = files.local_directory_identity(app.path)?;
    let info_path = app.path.join("Contents/Info.plist");
    let info = files.read_regular(&info_path, MAX_INFO_BYTES)?;
    let metadata = plist::dictionary(&info)?;
    if plist::string(&metadata, "CFBundleIdentifier").as_deref() != Some(app.bundle_id) {
        return Err(
            invalid("the application identifier changed before signature discovery").into(),
        );
    }
    let Some(executable) = plist::string(&metadata, "CFBundleExecutable").filter(|name| {
        !name.is_empty()
            && name.len() <= MAX_EXECUTABLE_NAME_BYTES
            && !matches!(name.as_str(), "." | "..")
            && !name.contains('/')
            && !name.chars().any(char::is_control)
    }) else {
        return Ok(None);
    };
    let executable = app.path.join("Contents/MacOS").join(executable);
    let observed = executable_stamp(files, &executable)?;
    let code = static_code(app.path)?;
    cancel.check()?;
    let valid = validate(&code, app.bundle_id, signer, None)?;
    cancel.check()?;
    if !valid {
        return Ok(None);
    }
    let information = signing_information(&code)?;
    // SAFETY: Security exports these immutable process-lifetime keys.
    let (id_key, executable_key) = unsafe { (kSecCodeInfoIdentifier, kSecCodeInfoMainExecutable) };
    if value::<CFString>(&information, id_key)
        .is_none_or(|value| Cow::from(&value).as_ref() != app.bundle_id)
        || value::<CFURL>(&information, executable_key)
            .and_then(|value| value.to_path())
            .as_deref()
            != Some(executable.as_path())
    {
        return Err(
            invalid("the signed identifier or executable differs from the reviewed app").into(),
        );
    }
    let evidence = read(&VerifiedSignature {
        code,
        information,
        bundle_id: app.bundle_id,
        signer,
    })?;
    if evidence.is_some()
        && (files.local_directory_identity(app.path)? != directory
            || executable_stamp(files, &executable)? != observed
            || files.read_regular(&info_path, MAX_INFO_BYTES)? != info)
    {
        return Err(invalid("the application changed during signature verification").into());
    }
    cancel.check()?;
    Ok(evidence)
}

fn leaf_common_name(information: &CFDictionary) -> io::Result<Option<String>> {
    // SAFETY: Security exports this immutable process-lifetime key.
    let Some(certificates) = value::<CFArray>(information, unsafe { kSecCodeInfoCertificates })
    else {
        return Ok(None);
    };
    // Security's signing certificate chain starts with the signing leaf.
    let Some(leaf) = certificates.get(0).map(|certificate| *certificate) else {
        return Ok(None);
    };
    // SAFETY: The non-null element is owned by the live certificate array.
    if leaf.is_null() || unsafe { CFGetTypeID(leaf) != SecCertificateGetTypeID() } {
        return Ok(None);
    }
    let mut name = ptr::null();
    // SAFETY: The checked leaf and output slot are live for the call.
    let status = unsafe { SecCertificateCopyCommonName(leaf, &mut name) };
    if status != 0 {
        return Err(io::Error::other(format!(
            "could not read the signing certificate common name ({status})"
        )));
    }
    if name.is_null() {
        return Ok(None);
    }
    // SAFETY: Security returns the name as an owned Core Foundation string.
    let name = unsafe { CFString::wrap_under_create_rule(name) };
    let max_name = MAX_PUBLISHER_BYTES + DEVELOPER_ID_LABEL.len() + " (0123456789)".len();
    Ok(usize::try_from(name.char_len())
        .is_ok_and(|length| length <= max_name)
        .then(|| name.to_string()))
}

fn valid_team_identifier(team: &str) -> bool {
    team.len() == 10
        && team
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

#[derive(PartialEq)]
struct ExecutableStamp {
    identity: (u64, u64),
    length: u64,
    changed: (i64, i64),
    modified: (i64, i64),
}

fn executable_stamp(files: &UnixFiles, path: &Path) -> io::Result<ExecutableStamp> {
    if !files
        .probe_discovery_target(path)?
        .is_some_and(|target| target.category == Category::File)
    {
        return Err(invalid("the app executable is not a local regular file"));
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > MAX_EXECUTABLE_BYTES {
        return Err(invalid(
            "the app executable is outside the supported discovery scope",
        ));
    }
    Ok(ExecutableStamp {
        identity: (metadata.dev(), metadata.ino()),
        length: metadata.len(),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
    })
}

fn static_code(path: &Path) -> io::Result<CFType> {
    let url =
        CFURL::from_path(path, true).ok_or_else(|| invalid("invalid local application URL"))?;
    let mut code = ptr::null();
    // SAFETY: The file URL and output pointer remain live during the call.
    let status = unsafe { SecStaticCodeCreateWithPath(url.as_concrete_TypeRef(), 0, &mut code) };
    if status != 0 || code.is_null() {
        return Err(io::Error::other(format!(
            "could not inspect the application signature ({status})"
        )));
    }
    // SAFETY: The successful create call returned an owned Security object.
    Ok(unsafe { CFType::wrap_under_create_rule(code) })
}

fn validate(
    code: &CFType,
    bundle_id: &str,
    signer: Signer,
    team: Option<&str>,
) -> io::Result<bool> {
    let anchor = match signer {
        Signer::AppleAnchored => "anchor apple generic",
        Signer::DeveloperIdApplication => DEVELOPER_ID_REQUIREMENT,
    };
    let mut text = format!("{anchor} and identifier \"{bundle_id}\"");
    if let Some(team) = team {
        text.push_str(&format!(" and certificate leaf[subject.OU] = \"{team}\""));
    }
    let text = CFString::new(&text);
    let mut requirement = ptr::null();
    // SAFETY: The inputs and output storage remain live. The caller bounds
    // identifiers and team IDs to literal, quoted-safe characters.
    let status =
        unsafe { SecRequirementCreateWithString(text.as_concrete_TypeRef(), 0, &mut requirement) };
    if status != 0 || requirement.is_null() {
        return Err(invalid("could not compile the local signing requirement"));
    }
    // SAFETY: A successful create returns an owned Security object.
    let requirement = unsafe { CFType::wrap_under_create_rule(requirement) };
    // SAFETY: Both Security objects remain live. The flags request offline
    // validation of the selected architecture without resource traversal.
    let status = unsafe {
        SecStaticCodeCheckValidity(
            code.as_CFTypeRef(),
            VALIDATE_FLAGS,
            requirement.as_CFTypeRef(),
        )
    };
    match status {
        0 => Ok(true),
        UNSIGNED | REQUIREMENT_FAILED => Ok(false),
        _ => Err(io::Error::other(format!(
            "could not validate the application signature ({status})"
        ))),
    }
}

fn signing_information(code: &CFType) -> io::Result<CFDictionary> {
    let mut information = ptr::null();
    // SAFETY: The code object has already been validated offline, and the
    // output pointer remains writable during the copy operation.
    let status = unsafe {
        SecCodeCopySigningInformation(code.as_CFTypeRef(), SIGNING_INFORMATION, &mut information)
    };
    if status != 0 || information.is_null() {
        return Err(io::Error::other(format!(
            "could not read the application signature ({status})"
        )));
    }
    // SAFETY: A successful copy returned an owned Core Foundation dictionary.
    Ok(unsafe { CFDictionary::wrap_under_create_rule(information) })
}

fn value<T: ConcreteCFType>(dictionary: &CFDictionary, key: CFStringRef) -> Option<T> {
    if key.is_null() {
        return None;
    }
    let value = dictionary.find(key.cast())?;
    // SAFETY: The live dictionary retains the borrowed value. The downcast
    // checks its dynamic type before use.
    unsafe { CFType::wrap_under_get_rule(*value) }.downcast_into::<T>()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
