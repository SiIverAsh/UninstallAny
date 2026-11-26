//! Read-only App Group declarations from local macOS application signatures.

use std::{collections::BTreeSet, io, path::Path};

use core_foundation::{
    base::{CFType, TCFType},
    string::CFString,
};
use uninstallany_core::{Cancellation, Error, Result, Scan};
use uninstallany_unix::UnixFiles;

use crate::{app_signature, scan};

const GROUPS_ENTITLEMENT: &str = "com.apple.security.application-groups";
const MAX_GROUPS: isize = 128;
const MAX_NAME_BYTES: usize = 255;

/// Signed declarations retained during a reversible application bundle move.
pub(super) struct UninstallAppGroups {
    identifiers: Vec<String>,
    warning: Option<String>,
}

impl UninstallAppGroups {
    /// Reads the declarations while the application is still at its reviewed path.
    pub(super) fn capture(
        files: &UnixFiles,
        app_path: &Path,
        bundle_id: &str,
        cancel: &Cancellation,
    ) -> Result<Self> {
        match read(files, app_path, bundle_id, None, cancel) {
            Ok(identifiers) => Ok(Self {
                identifiers,
                warning: None,
            }),
            Err(Error::Cancelled) => Err(Error::Cancelled),
            Err(error) => Ok(Self {
                identifiers: Vec::new(),
                warning: Some(format!(
                    "Could not capture signed App Groups for {} before uninstall: {error}",
                    app_path.display()
                )),
            }),
        }
    }

    /// Resolves shared groups for display without obscuring a completed move.
    pub(super) fn resolve_after_move(
        self,
        files: &UnixFiles,
        home: &Path,
        cancel: &Cancellation,
    ) -> Scan {
        let mut result = Scan::default();
        if !self.identifiers.is_empty() {
            match scan::declared_groups(files, home, &self.identifiers, cancel) {
                Ok(groups) => result = groups,
                // The engine reports cancellation for the entire leftover scan.
                Err(Error::Cancelled) => {}
                Err(error) => result.warnings.push(format!(
                    "Could not scan signed App Group leftovers after uninstall: {error}"
                )),
            }
        }
        result.warnings.extend(self.warning);
        result
    }
}

/// Returns declarations from the selected architecture of a signed main executable.
///
/// An approved hash binds a pre-uninstall read to the reviewed signature.
/// Declarations can identify shared data for display. They do not establish
/// provisioning authorization or inspect any group container.
pub(super) fn read(
    files: &UnixFiles,
    app_path: &Path,
    bundle_id: &str,
    approved_code_hash: Option<&[u8]>,
    cancel: &Cancellation,
) -> Result<Vec<String>> {
    let groups =
        app_signature::with_apple_signature(files, app_path, bundle_id, cancel, |signature| {
            if approved_code_hash.is_some_and(|hash| !signature.matches_code_hash(hash)) {
                return Err(invalid(
                    "the App Group declaration differs from the approved signature",
                )
                .into());
            }
            let Some(groups) = signature.array_entitlement(GROUPS_ENTITLEMENT) else {
                return Ok(None);
            };
            if groups.len() > MAX_GROUPS {
                return Err(
                    invalid("the App Group declaration exceeds the discovery limit").into(),
                );
            }
            let team = signature.team_identifier();
            let mut team_verified = None;
            let mut declarations = BTreeSet::new();
            for item in &groups {
                cancel.check()?;
                // SAFETY: The live array retains each borrowed item, and its
                // type is checked before treating it as a string.
                let value = unsafe { CFType::wrap_under_get_rule(*item) };
                let Some(name) = value.downcast_into::<CFString>().filter(|name| {
                    usize::try_from(name.char_len()).is_ok_and(|len| len <= MAX_NAME_BYTES)
                }) else {
                    continue;
                };
                let name = name.to_string();
                let Some((prefix, _)) = name.split_once('.') else {
                    continue;
                };
                if name.len() > MAX_NAME_BYTES || !name.split('.').all(literal_component) {
                    continue;
                }
                if prefix != "group" {
                    if Some(prefix) != team.as_deref() {
                        continue;
                    }
                    // Team-prefixed paths must agree with the leaf certificate
                    // as well as the team's field reported by Security.
                    if team_verified.is_none() {
                        team_verified = Some(signature.verify_team(prefix, cancel)?);
                    }
                    if team_verified != Some(true) {
                        continue;
                    }
                }
                declarations.insert(name);
            }
            Ok((!declarations.is_empty()).then(|| declarations.into_iter().collect()))
        })?;
    Ok(groups.unwrap_or_default())
}

fn literal_component(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
