use std::path::Path;

use uninstallany_core::{Cancellation, Result};

use crate::{
    command::{Program, query_strict},
    dpkg::{DPKG_QUERY_BIN, DPKG_VERIFICATION_ARGUMENTS, DpkgRequest},
    system_helper::SystemHelper,
};

pub(crate) const HELPER: SystemHelper = SystemHelper {
    executable: "/usr/libexec/uninstallany-dpkg-helper",
    policy_path: "/usr/share/polkit-1/actions/io.github.siiverash.uninstallany.dpkg.policy",
    policy: include_bytes!(
        "../../../packaging/debian-dpkg-helper/io.github.siiverash.uninstallany.dpkg.policy"
    ),
};

pub(crate) fn verify_removed(
    request: DpkgRequest<'_>,
    home: &Path,
    data: &Path,
    cancel: &Cancellation,
) -> Result<bool> {
    let program = Program::fixed(Path::new(DPKG_QUERY_BIN))?;
    let output = query_strict(&program, home, data, DPKG_VERIFICATION_ARGUMENTS, cancel)?;
    request.require_removed(&output)?;
    Ok(true)
}
