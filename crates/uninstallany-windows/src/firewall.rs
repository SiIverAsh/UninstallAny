//! Read-only Windows Firewall rules associated with an installation directory.

use std::{ffi::OsString, io, os::windows::ffi::OsStringExt, path::Path};

use uninstallany_core::{Access, Cancellation, Category, Proposal, Result, Risk, Scan, Target};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT, NetFwPolicy2,
};
use windows::Win32::System::{
    Com::{CLSCTX_INPROC_SERVER, CoCreateInstance, IDispatch},
    Ole::IEnumVARIANT,
    Variant::{VARIANT, VT_DISPATCH, VT_UNKNOWN},
};
use windows::core::{IUnknown, Interface};

use super::{
    highrisk::ComApartment,
    uninstall::{RegisteredScope, registered_image},
};

const MAX_RULES: usize = 4_096;
const MAX_APP_PATH_UNITS: usize = 32_767;
const MAX_RULE_NAME_UNITS: usize = 1_024;

/// Lists rules whose application path points into the verified installation.
pub(super) fn discover_rules(scope: &RegisteredScope, cancel: &Cancellation) -> Result<Scan> {
    cancel.check()?;
    let _apartment = ComApartment::initialize()?;
    // SAFETY: COM is initialized on this thread. The registered local class is
    // opened without aggregation and only used to read the policy collection.
    let policy: INetFwPolicy2 =
        unsafe { CoCreateInstance(&NetFwPolicy2, None::<&IUnknown>, CLSCTX_INPROC_SERVER) }
            .map_err(io::Error::other)?;
    // SAFETY: Both interfaces remain alive in the same COM apartment.
    let rules = unsafe { policy.Rules() }.map_err(io::Error::other)?;
    // SAFETY: The live rules collection exposes its enumerator via _NewEnum.
    let rules_enum: IEnumVARIANT = unsafe { rules._NewEnum() }
        .and_then(|unknown| unknown.cast())
        .map_err(io::Error::other)?;

    let mut scan = Scan::default();
    let mut unreadable = 0usize;
    for index in 0..=MAX_RULES {
        cancel.check()?;
        let mut value = VARIANT::default();
        let mut fetched = 0;
        // SAFETY: The array is a writable, empty VARIANT and fetched is a
        // writable count. The windows crate clears the element when it drops.
        let status = unsafe { rules_enum.Next(std::slice::from_mut(&mut value), &mut fetched) };
        if let Err(error) = status.ok() {
            scan.warnings.push(format!(
                "could not finish Windows Firewall rule enumeration: {error}"
            ));
            break;
        }
        if fetched == 0 {
            break;
        }
        if fetched != 1 {
            scan.warnings
                .push("Windows Firewall returned an invalid enumeration count".into());
            break;
        }
        if index == MAX_RULES {
            scan.warnings
                .push("Windows Firewall enumeration reached its rule limit".into());
            break;
        }
        match as_rule(&value).and_then(|rule| proposal_for_rule(&rule, scope)) {
            Ok(Some(proposal)) => scan.proposals.push(proposal),
            Ok(None) => {}
            Err(_) => unreadable += 1,
        }
    }
    if unreadable > 0 {
        scan.warnings.push(format!(
            "could not inspect {unreadable} Windows Firewall rules or their application paths"
        ));
    }
    Ok(scan)
}

fn proposal_for_rule(rule: &INetFwRule, scope: &RegisteredScope) -> io::Result<Option<Proposal>> {
    // SAFETY: The rule is live and ApplicationName is a read-only property query.
    let application = unsafe { rule.ApplicationName() }.map_err(io::Error::other)?;
    if application.is_empty() || application.len() > MAX_APP_PATH_UNITS {
        return Ok(None);
    }
    // This is a path-valued property. Do not interpret quotes, environment
    // variables, or command-line syntax to infer ownership.
    let path = OsString::from_wide(&application);
    let Some(image) = registered_image(Path::new(&path), scope)? else {
        return Ok(None);
    };
    // SAFETY: These property queries read the same live rule in its apartment.
    let (name, direction) = unsafe { (rule.Name(), rule.Direction()) };
    let name = name.map_err(io::Error::other)?;
    if name.is_empty() || name.len() > MAX_RULE_NAME_UNITS {
        return Ok(None);
    }
    let name = String::try_from(name).map_err(io::Error::other)?;
    if name.trim().is_empty() || name.chars().any(char::is_control) {
        return Ok(None);
    }
    let direction = match direction.map_err(io::Error::other)? {
        NET_FW_RULE_DIR_IN => "inbound",
        NET_FW_RULE_DIR_OUT => "outbound",
        _ => return Ok(None),
    };
    Ok(Some(Proposal {
        target: Target::Reference(format!(
            "Windows Firewall: {name} ({direction}) — {}",
            image.path.display()
        )),
        category: Category::Firewall,
        evidence: image.evidence,
        reason: image
            .reason("firewall rule application path matches the verified installation directory"),
        risk: Risk::High,
        access: Access::ReadOnly("firewall rule backup and restore are not implemented".into()),
    }))
}

fn as_rule(value: &VARIANT) -> io::Result<INetFwRule> {
    match value.vt() {
        VT_DISPATCH => IDispatch::try_from(value).and_then(|interface| interface.cast()),
        VT_UNKNOWN => IUnknown::try_from(value).and_then(|interface| interface.cast()),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "firewall rule interface missing",
            ));
        }
    }
    .map_err(io::Error::other)
}
