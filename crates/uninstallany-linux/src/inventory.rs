use std::{collections::HashSet, path::Path};

use chrono::{DateTime, Utc};
use uninstallany_core::{AppId, AppRecord, Cancellation, Error, Inventory, Result};

use crate::command::{Program, query};

const MAX_PACKAGES: usize = 50_000;
const DPKG_FORMAT: &str = "${db:Status-Status}\\t${Package}\\t${Architecture}\\t${Version}\\t${Installed-Size}\\t${Maintainer}\\t${Essential}\\t${Priority}\\t${Section}\\n";
const RPM_FORMAT: &str = "%{NAME}\\t%{ARCH}\\t%{EPOCH}\\t%{VERSION}\\t%{RELEASE}\\t%{SIZE}\\t%{PACKAGER}\\t%{INSTALLTIME}\\t%{GROUP}\\n";
const FLATPAK_COLUMNS: &str = "--columns=ref:full,name:full,version:full,origin:full,size:full";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Source {
    Dpkg,
    Rpm,
    Pacman,
    FlatpakUser,
    FlatpakSystem,
    Snap,
    AppImage,
    Desktop,
}

impl Source {
    pub(crate) fn manager(self) -> &'static str {
        match self {
            Self::Dpkg => "dpkg",
            Self::Rpm => "rpm",
            Self::Pacman => "pacman",
            Self::FlatpakUser => "flatpak-user",
            Self::FlatpakSystem => "flatpak-system",
            Self::Snap => "snap",
            Self::AppImage => "appimage",
            Self::Desktop => "desktop",
        }
    }

    pub(crate) fn identify(app: &AppId) -> Option<(Self, &str)> {
        let AppId::Package { manager, id } = app else {
            return None;
        };
        let source = match manager.as_str() {
            "dpkg" => Self::Dpkg,
            "rpm" => Self::Rpm,
            "pacman" => Self::Pacman,
            "flatpak-user" => Self::FlatpakUser,
            "flatpak-system" => Self::FlatpakSystem,
            "snap" => Self::Snap,
            "appimage" => Self::AppImage,
            "desktop" => Self::Desktop,
            _ => return None,
        };
        Some((source, id))
    }

    pub(crate) fn flatpak_scope(self) -> Option<&'static str> {
        match self {
            Self::FlatpakUser => Some("--user"),
            Self::FlatpakSystem => Some("--system"),
            _ => None,
        }
    }

    pub(crate) fn command(self) -> Option<&'static str> {
        match self {
            Self::Dpkg => Some("dpkg-query"),
            Self::Rpm => Some("rpm"),
            Self::Pacman => Some("pacman"),
            Self::FlatpakUser | Self::FlatpakSystem => Some("flatpak"),
            Self::Snap => Some("snap"),
            Self::AppImage | Self::Desktop => None,
        }
    }

    fn query_arguments(self) -> &'static [&'static str] {
        match self {
            Self::Dpkg => &["--show", "--showformat", DPKG_FORMAT],
            Self::Rpm => &["--query", "--all", "--queryformat", RPM_FORMAT],
            Self::Pacman => &["--query", "--info", "--color", "never"],
            Self::FlatpakUser => &["list", "--user", "--app", FLATPAK_COLUMNS],
            Self::FlatpakSystem => &["list", "--system", "--app", FLATPAK_COLUMNS],
            Self::Snap => &["list"],
            Self::AppImage | Self::Desktop => &[],
        }
    }
}

pub(crate) const PACKAGE_SOURCES: [Source; 6] = [
    Source::Dpkg,
    Source::Rpm,
    Source::Pacman,
    Source::FlatpakUser,
    Source::FlatpakSystem,
    Source::Snap,
];

pub(crate) fn visit(
    source: Source,
    home: &Path,
    data: &Path,
    cancel: &Cancellation,
) -> Result<Option<Inventory>> {
    cancel.check()?;
    let Some(program) = source.command().and_then(Program::find) else {
        return Ok(None);
    };
    let output = query(&program, home, data, source.query_arguments(), cancel)?;
    parse(source, &output, cancel).map(Some)
}

fn parse(source: Source, output: &str, cancel: &Cancellation) -> Result<Inventory> {
    let mut inventory = Inventory::default();
    let mut seen = HashSet::new();
    let mut invalid = 0_usize;
    let rows = if source == Source::Pacman {
        Box::new(output.split("\n\n")) as Box<dyn Iterator<Item = &str>>
    } else {
        Box::new(output.lines())
    };
    for line in rows {
        cancel.check()?;
        if inventory.applications.len() >= MAX_PACKAGES {
            inventory
                .warnings
                .push("package inventory reached its record limit".into());
            break;
        }
        if line.trim().is_empty() {
            continue;
        }
        let record = match source {
            Source::Dpkg => dpkg(line),
            Source::Rpm => rpm(line),
            Source::Pacman => pacman(line),
            Source::FlatpakUser | Source::FlatpakSystem => flatpak(source, line),
            Source::Snap => snap(line),
            _ => Ok(None),
        };
        match record {
            Ok(Some(record)) if seen.insert(record.id.clone()) => {
                inventory.applications.push(record)
            }
            Ok(_) => {}
            Err(()) => invalid += 1,
        }
    }
    if invalid > 0 {
        inventory.warnings.push(format!(
            "{} returned {invalid} unrecognized package records",
            source.manager()
        ));
    }
    Ok(inventory)
}

pub(crate) fn record(source: Source, id: &str, name: &str) -> AppRecord {
    AppRecord {
        id: AppId::Package {
            manager: source.manager().into(),
            id: id.into(),
        },
        name: name.into(),
        publisher: None,
        version: None,
        install_location: None,
        size_bytes: None,
        install_date: None,
        system_component: false,
        official_uninstall_available: false,
    }
}

fn field(text: &str) -> Option<String> {
    let text = text.trim();
    if text.is_empty() || matches!(text, "-" | "—" | "N/A" | "(none)" | "None") {
        None
    } else {
        Some(text.into())
    }
}

fn component(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && value.len() <= 250
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

fn core_system_package(name: &str) -> bool {
    matches!(
        name,
        "apt"
            | "base"
            | "base-files"
            | "bash"
            | "coreutils"
            | "dnf"
            | "dpkg"
            | "filesystem"
            | "glibc"
            | "libc6"
            | "pacman"
            | "polkit"
            | "rpm"
            | "sudo"
            | "systemd"
    ) || [
        "kernel-",
        "linux-image-",
        "linux-headers-",
        "systemd-",
        "glibc-",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

fn dpkg(line: &str) -> std::result::Result<Option<AppRecord>, ()> {
    let mut fields = line.splitn(9, '\t');
    let status = fields.next().ok_or(())?;
    if status != "installed" {
        return Ok(None);
    }
    let name = fields.next().filter(|field| component(field)).ok_or(())?;
    let arch = fields.next().filter(|field| component(field)).ok_or(())?;
    let version = field(fields.next().ok_or(())?);
    let size = fields
        .next()
        .ok_or(())?
        .parse::<u64>()
        .ok()
        .and_then(|kb| kb.checked_mul(1024));
    let publisher = field(fields.next().ok_or(())?);
    let essential = fields.next().ok_or(())? == "yes";
    let priority = fields.next().ok_or(())?;
    let section = fields.next().ok_or(())?.rsplit('/').next().ok_or(())?;
    Ok(Some(AppRecord {
        version,
        publisher,
        size_bytes: size,
        system_component: essential
            || core_system_package(name)
            || matches!(priority, "required" | "important")
            || matches!(section, "libs" | "libdevel" | "kernel" | "debian-installer"),
        ..record(Source::Dpkg, &format!("{name}:{arch}"), name)
    }))
}

fn rpm(line: &str) -> std::result::Result<Option<AppRecord>, ()> {
    let mut fields = line.splitn(9, '\t');
    let name = fields.next().filter(|field| component(field)).ok_or(())?;
    let arch = fields.next().filter(|field| component(field)).ok_or(())?;
    let epoch = fields.next().ok_or(())?;
    let version = fields.next().filter(|field| component(field)).ok_or(())?;
    let release = fields.next().filter(|field| component(field)).ok_or(())?;
    let size = fields.next().ok_or(())?.parse::<u64>().ok();
    let publisher = field(fields.next().ok_or(())?);
    let install_date = fields
        .next()
        .ok_or(())?
        .parse::<i64>()
        .ok()
        .and_then(DateTime::<Utc>::from_timestamp_secs)
        .map(|timestamp| timestamp.format("%Y%m%d").to_string());
    let group = fields.next().ok_or(())?;
    let version = match epoch {
        "(none)" | "0" => format!("{version}-{release}"),
        epoch if epoch.parse::<u32>().is_ok() => format!("{epoch}:{version}-{release}"),
        _ => return Err(()),
    };
    Ok(Some(AppRecord {
        version: Some(version.clone()),
        publisher,
        size_bytes: size,
        install_date,
        system_component: core_system_package(name) || group.starts_with("System Environment/"),
        ..record(Source::Rpm, &format!("{name}.{arch}={version}"), name)
    }))
}

fn pacman(block: &str) -> std::result::Result<Option<AppRecord>, ()> {
    let mut name = None;
    let mut version = None;
    let mut publisher = None;
    let mut size = None;
    let mut system = false;
    for (key, value) in block.lines().filter_map(|line| line.split_once(':')) {
        match key.trim_end() {
            "Name" => name = Some(value.trim()),
            "Version" => version = field(value),
            "Packager" => publisher = field(value),
            "Installed Size" => size = parse_size(value),
            "Install Reason" => {
                system = value.trim_start().starts_with("Installed as a dependency")
            }
            _ => {}
        }
    }
    let name = name.filter(|value| component(value)).ok_or(())?;
    Ok(Some(AppRecord {
        version,
        publisher,
        size_bytes: size,
        system_component: system || core_system_package(name),
        ..record(Source::Pacman, name, name)
    }))
}

pub(crate) fn app_id_from_ref(reference: &str) -> Option<&str> {
    let mut pieces = reference.split('/');
    let "app" = pieces.next()? else { return None };
    let app_id = pieces.next().filter(|value| component(value))?;
    let _arch = pieces.next().filter(|value| component(value))?;
    let _branch = pieces.next().filter(|value| component(value))?;
    (app_id.split('.').count() >= 3 && pieces.next().is_none()).then_some(app_id)
}

fn flatpak(source: Source, row: &str) -> std::result::Result<Option<AppRecord>, ()> {
    let mut fields = row.splitn(5, '\t');
    let listed_ref = fields.next().ok_or(())?.trim();
    if listed_ref == "Ref" || listed_ref.starts_with("runtime/") {
        return Ok(None);
    }
    // This query uses --app. Some versions of the Flatpak CLI omit the
    // app/ prefix in the ref column, even though uninstall accepts it.
    let reference = if listed_ref.starts_with("app/") {
        listed_ref.to_owned()
    } else {
        format!("app/{listed_ref}")
    };
    let id = app_id_from_ref(&reference).ok_or(())?;
    let name = fields
        .next()
        .and_then(field)
        .unwrap_or_else(|| id.to_owned());
    let version = fields.next().and_then(field);
    // Origin is a repository name, not verified publisher metadata.
    let _origin = fields.next();
    let size = fields.next().and_then(parse_size);
    Ok(Some(AppRecord {
        version,
        size_bytes: size,
        official_uninstall_available: true,
        ..record(source, &reference, &name)
    }))
}

pub(crate) fn valid_snap_instance(name: &str) -> bool {
    let mut parts = name.split('_');
    let Some(name) = parts.next() else {
        return false;
    };
    let suffix_valid = parts.next().is_none_or(|suffix| {
        !suffix.is_empty()
            && suffix.len() <= 10
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    });
    suffix_valid
        && parts.next().is_none()
        && (2..=40).contains(&name.len())
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !name.contains("--")
        && name.bytes().any(|byte| byte.is_ascii_lowercase())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn snap(line: &str) -> std::result::Result<Option<AppRecord>, ()> {
    if line.starts_with("No snaps are installed") {
        return Ok(None);
    }
    let mut fields = line.split_whitespace();
    let name = fields.next().ok_or(())?;
    if name == "Name" {
        return Ok(None);
    }
    if !valid_snap_instance(name) {
        return Err(());
    }
    let version = field(fields.next().ok_or(())?);
    let _revision = fields.next().ok_or(())?;
    let _tracking = fields.next().ok_or(())?;
    let publisher = field(fields.next().ok_or(())?.trim_end_matches(['✓', '*']));
    let notes = fields.next().ok_or(())?;
    let system = matches!(
        name,
        "core" | "core16" | "core18" | "core20" | "core22" | "core24" | "snapd"
    ) || notes
        .split(',')
        .any(|item| matches!(item, "base" | "snapd" | "kernel" | "gadget"));
    Ok(Some(AppRecord {
        version,
        publisher,
        system_component: system,
        official_uninstall_available: !system,
        ..record(Source::Snap, name, name)
    }))
}

fn parse_size(text: &str) -> Option<u64> {
    let mut fields = text.split_whitespace();
    let quantity = fields.next()?.parse::<f64>().ok()?;
    let units = match fields.next() {
        None | Some("B" | "bytes") => 1.0,
        Some("kB" | "KB") => 1_000.0,
        Some("MB") => 1_000_000.0,
        Some("GB") => 1_000_000_000.0,
        Some("KiB") => 1_024.0,
        Some("MiB") => 1_048_576.0,
        Some("GiB") => 1_073_741_824.0,
        _ => return None,
    };
    let bytes = quantity * units;
    (bytes.is_finite() && (0.0..u64::MAX as f64).contains(&bytes)).then_some(bytes.round() as u64)
}

pub(crate) fn is_absent(inventory: Inventory, app: &AppId) -> Result<bool> {
    if !inventory.warnings.is_empty() {
        return Err(Error::Rejected(format!(
            "package identity could not be rechecked: {}",
            inventory.warnings.join("; ")
        )));
    }
    Ok(!inventory
        .applications
        .iter()
        .any(|candidate| &candidate.id == app))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_provider_does_not_report_a_successful_empty_inventory() -> Result<()> {
        let unused = Path::new("/");
        assert!(visit(Source::Desktop, unused, unused, &Cancellation::default())?.is_none());
        Ok(())
    }

    #[test]
    fn dpkg_filters_residual_configuration_rows_and_preserves_multiarch_identity() -> Result<()> {
        let inventory = parse(
            Source::Dpkg,
            "config-files\tretired\tamd64\t1\t5\tExample\tno\toptional\tutils\ninstalled\tlibexample\tarm64\t1.2\t42\tExample\tno\toptional\tlibs\n",
            &Cancellation::default(),
        )?;
        assert_eq!(inventory.applications.len(), 1);
        let record = &inventory.applications[0];
        assert_eq!(
            Source::identify(&record.id),
            Some((Source::Dpkg, "libexample:arm64"))
        );
        assert!(record.system_component);
        assert_eq!(record.size_bytes, Some(43_008));
        Ok(())
    }

    #[test]
    fn rpm_keeps_distinct_installed_releases_and_date() -> Result<()> {
        let output = "Example\taarch64\t(none)\t1.0\t1.fc38\t12\tVendor\t1700000000\tUtilities\nExample\taarch64\t3\t1.0\t2.fc38\t16\tVendor\t1700000000\tUtilities\n";
        let inventory = parse(Source::Rpm, output, &Cancellation::default())?;
        assert_eq!(inventory.applications.len(), 2);
        assert_eq!(
            inventory.applications[0].install_date.as_deref(),
            Some("20231114")
        );
        assert_ne!(inventory.applications[0].id, inventory.applications[1].id);
        Ok(())
    }

    #[test]
    fn pacman_marks_dependency_rows_and_parses_size() -> Result<()> {
        let output = "Name            : xreader\nVersion         : 1.2-1\nInstall Reason  : Explicitly installed\nInstalled Size  : 4.00 MiB\n\nName            : libc\nVersion         : 2\nInstall Reason  : Installed as a dependency for another package\n";
        let inventory = parse(Source::Pacman, output, &Cancellation::default())?;
        assert_eq!(inventory.applications.len(), 2);
        assert_eq!(inventory.applications[0].size_bytes, Some(4_194_304));
        assert!(inventory.applications[1].system_component);
        Ok(())
    }

    #[test]
    fn rejects_bad_refs_and_keeps_flatpak_scope_separate() -> Result<()> {
        let row = "app/org.example.Editor/x86_64/stable\tExample Editor\t1\tflathub\t12.5 MB\n";
        let user = parse(
            Source::FlatpakUser,
            row.trim_start_matches("app/"),
            &Cancellation::default(),
        )?;
        let system = parse(Source::FlatpakSystem, row, &Cancellation::default())?;
        assert_ne!(user.applications[0].id, system.applications[0].id);
        assert_eq!(
            Source::identify(&user.applications[0].id),
            Some((Source::FlatpakUser, "app/org.example.Editor/x86_64/stable"))
        );
        assert_eq!(user.applications[0].size_bytes, Some(12_500_000));
        assert_eq!(app_id_from_ref("app/org.example.Editor/x86_64/--all"), None);
        assert_eq!(
            app_id_from_ref("runtime/org.example.Editor/x86_64/stable"),
            None
        );
        assert_eq!(
            app_id_from_ref("app/org.example.Editor/x86_64/stable/extra"),
            None
        );
        Ok(())
    }

    #[test]
    fn snap_inventory_protects_core_and_rejects_option_like_names() -> Result<()> {
        let output = "Name Version Rev Tracking Publisher Notes\ncore24 2024 3 latest/stable canonical✓ base\nexample 1 5 latest/stable vendor✓ -\n";
        let inventory = parse(Source::Snap, output, &Cancellation::default())?;
        assert_eq!(inventory.applications.len(), 2);
        assert!(inventory.applications[0].system_component);
        assert_eq!(
            inventory.applications[1].publisher.as_deref(),
            Some("vendor")
        );
        assert!(!valid_snap_instance("--purge"));
        assert!(!valid_snap_instance("abc___def"));
        Ok(())
    }
}
