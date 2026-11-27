use std::{collections::HashSet, io};

use crate::inventory::core_system_package;

pub(crate) const DPKG_QUERY_BIN: &str = "/usr/bin/dpkg-query";
pub(crate) const DPKG_ADMIN_DIR: &str = "--admindir=/var/lib/dpkg";
pub(crate) const DPKG_FORMAT: &str = concat!(
    "${db:Status-Status}\\t${Package}\\t${Architecture}\\t${Version}\\t",
    "${Installed-Size}\\t${Maintainer}\\t${Essential}\\t${Priority}\\t${Section}\\t",
    "${Protected}\\t${db:Status-Want}\\t${db:Status-Eflag}\\n",
);

#[cfg(target_os = "linux")]
pub(crate) const DPKG_VERIFICATION_ARGUMENTS: &[&str] = &[
    DPKG_ADMIN_DIR,
    "--no-pager",
    "--show",
    "--showformat",
    concat!(
        "${db:Status-Status}\\t${Package}\\t${Architecture}\\t${Version}\\t\\t\\t",
        "${Essential}\\t${Priority}\\t${Section}\\t${Protected}\\t${db:Status-Want}\\t${db:Status-Eflag}\\n",
    ),
];

/// One record from an unfiltered, native `dpkg-query` database listing.
pub(crate) struct DpkgRow<'a> {
    pub(crate) status: &'a str,
    pub(crate) name: &'a str,
    pub(crate) architecture: &'a str,
    pub(crate) version: &'a str,
    pub(crate) installed_size: &'a str,
    pub(crate) maintainer: &'a str,
    essential: &'a str,
    priority: &'a str,
    section: &'a str,
    protected: &'a str,
    wanted: &'a str,
    error: &'a str,
}

impl<'a> DpkgRow<'a> {
    pub(crate) fn parse(line: &'a str) -> Result<Self, ()> {
        let mut fields = line.split('\t');
        let row = Self {
            status: fields.next().ok_or(())?,
            name: fields.next().ok_or(())?,
            architecture: fields.next().ok_or(())?,
            version: fields.next().ok_or(())?,
            installed_size: fields.next().ok_or(())?,
            maintainer: fields.next().ok_or(())?,
            essential: fields.next().ok_or(())?,
            priority: fields.next().ok_or(())?,
            section: fields.next().ok_or(())?,
            protected: fields.next().ok_or(())?,
            wanted: fields.next().ok_or(())?,
            error: fields.next().ok_or(())?,
        };
        let status_is_known = matches!(
            row.status,
            "not-installed"
                | "config-files"
                | "half-installed"
                | "unpacked"
                | "half-configured"
                | "triggers-awaited"
                | "triggers-pending"
                | "installed"
        );
        let version_is_known =
            valid_version(row.version) || (row.status == "not-installed" && row.version.is_empty());
        let size_is_known = row.installed_size.is_empty()
            || (decimal(row.installed_size) && row.installed_size.parse::<u64>().is_ok());
        if fields.next().is_some()
            || line.chars().any(|ch| ch.is_control() && ch != '\t')
            || !status_is_known
            || !valid_name(row.name)
            || !valid_architecture(row.architecture)
            || !version_is_known
            || !size_is_known
            || !matches!(row.essential, "" | "no" | "yes")
            || !matches!(row.protected, "" | "no" | "yes")
            || !matches!(
                row.wanted,
                "unknown" | "install" | "hold" | "deinstall" | "purge"
            )
            || !matches!(row.error, "ok" | "reinstreq")
        {
            return Err(());
        }
        Ok(row)
    }

    /// Applies native protection fields and conservative system-package rules.
    pub(crate) fn system_component(&self) -> bool {
        let section = self.section.rsplit('/').next().unwrap_or_default();
        self.essential == "yes"
            || self.protected == "yes"
            || core_system_package(self.name)
            || matches!(
                self.name,
                "uninstallany-dpkg-helper" | "pkexec" | "polkitd" | "policykit-1"
            )
            || matches!(self.priority, "required" | "important")
            || matches!(
                section,
                "base" | "libs" | "libdevel" | "kernel" | "debian-installer"
            )
    }

    /// Only healthy packages selected for installation are eligible.
    pub(crate) fn removable(&self) -> bool {
        self.status == "installed"
            && self.wanted == "install"
            && self.error == "ok"
            && matches!(self.essential, "" | "no")
            && matches!(self.protected, "" | "no")
            && !self.system_component()
    }
}

/// Exact name, architecture and installed version accepted by the helper.
#[derive(Clone, Copy)]
pub(crate) struct DpkgRequest<'a> {
    pub(crate) id: &'a str,
    pub(crate) version: &'a str,
    name: &'a str,
    architecture: &'a str,
}

impl<'a> DpkgRequest<'a> {
    pub(crate) fn parse(id: &'a str, version: &'a str) -> io::Result<Self> {
        const INVALID: &str = "expected an exact Debian package name, architecture and version";
        let (name, architecture) = id
            .split_once(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, INVALID))?;
        if !valid_name(name) || !valid_architecture(architecture) || !valid_version(version) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, INVALID));
        }
        Ok(Self {
            id,
            version,
            name,
            architecture,
        })
    }

    /// Rechecks exact installed identity and protection before native removal.
    #[cfg(any(all(target_os = "linux", feature = "dpkg-helper"), test))]
    pub(crate) fn require_installed(self, output: &str) -> io::Result<()> {
        let Some(row) = self.find(output)? else {
            return Err(io::Error::other("the selected Debian package is absent"));
        };
        if row.version != self.version {
            return Err(io::Error::other(
                "the selected Debian package version changed",
            ));
        }
        if !row.removable() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the Debian package is protected, held or in an ineligible state",
            ));
        }
        Ok(())
    }

    /// A plain remove may retain the original version's configuration row.
    pub(crate) fn require_removed(self, output: &str) -> io::Result<()> {
        if let Some(row) = self.find(output)? {
            let configuration_only = row.status == "config-files" && row.version == self.version;
            let not_installed = row.status == "not-installed"
                && (row.version.is_empty() || row.version == self.version);
            if row.error != "ok" || !(configuration_only || not_installed) {
                return Err(io::Error::other(
                    "could not verify the exact Debian package removal",
                ));
            }
        }
        Ok(())
    }

    fn find(self, output: &str) -> io::Result<Option<DpkgRow<'_>>> {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed Debian package listing",
            )
        };
        if !output.is_empty() && !output.ends_with('\n') {
            return Err(invalid());
        }
        let mut identities = HashSet::new();
        let mut selected = None;
        // Inspect the whole listing even after a match. An inconsistent
        // database must not establish either presence or absence.
        for line in output.split_terminator('\n') {
            let row = DpkgRow::parse(line).map_err(|()| invalid())?;
            if !identities.insert((row.name, row.architecture)) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate Debian package identity in the listing",
                ));
            }
            if row.name == self.name && row.architecture == self.architecture {
                selected = Some(row);
            }
        }
        Ok(selected)
    }
}

fn valid_name(name: &str) -> bool {
    name.len() >= 2
        && name
            .as_bytes()
            .first()
            .is_some_and(|byte| lowercase_or_digit(*byte))
        && name
            .bytes()
            .all(|byte| lowercase_or_digit(byte) || matches!(byte, b'+' | b'-' | b'.'))
}

fn valid_architecture(architecture: &str) -> bool {
    architecture.split('-').all(|part| {
        !part.is_empty()
            && !matches!(part, "any" | "native" | "source" | "none")
            && part.bytes().all(lowercase_or_digit)
    })
}

fn valid_version(version: &str) -> bool {
    let remaining = match version.split_once(':') {
        Some((epoch, rest)) if decimal(epoch) && epoch.parse::<u32>().is_ok() => rest,
        Some(_) => return false,
        None => version,
    };
    let version_char =
        |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'.' | b'~');
    let upstream = match remaining.rsplit_once('-') {
        Some((upstream, revision))
            if !revision.is_empty() && revision.bytes().all(version_char) =>
        {
            upstream
        }
        Some(_) => return false,
        None => remaining,
    };
    upstream.as_bytes().first().is_some_and(u8::is_ascii_digit)
        && upstream
            .bytes()
            .all(|byte| version_char(byte) || matches!(byte, b'-' | b':'))
}

fn decimal(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn lowercase_or_digit(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

#[cfg(test)]
mod tests {
    use super::DpkgRequest;

    const ROW: &str = "installed\tcode-editor\tamd64\t2:1.0~rc1-3\t12\tExample\tno\toptional\teditors\t\tinstall\tok\n";
    const VERSION: &str = "2:1.0~rc1-3";

    #[test]
    fn rejects_special_selectors_and_unknown_versions() -> std::io::Result<()> {
        for identity in [
            "-editor:amd64",
            "code-editor:linux-any",
            "code-editor:native",
        ] {
            assert!(DpkgRequest::parse(identity, VERSION).is_err());
        }
        let request = DpkgRequest::parse("code-editor:amd64", "1.0")?;
        assert!(request.require_installed(ROW).is_err());
        Ok(())
    }

    #[test]
    fn rejects_protected_and_inconsistent_records() -> std::io::Result<()> {
        let request = DpkgRequest::parse("code-editor:amd64", VERSION)?;
        assert!(request.require_installed(ROW).is_ok());
        assert!(
            request
                .require_installed(&ROW.replace("\t\tinstall\t", "\tyes\tinstall\t"))
                .is_err()
        );
        assert!(
            request
                .require_installed(&ROW.replace("\tinstall\t", "\thold\t"))
                .is_err()
        );
        assert!(request.require_installed(&format!("{ROW}{ROW}")).is_err());
        assert!(
            request
                .require_installed(&format!("{ROW}invalid\n"))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn removal_requires_absence_or_the_same_config_files_version() -> std::io::Result<()> {
        let request = DpkgRequest::parse("code-editor:amd64", VERSION)?;
        assert!(request.require_removed("").is_ok());
        assert!(
            request
                .require_removed(&ROW.replacen("installed", "config-files", 1))
                .is_ok()
        );
        assert!(
            request
                .require_removed(&ROW.replacen("installed", "half-installed", 1))
                .is_err()
        );
        assert!(
            request
                .require_removed(
                    &ROW.replacen("installed", "config-files", 1)
                        .replace(VERSION, "1.0")
                )
                .is_err()
        );
        Ok(())
    }
}
