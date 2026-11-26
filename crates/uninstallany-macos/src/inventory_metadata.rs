//! Bounded display metadata for the application list.

use std::{
    borrow::Cow,
    io,
    path::Path,
    time::{Duration, Instant},
};

use uninstallany_core::{AppId, AppRecord, Cancellation, Error, Inventory, Result};
use uninstallany_unix::UnixFiles;

use crate::{app_signature, brew, bundle};

const SIZE_WINDOW: Duration = Duration::from_millis(400);
const MAX_SIZE_ENTRIES: usize = 150_000;
const PUBLISHER_WINDOW: Duration = Duration::from_millis(150);
const MAX_PUBLISHER_CHECKS: usize = 32;
const MAX_ERROR_EXAMPLES: usize = 3;

/// Adds logical bundle sizes and verified certificate names to the display.
pub(super) fn populate(
    files: &UnixFiles,
    inventory: &mut Inventory,
    cancel: &Cancellation,
) -> Result<()> {
    populate_sizes(files, inventory, cancel)?;
    populate_publishers(files, inventory, cancel)
}

fn populate_sizes(
    files: &UnixFiles,
    inventory: &mut Inventory,
    cancel: &Cancellation,
) -> Result<()> {
    cancel.check()?;
    let deadline = Instant::now() + SIZE_WINDOW;
    let mut remaining_entries = MAX_SIZE_ENTRIES;
    let mut unmeasured = 0;
    let mut incomplete = 0;
    let mut errors = 0;
    let mut examples = Vec::new();

    for is_system in [false, true] {
        // Prioritize applications visible by default without changing order.
        for app in inventory
            .applications
            .iter_mut()
            .filter(|app| app.system_component == is_system && app.size_bytes.is_none())
        {
            let Some(bundle) = CataloguedBundle::from_record(app) else {
                continue;
            };
            cancel.check()?;
            if remaining_entries == 0 || Instant::now() >= deadline {
                unmeasured += 1;
                continue;
            }
            match bundle.measure(files, &mut remaining_entries, deadline, cancel) {
                Ok(Some(size)) => app.size_bytes = Some(size),
                Ok(None) => incomplete += 1,
                Err(Error::Cancelled) => return Err(Error::Cancelled),
                Err(error) => {
                    errors += 1;
                    if examples.len() < MAX_ERROR_EXAMPLES {
                        examples.push(format!(
                            "Could not measure the application bundle at {}: {error}",
                            bundle.path.display(),
                        ));
                    }
                }
            }
        }
    }
    cancel.check()?;
    if unmeasured + incomplete + errors > 0 {
        inventory.warnings.push(format!(
            "Application bundle sizes unavailable: {unmeasured} skipped at the collection limit, {incomplete} incomplete measurements, {errors} read errors."
        ));
        inventory.warnings.extend(examples);
    }
    Ok(())
}

fn populate_publishers(
    files: &UnixFiles,
    inventory: &mut Inventory,
    cancel: &Cancellation,
) -> Result<()> {
    let deadline = Instant::now() + PUBLISHER_WINDOW;
    let mut attempted = 0;
    let mut errors = 0;
    let mut skipped = 0;
    let mut examples = Vec::new();
    for app in inventory
        .applications
        .iter_mut()
        .filter(|app| !app.system_component && app.publisher.is_none())
    {
        cancel.check()?;
        let Some(bundle) = CataloguedBundle::from_record(app) else {
            continue;
        };
        if attempted == MAX_PUBLISHER_CHECKS || Instant::now() >= deadline {
            skipped += 1;
            continue;
        }
        attempted += 1;
        match app_signature::read_publisher(files, bundle.path, &bundle.identifier, cancel) {
            Ok(publisher) => app.publisher = publisher,
            Err(Error::Cancelled) => return Err(Error::Cancelled),
            Err(error) => {
                errors += 1;
                if examples.len() < MAX_ERROR_EXAMPLES {
                    examples.push(format!(
                        "Could not read the publisher certificate at {}: {error}",
                        bundle.path.display(),
                    ));
                }
            }
        }
    }
    cancel.check()?;
    if skipped + errors > 0 {
        inventory.warnings.push(format!(
            "Publisher checks: {skipped} skipped at the collection limit, {errors} read errors."
        ));
        inventory.warnings.extend(examples);
    }
    Ok(())
}

struct CataloguedBundle<'a> {
    path: &'a Path,
    identifier: Cow<'a, str>,
}

impl<'a> CataloguedBundle<'a> {
    fn from_record(app: &'a AppRecord) -> Option<Self> {
        let path = app.install_location.as_deref()?;
        if !path.is_absolute() || !bundle::is_app(path) {
            return None;
        }
        let identifier = match &app.id {
            AppId::Package { manager, id } if manager == bundle::MANAGER => {
                Cow::Borrowed(id.split_once(':')?.0)
            }
            AppId::Package { manager, id } if manager == brew::MANAGER => {
                // Only a cask paired with a discovered bundle has a Bundle ID.
                Cow::Owned(brew::CaskId::parse(id)?.bundle_id()?.to_owned())
            }
            _ => return None,
        };
        Some(Self { path, identifier })
    }

    fn measure(
        &self,
        files: &UnixFiles,
        remaining_entries: &mut usize,
        deadline: Instant,
        cancel: &Cancellation,
    ) -> Result<Option<u64>> {
        let identity = files.local_directory_identity(self.path)?;
        let current = bundle::read(files, self.path)?;
        if current.identifier != self.identifier.as_ref() {
            return Err(changed_bundle().into());
        }

        let measured =
            files.measure_macos_bundle_size(self.path, remaining_entries, deadline, cancel)?;
        if measured.is_some() && files.local_directory_identity(self.path)? != identity {
            return Err(changed_bundle().into());
        }
        Ok(measured)
    }
}

fn changed_bundle() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "the application bundle changed since it was catalogued",
    )
}
