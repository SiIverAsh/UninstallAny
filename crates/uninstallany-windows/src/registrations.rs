use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    path::Path,
};

use uninstallany_core::{
    Access, Cancellation, Category, Proposal, RegistryHive, RegistryTarget, RegistryView, Result,
    Risk, Scan, Target,
};
use uuid::Uuid;

use crate::{
    registry,
    uninstall::{self, RegisteredReference, RegisteredScope},
};

const CLASSES: &str = r"Software\Classes";
const MAX_REFERENCES: usize = 512;
const MAX_SOURCE_READS: usize = 32_768;
const OBJECT_CLASSES: &[&str] = &[
    "*",
    "AllFilesystemObjects",
    "Directory",
    r"Directory\Background",
    "Drive",
    "Folder",
];
const MULTIPLE_HANDLERS: &[&str] = &["ContextMenuHandlers", "PropertySheetHandlers"];

/// Discovers direct file, COM, and Shell registrations without activating them.
pub(super) fn discover_registrations(
    scope: &RegisteredScope,
    cancel: &Cancellation,
) -> Result<Scan> {
    let mut scan = Scan::default();
    for hive in [RegistryHive::CurrentUser, RegistryHive::LocalMachine] {
        cancel.check()?;
        if scan.proposals.len() >= MAX_REFERENCES {
            break;
        }
        // The non-COM Classes keys are shared across views on supported Windows.
        let mut classes = Source::new(hive, RegistryView::Native);
        let prog_ids = find_file_associations(&mut classes, &mut scan, scope, cancel)?;
        for &view in registry::machine_views() {
            if scan.proposals.len() >= MAX_REFERENCES {
                break;
            }
            let mut servers = Source::new(hive, view);
            let dll_classes = find_servers(&mut servers, &mut scan, scope, cancel)?;
            if !dll_classes.is_empty() {
                find_shell_handlers(
                    &mut classes,
                    &mut scan,
                    view,
                    &prog_ids,
                    &dll_classes,
                    cancel,
                )?;
            }
            servers.report(&mut scan, "COM registrations");
        }
        classes.report(&mut scan, "file associations and Shell registrations");
    }
    if scan.proposals.len() >= MAX_REFERENCES {
        scan.warnings.push(format!(
            "Windows Class registration results reached the {MAX_REFERENCES} reference limit"
        ));
    }
    Ok(scan)
}

fn find_file_associations(
    source: &mut Source,
    scan: &mut Scan,
    scope: &RegisteredScope,
    cancel: &Cancellation,
) -> Result<BTreeMap<String, RegisteredReference>> {
    let mut prog_ids: BTreeMap<String, RegisteredReference> = BTreeMap::new();
    for extension in source.subkeys(CLASSES) {
        cancel.check()?;
        if source.exhausted(scan) {
            break;
        }
        if !extension.starts_with('.') || !valid_component(&extension) {
            continue;
        }
        let association = format!(r"{CLASSES}\{extension}");
        let Some(prog_id) = source
            .read(&association, "")
            .flatten()
            .filter(|name| valid_component(name))
        else {
            continue;
        };
        let command = format!(r"{CLASSES}\{prog_id}\shell\open\command");
        let Some(open) = source.read(&command, "").flatten() else {
            continue;
        };
        let command_key = source.target(&command, None);
        let Some(values) = source.observe(|| registry::value_names(&command_key)) else {
            continue;
        };
        if values
            .iter()
            .any(|name| name.eq_ignore_ascii_case("DelegateExecute"))
        {
            continue;
        }
        let Some(image) = source
            .observe(|| uninstall::service_image(&open, scope))
            .flatten()
        else {
            continue;
        };
        scan.proposals.push(reference(
            format!(
                "{} -> {}",
                Target::Registry(source.target(&association, Some(""))).display(),
                Target::Registry(source.target(&command, Some(""))).display()
            ),
            Category::FileAssociation,
            &image,
            "registered default ProgID has a direct open command in the verified application directory",
        ));
        if prog_ids
            .get(&prog_id)
            .is_none_or(|previous| image.evidence < previous.evidence)
        {
            prog_ids.insert(prog_id, image);
        }
    }
    Ok(prog_ids)
}

fn find_servers(
    source: &mut Source,
    scan: &mut Scan,
    scope: &RegisteredScope,
    cancel: &Cancellation,
) -> Result<BTreeMap<Uuid, RegisteredReference>> {
    let root = format!(r"{CLASSES}\CLSID");
    let mut libraries = BTreeMap::new();
    for name in source.subkeys(&root) {
        cancel.check()?;
        if source.exhausted(scan) {
            break;
        }
        let Some(class) = class_id(&name) else {
            continue;
        };
        let library = format!(r"{root}\{name}\InprocServer32");
        let owned_library = source.read(&library, "").flatten().and_then(|program| {
            source
                .observe(|| uninstall::registered_library(Path::new(&program), scope))
                .flatten()
        });
        if let Some(image) = owned_library {
            scan.proposals.push(reference(
                Target::Registry(source.target(&library, Some(""))).display(),
                Category::Com,
                &image,
                "registered in-process library is in the verified application directory",
            ));
            libraries.insert(class, image);
        }
        if source.exhausted(scan) {
            break;
        }
        let server = format!(r"{root}\{name}\LocalServer32");
        let value = match source.read(&server, "ServerExecutable") {
            Some(Some(program)) => source
                .observe(|| uninstall::registered_image(Path::new(&program), scope))
                .flatten()
                .map(|image| ("ServerExecutable", image)),
            Some(None) => source.read(&server, "").flatten().and_then(|command| {
                source
                    .observe(|| uninstall::service_image(&command, scope))
                    .flatten()
                    .map(|image| ("", image))
            }),
            None => None,
        };
        if let Some((value_name, image)) = value {
            scan.proposals.push(reference(
                Target::Registry(source.target(&server, Some(value_name))).display(),
                Category::Com,
                &image,
                "registered local server executable is in the verified application directory",
            ));
        }
    }
    Ok(libraries)
}

fn find_shell_handlers(
    source: &mut Source,
    scan: &mut Scan,
    server_view: RegistryView,
    prog_ids: &BTreeMap<String, RegisteredReference>,
    known_classes: &BTreeMap<Uuid, RegisteredReference>,
    cancel: &Cancellation,
) -> Result<()> {
    let types: BTreeSet<_> = OBJECT_CLASSES
        .iter()
        .copied()
        .chain(prog_ids.keys().map(String::as_str))
        .collect();
    for object in types {
        for handler in MULTIPLE_HANDLERS {
            cancel.check()?;
            if source.exhausted(scan) {
                return Ok(());
            }
            let root = format!(r"{CLASSES}\{object}\shellex\{handler}");
            for name in source.subkeys(&root) {
                cancel.check()?;
                if source.exhausted(scan) {
                    return Ok(());
                }
                if !valid_component(&name) {
                    continue;
                }
                let handler = format!(r"{root}\{name}");
                let (id, value_name) = match source.read(&handler, "") {
                    Some(Some(value)) => (class_id(&value), Some("")),
                    Some(None) => (class_id(&name), None),
                    None => continue,
                };
                if let Some(library) = id.and_then(|id| known_classes.get(&id)) {
                    // A ProgID and its COM registration can supply different levels of evidence.
                    let image = prog_ids
                        .get(object)
                        .filter(|association| association.evidence < library.evidence)
                        .unwrap_or(library);
                    let address = source.target(&handler, value_name);
                    scan.proposals.push(reference(
                        format!(
                            "{} (COM server view: {server_view:?})",
                            Target::Registry(address).display()
                        ),
                        Category::ShellExtension,
                        image,
                        "handler CLSID links to a verified in-process library in the same hive",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn reference(
    address: String,
    category: Category,
    image: &RegisteredReference,
    reason: &str,
) -> Proposal {
    Proposal {
        target: Target::Reference(address),
        category,
        evidence: image.evidence,
        reason: image.reason(reason),
        risk: Risk::High,
        access: Access::ReadOnly("class registrations can affect other applications".into()),
    }
}

fn valid_component(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains(['\\', '/'])
        && !name.chars().any(char::is_control)
        && name.encode_utf16().count() <= 255
}

fn class_id(value: &str) -> Option<Uuid> {
    let contents = value.strip_prefix('{')?.strip_suffix('}')?;
    if contents.len() != 36 {
        return None;
    }
    Uuid::parse_str(contents).ok()
}

struct Source {
    hive: RegistryHive,
    view: RegistryView,
    remaining: usize,
    errors: usize,
    first_error: Option<io::Error>,
}

impl Source {
    fn new(hive: RegistryHive, view: RegistryView) -> Self {
        Self {
            hive,
            view,
            remaining: MAX_SOURCE_READS,
            errors: 0,
            first_error: None,
        }
    }

    fn exhausted(&self, scan: &Scan) -> bool {
        self.remaining == 0 || scan.proposals.len() >= MAX_REFERENCES
    }

    fn read(&mut self, key: &str, value: &str) -> Option<Option<String>> {
        let address = self.target(key, Some(value));
        self.observe(|| registry::string_value(&address))
    }

    fn subkeys(&mut self, key: &str) -> Vec<String> {
        let address = self.target(key, None);
        self.observe(|| registry::subkeys(&address))
            .unwrap_or_default()
    }

    fn observe<T>(&mut self, read: impl FnOnce() -> io::Result<T>) -> Option<T> {
        self.remaining = self.remaining.checked_sub(1)?;
        match read() {
            Ok(value) => Some(value),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => {
                self.errors += 1;
                self.first_error.get_or_insert(error);
                None
            }
        }
    }

    fn target(&self, key: &str, value: Option<&str>) -> RegistryTarget {
        RegistryTarget {
            hive: self.hive,
            view: self.view,
            key: key.to_owned(),
            value: value.map(str::to_owned),
        }
    }

    fn report(&self, scan: &mut Scan, label: &str) {
        if self.remaining == 0 {
            scan.warnings.push(format!(
                "{label} in {:?}/{:?} reached the read limit",
                self.hive, self.view
            ));
        }
        if let Some(error) = &self.first_error {
            scan.warnings.push(format!(
                "{label} in {:?}/{:?}: {} reads could not be verified ({error})",
                self.hive, self.view, self.errors
            ));
        }
    }
}
