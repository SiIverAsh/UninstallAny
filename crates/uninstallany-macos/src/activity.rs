use std::path::{Component, Path};

use objc2::rc::autoreleasepool;
use objc2_app_kit::{NSRunningApplication, NSWorkspace};
use objc2_foundation::NSString;
use uninstallany_unix::UnixFiles;

use crate::bundle;

const DATA_VOLUME: &str = "/System/Volumes/Data";

/// Checks the application instances registered with its exact Bundle ID.
pub(super) fn bundle_is_running(bundle_id: &str) -> bool {
    autoreleasepool(|_| {
        let identifier = NSString::from_str(bundle_id);
        !NSRunningApplication::runningApplicationsWithBundleIdentifier(&identifier).is_empty()
    })
}

/// Checks the main app and AppKit-visible components of the reviewed bundle.
pub(super) fn at_location(files: &UnixFiles, location: Option<&Path>, bundle_id: &str) -> bool {
    if bundle_is_running(bundle_id) {
        return true;
    }
    let Some(location) = location.filter(|path| path.is_absolute() && bundle::is_app(path)) else {
        return false;
    };
    let Some(parent) = location.parent() else {
        return false;
    };
    let expected = without_data_volume(location);
    let expected_parent = without_data_volume(parent).as_os_str();
    running_bundle(|observed| {
        if observed == expected {
            return true;
        }
        let parent_matches = observed
            .parent()
            .is_some_and(|actual| actual.as_os_str().eq_ignore_ascii_case(expected_parent));
        let Some(alternate_name) = observed.file_name().filter(|_| parent_matches) else {
            return false;
        };

        // Compare an alternate spelling through the same no-follow parent.
        // On case-sensitive volumes the two names may be different apps.
        let Ok(expected_identity) = files.local_directory_identity(location) else {
            return false;
        };
        files
            .local_directory_identity(&parent.join(alternate_name))
            .is_ok_and(|observed_identity| observed_identity == expected_identity)
    })
}

/// Rechecks the path identity encoded in an ordinary bundle's approved AppId.
pub(super) fn for_app_id(app_id: &str, bundle_id: &str) -> bool {
    bundle_is_running(bundle_id)
        || running_bundle(|observed| bundle::app_id_matches_path(app_id, observed))
}

fn running_bundle(matches_bundle: impl FnMut(&Path) -> bool) -> bool {
    autoreleasepool(move |_| {
        let mut matches_bundle = matches_bundle;
        let applications = NSWorkspace::sharedWorkspace().runningApplications();
        applications.to_vec().into_iter().any(|application| {
            [application.bundleURL(), application.executableURL()]
                .into_iter()
                .flatten()
                .filter(|url| url.isFileURL())
                .filter_map(|url| url.to_file_path())
                .filter(|path| {
                    path.is_absolute()
                        && !path.components().any(|part| part == Component::ParentDir)
                })
                .any(|path| {
                    // A component may have its own Bundle ID, or only an
                    // executable URL. Inspect the path without opening its tail.
                    without_data_volume(&path)
                        .ancestors()
                        .filter(|ancestor| bundle::is_app(ancestor))
                        .any(&mut matches_bundle)
                })
        })
    })
}

fn without_data_volume(path: &Path) -> &Path {
    path.strip_prefix(DATA_VOLUME)
        .or_else(|_| path.strip_prefix("/"))
        .unwrap_or(path)
}
