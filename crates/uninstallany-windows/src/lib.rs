//! Windows application discovery and native cleanup operations.

#[cfg(windows)]
mod files;
#[cfg(windows)]
mod firewall;
#[cfg(windows)]
mod helper;
#[cfg(windows)]
mod helper_ipc;
#[cfg(windows)]
mod helper_msi;
#[cfg(windows)]
mod helper_trust;
#[cfg(windows)]
mod highrisk;
#[cfg(windows)]
mod msix;
#[cfg(windows)]
mod platform;
#[cfg(windows)]
mod registrations;
#[cfg(windows)]
mod registry;
#[cfg(windows)]
mod shortcuts;
#[cfg(windows)]
mod tasks;
#[cfg(windows)]
mod uninstall;

#[cfg(windows)]
pub use platform::open;
#[cfg(windows)]
pub use uninstall::{ExitObservation, capture_exit_observation};

#[cfg(all(windows, feature = "privileged-helper"))]
pub use helper::run_privileged_helper;
