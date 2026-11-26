#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() -> std::process::ExitCode {
    #[cfg(windows)]
    if uninstallany_windows::run_privileged_helper().is_ok() {
        return std::process::ExitCode::SUCCESS;
    }
    std::process::ExitCode::FAILURE
}
