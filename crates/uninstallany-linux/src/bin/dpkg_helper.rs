#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
use std::env;
use std::process::ExitCode;

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    let arguments = env::args_os()
        .skip(1)
        .map(|argument| argument.into_string())
        .collect::<Result<Vec<_>, _>>();
    let Ok(arguments) = arguments else {
        eprintln!("The Debian helper requires a valid package identity.");
        return ExitCode::FAILURE;
    };
    match uninstallany_linux::run_dpkg_helper(&arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Debian package removal failed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!("The Debian helper runs on Linux.");
    ExitCode::FAILURE
}
