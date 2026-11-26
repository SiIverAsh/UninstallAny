use std::{env, io, path::PathBuf, process::Command};

fn main() -> io::Result<()> {
    println!("cargo::rerun-if-changed=helper");
    if env::var_os("CARGO_FEATURE_PRIVILEGED_INSPECTION").is_none()
        || !matches!(env::var("CARGO_CFG_TARGET_OS").as_deref(), Ok("macos"))
    {
        return Ok(());
    }
    if !env::var("HOST").is_ok_and(|host| host.ends_with("-apple-darwin")) {
        return Err(io::Error::other(
            "building macOS privileged inspection requires the Apple host toolchain",
        ));
    }
    let architecture = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64",
        Ok("x86_64") => "x86_64",
        _ => return Err(io::Error::other("unsupported macOS helper architecture")),
    };
    let out = env::var_os("OUT_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other("Cargo did not provide a helper output directory"))?;
    let object = out.join("macos_helper_client.o");
    let authorization = out.join("macos_helper_authorization_client.o");
    let registration = out.join("macos_helper_service_registration.o");
    let archive = out.join("libuninstallany_helper_client.a");
    let helper = out.join("UninstallAnyPrivilegedHelper");
    let flags = [
        "-arch",
        architecture,
        "-mmacosx-version-min=13.0",
        "-Os",
        "-fobjc-arc",
        "-fblocks",
    ];
    run(Command::new("/usr/bin/clang")
        .args(flags)
        .args(["-c", "helper/client.m", "-o"])
        .arg(&object))?;
    run(Command::new("/usr/bin/clang")
        .args(flags)
        .args([
            "-DUA_AUTHORIZATION_CLIENT",
            "-c",
            "helper/authorization.m",
            "-o",
        ])
        .arg(&authorization))?;
    run(Command::new("/usr/bin/clang")
        .args(flags)
        .args(["-c", "helper/service_registration.m", "-o"])
        .arg(&registration))?;
    run(Command::new("/usr/bin/ar")
        .arg("-crs")
        .arg(&archive)
        .arg(&object)
        .arg(&authorization)
        .arg(&registration))?;
    run(Command::new("/usr/bin/clang")
        .args(flags)
        .args([
            "-DUA_AUTHORIZATION_DAEMON",
            "helper/main.m",
            "helper/inspect.m",
            "helper/authorization.m",
            "helper/bundle_activity.m",
            "helper/bundle_background.m",
            "helper/bundle_homebrew.m",
            "helper/bundle_signature.m",
            "helper/bundle_tree.m",
            "helper/expiry_tree.m",
            "helper/installer_ownership.m",
            "helper/pkgutil_query.m",
            "helper/quarantine.m",
            "-framework",
            "Foundation",
            "-framework",
            "Security",
            "-o",
        ])
        .arg(&helper))?;
    println!("cargo::rustc-link-search=native={}", out.display());
    println!("cargo::rustc-link-lib=static=uninstallany_helper_client");
    println!("cargo::rustc-link-lib=framework=Foundation");
    println!("cargo::rustc-link-lib=framework=Security");
    println!("cargo::rustc-link-lib=framework=ServiceManagement");
    Ok(())
}

fn run(command: &mut Command) -> io::Result<()> {
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "macOS helper tool failed with {status}: {command:?}"
        )))
    }
}
