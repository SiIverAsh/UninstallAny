fn main() {
    if std::env::var_os("CARGO_CFG_TARGET_OS").is_some_and(|target| target == "windows") {
        println!("cargo:rerun-if-changed=icons/icon.ico");
        // The desktop host inherits the caller's token. Only the helper elevates.
        let windows = tauri_build::WindowsAttributes::new()
            .app_manifest(include_str!("windows-app-manifest.xml"));
        let attributes = tauri_build::Attributes::new().windows_attributes(windows);
        if let Err(error) = tauri_build::try_build(attributes) {
            eprintln!("could not prepare Windows application resources: {error:#}");
            std::process::exit(1);
        }
    } else {
        tauri_build::build();
    }
}
