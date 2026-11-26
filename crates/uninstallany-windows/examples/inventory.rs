//! Read-only Windows inventory smoke test.

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let engine = uninstallany_windows::open()?;
    let inventory = engine.inventory(false, &uninstallany_core::Cancellation::default())?;
    for item in inventory.applications {
        let version = item.version.as_deref().unwrap_or("version unknown");
        println!("{} ({version})", item.name);
    }
    for warning in inventory.warnings {
        eprintln!("{warning}");
    }
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("The inventory smoke test requires Windows.");
}
