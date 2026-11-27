#![forbid(unsafe_code)]
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod dto;
#[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
mod helper_activation;
mod session;
mod worker;

#[cfg(windows)]
use std::{cell::Cell, rc::Rc};
use std::{num::NonZeroU16, path::PathBuf};

use tauri::{AppHandle, Manager, RunEvent, State, WindowEvent};
use uninstallany_core::AppId;
use uuid::Uuid;

#[cfg(windows)]
use crate::dto::CleanupPreview;
#[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
use crate::helper_activation::{HelperActivationPreviewPayload, HelperActivationReportPayload};
use crate::{
    dto::{
        AuditExportedPayload, BackupInventoryPayload, ChangeReportPayload, ExpiryReviewPayload,
        InventoryPayload, LoadedPreferencesPayload, OfficialRow, RestoreReviewPayload,
        RulesSavedPayload, UninstallReviewPayload,
    },
    worker::{Host, Operation},
};

#[tauri::command]
async fn list_applications(host: State<'_, Host>) -> Result<InventoryPayload, String> {
    host.run(Operation::Inventory).await
}

#[tauri::command]
async fn load_preferences(host: State<'_, Host>) -> Result<LoadedPreferencesPayload, String> {
    host.load_preferences().await
}

#[tauri::command]
async fn set_retention(days: NonZeroU16, host: State<'_, Host>) -> Result<u16, String> {
    host.run(|reply| Operation::SetRetention(days, reply)).await
}

#[tauri::command]
async fn set_custom_rules(
    text: String,
    host: State<'_, Host>,
) -> Result<RulesSavedPayload, String> {
    host.run(|reply| Operation::SetCustomRules(text, reply))
        .await
}

#[tauri::command]
async fn export_audit(
    path: PathBuf,
    host: State<'_, Host>,
) -> Result<AuditExportedPayload, String> {
    host.run(|reply| Operation::ExportAudit(path, reply)).await
}

#[tauri::command]
async fn review_uninstall(
    app_ids: Vec<AppId>,
    host: State<'_, Host>,
) -> Result<UninstallReviewPayload, String> {
    host.run(|reply| Operation::Review(app_ids, reply)).await
}

#[tauri::command]
async fn run_uninstall(
    ticket: Uuid,
    app: AppHandle,
    host: State<'_, Host>,
) -> Result<Vec<OfficialRow>, String> {
    host.run(|reply| Operation::Uninstall(ticket, app, reply))
        .await
}

#[cfg(windows)]
#[tauri::command]
async fn scan_portable(path: PathBuf, host: State<'_, Host>) -> Result<CleanupPreview, String> {
    host.run(|reply| Operation::ScanPortable(path, reply)).await
}

#[cfg(windows)]
#[tauri::command]
async fn scan_force_removal(
    app_id: AppId,
    host: State<'_, Host>,
) -> Result<CleanupPreview, String> {
    host.run(|reply| Operation::ScanForceRemoval(app_id, reply))
        .await
}

#[tauri::command]
async fn apply_cleanup(
    plan_id: Uuid,
    items: Vec<usize>,
    host: State<'_, Host>,
) -> Result<ChangeReportPayload, String> {
    host.run(|reply| Operation::Cleanup(plan_id, items, reply))
        .await
}

#[tauri::command]
async fn list_backups(host: State<'_, Host>) -> Result<BackupInventoryPayload, String> {
    host.run(Operation::Backups).await
}

#[tauri::command]
async fn review_restore(
    batch_id: Uuid,
    host: State<'_, Host>,
) -> Result<RestoreReviewPayload, String> {
    host.run(|reply| Operation::ReviewRestore(batch_id, reply))
        .await
}

#[tauri::command]
async fn run_restore(ticket: Uuid, host: State<'_, Host>) -> Result<ChangeReportPayload, String> {
    host.run(|reply| Operation::Restore(ticket, reply)).await
}

#[tauri::command]
async fn review_expiry(host: State<'_, Host>) -> Result<ExpiryReviewPayload, String> {
    host.run(Operation::ReviewExpiry).await
}

#[tauri::command]
async fn purge_expired(
    ticket: Uuid,
    items: Vec<Uuid>,
    host: State<'_, Host>,
) -> Result<ChangeReportPayload, String> {
    host.run(|reply| Operation::PurgeExpired(ticket, items, reply))
        .await
}

#[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
#[tauri::command]
async fn review_system_helper_activation(
    app_id: AppId,
    host: State<'_, Host>,
) -> Result<HelperActivationPreviewPayload, String> {
    host.run(|reply| Operation::ReviewHelperActivation(app_id, reply))
        .await
}

#[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
#[tauri::command]
async fn run_system_helper_activation(
    ticket: Uuid,
    host: State<'_, Host>,
) -> Result<HelperActivationReportPayload, String> {
    host.run(|reply| Operation::RunHelperActivation(ticket, reply))
        .await
}

#[tauri::command]
fn cancel_operation(host: State<'_, Host>) -> Result<(), String> {
    host.cancel().map(|_| ())
}

fn main() -> tauri::Result<()> {
    let app = tauri::Builder::default()
        .manage(Host::start()?)
        .invoke_handler(tauri::generate_handler![
            list_applications,
            load_preferences,
            set_retention,
            set_custom_rules,
            export_audit,
            review_uninstall,
            run_uninstall,
            #[cfg(windows)]
            scan_portable,
            #[cfg(windows)]
            scan_force_removal,
            apply_cleanup,
            list_backups,
            review_restore,
            run_restore,
            review_expiry,
            purge_expired,
            #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
            review_system_helper_activation,
            #[cfg(all(target_os = "macos", feature = "macos-privileged-helper"))]
            run_system_helper_activation,
            cancel_operation,
        ])
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event
                && window.state::<Host>().cancel().unwrap_or(true)
            {
                api.prevent_close();
            }
        })
        .build(tauri::generate_context!())?;

    #[cfg(windows)]
    let observation = Rc::new(Cell::new(None));
    #[cfg(windows)]
    let captured = Rc::clone(&observation);
    let on_run_event = move |app: &AppHandle, event| match event {
        // A normal close must not kill the worker mid-quarantine or uninstall.
        RunEvent::ExitRequested { api, .. } if app.state::<Host>().cancel().unwrap_or(true) => {
            api.prevent_exit();
        }
        #[cfg(windows)]
        RunEvent::Exit => {
            // Capture the Job before Tauri starts exit cleanup.
            captured.set(uninstallany_windows::capture_exit_observation().transpose());
        }
        _ => {}
    };
    #[cfg(not(windows))]
    app.run(on_run_event);
    #[cfg(windows)]
    {
        let exit_code = app.run_return(on_run_event);
        if let Some(observation) = observation.take() {
            observation?.finish()?;
        }
        if exit_code != 0 {
            std::process::exit(exit_code);
        }
    }
    Ok(())
}
