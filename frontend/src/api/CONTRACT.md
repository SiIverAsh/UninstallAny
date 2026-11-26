# UninstallAny Tauri v2 IPC Contract

This document defines the exact Tauri v2 command & event contract expected by `frontend/src/api/client.ts` so the Rust backend team can wire `uninstallany-core` with zero ambiguity.

## Commands (`#[tauri::command]`)

All authorization plans and confirmation tickets remain **owned by the Rust session state** (`tauri::State<Mutex<Session>>`). The frontend only receives read-only preview DTOs and submits ticket/plan UUIDs + approved IDs.

| Command | Arguments (camelCase JSON) | Return DTO (`src/types/domain.ts`) |
| --- | --- | --- |
| `list_applications` | — | `Inventory` |
| `scan_app` | `{ appId: AppId }` | `CleanupPreview` |
| `scan_force_removal` | `{ appId: AppId }` | `CleanupPreview` |
| `scan_portable` | `{ path: string }` | `CleanupPreview` |
| `review_uninstall` | `{ appIds: AppId[] }` | `UninstallReviewPayload` |
| `run_uninstall` | `{ ticket: string }` | `OfficialRow[]` |
| `apply_cleanup` | `{ planId: string, items: number[] }` | `ChangeReport` |
| `list_backups` | — | `BackupInventory` |
| `review_restore` | `{ batchId: string }` | `RestoreReviewPayload` |
| `run_restore` | `{ ticket: string }` | `ChangeReport` |
| `review_expiry` | — | `ExpiryReviewPayload` |
| `purge_expired` | `{ ticket: string, items: string[] }` | `ChangeReport` |
| `load_preferences` | — | `LoadedPreferences` |
| `set_retention` | `{ days: number }` | `number` |
| `set_custom_rules` | `{ text: string }` | `RulesSavedPayload` |
| `export_audit` | `{ path: string }` | `AuditExportedPayload` |
| `cancel_operation` | — | `()` |

## Events (`app_handle.emit(...)`)

- **`uninstallany://progress`**: payload `{ done: number, total: number }` emitted during batch uninstall queues or long-running scans.

## Error Convention

Return `Result<T, String>` from Tauri commands. If a command was cooperatively cancelled via `Cancellation`, reject with `"Operation cancelled"` (or structured error code once added) so the UI displays a warning toast instead of a hard error.
