import type {
  AppId,
  AuditExportedPayload,
  BackupInventory,
  ChangeReport,
  CleanupPreview,
  ExpiryReviewPayload,
  Inventory,
  LoadedPreferences,
  OfficialRow,
  OperationProgress,
  RestoreReviewPayload,
  RulesSavedPayload,
  UninstallReviewPayload,
} from "@/types/domain";
import { createMockBackendClient } from "./mock";

export const TAURI_PROGRESS_EVENT = "uninstallany://progress";

export interface BackendClient {
  readonly mode: "tauri" | "mock";
  listApplications(): Promise<Inventory>;
  scanApp(appId: AppId): Promise<CleanupPreview>;
  scanForceRemoval(appId: AppId): Promise<CleanupPreview>;
  scanPortable(path: string): Promise<CleanupPreview>;
  reviewUninstall(appIds: AppId[]): Promise<UninstallReviewPayload>;
  runUninstall(ticket: string): Promise<OfficialRow[]>;
  applyCleanup(planId: string, items: number[]): Promise<ChangeReport>;
  listBackups(): Promise<BackupInventory>;
  reviewRestore(batchId: string): Promise<RestoreReviewPayload>;
  runRestore(ticket: string): Promise<ChangeReport>;
  reviewExpiry(): Promise<ExpiryReviewPayload>;
  purgeExpired(ticket: string, items: string[]): Promise<ChangeReport>;
  loadPreferences(): Promise<LoadedPreferences>;
  setRetention(days: number): Promise<number>;
  setCustomRules(text: string): Promise<RulesSavedPayload>;
  exportAudit(path: string): Promise<AuditExportedPayload>;
  cancelOperation(): Promise<void>;
  subscribeProgress(listener: (progress: OperationProgress) => void): () => void;
}

export function isTauriRuntime(): boolean {
  if (typeof window === "undefined") return false;
  return "__TAURI_INTERNALS__" in window;
}

class TauriBackendClient implements BackendClient {
  readonly mode = "tauri" as const;

  private async invoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<T>(command, args);
  }

  listApplications() {
    return this.invoke<Inventory>("list_applications");
  }

  scanApp(appId: AppId) {
    return this.invoke<CleanupPreview>("scan_app", { appId });
  }

  scanForceRemoval(appId: AppId) {
    return this.invoke<CleanupPreview>("scan_force_removal", { appId });
  }

  scanPortable(path: string) {
    return this.invoke<CleanupPreview>("scan_portable", { path });
  }

  reviewUninstall(appIds: AppId[]) {
    return this.invoke<UninstallReviewPayload>("review_uninstall", { appIds });
  }

  runUninstall(ticket: string) {
    return this.invoke<OfficialRow[]>("run_uninstall", { ticket });
  }

  applyCleanup(planId: string, items: number[]) {
    return this.invoke<ChangeReport>("apply_cleanup", { planId, items });
  }

  listBackups() {
    return this.invoke<BackupInventory>("list_backups");
  }

  reviewRestore(batchId: string) {
    return this.invoke<RestoreReviewPayload>("review_restore", { batchId });
  }

  runRestore(ticket: string) {
    return this.invoke<ChangeReport>("run_restore", { ticket });
  }

  reviewExpiry() {
    return this.invoke<ExpiryReviewPayload>("review_expiry");
  }

  purgeExpired(ticket: string, items: string[]) {
    return this.invoke<ChangeReport>("purge_expired", { ticket, items });
  }

  loadPreferences() {
    return this.invoke<LoadedPreferences>("load_preferences");
  }

  setRetention(days: number) {
    return this.invoke<number>("set_retention", { days });
  }

  setCustomRules(text: string) {
    return this.invoke<RulesSavedPayload>("set_custom_rules", { text });
  }

  exportAudit(path: string) {
    return this.invoke<AuditExportedPayload>("export_audit", { path });
  }

  cancelOperation() {
    return this.invoke<void>("cancel_operation");
  }

  subscribeProgress(listener: (progress: OperationProgress) => void): () => void {
    let active = true;
    let unlisten: (() => void) | null = null;
    void import("@tauri-apps/api/event").then(async ({ listen }) => {
      const fn = await listen<OperationProgress>(TAURI_PROGRESS_EVENT, (event) => {
        if (active) listener(event.payload);
      });
      if (!active) {
        fn();
      } else {
        unlisten = fn;
      }
    });
    return () => {
      active = false;
      unlisten?.();
    };
  }
}

let cachedClient: BackendClient | null = null;

export function getBackendClient(): BackendClient {
  if (!cachedClient) {
    cachedClient = isTauriRuntime() ? new TauriBackendClient() : createMockBackendClient();
  }
  return cachedClient;
}
