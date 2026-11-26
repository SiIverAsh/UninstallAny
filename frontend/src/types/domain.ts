/**
 * Domain types mirroring `uninstallany-core` Rust models for Tauri v2 IPC.
 * Keep enum discriminants and field names aligned with `crates/uninstallany-core/src/model.rs`.
 */

export type Language = "en" | "zh";

export type Page = "applications" | "quarantine" | "settings" | "review";

export type SortField = "name" | "publisher" | "size" | "date";

export type RegistryHive = "CurrentUser" | "LocalMachine";

export type RegistryView = "Native" | "Registry32" | "Registry64";

export interface RegistryTarget {
  hive: RegistryHive;
  view: RegistryView;
  key: string;
  value?: string | null;
}

/** Platform-specific application identity, independent of display name. */
export type AppId =
  | { WindowsRegistry: RegistryTarget }
  | { WindowsPackage: string }
  | { Package: { manager: string; id: string } };

/** Stable string key for indexing `AppId` in Sets/Maps/React keys. */
export function appIdKey(id: AppId): string {
  if ("WindowsRegistry" in id) {
    const r = id.WindowsRegistry;
    return `winreg:${r.hive}:${r.view}:${r.key}:${r.value ?? ""}`;
  }
  if ("WindowsPackage" in id) {
    return `winpkg:${id.WindowsPackage}`;
  }
  return `pkg:${id.Package.manager}:${id.Package.id}`;
}

export interface AppRecord {
  id: AppId;
  name: string;
  publisher?: string | null;
  version?: string | null;
  install_location?: string | null;
  size_bytes?: number | null;
  install_date?: string | null;
  system_component: boolean;
  official_uninstall_available: boolean;
}

export interface Inventory {
  applications: AppRecord[];
  warnings: string[];
}

export type Category =
  | "File"
  | "Directory"
  | "Shortcut"
  | "Registry"
  | "Startup"
  | "Service"
  | "ScheduledTask"
  | "Firewall"
  | "FileAssociation"
  | "ShellExtension"
  | "Com";

export const ALL_CATEGORIES: readonly Category[] = [
  "File",
  "Directory",
  "Shortcut",
  "Registry",
  "Startup",
  "Service",
  "ScheduledTask",
  "Firewall",
  "FileAssociation",
  "ShellExtension",
  "Com",
] as const;

export type Confidence = "Low" | "Medium" | "High";

export type MatchKind =
  | "RuleHint"
  | "FuzzyName"
  | "AppName"
  | "PublisherAndApp"
  | "ExactIdentity";

export type Risk = "Normal" | "High";

export type Access = "Allowed" | { ReadOnly: string };

export function isAccessAllowed(access: Access): boolean {
  return access === "Allowed";
}

export function readOnlyReason(access: Access): string | null {
  return typeof access === "object" && "ReadOnly" in access ? access.ReadOnly : null;
}

export type ScanMode = "Leftovers" | "ForceRemoval" | "AfterOfficialUninstall";

export interface Candidate {
  id: number;
  /** Human-readable display string rendered from Rust `Target::display()`. */
  target_display: string;
  category: Category;
  confidence: Confidence;
  evidence: MatchKind;
  reason: string;
  risk: Risk;
  access: Access;
}

/** Matches Rust `Candidate::default_selected()`: High confidence, Normal risk, Allowed access. */
export function isDefaultSelected(candidate: Candidate): boolean {
  return (
    candidate.confidence === "High" &&
    candidate.risk === "Normal" &&
    candidate.access === "Allowed"
  );
}

export interface CleanupPreview {
  id: string; // UUID
  candidates: Candidate[];
  mode: ScanMode;
  warnings: string[];
  subject?: string;
}

export interface OfficialIntent {
  application: string;
  method: string;
  quiet: boolean;
  notice: string;
}

export type OfficialOutcome =
  | "Completed"
  | "NeedsRestart"
  | "Cancelled"
  | { Failed: number }
  | { Unverified: number };

export interface OfficialRow {
  application: string;
  outcome: { Ok: OfficialOutcome } | { Err: string };
  cleanup?: CleanupPreview | null;
  warnings: string[];
}

export type RecoveryState =
  | "Applied"
  | "Restored"
  | "Purged"
  | "Staged"
  | "NeedsReview";

export interface BackupSummary {
  id: string; // UUID
  batch_id: string; // UUID
  target: string;
  backup: string;
  expires_unix_ms: number;
  state: RecoveryState;
}

export interface BackupInventory {
  items: BackupSummary[];
  warnings: string[];
}

export type ChangeResult =
  | "Applied"
  | "Restored"
  | "Purged"
  | { Skipped: string }
  | { NeedsReview: string };

export interface ItemResult {
  target: string;
  backup_id?: string | null;
  result: ChangeResult;
}

export interface ChangeReport {
  batch_id: string;
  items: ItemResult[];
}

export interface UninstallReviewPayload {
  ticket: string;
  intents: OfficialIntent[];
  warnings: string[];
}

export interface RestoreReviewPayload {
  ticket: string;
  entries: BackupSummary[];
  warnings: string[];
}

export interface ExpiryReviewPayload {
  ticket: string;
  entries: BackupSummary[];
  warnings: string[];
}

export interface LoadedPreferences {
  retention_days: number;
  custom_rules: string;
  warnings: string[];
}

export interface RulesSavedPayload {
  text: string;
  count: number;
}

export interface AuditExport {
  written: number;
  warnings: string[];
}

export interface AuditExportedPayload {
  path: string;
  report: AuditExport;
}

export interface OperationProgress {
  done: number;
  total: number;
}

export type OperationKind =
  | "inventory"
  | "scan"
  | "prepare_uninstall"
  | "uninstall"
  | "backups"
  | "prepare_restore"
  | "restore"
  | "cleanup"
  | "expiry_preview"
  | "purge_expired"
  | "preferences"
  | "audit_export";

export type ReviewModal =
  | {
      kind: "uninstall";
      ticket: string;
      intents: OfficialIntent[];
      warnings: string[];
    }
  | {
      kind: "cleanup";
      planId: string;
      items: number[];
      targets: string[];
      hasHighRisk: boolean;
    }
  | {
      kind: "restore";
      ticket: string;
      entries: BackupSummary[];
      warnings: string[];
    }
  | {
      kind: "expiry";
      ticket: string;
      entries: BackupSummary[];
      warnings: string[];
    };

export type ToastKind = "success" | "info" | "warning" | "error";

export interface ToastItem {
  id: number;
  kind: ToastKind;
  message: string;
  durationMs: number;
  createdAt: number;
}
