import {
  appIdKey,
  type AppId,
  type AppRecord,
  type AuditExportedPayload,
  type BackupInventory,
  type BackupSummary,
  type Candidate,
  type ChangeReport,
  type CleanupPreview,
  type ExpiryReviewPayload,
  type Inventory,
  type LoadedPreferences,
  type OfficialRow,
  type OperationProgress,
  type RestoreReviewPayload,
  type RulesSavedPayload,
  type ScanMode,
  type UninstallReviewPayload,
} from "@/types/domain";
import type { BackendClient } from "./client";

function uuid(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === "x" ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

const DAY_MS = 86_400_000;

function initialApps(): AppRecord[] {
  return [
    {
      id: { Package: { manager: "macos-bundle", id: "com.adobe.Photoshop" } },
      name: "Adobe Photoshop 2025",
      publisher: "Adobe Inc.",
      version: "26.4.1",
      install_location: "/Applications/Adobe Photoshop 2025/Adobe Photoshop 2025.app",
      size_bytes: 3_420_000_000,
      install_date: "20260914",
      system_component: false,
      official_uninstall_available: true,
    },
    {
      id: { Package: { manager: "homebrew-cask", id: "claude" } },
      name: "Claude",
      publisher: "Anthropic PBC",
      version: "0.9.3",
      install_location: "/Applications/Claude.app",
      size_bytes: 284_000_000,
      install_date: "20261102",
      system_component: false,
      official_uninstall_available: true,
    },
    {
      id: { Package: { manager: "macos-bundle", id: "com.docker.docker" } },
      name: "Docker Desktop",
      publisher: "Docker Inc.",
      version: "4.41.0",
      install_location: "/Applications/Docker.app",
      size_bytes: 1_960_000_000,
      install_date: "20260821",
      system_component: false,
      official_uninstall_available: true,
    },
    {
      id: { Package: { manager: "homebrew-cask", id: "visual-studio-code" } },
      name: "Visual Studio Code",
      publisher: "Microsoft Corporation",
      version: "1.99.2",
      install_location: "/Applications/Visual Studio Code.app",
      size_bytes: 492_000_000,
      install_date: "20261018",
      system_component: false,
      official_uninstall_available: true,
    },
    {
      id: { Package: { manager: "macos-bundle", id: "com.figma.Desktop" } },
      name: "Figma",
      publisher: "Figma, Inc.",
      version: "125.2.0",
      install_location: "/Applications/Figma.app",
      size_bytes: 318_000_000,
      install_date: "20261110",
      system_component: false,
      official_uninstall_available: true,
    },
    {
      id: { Package: { manager: "apple-pkg-receipt", id: "com.example.legacy-driver" } },
      name: "Legacy Audio Companion",
      publisher: "Acme Audio Labs",
      version: "2.1.0",
      install_location: "/Library/Audio/Plug-Ins/HAL/AcmeCompanion.driver",
      size_bytes: 18_400_000,
      install_date: "20251203",
      system_component: false,
      official_uninstall_available: false,
    },
    {
      id: { Package: { manager: "homebrew-formula", id: "ripgrep" } },
      name: "ripgrep",
      publisher: "Andrew Gallant",
      version: "14.1.1",
      install_location: "/opt/homebrew/Cellar/ripgrep/14.1.1",
      size_bytes: 5_200_000,
      install_date: "20261005",
      system_component: false,
      official_uninstall_available: true,
    },
    {
      id: { Package: { manager: "macos-bundle", id: "md.obsidian" } },
      name: "Obsidian",
      publisher: "Dynalist Inc.",
      version: "1.8.9",
      install_location: "/Applications/Obsidian.app",
      size_bytes: 214_000_000,
      install_date: "20261119",
      system_component: false,
      official_uninstall_available: true,
    },
    {
      id: { Package: { manager: "apple-pkg-receipt", id: "com.apple.pkg.CLTools_Executables" } },
      name: "Command Line Tools Runtime",
      publisher: "Apple Inc.",
      version: "16.2",
      install_location: "/Library/Developer/CommandLineTools",
      size_bytes: 820_000_000,
      install_date: "20260711",
      system_component: true,
      official_uninstall_available: false,
    },
  ];
}

function initialBackups(): BackupSummary[] {
  const now = Date.now();
  const batchA = "7f42a91c-3c88-4c1b-9a0b-5d4e21a8e012";
  const batchB = "c19d4e07-821b-4f9e-b13a-992c0a7e4f88";
  return [
    {
      id: uuid(),
      batch_id: batchA,
      target: "~/Library/Caches/com.figma.Desktop",
      backup: "~/.uninstallany/quarantine/7f42a91c/Caches_figma",
      expires_unix_ms: now + 11 * DAY_MS,
      state: "Applied",
    },
    {
      id: uuid(),
      batch_id: batchA,
      target: "~/Library/Preferences/com.figma.Desktop.plist",
      backup: "~/.uninstallany/quarantine/7f42a91c/figma.plist",
      expires_unix_ms: now + 11 * DAY_MS,
      state: "Applied",
    },
    {
      id: uuid(),
      batch_id: batchB,
      target: "~/Library/Application Support/OldLauncher/cache.db",
      backup: "~/.uninstallany/quarantine/c19d4e07/cache.db",
      expires_unix_ms: now - 2 * DAY_MS,
      state: "Applied",
    },
    {
      id: uuid(),
      batch_id: batchB,
      target: "~/Library/Logs/OldLauncher.log",
      backup: "~/.uninstallany/quarantine/c19d4e07/OldLauncher.log",
      expires_unix_ms: now - 2 * DAY_MS,
      state: "Restored",
    },
  ];
}

function buildCandidates(appName: string, mode: ScanMode): Candidate[] {
  const slug = appName.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "app";
  const list: Candidate[] = [
    {
      id: 1,
      target_display: `~/Library/Caches/${slug}`,
      category: "Directory",
      confidence: "High",
      evidence: "ExactIdentity",
      reason: "Bundle identifier matches cache container",
      risk: "Normal",
      access: "Allowed",
    },
    {
      id: 2,
      target_display: `~/Library/Preferences/com.${slug}.plist`,
      category: "File",
      confidence: "High",
      evidence: "ExactIdentity",
      reason: "Exact preference property list",
      risk: "Normal",
      access: "Allowed",
    },
    {
      id: 3,
      target_display: `~/Library/Logs/${appName}`,
      category: "Directory",
      confidence: "High",
      evidence: "ExactIdentity",
      reason: "Application-owned diagnostics directory",
      risk: "Normal",
      access: "Allowed",
    },
    {
      id: 4,
      target_display: `~/Library/Application Support/${appName}/Preferences`,
      category: "Directory",
      confidence: "Medium",
      evidence: "PublisherAndApp",
      reason: "Publisher and application name match",
      risk: "Normal",
      access: "Allowed",
    },
    {
      id: 5,
      target_display: `~/Library/LaunchAgents/com.${slug}.updater.plist`,
      category: "Startup",
      confidence: "High",
      evidence: "ExactIdentity",
      reason: "Background updater agent registered by app",
      risk: "High",
      access: "Allowed",
    },
    {
      id: 6,
      target_display: `/Library/Application Support/Shared/${slug}.framework`,
      category: "Directory",
      confidence: "Low",
      evidence: "FuzzyName",
      reason: "Shared container may be referenced by sibling tools",
      risk: "High",
      access: { ReadOnly: "Protected shared system directory" },
    },
  ];
  if (mode === "ForceRemoval") {
    list.unshift({
      id: 0,
      target_display: `/Applications/${appName}.app`,
      category: "Directory",
      confidence: "High",
      evidence: "ExactIdentity",
      reason: "Primary bundle queued for forced quarantine removal",
      risk: "High",
      access: "Allowed",
    });
  }
  return list;
}

export function createMockBackendClient(): BackendClient {
  let apps = initialApps();
  let backups = initialBackups();
  let retentionDays = 14;
  let customRules = "";
  let cancelled = false;
  const progressListeners = new Set<(p: OperationProgress) => void>();

  const pendingPlans = new Map<string, CleanupPreview>();
  const pendingUninstall = new Map<string, AppRecord[]>();
  const pendingRestore = new Map<string, BackupSummary[]>();
  const pendingExpiry = new Map<string, BackupSummary[]>();

  const emitProgress = (done: number, total: number) => {
    for (const fn of progressListeners) fn({ done, total });
  };

  const delay = async (ms: number) => {
    cancelled = false;
    await new Promise((resolve) => setTimeout(resolve, ms));
    if (cancelled) throw new Error("Operation cancelled");
  };

  return {
    mode: "mock",

    async listApplications(): Promise<Inventory> {
      await delay(320);
      return { applications: [...apps], warnings: [] };
    },

    async scanApp(appId: AppId): Promise<CleanupPreview> {
      await delay(420);
      const target = apps.find((a) => appIdKey(a.id) === appIdKey(appId));
      const name = target?.name ?? "Application";
      const plan: CleanupPreview = {
        id: uuid(),
        candidates: buildCandidates(name, "Leftovers"),
        mode: "Leftovers",
        warnings: [],
        subject: name,
      };
      pendingPlans.set(plan.id, plan);
      return plan;
    },

    async scanForceRemoval(appId: AppId): Promise<CleanupPreview> {
      await delay(450);
      const target = apps.find((a) => appIdKey(a.id) === appIdKey(appId));
      const name = target?.name ?? "Application";
      const plan: CleanupPreview = {
        id: uuid(),
        candidates: buildCandidates(name, "ForceRemoval"),
        mode: "ForceRemoval",
        warnings: ["Official uninstaller skipped; verify high-risk entries before applying."],
        subject: name,
      };
      pendingPlans.set(plan.id, plan);
      return plan;
    },

    async scanPortable(path: string): Promise<CleanupPreview> {
      await delay(380);
      const clean = path.trim();
      if (!clean.startsWith("/") && !/^[A-Za-z]:\\/.test(clean)) {
        throw new Error("Please enter an absolute directory path.");
      }
      const plan: CleanupPreview = {
        id: uuid(),
        candidates: [
          {
            id: 1,
            target_display: clean,
            category: "Directory",
            confidence: "High",
            evidence: "ExactIdentity",
            reason: "Selected portable application folder",
            risk: "Normal",
            access: "Allowed",
          },
          {
            id: 2,
            target_display: `${clean}/settings.ini`,
            category: "File",
            confidence: "High",
            evidence: "ExactIdentity",
            reason: "Local configuration inside portable directory",
            risk: "Normal",
            access: "Allowed",
          },
        ],
        mode: "Leftovers",
        warnings: [],
        subject: clean.split(/[\\/]/).filter(Boolean).pop() ?? clean,
      };
      pendingPlans.set(plan.id, plan);
      return plan;
    },

    async reviewUninstall(appIds: AppId[]): Promise<UninstallReviewPayload> {
      await delay(260);
      const keys = new Set(appIds.map(appIdKey));
      const matched = apps.filter((a) => keys.has(appIdKey(a.id)));
      const ticket = uuid();
      pendingUninstall.set(ticket, matched);
      return {
        ticket,
        intents: matched.map((a) => ({
          application: a.name,
          method:
            "Package" in a.id && a.id.Package.manager.startsWith("homebrew")
              ? `brew uninstall --cask ${a.id.Package.id}`
              : `Native vendor uninstaller (${a.install_location ?? a.name})`,
          quiet: "Package" in a.id && a.id.Package.manager.startsWith("homebrew"),
          notice:
            "Quarantine only covers leftover cleanup performed by UninstallAny after the official uninstaller finishes.",
        })),
        warnings: [],
      };
    },

    async runUninstall(ticket: string): Promise<OfficialRow[]> {
      const matched = pendingUninstall.get(ticket);
      pendingUninstall.delete(ticket);
      if (!matched) {
        throw new Error("This review ticket has expired. Please review again.");
      }
      const rows: OfficialRow[] = [];
      emitProgress(0, matched.length);
      for (let i = 0; i < matched.length; i++) {
        const app = matched[i]!;
        await delay(500);
        const cleanup: CleanupPreview = {
          id: uuid(),
          candidates: buildCandidates(app.name, "AfterOfficialUninstall"),
          mode: "AfterOfficialUninstall",
          warnings: [],
          subject: app.name,
        };
        pendingPlans.set(cleanup.id, cleanup);
        rows.push({
          application: app.name,
          outcome: { Ok: "Completed" },
          cleanup,
          warnings: [],
        });
        apps = apps.filter((a) => appIdKey(a.id) !== appIdKey(app.id));
        emitProgress(i + 1, matched.length);
      }
      return rows;
    },

    async applyCleanup(planId: string, items: number[]): Promise<ChangeReport> {
      const plan = pendingPlans.get(planId);
      pendingPlans.delete(planId);
      if (!plan) {
        throw new Error("This cleanup plan is no longer available.");
      }
      await delay(420);
      const batchId = uuid();
      const now = Date.now();
      const selected = plan.candidates.filter(
        (c) => c.access === "Allowed" && items.includes(c.id),
      );
      const reportItems = selected.map((c) => {
        const backupId = uuid();
        backups.unshift({
          id: backupId,
          batch_id: batchId,
          target: c.target_display,
          backup: `~/.uninstallany/quarantine/${batchId.slice(0, 8)}/${c.id}`,
          expires_unix_ms: now + retentionDays * DAY_MS,
          state: "Applied",
        });
        return {
          target: c.target_display,
          backup_id: backupId,
          result: "Applied" as const,
        };
      });
      return { batch_id: batchId, items: reportItems };
    },

    async listBackups(): Promise<BackupInventory> {
      await delay(260);
      return { items: [...backups], warnings: [] };
    },

    async reviewRestore(batchId: string): Promise<RestoreReviewPayload> {
      await delay(200);
      const entries = backups.filter(
        (b) => b.batch_id === batchId && b.state === "Applied",
      );
      const ticket = uuid();
      pendingRestore.set(ticket, entries);
      return { ticket, entries, warnings: [] };
    },

    async runRestore(ticket: string): Promise<ChangeReport> {
      const entries = pendingRestore.get(ticket);
      pendingRestore.delete(ticket);
      if (!entries) throw new Error("Restore review ticket expired.");
      await delay(360);
      const restoredIds = new Set(entries.map((e) => e.id));
      backups = backups.map((b) =>
        restoredIds.has(b.id) ? { ...b, state: "Restored" } : b,
      );
      return {
        batch_id: entries[0]?.batch_id ?? uuid(),
        items: entries.map((e) => ({
          target: e.target,
          backup_id: e.id,
          result: "Restored",
        })),
      };
    },

    async reviewExpiry(): Promise<ExpiryReviewPayload> {
      await delay(240);
      const now = Date.now();
      const entries = backups.filter(
        (b) => b.state === "Applied" && b.expires_unix_ms <= now,
      );
      const ticket = uuid();
      pendingExpiry.set(ticket, entries);
      return { ticket, entries, warnings: [] };
    },

    async purgeExpired(ticket: string, items: string[]): Promise<ChangeReport> {
      const entries = pendingExpiry.get(ticket);
      pendingExpiry.delete(ticket);
      if (!entries) throw new Error("Expiry review ticket expired.");
      await delay(340);
      const purgeSet = new Set(items);
      const targets = entries.filter((e) => purgeSet.has(e.id));
      backups = backups.map((b) =>
        purgeSet.has(b.id) ? { ...b, state: "Purged" } : b,
      );
      return {
        batch_id: uuid(),
        items: targets.map((e) => ({
          target: e.target,
          backup_id: e.id,
          result: "Purged",
        })),
      };
    },

    async loadPreferences(): Promise<LoadedPreferences> {
      return {
        retention_days: retentionDays,
        custom_rules: customRules,
        warnings: [],
      };
    },

    async setRetention(days: number): Promise<number> {
      await delay(220);
      retentionDays = Math.max(1, Math.min(65535, Math.floor(days)));
      return retentionDays;
    },

    async setCustomRules(text: string): Promise<RulesSavedPayload> {
      await delay(240);
      customRules = text;
      const count = (text.match(/\[\[rules\]\]/g) ?? []).length;
      return { text, count };
    },

    async exportAudit(path: string): Promise<AuditExportedPayload> {
      await delay(300);
      const trimmed = path.trim();
      if (!trimmed.endsWith(".jsonl")) {
        throw new Error("Audit export destination must end with .jsonl");
      }
      return {
        path: trimmed,
        report: { written: 42, warnings: [] },
      };
    },

    async cancelOperation(): Promise<void> {
      cancelled = true;
    },

    subscribeProgress(listener: (progress: OperationProgress) => void): () => void {
      progressListeners.add(listener);
      return () => {
        progressListeners.delete(listener);
      };
    },
  };
}
