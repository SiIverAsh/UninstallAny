import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { getBackendClient, type BackendClient } from "@/api/client";
import { detectInitialLanguage, t } from "@/i18n/messages";
import {
  appIdKey,
  isDefaultSelected,
  type AppId,
  type AppRecord,
  type AuditExport,
  type BackupInventory,
  type Category,
  type ChangeReport,
  type CleanupPreview,
  type Inventory,
  type Language,
  type OfficialRow,
  type OperationKind,
  type OperationProgress,
  type Page,
  type ReviewModal,
  type SortField,
  type ToastItem,
  type ToastKind,
} from "@/types/domain";

export interface CleanupPlanState {
  preview: CleanupPreview;
  selectedIds: Set<number>;
  lastSelectedId: number | null;
  category: Category | null;
}

export interface ActiveOperationState {
  kind: OperationKind;
  progress: OperationProgress | null;
  cancelling: boolean;
}

export type StatusBanner =
  | { kind: "error"; message: string }
  | { kind: "cancelled" }
  | { kind: "retention_saved" }
  | { kind: "rules_saved"; count: number }
  | { kind: "audit_exported" }
  | null;

export type ThemeMode = "dark" | "light";

interface AppContextValue {
  client: BackendClient;
  lang: Language;
  setLang: (lang: Language) => void;
  theme: ThemeMode;
  setTheme: (theme: ThemeMode) => void;
  page: Page;
  navigate: (page: Page) => void;

  // Applications
  inventory: Inventory | null;
  visibleApps: AppRecord[];
  totalInScope: number;
  selectedAppKeys: Set<string>;
  selectedVisibleApps: AppRecord[];
  selectedTotalBytes: number | null;
  search: string;
  setSearch: (q: string) => void;
  includeSystem: boolean;
  setIncludeSystem: (v: boolean) => void;
  sortField: SortField;
  sortDesc: boolean;
  sortOn: (field: SortField) => void;
  toggleAppRow: (appId: AppId, extendRange: boolean) => void;
  selectAllVisibleApps: () => void;
  clearAppSelection: () => void;
  portableOpen: boolean;
  setPortableOpen: (open: boolean) => void;
  portablePath: string;
  setPortablePath: (path: string) => void;
  searchInputRef: React.RefObject<HTMLInputElement | null>;

  // Quarantine
  quarantine: BackupInventory | null;

  // Review & Results
  plans: CleanupPlanState[];
  uninstallResults: OfficialRow[];
  changeResult: ChangeReport | null;
  hasReview: boolean;
  toggleCandidate: (visibleAllowedIds: number[], id: number, extendRange: boolean) => void;
  setPlanSelectedIds: (ids: Set<number>) => void;
  setPlanCategory: (category: Category | null) => void;
  dismissFrontPlan: () => void;

  // Settings
  retention: number;
  savedRetention: number;
  setRetention: (days: number) => void;
  ruleText: string;
  savedRuleText: string;
  setRuleText: (text: string) => void;
  exportDestination: string;
  setExportDestination: (path: string) => void;
  exportResult: { path: string; report: AuditExport } | null;
  preferenceWarnings: string[];

  // Modals, operations, status, toasts
  modal: ReviewModal | null;
  setModal: (modal: ReviewModal | null) => void;
  activeOp: ActiveOperationState | null;
  isBusy: boolean;
  isRunning: (kind: OperationKind) => boolean;
  status: StatusBanner;
  clearStatus: () => void;
  toasts: ToastItem[];
  pushToast: (kind: ToastKind, message: string) => void;
  dismissToast: (id: number) => void;
  copyText: (text: string, label: string) => void;

  // Commands
  refreshApplications: () => Promise<void>;
  refreshBackups: () => Promise<void>;
  scanApp: (appId: AppId) => Promise<void>;
  scanForceRemoval: (appId: AppId) => Promise<void>;
  scanPortable: (path: string) => Promise<void>;
  reviewUninstall: (appIds: AppId[]) => Promise<void>;
  reviewRestore: (batchId: string) => Promise<void>;
  reviewExpiry: () => Promise<void>;
  approveUninstall: (ticket: string) => Promise<void>;
  approveCleanup: (planId: string, items: number[]) => Promise<void>;
  approveRestore: (ticket: string) => Promise<void>;
  approvePurgeExpired: (ticket: string, items: string[]) => Promise<void>;
  saveRetention: () => Promise<void>;
  saveRules: () => Promise<void>;
  exportAudit: () => Promise<void>;
  cancelActive: () => Promise<void>;
}

const AppContext = createContext<AppContextValue | null>(null);

function makePlanState(preview: CleanupPreview): CleanupPlanState {
  return {
    preview,
    selectedIds: new Set(
      preview.candidates.filter(isDefaultSelected).map((c) => c.id),
    ),
    lastSelectedId: null,
    category: null,
  };
}

function matchesSearch(app: AppRecord, query: string): boolean {
  if (!query) return true;
  return (
    app.name.toLowerCase().includes(query) ||
    (app.publisher?.toLowerCase().includes(query) ?? false) ||
    (app.version?.toLowerCase().includes(query) ?? false) ||
    (app.install_location?.toLowerCase().includes(query) ?? false)
  );
}

function compareApps(a: AppRecord, b: AppRecord, field: SortField, desc: boolean): number {
  const compareOptStr = (x?: string | null, y?: string | null) => {
    const xv = x?.trim().toLowerCase() ?? "";
    const yv = y?.trim().toLowerCase() ?? "";
    if (!xv && !yv) return 0;
    if (!xv) return 1;
    if (!yv) return -1;
    const cmp = xv.localeCompare(yv);
    return desc ? -cmp : cmp;
  };
  let primary = 0;
  switch (field) {
    case "name":
      primary = compareOptStr(a.name, b.name);
      break;
    case "publisher":
      primary = compareOptStr(a.publisher, b.publisher);
      break;
    case "date":
      primary = compareOptStr(a.install_date, b.install_date);
      break;
    case "size": {
      const xs = a.size_bytes;
      const ys = b.size_bytes;
      if (xs == null && ys == null) primary = 0;
      else if (xs == null) primary = 1;
      else if (ys == null) primary = -1;
      else primary = desc ? ys - xs : xs - ys;
      break;
    }
  }
  if (primary !== 0) return primary;
  return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
}

export function AppProvider({ children }: { children: ReactNode }) {
  const client = useMemo(() => getBackendClient(), []);
  const [lang, setLang] = useState<Language>(detectInitialLanguage);
  const [theme, setTheme] = useState<ThemeMode>(() => {
    if (typeof window !== "undefined") {
      const saved = window.localStorage.getItem("uninstallany.theme");
      if (saved === "light" || saved === "dark") return saved;
    }
    return "dark";
  });
  const [page, setPage] = useState<Page>("applications");

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      window.localStorage.setItem("uninstallany.theme", theme);
    } catch {
      // Ignore storage errors in restricted contexts.
    }
  }, [theme]);

  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [appsNeedRefresh, setAppsNeedRefresh] = useState(false);
  const [selectedAppKeys, setSelectedAppKeys] = useState<Set<string>>(() => new Set());
  const [lastSelectedAppKey, setLastSelectedAppKey] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [includeSystem, setIncludeSystem] = useState(false);
  const [sortField, setSortField] = useState<SortField>("name");
  const [sortDesc, setSortDesc] = useState(false);
  const [portableOpen, setPortableOpen] = useState(false);
  const [portablePath, setPortablePath] = useState("");
  const searchInputRef = useRef<HTMLInputElement | null>(null);

  const [quarantine, setQuarantine] = useState<BackupInventory | null>(null);
  const [quarantineNeedsRefresh, setQuarantineNeedsRefresh] = useState(true);

  const [plans, setPlans] = useState<CleanupPlanState[]>([]);
  const [uninstallResults, setUninstallResults] = useState<OfficialRow[]>([]);
  const [changeResult, setChangeResult] = useState<ChangeReport | null>(null);

  const [retention, setRetention] = useState(14);
  const [savedRetention, setSavedRetention] = useState(14);
  const [ruleText, setRuleText] = useState("");
  const [savedRuleText, setSavedRuleText] = useState("");
  const [exportDestination, setExportDestination] = useState("");
  const [exportResult, setExportResult] = useState<{
    path: string;
    report: AuditExport;
  } | null>(null);
  const [preferenceWarnings, setPreferenceWarnings] = useState<string[]>([]);

  const [modal, setModal] = useState<ReviewModal | null>(null);
  const [activeOp, setActiveOp] = useState<ActiveOperationState | null>(null);
  const [status, setStatus] = useState<StatusBanner>(null);
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const toastSeq = useRef(1);

  const isBusy = activeOp !== null;
  const isRunning = useCallback(
    (kind: OperationKind) => activeOp?.kind === kind,
    [activeOp],
  );

  const pushToast = useCallback((kind: ToastKind, message: string) => {
    const trimmed = message.trim();
    if (!trimmed) return;
    const durationMs = kind === "error" ? 5500 : kind === "warning" ? 4500 : 3400;
    setToasts((prev) => {
      const id = toastSeq.current++;
      const next = [...prev.filter((item) => item.message !== trimmed), {
        id,
        kind,
        message: trimmed,
        durationMs,
        createdAt: Date.now(),
      }];
      return next.slice(-3);
    });
  }, []);

  const dismissToast = useCallback((id: number) => {
    setToasts((prev) => prev.filter((item) => item.id !== id));
  }, []);

  const copyText = useCallback(
    (text: string, label: string) => {
      void navigator.clipboard?.writeText(text);
      pushToast(
        "success",
        lang === "zh" ? `已复制${label}` : `Copied ${label}`,
      );
    },
    [lang, pushToast],
  );

  // Subscribe to backend progress events
  useEffect(() => {
    return client.subscribeProgress((progress) => {
      setActiveOp((prev) => (prev ? { ...prev, progress } : prev));
    });
  }, [client]);

  const runOp = useCallback(
    async <T,>(kind: OperationKind, task: () => Promise<T>): Promise<T | null> => {
      if (activeOp) return null;
      setActiveOp({ kind, progress: null, cancelling: false });
      setStatus(null);
      try {
        return await task();
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (message.toLowerCase().includes("cancel")) {
          setStatus({ kind: "cancelled" });
          pushToast("warning", t(lang, "Operation cancelled", "操作已取消"));
        } else {
          setStatus({ kind: "error", message });
          pushToast("error", message);
        }
        return null;
      } finally {
        setActiveOp(null);
      }
    },
    [activeOp, lang, pushToast],
  );

  const refreshApplications = useCallback(async () => {
    const data = await runOp("inventory", () => client.listApplications());
    if (!data) return;
    const currentKeys = new Set(data.applications.map((a) => appIdKey(a.id)));
    setSelectedAppKeys((prev) => {
      const next = new Set<string>();
      for (const key of prev) {
        if (currentKeys.has(key)) next.add(key);
      }
      return next;
    });
    setInventory(data);
    setAppsNeedRefresh(false);
  }, [client, runOp]);

  const refreshBackups = useCallback(async () => {
    const data = await runOp("backups", () => client.listBackups());
    if (!data) return;
    setQuarantine(data);
    setQuarantineNeedsRefresh(false);
  }, [client, runOp]);

  // Initial load on mount
  const initialized = useRef(false);
  useEffect(() => {
    if (initialized.current) return;
    initialized.current = true;
    void client
      .loadPreferences()
      .then((prefs) => {
        setRetention(prefs.retention_days);
        setSavedRetention(prefs.retention_days);
        setRuleText(prefs.custom_rules);
        setSavedRuleText(prefs.custom_rules);
        setPreferenceWarnings(prefs.warnings);
      })
      .catch(() => {});
    void refreshApplications();
  }, [client, refreshApplications]);

  const totalInScope = useMemo(() => {
    if (!inventory) return 0;
    return inventory.applications.filter(
      (app) => includeSystem || !app.system_component,
    ).length;
  }, [includeSystem, inventory]);

  const visibleApps = useMemo(() => {
    if (!inventory) return [];
    const query = search.trim().toLowerCase();
    return inventory.applications
      .filter((app) => (includeSystem || !app.system_component) && matchesSearch(app, query))
      .sort((a, b) => compareApps(a, b, sortField, sortDesc));
  }, [includeSystem, inventory, search, sortDesc, sortField]);

  const selectedVisibleApps = useMemo(
    () => visibleApps.filter((app) => selectedAppKeys.has(appIdKey(app.id))),
    [selectedAppKeys, visibleApps],
  );

  const selectedTotalBytes = useMemo(() => {
    let sum = 0;
    let any = false;
    for (const app of selectedVisibleApps) {
      if (app.size_bytes != null) {
        sum += app.size_bytes;
        any = true;
      }
    }
    return any ? sum : null;
  }, [selectedVisibleApps]);

  const sortOn = useCallback((field: SortField) => {
    setSortDesc((prevDesc) => (sortField === field ? !prevDesc : false));
    setSortField(field);
  }, [sortField]);

  const toggleAppRow = useCallback(
    (appId: AppId, extendRange: boolean) => {
      const key = appIdKey(appId);
      setSelectedAppKeys((prev) => {
        const next = new Set(prev);
        if (extendRange && lastSelectedAppKey) {
          const anchorIdx = visibleApps.findIndex(
            (a) => appIdKey(a.id) === lastSelectedAppKey,
          );
          const targetIdx = visibleApps.findIndex((a) => appIdKey(a.id) === key);
          if (anchorIdx !== -1 && targetIdx !== -1) {
            const [lo, hi] =
              anchorIdx <= targetIdx ? [anchorIdx, targetIdx] : [targetIdx, anchorIdx];
            for (let i = lo; i <= hi; i++) {
              next.add(appIdKey(visibleApps[i]!.id));
            }
            return next;
          }
        }
        if (next.has(key)) next.delete(key);
        else next.add(key);
        return next;
      });
      setLastSelectedAppKey(key);
    },
    [lastSelectedAppKey, visibleApps],
  );

  const selectAllVisibleApps = useCallback(() => {
    setSelectedAppKeys((prev) => {
      const next = new Set(prev);
      for (const app of visibleApps) next.add(appIdKey(app.id));
      return next;
    });
  }, [visibleApps]);

  const clearAppSelection = useCallback(() => {
    setSelectedAppKeys(new Set());
    setLastSelectedAppKey(null);
  }, []);

  const navigate = useCallback(
    (nextPage: Page) => {
      setPage(nextPage);
      if (isBusy || modal) return;
      if (nextPage === "applications" && appsNeedRefresh) {
        void refreshApplications();
      } else if (nextPage === "quarantine" && quarantineNeedsRefresh) {
        void refreshBackups();
      }
    },
    [appsNeedRefresh, isBusy, modal, quarantineNeedsRefresh, refreshApplications, refreshBackups],
  );

  const scanApp = useCallback(
    async (appId: AppId) => {
      const preview = await runOp("scan", () => client.scanApp(appId));
      if (!preview) return;
      setPlans([makePlanState(preview)]);
      setPage("review");
      pushToast(
        "info",
        lang === "zh"
          ? `扫描完成，发现 ${preview.candidates.length} 个候选项`
          : `Scan complete: ${preview.candidates.length} candidates found`,
      );
    },
    [client, lang, pushToast, runOp],
  );

  const scanForceRemoval = useCallback(
    async (appId: AppId) => {
      const preview = await runOp("scan", () => client.scanForceRemoval(appId));
      if (!preview) return;
      setPlans([makePlanState(preview)]);
      setPage("review");
      pushToast(
        "warning",
        lang === "zh"
          ? `已生成强制移除预览（${preview.candidates.length} 项）`
          : `Force removal preview ready (${preview.candidates.length} items)`,
      );
    },
    [client, lang, pushToast, runOp],
  );

  const scanPortable = useCallback(
    async (path: string) => {
      const preview = await runOp("scan", () => client.scanPortable(path));
      if (!preview) return;
      setPlans([makePlanState(preview)]);
      setPage("review");
      pushToast(
        "info",
        lang === "zh"
          ? `目录扫描完成，发现 ${preview.candidates.length} 个候选项`
          : `Folder scan complete: ${preview.candidates.length} candidates`,
      );
    },
    [client, lang, pushToast, runOp],
  );

  const reviewUninstall = useCallback(
    async (appIds: AppId[]) => {
      const res = await runOp("prepare_uninstall", () => client.reviewUninstall(appIds));
      if (!res) return;
      setModal({
        kind: "uninstall",
        ticket: res.ticket,
        intents: res.intents,
        warnings: res.warnings,
      });
    },
    [client, runOp],
  );

  const approveUninstall = useCallback(
    async (ticket: string) => {
      setModal(null);
      const rows = await runOp("uninstall", () => client.runUninstall(ticket));
      if (!rows) return;
      const queued: CleanupPlanState[] = [];
      for (const row of rows) {
        if (row.cleanup) {
          queued.push(
            makePlanState({ ...row.cleanup, subject: row.cleanup.subject ?? row.application }),
          );
        }
      }
      setPlans(queued);
      setUninstallResults(rows);
      clearAppSelection();
      setAppsNeedRefresh(true);
      setPage("review");
      pushToast(
        "info",
        lang === "zh"
          ? `已完成 ${rows.length} 项官方卸载任务`
          : `Finished ${rows.length} official uninstall task(s)`,
      );
    },
    [clearAppSelection, client, lang, pushToast, runOp],
  );

  const approveCleanup = useCallback(
    async (planId: string, items: number[]) => {
      setModal(null);
      const report = await runOp("cleanup", () => client.applyCleanup(planId, items));
      if (!report) return;
      setPlans((prev) => prev.filter((p) => p.preview.id !== planId));
      setChangeResult(report);
      setAppsNeedRefresh(true);
      setQuarantineNeedsRefresh(true);
      setPage("review");
      const warn = report.items.some(
        (i) => typeof i.result === "object" && ("Skipped" in i.result || "NeedsReview" in i.result),
      );
      pushToast(
        warn ? "warning" : "success",
        warn
          ? lang === "zh"
            ? `已处理 ${report.items.length} 个项目，部分需复核或跳过`
            : `Processed ${report.items.length} item(s); some need review`
          : lang === "zh"
            ? `已安全隔离 ${report.items.length} 个项目`
            : `Safely quarantined ${report.items.length} item(s)`,
      );
    },
    [client, lang, pushToast, runOp],
  );

  const reviewRestore = useCallback(
    async (batchId: string) => {
      const res = await runOp("prepare_restore", () => client.reviewRestore(batchId));
      if (!res) return;
      setModal({
        kind: "restore",
        ticket: res.ticket,
        entries: res.entries,
        warnings: res.warnings,
      });
    },
    [client, runOp],
  );

  const approveRestore = useCallback(
    async (ticket: string) => {
      setModal(null);
      const report = await runOp("restore", () => client.runRestore(ticket));
      if (!report) return;
      setChangeResult(report);
      setQuarantineNeedsRefresh(true);
      setPage("review");
      pushToast(
        "success",
        lang === "zh"
          ? `已还原 ${report.items.length} 个项目`
          : `Restored ${report.items.length} item(s)`,
      );
    },
    [client, lang, pushToast, runOp],
  );

  const reviewExpiry = useCallback(async () => {
    const res = await runOp("expiry_preview", () => client.reviewExpiry());
    if (!res) return;
    setModal({
      kind: "expiry",
      ticket: res.ticket,
      entries: res.entries,
      warnings: res.warnings,
    });
  }, [client, runOp]);

  const approvePurgeExpired = useCallback(
    async (ticket: string, items: string[]) => {
      setModal(null);
      const report = await runOp("purge_expired", () => client.purgeExpired(ticket, items));
      if (!report) return;
      setChangeResult(report);
      setQuarantineNeedsRefresh(true);
      setPage("review");
      pushToast(
        "success",
        lang === "zh"
          ? `已永久清理 ${report.items.length} 个到期备份`
          : `Permanently removed ${report.items.length} expired item(s)`,
      );
    },
    [client, lang, pushToast, runOp],
  );

  const saveRetention = useCallback(async () => {
    const saved = await runOp("preferences", () => client.setRetention(retention));
    if (saved == null) return;
    setRetention(saved);
    setSavedRetention(saved);
    setStatus({ kind: "retention_saved" });
    pushToast(
      "success",
      lang === "zh" ? `隔离保留期已更新为 ${saved} 天` : `Retention updated to ${saved} days`,
    );
  }, [client, lang, pushToast, retention, runOp]);

  const saveRules = useCallback(async () => {
    const res = await runOp("preferences", () => client.setCustomRules(ruleText));
    if (!res) return;
    setSavedRuleText(res.text);
    setStatus({ kind: "rules_saved", count: res.count });
    pushToast(
      "success",
      res.count === 0
        ? t(lang, "Using built-in rules only", "已切换为仅使用内置规则")
        : lang === "zh"
          ? `已保存 ${res.count} 条自定义规则`
          : `Saved ${res.count} custom rules`,
    );
  }, [client, lang, pushToast, ruleText, runOp]);

  const exportAudit = useCallback(async () => {
    const res = await runOp("audit_export", () => client.exportAudit(exportDestination.trim()));
    if (!res) return;
    setExportResult(res);
    setStatus({ kind: "audit_exported" });
    pushToast(
      "success",
      lang === "zh"
        ? `已导出 ${res.report.written} 条操作日志`
        : `Exported ${res.report.written} audit records`,
    );
  }, [client, exportDestination, lang, pushToast, runOp]);

  const cancelActive = useCallback(async () => {
    setActiveOp((prev) => (prev ? { ...prev, cancelling: true } : prev));
    await client.cancelOperation();
  }, [client]);

  const toggleCandidate = useCallback(
    (visibleAllowedIds: number[], id: number, extendRange: boolean) => {
      setPlans((prev) => {
        if (prev.length === 0) return prev;
        const [front, ...rest] = prev;
        const nextSet = new Set(front!.selectedIds);
        if (extendRange && front!.lastSelectedId != null) {
          const a = visibleAllowedIds.indexOf(front!.lastSelectedId);
          const b = visibleAllowedIds.indexOf(id);
          if (a !== -1 && b !== -1) {
            const [lo, hi] = a <= b ? [a, b] : [b, a];
            for (let i = lo; i <= hi; i++) nextSet.add(visibleAllowedIds[i]!);
            return [{ ...front!, selectedIds: nextSet, lastSelectedId: id }, ...rest];
          }
        }
        if (nextSet.has(id)) nextSet.delete(id);
        else nextSet.add(id);
        return [{ ...front!, selectedIds: nextSet, lastSelectedId: id }, ...rest];
      });
    },
    [],
  );

  const setPlanSelectedIds = useCallback((ids: Set<number>) => {
    setPlans((prev) => {
      if (prev.length === 0) return prev;
      const [front, ...rest] = prev;
      return [{ ...front!, selectedIds: ids, lastSelectedId: null }, ...rest];
    });
  }, []);

  const setPlanCategory = useCallback((category: Category | null) => {
    setPlans((prev) => {
      if (prev.length === 0) return prev;
      const [front, ...rest] = prev;
      return [{ ...front!, category }, ...rest];
    });
  }, []);

  const dismissFrontPlan = useCallback(() => {
    setPlans((prev) => prev.slice(1));
  }, []);

  // Global desktop keyboard shortcuts
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (modal) return;
      const cmd = e.metaKey || e.ctrlKey;
      const target = e.target as HTMLElement | null;
      const inEditable =
        target instanceof HTMLInputElement ||
        target instanceof HTMLTextAreaElement ||
        Boolean(target?.isContentEditable);

      if (cmd && e.key.toLowerCase() === "f") {
        e.preventDefault();
        if (page !== "applications") setPage("applications");
        window.setTimeout(() => {
          searchInputRef.current?.focus();
          searchInputRef.current?.select();
        }, 0);
        return;
      }

      if (((cmd && e.key.toLowerCase() === "r") || e.key === "F5") && !inEditable && !isBusy) {
        e.preventDefault();
        if (page === "applications") void refreshApplications();
        else if (page === "quarantine") void refreshBackups();
        return;
      }

      if (cmd && e.key.toLowerCase() === "a" && !inEditable && page === "applications") {
        e.preventDefault();
        selectAllVisibleApps();
        return;
      }

      if (cmd && e.key.toLowerCase() === "s" && page === "settings" && !isBusy) {
        e.preventDefault();
        if (ruleText !== savedRuleText) void saveRules();
        else if (retention !== savedRetention) void saveRetention();
        return;
      }

      if (e.key === "Escape") {
        if (portableOpen) {
          setPortableOpen(false);
        } else if (status?.kind === "error") {
          setStatus(null);
        } else if (page === "applications" && search.length > 0) {
          setSearch("");
        } else if (page === "applications" && selectedAppKeys.size > 0) {
          clearAppSelection();
        }
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [
    clearAppSelection,
    isBusy,
    modal,
    page,
    portableOpen,
    refreshApplications,
    refreshBackups,
    retention,
    ruleText,
    saveRetention,
    saveRules,
    savedRetention,
    savedRuleText,
    search.length,
    selectAllVisibleApps,
    selectedAppKeys.size,
    status?.kind,
  ]);

  const hasReview =
    plans.length > 0 || uninstallResults.length > 0 || changeResult !== null;

  const value: AppContextValue = {
    client,
    lang,
    setLang,
    theme,
    setTheme,
    page,
    navigate,
    inventory,
    visibleApps,
    totalInScope,
    selectedAppKeys,
    selectedVisibleApps,
    selectedTotalBytes,
    search,
    setSearch,
    includeSystem,
    setIncludeSystem,
    sortField,
    sortDesc,
    sortOn,
    toggleAppRow,
    selectAllVisibleApps,
    clearAppSelection,
    portableOpen,
    setPortableOpen,
    portablePath,
    setPortablePath,
    searchInputRef,
    quarantine,
    plans,
    uninstallResults,
    changeResult,
    hasReview,
    toggleCandidate,
    setPlanSelectedIds,
    setPlanCategory,
    dismissFrontPlan,
    retention,
    savedRetention,
    setRetention,
    ruleText,
    savedRuleText,
    setRuleText,
    exportDestination,
    setExportDestination,
    exportResult,
    preferenceWarnings,
    modal,
    setModal,
    activeOp,
    isBusy,
    isRunning,
    status,
    clearStatus: () => setStatus(null),
    toasts,
    pushToast,
    dismissToast,
    copyText,
    refreshApplications,
    refreshBackups,
    scanApp,
    scanForceRemoval,
    scanPortable,
    reviewUninstall,
    reviewRestore,
    reviewExpiry,
    approveUninstall,
    approveCleanup,
    approveRestore,
    approvePurgeExpired,
    saveRetention,
    saveRules,
    exportAudit,
    cancelActive,
  };

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

export function useApp(): AppContextValue {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error("useApp must be used inside AppProvider");
  return ctx;
}
