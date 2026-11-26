import { useState } from "react";
import {
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  ChevronsUpDown,
  ChevronDown,
  Copy,
  FolderSearch,
  Info,
  RefreshCw,
  Search,
  Trash2,
  X,
} from "lucide-react";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Checkbox, ToggleSwitch } from "@/components/ui/Controls";
import { TextInput } from "@/components/ui/Inputs";
import {
  DiagnosticsBlock,
  EmptyState,
  LoadingSkeleton,
  PopoverMenu,
} from "@/components/ui/Primitives";
import { t } from "@/i18n/messages";
import { useApp } from "@/store/AppContext";
import { appIdKey, type AppRecord, type SortField } from "@/types/domain";
import {
  formatBytes,
  formatInstallDate,
  glyphClasses,
  glyphLetter,
  isMacPlatform,
  sourceBadgeMeta,
} from "@/utils/format";

export function ApplicationsPage() {
  const {
    lang,
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
    isBusy,
    isRunning,
    refreshApplications,
    scanApp,
    scanForceRemoval,
    scanPortable,
    reviewUninstall,
    copyText,
  } = useApp();

  const [moreOpen, setMoreOpen] = useState(false);
  const [contextMenu, setContextMenu] = useState<{
    app: AppRecord;
    x: number;
    y: number;
  } | null>(null);

  const selectedCount = selectedVisibleApps.length;
  const allVisibleSelected =
    visibleApps.length > 0 && selectedCount === visibleApps.length;
  const indeterminate = selectedCount > 0 && selectedCount < visibleApps.length;

  const canUninstall =
    selectedCount > 0 &&
    selectedVisibleApps.every(
      (a) => a.official_uninstall_available && !a.system_component,
    );

  const singleApp = selectedCount === 1 ? selectedVisibleApps[0]! : null;
  const canSingleAction = !isBusy && singleApp !== null && !singleApp.system_component;

  const uninstallLabel =
    selectedCount > 1
      ? lang === "zh"
        ? `预览卸载 (${selectedCount})`
        : `Review uninstall (${selectedCount})`
      : t(lang, "Review uninstall", "预览卸载");

  const uninstallHint =
    selectedCount === 0
      ? t(lang, "Select one or more applications first.", "请先选择一个或多个应用程序。")
      : !canUninstall
        ? t(
            lang,
            "One or more selected apps lack an available official uninstaller.",
            "所选应用中包含无官方卸载程序或系统组件的项目。",
          )
        : t(lang, "Wait for the current operation to finish.", "请等待当前操作完成。");

  const scanHint =
    selectedCount === 0
      ? t(lang, "Select a single application to scan leftovers.", "请选择单个应用以扫描残留。")
      : selectedCount > 1
        ? t(lang, "Leftover scan works on one application at a time.", "残留扫描每次仅针对单个应用程序。")
        : t(lang, "System components cannot be scanned directly.", "系统组件不支持直接扫描残留。");

  const shortcutHint = isMacPlatform() ? "⌘F" : "Ctrl+F";

  const renderSortIcon = (field: SortField) => {
    if (sortField !== field) {
      return (
        <ChevronsUpDown className="w-3 h-3 text-[var(--text-subtle)] opacity-0 group-hover:opacity-100 transition-opacity" />
      );
    }
    return sortDesc ? (
      <ArrowDown className="w-3 h-3 text-[var(--accent-text)]" />
    ) : (
      <ArrowUp className="w-3 h-3 text-[var(--accent-text)]" />
    );
  };

  return (
    <div className="flex flex-col h-full min-h-0 animate-page-enter">
      {/* Page Header */}
      <div className="flex items-center justify-between gap-3 shrink-0">
        <div className="flex items-center gap-2.5 min-w-0">
          <h1 className="text-[22px] font-semibold tracking-[-0.015em] text-[var(--text-ink)] truncate">
            {t(lang, "Applications", "应用程序")}
          </h1>
          {inventory && (
            <Badge tone="neutral" className="tabular-nums">
              {search.trim()
                ? `${visibleApps.length} / ${totalInScope}`
                : totalInScope}
            </Badge>
          )}
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <Button
            variant="secondary"
            active={portableOpen}
            icon={<FolderSearch className="w-3.5 h-3.5" />}
            onClick={() => setPortableOpen(!portableOpen)}
          >
            {portableOpen
              ? t(lang, "Hide folder scan", "收起目录扫描")
              : t(lang, "Scan a folder", "扫描目录")}
          </Button>
          <Button
            variant="secondary"
            icon={<RefreshCw className="w-3.5 h-3.5" />}
            busy={isRunning("inventory")}
            disabled={isBusy}
            disabledHint={t(
              lang,
              "Wait for the current operation to finish.",
              "请等待当前操作完成。",
            )}
            onClick={() => void refreshApplications()}
          >
            {t(lang, "Refresh", "刷新")}
          </Button>
        </div>
      </div>

      {/* Collapsible Portable Folder Scan Drawer (smooth open & close) */}
      <div
        aria-hidden={!portableOpen}
        className={[
          "grid transition-[grid-template-rows,opacity,margin] duration-180 ease-out shrink-0",
          portableOpen
            ? "grid-rows-[1fr] opacity-100 mt-3"
            : "grid-rows-[0fr] opacity-0 mt-0 pointer-events-none",
        ].join(" ")}
      >
        <div className="overflow-hidden">
          <div className="p-4 rounded-[10px] bg-[var(--bg-surface)] border border-[var(--border-line)] shadow-[var(--shadow-card)]">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <FolderSearch className="w-4 h-4 text-[var(--accent-text)]" />
                <span className="text-[13.5px] font-semibold text-[var(--text-ink)]">
                  {t(lang, "Portable application folder", "便携应用目录")}
                </span>
              </div>
              <button
                type="button"
                tabIndex={portableOpen ? 0 : -1}
                onClick={() => setPortableOpen(false)}
                title={t(lang, "Close", "收起")}
                className="inline-flex items-center justify-center w-6 h-6 rounded-full text-[var(--text-subtle)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-ink)] cursor-pointer transition-colors"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
            <p className="text-[12px] text-[var(--text-muted)] mt-0.5 mb-2.5">
              {t(
                lang,
                "Scan an unpacked directory for files and related entries",
                "扫描绿色版或免安装目录的文件及相关记录",
              )}
            </p>
            <div className="flex items-center gap-2">
              <TextInput
                tabIndex={portableOpen ? 0 : -1}
                value={portablePath}
                onChange={setPortablePath}
                onSubmit={() => {
                  if (!isBusy && portablePath.trim()) void scanPortable(portablePath);
                }}
                icon={<FolderSearch className="w-3.5 h-3.5" />}
                placeholder={t(lang, "Absolute path", "输入绝对路径")}
                containerClassName="flex-1"
              />
              <Button
                tabIndex={portableOpen ? 0 : -1}
                variant="tinted"
                icon={<Search className="w-3.5 h-3.5" />}
                busy={isRunning("scan")}
                disabled={isBusy || !portablePath.trim()}
                disabledHint={t(
                  lang,
                  "Enter an absolute folder path to preview.",
                  "请输入绝对目录路径以预览扫描。",
                )}
                onClick={() => void scanPortable(portablePath)}
              >
                {t(lang, "Preview scan", "预览扫描")}
              </Button>
            </div>
          </div>
        </div>
      </div>

      {/* Search & Filter Toolbar */}
      <div className="mt-3 flex flex-wrap items-center justify-between gap-3 shrink-0">
        <div className="flex items-center gap-3 flex-1 min-w-[240px]">
          <TextInput
            ref={searchInputRef}
            value={search}
            onChange={setSearch}
            icon={<Search className="w-3.5 h-3.5" />}
            shortcutHint={shortcutHint}
            placeholder={t(
              lang,
              "Search name, publisher, or path",
              "搜索名称、发行商或路径",
            )}
            containerClassName="w-full max-w-[360px]"
          />
          <ToggleSwitch
            checked={includeSystem}
            onChange={setIncludeSystem}
            label={t(lang, "Show system components", "显示系统组件")}
          />
        </div>
        {search.trim().length > 0 && (
          <Button
            variant="ghost"
            size="sm"
            icon={<X className="w-3 h-3" />}
            onClick={() => setSearch("")}
          >
            {t(lang, "Reset", "重置")}
          </Button>
        )}
      </div>

      {inventory && inventory.warnings.length > 0 && (
        <div className="mt-2.5 shrink-0">
          <DiagnosticsBlock
            warnings={inventory.warnings}
            label={
              lang === "zh"
                ? `${inventory.warnings.length} 条诊断信息`
                : `${inventory.warnings.length} diagnostics`
            }
          />
        </div>
      )}

      {/* Main Inventory Table Card */}
      <div className="mt-3 flex-1 min-h-0 flex flex-col rounded-[10px] bg-[var(--bg-surface)] border border-[var(--border-line)] shadow-[var(--shadow-card)] overflow-hidden">
        {/* Table Header */}
        <div className="grid grid-cols-[24px_minmax(0,2.2fr)_minmax(0,1.1fr)_88px_104px_104px] max-md:grid-cols-[24px_minmax(0,1fr)_80px_96px] items-center gap-3 h-[40px] px-4 bg-[var(--bg-surface-alt)] border-b border-[var(--border-soft)] text-[12px] font-semibold text-[var(--text-muted)] shrink-0">
          <div className="flex items-center justify-center">
            <Checkbox
              checked={allVisibleSelected}
              indeterminate={indeterminate}
              disabled={visibleApps.length === 0}
              ariaLabel={t(lang, "Select all visible applications", "选择全部可见应用")}
              title={t(lang, "Select all visible applications", "选择全部可见应用")}
              onChange={(checked) => {
                if (checked) selectAllVisibleApps();
                else clearAppSelection();
              }}
            />
          </div>

          <button
            type="button"
            onClick={() => sortOn("name")}
            className={[
              "group inline-flex items-center gap-1.5 h-7 px-1.5 -ml-1.5 rounded-[6px] hover:bg-[var(--bg-hover)] transition-colors cursor-pointer text-left truncate",
              sortField === "name" ? "text-[var(--accent-text)]" : "hover:text-[var(--text-ink)]",
            ].join(" ")}
          >
            <span className="truncate">{t(lang, "Application", "应用程序")}</span>
            {renderSortIcon("name")}
          </button>

          <button
            type="button"
            onClick={() => sortOn("publisher")}
            className={[
              "group hidden md:inline-flex items-center gap-1.5 h-7 px-1.5 -ml-1.5 rounded-[6px] hover:bg-[var(--bg-hover)] transition-colors cursor-pointer text-left truncate",
              sortField === "publisher"
                ? "text-[var(--accent-text)]"
                : "hover:text-[var(--text-ink)]",
            ].join(" ")}
          >
            <span className="truncate">{t(lang, "Publisher", "发行商")}</span>
            {renderSortIcon("publisher")}
          </button>

          <button
            type="button"
            onClick={() => sortOn("size")}
            className={[
              "group inline-flex items-center justify-end gap-1.5 h-7 px-1.5 -mr-1.5 rounded-[6px] hover:bg-[var(--bg-hover)] transition-colors cursor-pointer",
              sortField === "size" ? "text-[var(--accent-text)]" : "hover:text-[var(--text-ink)]",
            ].join(" ")}
          >
            <span>{t(lang, "Size", "大小")}</span>
            {renderSortIcon("size")}
          </button>

          <button
            type="button"
            onClick={() => sortOn("date")}
            className={[
              "group hidden md:inline-flex items-center gap-1.5 h-7 px-1.5 -ml-1.5 rounded-[6px] hover:bg-[var(--bg-hover)] transition-colors cursor-pointer truncate",
              sortField === "date" ? "text-[var(--accent-text)]" : "hover:text-[var(--text-ink)]",
            ].join(" ")}
          >
            <span className="truncate">{t(lang, "Installed", "安装日期")}</span>
            {renderSortIcon("date")}
          </button>

          <div className="text-right">{t(lang, "Source", "来源")}</div>
        </div>

        {/* Table Body */}
        <div className="flex-1 overflow-y-auto divide-y divide-[var(--border-soft)]">
          {!inventory ? (
            isBusy ? (
              <LoadingSkeleton
                message={t(
                  lang,
                  "Reading installed applications…",
                  "正在枚举已安装应用…",
                )}
              />
            ) : (
              <EmptyState
                icon={<Info className="w-5 h-5" />}
                heading={t(
                  lang,
                  "Application inventory is unavailable.",
                  "当前无法获取应用清单。",
                )}
                description={t(
                  lang,
                  "Try refreshing to read installed applications again.",
                  "点击刷新以重新读取本机已安装应用。",
                )}
                actionLabel={t(lang, "Refresh", "刷新")}
                onAction={() => void refreshApplications()}
              />
            )
          ) : visibleApps.length === 0 ? (
            <EmptyState
              icon={<Search className="w-5 h-5" />}
              heading={t(
                lang,
                "No applications match the current filter.",
                "没有符合当前筛选条件的应用。",
              )}
              description={
                search.trim()
                  ? t(
                      lang,
                      "Try another keyword or reset the search bar.",
                      "尝试更换关键词或清除搜索条件。",
                    )
                  : undefined
              }
              actionLabel={
                search.trim() ? t(lang, "Clear search", "清除搜索") : undefined
              }
              onAction={() => setSearch("")}
            />
          ) : (
            visibleApps.map((app) => {
              const key = appIdKey(app.id);
              const selected = selectedAppKeys.has(key);
              const src = sourceBadgeMeta(lang, app);
              return (
                <div
                  key={key}
                  onClick={(e) => toggleAppRow(app.id, e.shiftKey)}
                  onContextMenu={(e) => {
                    e.preventDefault();
                    setContextMenu({ app, x: e.clientX, y: e.clientY });
                  }}
                  className={[
                    "relative grid grid-cols-[24px_minmax(0,2.2fr)_minmax(0,1.1fr)_88px_104px_104px] max-md:grid-cols-[24px_minmax(0,1fr)_80px_96px] items-center gap-3 h-[58px] px-4 cursor-pointer transition-colors duration-100",
                    selected
                      ? "bg-[var(--bg-row-selected)] hover:bg-[var(--bg-row-selected-hover)]"
                      : "bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-pressed)]",
                  ].join(" ")}
                >
                  {selected && (
                    <span className="absolute left-0 top-2.5 bottom-2.5 w-[3px] rounded-r-full bg-[var(--accent)]" />
                  )}
                  <div className="flex items-center justify-center">
                    <Checkbox
                      checked={selected}
                      onChange={() => toggleAppRow(app.id, false)}
                      ariaLabel={app.name}
                    />
                  </div>

                  <div className="flex items-center gap-2.5 min-w-0">
                    <div
                      className={[
                        "inline-flex items-center justify-center w-8 h-8 rounded-[8px] border text-[13.5px] font-semibold shrink-0",
                        glyphClasses(app.name),
                      ].join(" ")}
                    >
                      {glyphLetter(app.name)}
                    </div>
                    <div className="min-w-0" title={app.install_location ?? app.name}>
                      <div className="text-[13.5px] font-semibold text-[var(--text-ink)] truncate leading-snug">
                        {app.name}
                      </div>
                      {app.version && (
                        <div className="text-[11.5px] text-[var(--text-subtle)] truncate leading-tight mt-0.5 tabular-nums">
                          {app.version}
                        </div>
                      )}
                    </div>
                  </div>

                  <div
                    className={[
                      "hidden md:block text-[12.5px] truncate",
                      app.publisher
                        ? "text-[var(--text-muted)]"
                        : "text-[var(--text-disabled)]",
                    ].join(" ")}
                    title={app.publisher ?? undefined}
                  >
                    {app.publisher ?? "—"}
                  </div>

                  <div
                    className={[
                      "text-right text-[12.5px] tabular-nums",
                      app.size_bytes != null
                        ? "text-[var(--text-muted)]"
                        : "text-[var(--text-disabled)]",
                    ].join(" ")}
                  >
                    {app.size_bytes != null ? formatBytes(app.size_bytes) : "—"}
                  </div>

                  <div
                    className={[
                      "hidden md:block text-[12.5px] tabular-nums",
                      app.install_date
                        ? "text-[var(--text-muted)]"
                        : "text-[var(--text-disabled)]",
                    ].join(" ")}
                  >
                    {app.install_date ? formatInstallDate(app.install_date) : "—"}
                  </div>

                  <div className="flex justify-end">
                    <Badge tone={src.tone} title={src.hint}>
                      {src.label}
                    </Badge>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Elevated Floating Bottom Action Bar */}
      <div
        className={[
          "mt-3 px-4 py-2.5 rounded-[10px] border shadow-[var(--shadow-card)] flex flex-wrap items-center justify-between gap-3 transition-colors duration-150 shrink-0",
          selectedCount > 0
            ? "bg-[var(--accent-soft)] border-[var(--accent-border)]"
            : "bg-[var(--bg-surface)] border-[var(--border-line)]",
        ].join(" ")}
      >
        <div className="flex items-center gap-2.5 min-w-0">
          {selectedCount > 0 ? (
            <>
              <Badge tone="accent" className="tabular-nums">
                {lang === "zh" ? `已选 ${selectedCount} 项` : `${selectedCount} selected`}
              </Badge>
              {selectedTotalBytes != null && (
                <span className="text-[12.5px] text-[var(--text-muted)] tabular-nums">
                  {lang === "zh"
                    ? `约 ${formatBytes(selectedTotalBytes)}`
                    : `Total ${formatBytes(selectedTotalBytes)}`}
                </span>
              )}
              <Button
                variant="ghost"
                size="sm"
                icon={<X className="w-3 h-3" />}
                onClick={clearAppSelection}
              >
                {t(lang, "Clear", "清除")}
              </Button>
            </>
          ) : (
            <div className="flex items-center gap-2 text-[12.5px] text-[var(--text-muted)]">
              <span className="tabular-nums">
                {lang === "zh"
                  ? `共 ${visibleApps.length} 个应用`
                  : `${visibleApps.length} shown`}
              </span>
              {visibleApps.length > 0 && (
                <span className="hidden lg:inline text-[var(--text-subtle)]">
                  ·{" "}
                  {t(
                    lang,
                    "Click rows or Shift+Click to select · Right-click for quick actions",
                    "点击行或 Shift+点击 多选 · 右键打开快捷菜单",
                  )}
                </span>
              )}
            </div>
          )}
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <div className="relative">
            <Button
              variant="secondary"
              active={moreOpen}
              trailingIcon={<ChevronDown className="w-3.5 h-3.5" />}
              disabled={!canSingleAction}
              disabledHint={scanHint}
              onClick={() => setMoreOpen((v) => !v)}
            >
              {t(lang, "More", "更多")}
            </Button>
            <PopoverMenu
              open={moreOpen}
              align="left"
              onClose={() => setMoreOpen(false)}
              items={[
                {
                  label: t(lang, "Review force removal", "预览强制移除"),
                  description: t(
                    lang,
                    "Use when official uninstaller fails",
                    "仅在官方卸载失效时使用",
                  ),
                  icon: <AlertTriangle className="w-3.5 h-3.5" />,
                  danger: true,
                  disabled: !canSingleAction,
                  onClick: () => {
                    if (singleApp) void scanForceRemoval(singleApp.id);
                  },
                },
              ]}
            />
          </div>

          <Button
            variant="secondary"
            icon={<Search className="w-3.5 h-3.5" />}
            busy={isRunning("scan")}
            disabled={!canSingleAction}
            disabledHint={scanHint}
            onClick={() => {
              if (singleApp) void scanApp(singleApp.id);
            }}
          >
            {t(lang, "Scan leftovers", "扫描残留")}
          </Button>

          <Button
            variant="primary"
            icon={<Trash2 className="w-3.5 h-3.5" />}
            busy={isRunning("prepare_uninstall")}
            disabled={isBusy || !canUninstall}
            disabledHint={uninstallHint}
            onClick={() => void reviewUninstall(selectedVisibleApps.map((a) => a.id))}
          >
            {uninstallLabel}
          </Button>
        </div>
      </div>

      {/* Row Right-Click Context Menu */}
      {contextMenu && (
        <PopoverMenu
          open
          onClose={() => setContextMenu(null)}
          position={{ x: contextMenu.x, y: contextMenu.y }}
          items={[
            {
              label: t(lang, "Scan leftovers", "扫描残留"),
              icon: <Search className="w-3.5 h-3.5" />,
              disabled: isBusy || contextMenu.app.system_component,
              onClick: () => void scanApp(contextMenu.app.id),
            },
            {
              label: t(lang, "Review uninstall", "预览卸载"),
              icon: <Trash2 className="w-3.5 h-3.5" />,
              disabled:
                isBusy ||
                contextMenu.app.system_component ||
                !contextMenu.app.official_uninstall_available,
              onClick: () => void reviewUninstall([contextMenu.app.id]),
            },
            {
              label: t(lang, "Review force removal", "预览强制移除"),
              icon: <AlertTriangle className="w-3.5 h-3.5" />,
              danger: true,
              disabled: isBusy || contextMenu.app.system_component,
              onClick: () => void scanForceRemoval(contextMenu.app.id),
            },
            ...(contextMenu.app.install_location
              ? [
                  {
                    label: t(lang, "Copy install path", "复制安装路径"),
                    icon: <Copy className="w-3.5 h-3.5" />,
                    dividerBefore: true,
                    onClick: () =>
                      copyText(
                        contextMenu.app.install_location!,
                        t(lang, "install path", "安装路径"),
                      ),
                  },
                ]
              : []),
          ]}
        />
      )}
    </div>
  );
}
