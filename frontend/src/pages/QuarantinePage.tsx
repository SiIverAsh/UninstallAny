import { useMemo } from "react";
import { Archive, Clock, Copy, RefreshCw, RotateCcw } from "lucide-react";
import { Badge, type BadgeTone } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import {
  CollapsibleSection,
  DiagnosticsBlock,
  EmptyState,
  LoadingSkeleton,
  MetricCard,
} from "@/components/ui/Primitives";
import { recoveryLabel, t } from "@/i18n/messages";
import { useApp } from "@/store/AppContext";
import type { BackupSummary, RecoveryState } from "@/types/domain";
import { formatExpiry } from "@/utils/format";

function recoveryTone(state: RecoveryState): BadgeTone {
  switch (state) {
    case "Applied":
      return "success";
    case "Staged":
      return "warning";
    case "NeedsReview":
      return "danger";
    default:
      return "neutral";
  }
}

export function QuarantinePage() {
  const {
    lang,
    quarantine,
    isBusy,
    isRunning,
    refreshBackups,
    reviewRestore,
    reviewExpiry,
    navigate,
    copyText,
  } = useApp();

  const batches = useMemo(() => {
    if (!quarantine) return [];
    const grouped = new Map<string, BackupSummary[]>();
    for (const item of quarantine.items) {
      const list = grouped.get(item.batch_id) ?? [];
      list.push(item);
      grouped.set(item.batch_id, list);
    }
    return Array.from(grouped.entries());
  }, [quarantine]);

  const now = Date.now();
  const recoverableTotal =
    quarantine?.items.filter((i) => i.state === "Applied").length ?? 0;
  const reachedTotal =
    quarantine?.items.filter(
      (i) => i.state === "Applied" && i.expires_unix_ms <= now,
    ).length ?? 0;

  return (
    <div className="flex flex-col h-full min-h-0 animate-page-enter">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 shrink-0">
        <h1 className="text-[22px] font-semibold tracking-[-0.015em] text-[var(--text-ink)]">
          {t(lang, "Quarantine", "隔离区")}
        </h1>
        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            icon={<Clock className="w-3.5 h-3.5" />}
            busy={isRunning("expiry_preview")}
            disabled={isBusy || !quarantine}
            onClick={() => void reviewExpiry()}
          >
            {t(lang, "Review expired files", "检查到期文件")}
          </Button>
          <Button
            variant="secondary"
            icon={<RefreshCw className="w-3.5 h-3.5" />}
            busy={isRunning("backups")}
            disabled={isBusy}
            onClick={() => void refreshBackups()}
          >
            {t(lang, "Refresh", "刷新")}
          </Button>
        </div>
      </div>

      {/* Body */}
      <div className="mt-3 flex-1 min-h-0 overflow-y-auto space-y-3 pr-0.5">
        {!quarantine ? (
          <div className="rounded-[10px] bg-[var(--bg-surface)] border border-[var(--border-line)] shadow-[var(--shadow-card)]">
            {isBusy ? (
              <LoadingSkeleton
                rows={4}
                message={t(
                  lang,
                  "Reading recoverable backups…",
                  "正在读取可恢复的备份…",
                )}
              />
            ) : (
              <EmptyState
                icon={<Archive className="w-5 h-5" />}
                heading={t(
                  lang,
                  "Quarantine inventory is unavailable.",
                  "当前无法获取隔离区清单。",
                )}
                actionLabel={t(lang, "Refresh", "刷新")}
                onAction={() => void refreshBackups()}
              />
            )}
          </div>
        ) : (
          <>
            <DiagnosticsBlock
              warnings={quarantine.warnings}
              label={
                lang === "zh"
                  ? `${quarantine.warnings.length} 条诊断信息`
                  : `${quarantine.warnings.length} diagnostics`
              }
            />

            {quarantine.items.length === 0 ? (
              <div className="rounded-[10px] bg-[var(--bg-surface)] border border-[var(--border-line)] shadow-[var(--shadow-card)]">
                <EmptyState
                  icon={<Archive className="w-5 h-5" />}
                  heading={t(lang, "No items have been quarantined.", "还没有隔离项目。")}
                  description={t(
                    lang,
                    "Files and backups isolated during cleanup appear here for safe restoration.",
                    "清理过程中隔离的文件与备份会显示在这里，随时可供还原。",
                  )}
                  actionLabel={t(lang, "Go to Applications", "前往应用程序")}
                  onAction={() => navigate("applications")}
                />
              </div>
            ) : (
              <>
                {/* 3-Tile Overview Strip */}
                <div className="grid grid-cols-3 gap-3">
                  <MetricCard
                    label={t(lang, "Quarantine batches", "隔离批次")}
                    value={batches.length}
                    tone="accent"
                    icon={<Archive className="w-4 h-4" />}
                  />
                  <MetricCard
                    label={t(lang, "Recoverable items", "可还原项目")}
                    value={recoverableTotal}
                    tone="success"
                    icon={<RotateCcw className="w-4 h-4" />}
                  />
                  <MetricCard
                    label={t(lang, "Retention reached", "已到保留期")}
                    value={reachedTotal}
                    tone={reachedTotal > 0 ? "warning" : "neutral"}
                    icon={<Clock className="w-4 h-4" />}
                  />
                </div>

                {/* Batch Cards */}
                <div className="space-y-3">
                  {batches.map(([batchId, items]) => {
                    const applied = items.filter((i) => i.state === "Applied");
                    const earliestDeadline = applied.reduce<number | null>(
                      (min, item) =>
                        min == null || item.expires_unix_ms < min
                          ? item.expires_unix_ms
                          : min,
                      null,
                    );
                    const exp =
                      earliestDeadline != null ? formatExpiry(lang, earliestDeadline) : null;

                    return (
                      <div
                        key={batchId}
                        className="p-4 rounded-[10px] bg-[var(--bg-surface)] border border-[var(--border-line)] shadow-[var(--shadow-card)]"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2.5">
                          <div className="flex flex-wrap items-center gap-2 min-w-0">
                            <Badge tone="accent" mono>
                              {batchId.slice(0, 8)}
                            </Badge>
                            <span className="text-[13.5px] font-semibold text-[var(--text-ink)]">
                              {lang === "zh"
                                ? `${applied.length} 项可还原 · 共 ${items.length} 项`
                                : `${applied.length} recoverable · ${items.length} total`}
                            </span>
                            {exp && <Badge tone={exp.tone}>{exp.label}</Badge>}
                          </div>

                          <Button
                            variant={applied.length > 0 ? "tinted" : "secondary"}
                            icon={<RotateCcw className="w-3.5 h-3.5" />}
                            disabled={isBusy || applied.length === 0}
                            disabledHint={t(
                              lang,
                              "No recoverable items remain in this batch.",
                              "此批次中没有可还原的项目。",
                            )}
                            onClick={() => void reviewRestore(batchId)}
                          >
                            {t(lang, "Review restore", "预览还原")}
                          </Button>
                        </div>

                        <div className="my-3 border-t border-[var(--border-soft)]" />

                        <CollapsibleSection
                          title={t(lang, "Files and backups", "文件与备份")}
                          meta={
                            lang === "zh" ? `${items.length} 项` : `${items.length} items`
                          }
                        >
                          <div className="space-y-2">
                            {items.map((item) => (
                              <div
                                key={item.id}
                                className="flex items-center gap-2.5 group"
                              >
                                <Badge tone={recoveryTone(item.state)}>
                                  {recoveryLabel(lang, item.state)}
                                </Badge>
                                <span
                                  title={item.backup}
                                  className="flex-1 min-w-0 text-[12.5px] font-mono text-[var(--text-ink)] truncate"
                                >
                                  {item.target}
                                </span>
                                <button
                                  type="button"
                                  onClick={() =>
                                    copyText(item.target, t(lang, "path", "路径"))
                                  }
                                  title={t(lang, "Copy path", "复制路径")}
                                  className="inline-flex items-center justify-center w-6 h-6 rounded-[6px] text-[var(--text-subtle)] opacity-60 group-hover:opacity-100 hover:bg-[var(--bg-hover)] hover:text-[var(--text-ink)] transition-all cursor-pointer shrink-0"
                                >
                                  <Copy className="w-3.5 h-3.5" />
                                </button>
                              </div>
                            ))}
                          </div>
                        </CollapsibleSection>
                      </div>
                    );
                  })}
                </div>
              </>
            )}
          </>
        )}
      </div>
    </div>
  );
}
