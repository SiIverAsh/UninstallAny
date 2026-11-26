import { useMemo } from "react";
import {
  AlertTriangle,
  ArrowLeft,
  Copy,
  Filter,
  Info,
  Shield,
  Sparkles,
} from "lucide-react";
import { Badge, type BadgeTone } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Checkbox } from "@/components/ui/Controls";
import {
  DiagnosticsBlock,
  EmptyState,
  FilterPill,
  Notice,
} from "@/components/ui/Primitives";
import {
  categoryLabel,
  confidenceLabel,
  evidenceLabel,
  officialOutcomeMeta,
  t,
} from "@/i18n/messages";
import { useApp } from "@/store/AppContext";
import {
  ALL_CATEGORIES,
  isAccessAllowed,
  isDefaultSelected,
  readOnlyReason,
  type Category,
  type Confidence,
} from "@/types/domain";

function confidenceTone(c: Confidence): BadgeTone {
  if (c === "High") return "success";
  if (c === "Medium") return "warning";
  return "neutral";
}

export function ReviewPage() {
  const {
    lang,
    plans,
    uninstallResults,
    changeResult,
    isBusy,
    navigate,
    toggleCandidate,
    setPlanSelectedIds,
    setPlanCategory,
    dismissFrontPlan,
    setModal,
    pushToast,
    copyText,
  } = useApp();

  const plan = plans[0] ?? null;
  const queued = plans.length;

  const presentCategories = useMemo(() => {
    if (!plan) return [];
    const counts: Array<[Category, number]> = [];
    for (const cat of ALL_CATEGORIES) {
      const n = plan.preview.candidates.filter((c) => c.category === cat).length;
      if (n > 0) counts.push([cat, n]);
    }
    return counts;
  }, [plan]);

  const visibleCandidates = useMemo(() => {
    if (!plan) return [];
    return plan.preview.candidates.filter(
      (c) => plan.category === null || c.category === plan.category,
    );
  }, [plan]);

  const visibleAllowedIds = useMemo(
    () =>
      visibleCandidates.filter((c) => isAccessAllowed(c.access)).map((c) => c.id),
    [visibleCandidates],
  );

  const selectedVisibleAllowedCount = useMemo(() => {
    if (!plan) return 0;
    return visibleAllowedIds.filter((id) => plan.selectedIds.has(id)).length;
  }, [plan, visibleAllowedIds]);

  const approvedCandidates = useMemo(() => {
    if (!plan) return [];
    return plan.preview.candidates.filter(
      (c) => isAccessAllowed(c.access) && plan.selectedIds.has(c.id),
    );
  }, [plan]);

  const highRiskSelected = approvedCandidates.filter((c) => c.risk === "High").length;

  return (
    <div className="flex flex-col h-full min-h-0 animate-page-enter">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 shrink-0">
        <div className="flex items-center gap-2.5 min-w-0">
          <h1 className="text-[22px] font-semibold tracking-[-0.015em] text-[var(--text-ink)] truncate">
            {queued > 0
              ? t(lang, "Cleanup preview", "清理预览")
              : t(lang, "Operation results", "操作结果")}
          </h1>
          {queued > 1 && (
            <Badge tone="accent">
              {lang === "zh" ? `还有 ${queued} 份清单` : `${queued} queued`}
            </Badge>
          )}
        </div>

        <Button
          variant="secondary"
          icon={<ArrowLeft className="w-3.5 h-3.5" />}
          onClick={() => navigate("applications")}
        >
          {t(lang, "Back to applications", "返回应用程序")}
        </Button>
      </div>

      {/* Main Content */}
      <div className="mt-3 flex-1 min-h-0 flex flex-col gap-3 overflow-y-auto pr-0.5">
        {plan && (
          <section className="flex flex-col gap-2.5">
            {plan.preview.mode === "ForceRemoval" && (
              <Notice tone="warning">
                {t(
                  lang,
                  "Force removal only affects the selected listing and leftovers. The application may remain installed.",
                  "强制移除仅处理所选卸载记录及残留。应用可能仍然安装在本机。",
                )}
              </Notice>
            )}

            <DiagnosticsBlock
              warnings={plan.preview.warnings}
              label={
                lang === "zh"
                  ? `${plan.preview.warnings.length} 条诊断信息`
                  : `${plan.preview.warnings.length} diagnostics`
              }
            />

            {/* Cleanup Toolbar */}
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                {plan.preview.subject && (
                  <Badge tone="neutral" className="!text-[var(--text-ink)]">
                    {plan.preview.subject}
                  </Badge>
                )}
                <span className="text-[13px] text-[var(--text-muted)]">
                  {lang === "zh"
                    ? `${plan.preview.candidates.length} 个候选项 · 共 ${queued} 份待处理清单`
                    : `${plan.preview.candidates.length} candidates · ${queued} pending plans`}
                </span>
              </div>

              <div className="flex items-center gap-1.5">
                <Button
                  variant="tinted"
                  size="sm"
                  icon={<Sparkles className="w-3.5 h-3.5" />}
                  onClick={() => {
                    setPlanSelectedIds(
                      new Set(
                        plan.preview.candidates
                          .filter(isDefaultSelected)
                          .map((c) => c.id),
                      ),
                    );
                    pushToast(
                      "info",
                      t(lang, "Reset to safe defaults", "已恢复推荐勾选项"),
                    );
                  }}
                >
                  {t(lang, "Safe defaults", "推荐项")}
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() =>
                    setPlanSelectedIds(
                      new Set(
                        plan.preview.candidates
                          .filter((c) => isAccessAllowed(c.access))
                          .map((c) => c.id),
                      ),
                    )
                  }
                >
                  {t(lang, "Select all", "全选")}
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setPlanSelectedIds(new Set())}
                >
                  {t(lang, "Clear", "清空")}
                </Button>
              </div>
            </div>

            {/* Category Filter Pill Strip */}
            {presentCategories.length > 1 && (
              <div className="flex items-center gap-1.5 overflow-x-auto pb-0.5">
                <FilterPill
                  selected={plan.category === null}
                  count={plan.preview.candidates.length}
                  onClick={() => setPlanCategory(null)}
                >
                  {t(lang, "All", "全部")}
                </FilterPill>
                {presentCategories.map(([cat, count]) => (
                  <FilterPill
                    key={cat}
                    selected={plan.category === cat}
                    count={count}
                    onClick={() => setPlanCategory(cat)}
                  >
                    {categoryLabel(lang, cat)}
                  </FilterPill>
                ))}
              </div>
            )}

            {/* Candidate Table Card */}
            <div className="rounded-[10px] bg-[var(--bg-surface)] border border-[var(--border-line)] shadow-[var(--shadow-card)] overflow-hidden">
              <div className="grid grid-cols-[24px_minmax(0,1fr)_96px_132px_92px] items-center gap-3 h-[38px] px-4 bg-[var(--bg-surface-alt)] border-b border-[var(--border-soft)] text-[12px] font-semibold text-[var(--text-muted)]">
                <div className="flex items-center justify-center">
                  <Checkbox
                    checked={
                      visibleAllowedIds.length > 0 &&
                      selectedVisibleAllowedCount === visibleAllowedIds.length
                    }
                    indeterminate={
                      selectedVisibleAllowedCount > 0 &&
                      selectedVisibleAllowedCount < visibleAllowedIds.length
                    }
                    disabled={visibleAllowedIds.length === 0}
                    title={t(lang, "Select all writable candidates", "选择全部可写候选项")}
                    onChange={(checked) => {
                      const next = new Set(plan.selectedIds);
                      for (const id of visibleAllowedIds) {
                        if (checked) next.add(id);
                        else next.delete(id);
                      }
                      setPlanSelectedIds(next);
                    }}
                  />
                </div>
                <div>{t(lang, "Target & reason", "目标与命中理由")}</div>
                <div>{t(lang, "Category", "类别")}</div>
                <div>{t(lang, "Confidence", "置信度")}</div>
                <div className="text-right">{t(lang, "Access", "状态")}</div>
              </div>

              <div className="max-h-[340px] overflow-y-auto divide-y divide-[var(--border-soft)]">
                {visibleCandidates.length === 0 ? (
                  <EmptyState
                    icon={<Filter className="w-5 h-5" />}
                    heading={t(
                      lang,
                      "No leftovers found for this preview.",
                      "此预览未发现可展示的残留。",
                    )}
                    actionLabel={
                      plan.category
                        ? t(lang, "Show all categories", "显示全部类别")
                        : undefined
                    }
                    onAction={() => setPlanCategory(null)}
                  />
                ) : (
                  visibleCandidates.map((cand) => {
                    const allowed = isAccessAllowed(cand.access);
                    const roReason = readOnlyReason(cand.access);
                    const checked = allowed && plan.selectedIds.has(cand.id);
                    return (
                      <div
                        key={cand.id}
                        onClick={(e) => {
                          if (allowed) {
                            toggleCandidate(visibleAllowedIds, cand.id, e.shiftKey);
                          }
                        }}
                        className={[
                          "relative grid grid-cols-[24px_minmax(0,1fr)_96px_132px_92px] items-center gap-3 min-h-[60px] py-2 px-4 transition-colors duration-100",
                          !allowed
                            ? "bg-[var(--bg-row-readonly)] cursor-default"
                            : checked
                              ? "bg-[var(--bg-row-selected)] hover:bg-[var(--bg-row-selected-hover)] cursor-pointer"
                              : "bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] cursor-pointer",
                        ].join(" ")}
                      >
                        {checked && (
                          <span className="absolute left-0 top-2.5 bottom-2.5 w-[3px] rounded-r-full bg-[var(--accent)]" />
                        )}
                        <div className="flex items-center justify-center">
                          <Checkbox
                            checked={checked}
                            disabled={!allowed}
                            title={roReason ?? undefined}
                            onChange={() =>
                              allowed && toggleCandidate(visibleAllowedIds, cand.id, false)
                            }
                          />
                        </div>

                        <div className="min-w-0" title={cand.target_display}>
                          <div
                            className={[
                              "text-[13px] font-semibold font-mono truncate",
                              allowed
                                ? "text-[var(--text-ink)]"
                                : "text-[var(--text-muted)]",
                            ].join(" ")}
                          >
                            {cand.target_display}
                          </div>
                          <div className="text-[11.5px] text-[var(--text-subtle)] truncate mt-0.5">
                            {roReason ? `${cand.reason} · ${roReason}` : cand.reason}
                          </div>
                        </div>

                        <div className="text-[12.5px] text-[var(--text-muted)] truncate">
                          {categoryLabel(lang, cand.category)}
                        </div>

                        <div>
                          <Badge
                            tone={confidenceTone(cand.confidence)}
                            title={evidenceLabel(lang, cand.evidence)}
                          >
                            {confidenceLabel(lang, cand.confidence)}
                          </Badge>
                        </div>

                        <div className="flex justify-end">
                          {!allowed ? (
                            <Badge tone="neutral" title={roReason ?? undefined}>
                              {t(lang, "Read-only", "只读")}
                            </Badge>
                          ) : cand.risk === "High" ? (
                            <Badge tone="danger">{t(lang, "High risk", "高风险")}</Badge>
                          ) : null}
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>

            {/* Bottom Cleanup Action Bar */}
            <div
              className={[
                "px-4 py-2.5 rounded-[10px] border shadow-[var(--shadow-card)] flex flex-wrap items-center justify-between gap-2.5 transition-colors",
                approvedCandidates.length > 0
                  ? "bg-[var(--accent-soft)] border-[var(--accent-border)]"
                  : "bg-[var(--bg-surface)] border-[var(--border-line)]",
              ].join(" ")}
            >
              <div className="flex items-center gap-2">
                <Badge tone={approvedCandidates.length > 0 ? "accent" : "neutral"}>
                  {lang === "zh"
                    ? `已选 ${approvedCandidates.length} 项`
                    : `${approvedCandidates.length} selected`}
                </Badge>
                {highRiskSelected > 0 && (
                  <Badge tone="danger" icon={<AlertTriangle className="w-3 h-3" />}>
                    {lang === "zh"
                      ? `含 ${highRiskSelected} 项高风险`
                      : `${highRiskSelected} high risk`}
                  </Badge>
                )}
              </div>

              <div className="flex items-center gap-2">
                <Button
                  variant="secondary"
                  disabled={isBusy}
                  onClick={dismissFrontPlan}
                >
                  {t(lang, "Dismiss this plan", "关闭此清单")}
                </Button>
                <Button
                  variant="primary"
                  icon={<Shield className="w-3.5 h-3.5" />}
                  disabled={isBusy || approvedCandidates.length === 0}
                  disabledHint={t(
                    lang,
                    "Select at least one writable item to continue.",
                    "请至少选择一个可写项目以继续。",
                  )}
                  onClick={() =>
                    setModal({
                      kind: "cleanup",
                      planId: plan.preview.id,
                      items: approvedCandidates.map((c) => c.id),
                      targets: approvedCandidates.map((c) => c.target_display),
                      hasHighRisk: highRiskSelected > 0,
                    })
                  }
                >
                  {t(lang, "Review selection", "确认所选项目")}
                </Button>
              </div>
            </div>
          </section>
        )}

        {/* Official Uninstall Results Card */}
        {uninstallResults.length > 0 && (
          <section className="p-4 rounded-[10px] bg-[var(--bg-surface)] border border-[var(--border-line)] shadow-[var(--shadow-card)]">
            <div className="flex items-center gap-2.5">
              <h2 className="text-[14.5px] font-semibold text-[var(--text-ink)]">
                {t(lang, "Official uninstall results", "官方卸载结果")}
              </h2>
              {(() => {
                const ok = uninstallResults.filter(
                  (r) => "Ok" in r.outcome && r.outcome.Ok === "Completed",
                ).length;
                return (
                  <Badge tone={ok === uninstallResults.length ? "success" : "warning"}>
                    {lang === "zh"
                      ? `${ok}/${uninstallResults.length} 已完成`
                      : `${ok}/${uninstallResults.length} completed`}
                  </Badge>
                );
              })()}
            </div>
            <div className="my-3 border-t border-[var(--border-soft)]" />
            <div className="space-y-2.5">
              {uninstallResults.map((row, idx) => {
                const meta = officialOutcomeMeta(lang, row.outcome);
                return (
                  <div key={idx} className="space-y-1">
                    <div className="flex items-center gap-2.5">
                      <Badge tone={meta.tone}>{meta.label}</Badge>
                      <span className="text-[13px] font-semibold text-[var(--text-ink)]">
                        {row.application}
                      </span>
                    </div>
                    {"Err" in row.outcome && (
                      <div className="text-[12.5px] text-[var(--text-muted)] pl-1">
                        {row.outcome.Err}
                      </div>
                    )}
                    {row.warnings.map((w, wi) => (
                      <div key={wi} className="text-[12px] text-[var(--warning-text)] pl-1">
                        {w}
                      </div>
                    ))}
                  </div>
                );
              })}
            </div>
          </section>
        )}

        {/* Cleanup or Restore Change Report */}
        {changeResult && (
          <section className="p-4 rounded-[10px] bg-[var(--bg-surface)] border border-[var(--border-line)] shadow-[var(--shadow-card)]">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <h2 className="text-[14.5px] font-semibold text-[var(--text-ink)]">
                  {t(lang, "Cleanup or restore report", "清理或还原报告")}
                </h2>
                {(() => {
                  const okCount = changeResult.items.filter(
                    (i) => typeof i.result === "string",
                  ).length;
                  const warnCount = changeResult.items.length - okCount;
                  return (
                    <>
                      {okCount > 0 && (
                        <Badge tone="success">
                          {lang === "zh" ? `${okCount} 项已处理` : `${okCount} succeeded`}
                        </Badge>
                      )}
                      {warnCount > 0 && (
                        <Badge tone="warning">
                          {lang === "zh"
                            ? `${warnCount} 项跳过/复核`
                            : `${warnCount} skipped/review`}
                        </Badge>
                      )}
                    </>
                  );
                })()}
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[11.5px] font-mono text-[var(--text-subtle)]">
                  {changeResult.batch_id.slice(0, 8)}
                </span>
                <Button
                  variant="ghost"
                  size="sm"
                  icon={<Copy className="w-3 h-3" />}
                  onClick={() =>
                    copyText(changeResult.batch_id, t(lang, "batch ID", "批次 ID"))
                  }
                >
                  {t(lang, "Copy ID", "复制 ID")}
                </Button>
              </div>
            </div>
            <div className="my-3 border-t border-[var(--border-soft)]" />
            <div className="space-y-2">
              {changeResult.items.map((item, idx) => {
                let tone: BadgeTone = "success";
                let label = t(lang, "Quarantined or backed up", "已隔离或备份");
                let reason: string | null = null;
                if (item.result === "Restored") {
                  label = t(lang, "Restored", "已还原");
                } else if (item.result === "Purged") {
                  tone = "neutral";
                  label = t(lang, "Permanently removed", "已永久清理");
                } else if (typeof item.result === "object" && "Skipped" in item.result) {
                  tone = "warning";
                  label = t(lang, "Skipped", "已跳过");
                  reason = item.result.Skipped;
                } else if (
                  typeof item.result === "object" &&
                  "NeedsReview" in item.result
                ) {
                  tone = "danger";
                  label = t(lang, "Needs review", "需要复核");
                  reason = item.result.NeedsReview;
                }
                return (
                  <div key={idx} className="space-y-0.5">
                    <div className="flex items-center gap-2.5">
                      <Badge tone={tone}>{label}</Badge>
                      <span
                        title={item.target}
                        className="text-[13px] font-mono text-[var(--text-ink)] truncate"
                      >
                        {item.target}
                      </span>
                    </div>
                    {reason && (
                      <div className="text-[12px] text-[var(--text-muted)] pl-1">{reason}</div>
                    )}
                  </div>
                );
              })}
            </div>
          </section>
        )}

        {/* Empty State */}
        {!plan && uninstallResults.length === 0 && !changeResult && !isBusy && (
          <div className="rounded-[10px] bg-[var(--bg-surface)] border border-[var(--border-line)] shadow-[var(--shadow-card)]">
            <EmptyState
              icon={<Info className="w-5 h-5" />}
              heading={t(lang, "No operation results to display.", "暂无操作结果。")}
              description={t(
                lang,
                "Scan an application or run a cleanup to see results here.",
                "扫描应用或执行清理后，结果会显示在此处。",
              )}
              actionLabel={t(lang, "Go to Applications", "前往应用程序")}
              onAction={() => navigate("applications")}
            />
          </div>
        )}
      </div>
    </div>
  );
}
