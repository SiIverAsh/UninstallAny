import { ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { operationLabel, t } from "@/i18n/messages";
import { useApp } from "@/store/AppContext";
import { isMacPlatform } from "@/utils/format";

export function StatusBar() {
  const { lang, activeOp, status, cancelActive } = useApp();
  const isMac = isMacPlatform();

  let dotColor = "bg-[var(--success-text)]";
  let statusText = t(lang, "Ready", "就绪");
  if (status) {
    switch (status.kind) {
      case "cancelled":
        dotColor = "bg-[var(--warning-text)]";
        statusText = t(lang, "Operation cancelled", "操作已取消");
        break;
      case "retention_saved":
        dotColor = "bg-[var(--success-text)]";
        statusText = t(lang, "Retention updated", "保留期已更新");
        break;
      case "rules_saved":
        dotColor = "bg-[var(--success-text)]";
        statusText = t(lang, "Rules saved", "规则已保存");
        break;
      case "audit_exported":
        dotColor = "bg-[var(--success-text)]";
        statusText = t(lang, "Audit log exported", "日志已导出");
        break;
      case "error":
        dotColor = "bg-[var(--danger)]";
        statusText = t(lang, "An operation needs attention", "有一项操作需要处理");
        break;
    }
  }

  return (
    <footer className="h-[38px] shrink-0 bg-[var(--bg-sidebar)] border-t border-[var(--border-line)] px-4 flex items-center justify-between gap-3 select-none">
      <div className="flex items-center gap-2.5 min-w-0">
        {activeOp ? (
          <>
            <span className="relative flex h-2.5 w-2.5 shrink-0">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[var(--accent)] opacity-60" />
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-[var(--accent)]" />
            </span>
            <span className="text-[12px] font-medium text-[var(--text-ink)] truncate">
              {activeOp.cancelling
                ? t(
                    lang,
                    "Stopping at the next safe point…",
                    "正在停止。已开始的单项操作会执行完毕。",
                  )
                : operationLabel(lang, activeOp.kind)}
            </span>

            {activeOp.progress && activeOp.progress.total > 0 ? (
              <div className="flex items-center gap-2">
                <div className="w-[120px] h-1.5 rounded-full bg-[var(--accent-pale)] overflow-hidden">
                  <div
                    className="h-full bg-[var(--accent)] rounded-full transition-[width] duration-200"
                    style={{
                      width: `${Math.min(100, (activeOp.progress.done / activeOp.progress.total) * 100)}%`,
                    }}
                  />
                </div>
                <span className="text-[11.5px] font-mono text-[var(--text-muted)] tabular-nums">
                  {activeOp.progress.done}/{activeOp.progress.total}
                </span>
              </div>
            ) : (
              <div className="w-[88px] h-1.5 rounded-full bg-[var(--accent-pale)] overflow-hidden">
                <div className="w-1/3 h-full bg-[var(--accent)] rounded-full animate-indeterminate" />
              </div>
            )}

            <Button
              variant="danger-subtle"
              size="sm"
              disabled={activeOp.cancelling}
              onClick={() => void cancelActive()}
            >
              {t(lang, "Cancel", "取消")}
            </Button>
          </>
        ) : (
          <>
            <span className={["w-2 h-2 rounded-full shrink-0", dotColor].join(" ")} />
            <span className="text-[12px] text-[var(--text-muted)] truncate">{statusText}</span>
          </>
        )}
      </div>

      <div className="flex items-center gap-3 shrink-0">
        {!activeOp && (
          <span className="hidden md:inline text-[11.5px] text-[var(--text-subtle)]">
            {isMac
              ? t(lang, "⌘F Search · ⌘R Refresh", "⌘F 搜索 · ⌘R 刷新")
              : t(lang, "Ctrl+F Search · F5 Refresh", "Ctrl+F 搜索 · F5 刷新")}
          </span>
        )}
        <Badge tone="success" icon={<ShieldCheck className="w-3 h-3" />}>
          {t(lang, "Local processing", "本机处理")}
        </Badge>
      </div>
    </footer>
  );
}
