import { useLayoutEffect, useRef, useState } from "react";
import {
  Archive,
  ClipboardCheck,
  LayoutGrid,
  ShieldCheck,
  SlidersHorizontal,
} from "lucide-react";
import { SegmentedControl } from "@/components/ui/Primitives";
import { t } from "@/i18n/messages";
import { useApp } from "@/store/AppContext";
import type { Page } from "@/types/domain";

export function Sidebar() {
  const {
    lang,
    setLang,
    page,
    navigate,
    totalInScope,
    inventory,
    quarantine,
    plans,
    hasReview,
    client,
  } = useApp();

  const itemRefs = useRef<Partial<Record<Page, HTMLButtonElement | null>>>({});
  const [indicatorY, setIndicatorY] = useState<number | null>(null);

  const recoverableCount =
    quarantine?.items.filter((i) => i.state === "Applied").length ?? 0;

  const navItems: Array<{
    id: Page;
    label: string;
    icon: React.ReactNode;
    count?: number;
  }> = [
    {
      id: "applications",
      label: t(lang, "Applications", "应用程序"),
      icon: <LayoutGrid className="w-[15px] h-[15px]" />,
      count: inventory && totalInScope > 0 ? totalInScope : undefined,
    },
    {
      id: "quarantine",
      label: t(lang, "Quarantine", "隔离区"),
      icon: <Archive className="w-[15px] h-[15px]" />,
      count: recoverableCount > 0 ? recoverableCount : undefined,
    },
    {
      id: "settings",
      label: t(lang, "Settings", "设置"),
      icon: <SlidersHorizontal className="w-[15px] h-[15px]" />,
    },
  ];

  if (hasReview || page === "review") {
    navItems.push({
      id: "review",
      label: t(lang, "Review & results", "预览与结果"),
      icon: <ClipboardCheck className="w-[15px] h-[15px]" />,
      count: plans.length > 0 ? plans.length : undefined,
    });
  }

  useLayoutEffect(() => {
    const el = itemRefs.current[page];
    if (el) {
      setIndicatorY(el.offsetTop + (el.offsetHeight - 18) / 2);
    }
  }, [page, hasReview]);

  return (
    <aside className="w-[220px] shrink-0 h-full bg-[var(--bg-sidebar)] border-r border-[var(--border-line)] flex flex-col p-3.5 select-none">
      {/* Brand Mark */}
      <div className="flex items-center gap-2.5 px-1 pt-0.5 pb-5">
        <div className="inline-flex items-center justify-center w-[34px] h-[34px] rounded-[9px] bg-[var(--accent)] text-white shadow-[0_2px_8px_rgba(59,130,246,0.35),inset_0_1px_0_rgba(255,255,255,0.25)] shrink-0">
          <ShieldCheck className="w-[18px] h-[18px] stroke-[2.2]" />
        </div>
        <div className="min-w-0">
          <div className="text-[15px] font-semibold text-[var(--text-ink)] leading-tight truncate">
            UninstallAny
          </div>
          <div className="text-[11.5px] text-[var(--text-subtle)] leading-tight mt-0.5">
            {t(lang, "Clean & Safe", "安全清理")}
          </div>
        </div>
      </div>

      {/* Navigation Group */}
      <div className="px-2 pb-1.5 text-[10.5px] font-semibold tracking-wider uppercase text-[var(--text-subtle)]">
        {t(lang, "Workspace", "工作区")}
      </div>

      <nav className="relative flex flex-col gap-1 flex-1">
        {indicatorY !== null && (
          <span
            aria-hidden="true"
            className="pointer-events-none absolute left-0.5 z-10 w-[3px] h-[18px] rounded-full bg-[var(--accent)] transition-transform duration-180 ease-out"
            style={{ transform: `translateY(${indicatorY}px)` }}
          />
        )}
        {navItems.map((item) => {
          const active = page === item.id;
          return (
            <button
              key={item.id}
              ref={(el) => {
                itemRefs.current[item.id] = el;
              }}
              type="button"
              onClick={() => navigate(item.id)}
              className={[
                "relative flex items-center gap-2.5 h-[36px] px-3 rounded-[8px] text-[13px] transition-all duration-120 cursor-pointer outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]/30",
                active
                  ? "bg-[var(--bg-surface-alt)] text-[var(--accent-text)] font-semibold border border-[var(--border-line)] shadow-[var(--shadow-card)]"
                  : "text-[var(--text-muted)] border border-transparent hover:bg-[var(--bg-hover)] hover:text-[var(--text-ink)] active:bg-[var(--bg-pressed)]",
              ].join(" ")}
            >
              <span className="inline-flex shrink-0">{item.icon}</span>
              <span className="flex-1 text-left truncate">{item.label}</span>
              {item.count !== undefined && (
                <span
                  className={[
                    "inline-flex items-center justify-center min-w-[22px] h-[20px] px-1.5 rounded-full text-[11px] font-semibold tabular-nums",
                    active
                      ? "bg-[var(--accent-pale)] text-[var(--accent-text)]"
                      : "bg-[var(--bg-surface-alt)] text-[var(--text-subtle)]",
                  ].join(" ")}
                >
                  {item.count}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Sidebar Footer */}
      <div className="pt-3 border-t border-[var(--border-line)] space-y-2.5">
        <SegmentedControl
          size="sm"
          value={lang}
          onChange={setLang}
          options={[
            { value: "en", label: "EN" },
            { value: "zh", label: "中文" },
          ]}
        />
        <div className="flex items-center justify-between px-1 text-[11px] text-[var(--text-subtle)]">
          <span>Version 0.1.0</span>
          <span
            className={[
              "inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold",
              client.mode === "tauri"
                ? "bg-[var(--success-bg)] text-[var(--success-text)]"
                : "bg-[var(--accent-pale)] text-[var(--accent-text)]",
            ].join(" ")}
          >
            <span
              className={[
                "w-1.5 h-1.5 rounded-full",
                client.mode === "tauri" ? "bg-[var(--success-text)]" : "bg-[var(--accent-text)]",
              ].join(" ")}
            />
            {client.mode === "tauri"
              ? t(lang, "Native", "原生")
              : t(lang, "Mock", "预览")}
          </span>
        </div>
      </div>
    </aside>
  );
}
