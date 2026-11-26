import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { AlertTriangle, Check, ChevronRight, Info, X } from "lucide-react";
import { Button } from "./Button";

export interface SegmentedOption<T extends string> {
  value: T;
  label: string;
}

export function SegmentedControl<T extends string>({
  value,
  options,
  onChange,
  size = "md",
}: {
  value: T;
  options: readonly [SegmentedOption<T>, SegmentedOption<T>];
  onChange: (next: T) => void;
  size?: "md" | "sm";
}) {
  const activeIdx = value === options[0].value ? 0 : 1;
  return (
    <div
      className={[
        "relative grid grid-cols-2 p-[3px] rounded-[8px] bg-[var(--bg-track)] border border-[var(--border-line)]",
        size === "sm" ? "h-[30px]" : "h-[34px]",
      ].join(" ")}
    >
      <div
        className="absolute top-[3px] bottom-[3px] w-[calc(50%-3px)] rounded-[6px] bg-[var(--bg-surface-alt)] border border-[var(--border-control)] shadow-[0_1px_2px_rgba(0,0,0,0.25)] transition-transform duration-160 ease-out"
        style={{ transform: activeIdx === 1 ? "translateX(100%)" : "translateX(0)" }}
      />
      {options.map((opt) => {
        const selected = opt.value === value;
        return (
          <button
            key={opt.value}
            type="button"
            onClick={() => !selected && onChange(opt.value)}
            className={[
              "relative z-10 inline-flex items-center justify-center px-3 text-[12.5px] rounded-[6px] transition-colors cursor-pointer whitespace-nowrap",
              selected
                ? "font-semibold text-[var(--text-ink)]"
                : "text-[var(--text-subtle)] hover:text-[var(--text-muted)]",
            ].join(" ")}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}

export function ChipButton({
  selected,
  onClick,
  children,
}: {
  selected: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={[
        "inline-flex items-center justify-center h-[34px] px-3 min-w-[58px] rounded-[7.5px] border text-[12.5px] font-semibold transition-all duration-120 cursor-pointer active:translate-y-[0.5px]",
        selected
          ? "bg-[var(--accent-pale)] text-[var(--accent-text)] border-[var(--accent)]"
          : "bg-[var(--bg-surface-alt)] text-[var(--text-muted)] border-[var(--border-control)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-ink)] hover:border-[var(--border-control-hover)]",
      ].join(" ")}
    >
      {children}
    </button>
  );
}

export function FilterPill({
  selected,
  count,
  onClick,
  children,
}: {
  selected: boolean;
  count?: number;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={[
        "inline-flex items-center h-[28px] px-2.5 gap-1.5 rounded-[7px] border text-[12px] font-semibold transition-all duration-120 cursor-pointer whitespace-nowrap shrink-0",
        selected
          ? "bg-[var(--accent-pale)] text-[var(--accent-text)] border-[var(--accent)]"
          : "bg-[var(--bg-surface)] text-[var(--text-muted)] border-[var(--border-line)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-ink)] hover:border-[var(--border-control)]",
      ].join(" ")}
    >
      <span>{children}</span>
      {count !== undefined && (
        <span
          className={[
            "tabular-nums text-[11px] px-1.5 py-0.5 rounded-full",
            selected
              ? "bg-[var(--accent)]/25 text-[var(--accent-text)]"
              : "bg-[var(--bg-surface-alt)] text-[var(--text-subtle)]",
          ].join(" ")}
        >
          {count}
        </span>
      )}
    </button>
  );
}

export function Notice({
  tone,
  children,
  onDismiss,
  dismissLabel = "Dismiss",
}: {
  tone: "danger" | "warning" | "success" | "info";
  children: ReactNode;
  onDismiss?: () => void;
  dismissLabel?: string;
}) {
  const styles = {
    danger: {
      wrap: "bg-[var(--danger-bg)] border-[var(--danger-border)] text-[var(--danger-text)]",
      bar: "bg-[var(--danger)]",
      icon: <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />,
    },
    warning: {
      wrap: "bg-[var(--warning-bg)] border-[var(--warning-border)] text-[var(--warning-text)]",
      bar: "bg-[var(--warning-text)]",
      icon: <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />,
    },
    success: {
      wrap: "bg-[var(--success-bg)] border-[var(--success-border)] text-[var(--success-text)]",
      bar: "bg-[var(--success-text)]",
      icon: <Check className="w-3.5 h-3.5 shrink-0 mt-0.5" />,
    },
    info: {
      wrap: "bg-[var(--accent-pale)] border-[var(--accent-border)] text-[var(--accent-text)]",
      bar: "bg-[var(--accent)]",
      icon: <Info className="w-3.5 h-3.5 shrink-0 mt-0.5" />,
    },
  }[tone];

  return (
    <div
      className={[
        "relative flex items-start gap-2.5 pl-4 pr-3 py-2.5 rounded-[8px] border text-[12.5px]",
        styles.wrap,
      ].join(" ")}
    >
      <span
        className={["absolute left-1.5 top-2 bottom-2 w-[3px] rounded-full", styles.bar].join(" ")}
      />
      {styles.icon}
      <div className="flex-1 min-w-0 leading-relaxed">{children}</div>
      {onDismiss && (
        <button
          type="button"
          onClick={onDismiss}
          title={dismissLabel}
          aria-label={dismissLabel}
          className="inline-flex items-center justify-center w-5 h-5 rounded-full hover:bg-white/10 transition-colors cursor-pointer shrink-0"
        >
          <X className="w-3 h-3" />
        </button>
      )}
    </div>
  );
}

export function MetricCard({
  label,
  value,
  icon,
  tone,
}: {
  label: string;
  value: string | number;
  icon: ReactNode;
  tone: "accent" | "success" | "warning" | "neutral";
}) {
  const wellStyles = {
    accent: "bg-[var(--accent-pale)] text-[var(--accent-text)]",
    success: "bg-[var(--success-bg)] text-[var(--success-text)]",
    warning: "bg-[var(--warning-bg)] text-[var(--warning-text)]",
    neutral: "bg-[var(--bg-surface-alt)] text-[var(--text-subtle)]",
  }[tone];

  return (
    <div className="flex items-center gap-3 px-4 py-3 rounded-[10px] bg-[var(--bg-surface)] border border-[var(--border-line)] shadow-[var(--shadow-card)]">
      <div
        className={[
          "inline-flex items-center justify-center w-9 h-9 rounded-[8px] shrink-0",
          wellStyles,
        ].join(" ")}
      >
        {icon}
      </div>
      <div className="min-w-0">
        <div className="text-[18px] font-semibold leading-tight text-[var(--text-ink)] tabular-nums">
          {value}
        </div>
        <div className="text-[11.5px] text-[var(--text-subtle)] truncate mt-0.5">{label}</div>
      </div>
    </div>
  );
}

export function CollapsibleSection({
  title,
  meta,
  defaultOpen = false,
  tone = "neutral",
  children,
}: {
  title: string;
  meta?: string;
  defaultOpen?: boolean;
  tone?: "neutral" | "warning";
  children: ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div
      className={
        tone === "warning"
          ? "rounded-[8px] bg-[var(--warning-bg)] border border-[var(--warning-border)] px-2.5 py-1"
          : ""
      }
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className={[
          "w-full flex items-center justify-between h-[30px] px-1.5 rounded-[6px] transition-colors cursor-pointer",
          tone === "warning" ? "hover:bg-white/5" : "hover:bg-[var(--bg-hover)]",
        ].join(" ")}
      >
        <span className="inline-flex items-center gap-1.5 min-w-0">
          <ChevronRight
            className={[
              "w-3.5 h-3.5 transition-transform duration-150 shrink-0",
              open ? "rotate-90" : "",
              tone === "warning" ? "text-[var(--warning-text)]" : "text-[var(--text-subtle)]",
            ].join(" ")}
          />
          <span
            className={[
              "text-[12.5px] font-semibold truncate",
              tone === "warning" ? "text-[var(--warning-text)]" : "text-[var(--text-muted)]",
            ].join(" ")}
          >
            {title}
          </span>
        </span>
        {meta && (
          <span className="text-[11.5px] text-[var(--text-subtle)] tabular-nums">{meta}</span>
        )}
      </button>
      {open && <div className="pt-2 pb-1 pl-5">{children}</div>}
    </div>
  );
}

export function EmptyState({
  icon,
  heading,
  description,
  actionLabel,
  onAction,
}: {
  icon: ReactNode;
  heading: string;
  description?: string;
  actionLabel?: string;
  onAction?: () => void;
}) {
  return (
    <div className="flex flex-col items-center justify-center text-center py-12 px-6">
      <div className="inline-flex items-center justify-center w-11 h-11 rounded-full bg-[var(--bg-surface-alt)] border border-[var(--border-line)] text-[var(--text-subtle)] mb-3">
        {icon}
      </div>
      <div className="text-[14px] font-semibold text-[var(--text-ink)]">{heading}</div>
      {description && (
        <p className="text-[12.5px] text-[var(--text-subtle)] mt-1 max-w-[360px]">{description}</p>
      )}
      {actionLabel && onAction && (
        <div className="mt-4">
          <Button variant="secondary" size="sm" onClick={onAction}>
            {actionLabel}
          </Button>
        </div>
      )}
    </div>
  );
}

export function LoadingSkeleton({
  message,
  rows = 5,
}: {
  message: string;
  rows?: number;
}) {
  return (
    <div className="py-3">
      <div className="flex items-center gap-2.5 px-4 pb-3 text-[13px] text-[var(--text-muted)]">
        <span className="inline-block w-3.5 h-3.5 rounded-full border-2 border-[var(--accent)]/25 border-t-[var(--accent)] animate-spin" />
        <span>{message}</span>
      </div>
      <div className="divide-y divide-[var(--border-soft)]">
        {Array.from({ length: rows }).map((_, i) => (
          <div key={i} className="flex items-center gap-3 px-4 h-[58px] animate-pulse">
            <div className="w-4 h-4 rounded bg-[var(--bg-surface-alt)]" />
            <div className="w-8 h-8 rounded-[8px] bg-[var(--bg-surface-alt)]" />
            <div className="flex-1 space-y-2">
              <div
                className="h-2.5 rounded bg-[var(--bg-surface-alt)]"
                style={{ width: `${32 + ((i * 13) % 24)}%` }}
              />
              <div
                className="h-2 rounded bg-[var(--bg-hover)]"
                style={{ width: `${18 + ((i * 7) % 14)}%` }}
              />
            </div>
            <div className="w-16 h-5 rounded-[6px] bg-[var(--bg-surface-alt)]" />
          </div>
        ))}
      </div>
    </div>
  );
}

export function DiagnosticsBlock({
  warnings,
  label,
}: {
  warnings: string[];
  label: string;
}) {
  if (warnings.length === 0) return null;
  return (
    <CollapsibleSection title={label} tone="warning">
      <ul className="space-y-1 text-[12px] text-[var(--warning-text)] list-disc pl-4">
        {warnings.map((w, idx) => (
          <li key={idx}>{w}</li>
        ))}
      </ul>
    </CollapsibleSection>
  );
}

export interface MenuItemSpec {
  label: string;
  description?: string;
  icon?: ReactNode;
  danger?: boolean;
  disabled?: boolean;
  dividerBefore?: boolean;
  onClick: () => void;
}

export function PopoverMenu({
  open,
  onClose,
  items,
  align = "right",
  position,
}: {
  open: boolean;
  onClose: () => void;
  items: MenuItemSpec[];
  align?: "left" | "right";
  position?: { x: number; y: number };
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [coords, setCoords] = useState<{ left: number; top: number } | null>(null);

  useLayoutEffect(() => {
    if (!open || !position) {
      setCoords(null);
      return;
    }
    const el = ref.current;
    const pad = 10;
    const w = el?.offsetWidth ?? 216;
    const h = el?.offsetHeight ?? 160;
    const maxX = Math.max(pad, window.innerWidth - w - pad);
    const maxY = Math.max(pad, window.innerHeight - h - pad);
    setCoords({
      left: Math.min(Math.max(position.x, pad), maxX),
      top: Math.min(Math.max(position.y, pad), maxY),
    });
  }, [open, position]);

  useEffect(() => {
    if (!open) return;
    const handlePointer = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        onClose();
      }
    };
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    const handleViewportChange = () => onClose();
    window.addEventListener("mousedown", handlePointer);
    window.addEventListener("keydown", handleKey);
    window.addEventListener("resize", handleViewportChange);
    window.addEventListener("scroll", handleViewportChange, true);
    return () => {
      window.removeEventListener("mousedown", handlePointer);
      window.removeEventListener("keydown", handleKey);
      window.removeEventListener("resize", handleViewportChange);
      window.removeEventListener("scroll", handleViewportChange, true);
    };
  }, [open, onClose]);

  if (!open) return null;

  const menuEl = (
    <div
      ref={ref}
      style={
        position
          ? {
              position: "fixed",
              left: coords ? coords.left : position.x,
              top: coords ? coords.top : position.y,
            }
          : undefined
      }
      className={[
        "min-w-[208px] max-w-[calc(100vw-20px)] p-1.5 rounded-[10px] bg-[var(--bg-popover)] border border-[var(--border-line)] shadow-[var(--shadow-popover)] animate-modal-panel",
        position
          ? "z-40"
          : `z-30 absolute bottom-full mb-2 ${align === "right" ? "right-0" : "left-0"}`,
      ].join(" ")}
    >
      {items.map((item, idx) => (
        <div key={idx}>
          {item.dividerBefore && <div className="my-1 border-t border-[var(--border-soft)]" />}
          <button
            type="button"
            disabled={item.disabled}
            onClick={() => {
              if (!item.disabled) {
                item.onClick();
                onClose();
              }
            }}
            className={[
              "w-full flex items-start gap-2.5 px-2.5 py-2 rounded-[6.5px] text-left transition-colors",
              item.disabled
                ? "text-[var(--text-disabled)] cursor-not-allowed"
                : item.danger
                  ? "text-[var(--danger-text)] hover:bg-[var(--danger-bg)] cursor-pointer"
                  : "text-[var(--text-ink)] hover:bg-[var(--bg-hover)] cursor-pointer",
            ].join(" ")}
          >
            {item.icon && (
              <span
                className={[
                  "inline-flex mt-0.5 shrink-0",
                  item.disabled
                    ? "text-[var(--text-disabled)]"
                    : item.danger
                      ? "text-[var(--danger-text)]"
                      : "text-[var(--text-subtle)]",
                ].join(" ")}
              >
                {item.icon}
              </span>
            )}
            <span className="min-w-0">
              <span className="block text-[13px] font-medium leading-tight">{item.label}</span>
              {item.description && (
                <span className="block text-[11px] text-[var(--text-subtle)] mt-0.5">
                  {item.description}
                </span>
              )}
            </span>
          </button>
        </div>
      ))}
    </div>
  );

  // Portal fixed context menus to document.body so ancestor transforms/overflow never clip or offset them.
  if (position && typeof document !== "undefined") {
    return createPortal(menuEl, document.body);
  }
  return menuEl;
}
