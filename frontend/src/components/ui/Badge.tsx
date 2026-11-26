import type { ReactNode } from "react";

export type BadgeTone = "neutral" | "accent" | "success" | "warning" | "danger";

const TONE_STYLES: Record<BadgeTone, string> = {
  neutral:
    "bg-[var(--bg-surface-alt)] text-[var(--text-muted)] border-[var(--border-line)]",
  accent:
    "bg-[var(--accent-pale)] text-[var(--accent-text)] border-[var(--accent-border)]",
  success:
    "bg-[var(--success-bg)] text-[var(--success-text)] border-[var(--success-border)]",
  warning:
    "bg-[var(--warning-bg)] text-[var(--warning-text)] border-[var(--warning-border)]",
  danger:
    "bg-[var(--danger-bg)] text-[var(--danger-text)] border-[var(--danger-border)]",
};

export interface BadgeProps {
  tone?: BadgeTone;
  icon?: ReactNode;
  title?: string;
  mono?: boolean;
  className?: string;
  children: ReactNode;
}

export function Badge({
  tone = "neutral",
  icon,
  title,
  mono = false,
  className = "",
  children,
}: BadgeProps) {
  return (
    <span
      title={title}
      className={[
        "inline-flex items-center h-[24px] px-2.5 gap-1 rounded-[6px] border text-[11.5px] font-semibold leading-none whitespace-nowrap",
        mono ? "font-mono" : "",
        TONE_STYLES[tone],
        className,
      ].join(" ")}
    >
      {icon && <span className="inline-flex shrink-0">{icon}</span>}
      <span>{children}</span>
    </span>
  );
}
