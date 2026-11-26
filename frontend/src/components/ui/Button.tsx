import type { ButtonHTMLAttributes, ReactNode } from "react";
import { Loader2 } from "lucide-react";

export type ButtonVariant =
  | "primary"
  | "secondary"
  | "danger"
  | "danger-subtle"
  | "tinted"
  | "ghost";

export type ButtonSize = "md" | "sm";

export interface ButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "children"> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  icon?: ReactNode;
  trailingIcon?: ReactNode;
  active?: boolean;
  busy?: boolean;
  disabledHint?: string;
  children: ReactNode;
}

const VARIANT_CLASSES: Record<ButtonVariant, string> = {
  primary:
    "bg-[var(--accent)] text-white border-[var(--accent)] shadow-[0_1px_2px_rgba(0,0,0,0.28),inset_0_1px_0_rgba(255,255,255,0.2)] hover:bg-[var(--accent-hover)] hover:border-[var(--accent-hover)] active:bg-[var(--accent-active)] focus-visible:ring-[var(--accent)]/35",
  danger:
    "bg-[var(--danger)] text-white border-[var(--danger)] shadow-[0_1px_2px_rgba(0,0,0,0.28),inset_0_1px_0_rgba(255,255,255,0.2)] hover:bg-[var(--danger-hover)] hover:border-[var(--danger-hover)] active:bg-[var(--danger-active)] focus-visible:ring-[var(--danger)]/35",
  secondary:
    "bg-[var(--bg-surface-alt)] text-[var(--text-ink)] border-[var(--border-control)] shadow-[0_1px_2px_rgba(0,0,0,0.12)] hover:bg-[var(--bg-hover)] hover:border-[var(--border-control-hover)] active:bg-[var(--bg-pressed)] focus-visible:ring-[var(--accent)]/30",
  tinted:
    "bg-[var(--accent-pale)] text-[var(--accent-text)] border-[var(--accent-border)] hover:bg-[var(--accent-pale-hover)] hover:border-[var(--accent)] active:bg-[var(--accent-pale-hover)] focus-visible:ring-[var(--accent)]/30",
  "danger-subtle":
    "bg-[var(--danger-bg)] text-[var(--danger-text)] border-[var(--danger-border)] hover:bg-[var(--danger-bg-hover)] hover:border-[var(--danger)] active:bg-[var(--danger-bg-hover)] focus-visible:ring-[var(--danger)]/30",
  ghost:
    "bg-transparent text-[var(--text-muted)] border-transparent hover:bg-[var(--bg-hover)] hover:text-[var(--text-ink)] active:bg-[var(--bg-pressed)] focus-visible:ring-[var(--accent)]/25",
};

const ACTIVE_SECONDARY_CLASSES =
  "!bg-[var(--accent-pale)] !text-[var(--accent-text)] !border-[var(--accent)] shadow-none";

const DISABLED_CLASSES: Record<ButtonVariant, string> = {
  primary: "bg-[var(--bg-disabled)] text-[var(--text-disabled)] border-[var(--border-soft)] shadow-none",
  danger: "bg-[var(--bg-disabled)] text-[var(--text-disabled)] border-[var(--border-soft)] shadow-none",
  secondary: "bg-[var(--bg-disabled)] text-[var(--text-disabled)] border-[var(--border-soft)] shadow-none",
  tinted: "bg-[var(--bg-disabled)] text-[var(--text-disabled)] border-[var(--border-soft)] shadow-none",
  "danger-subtle": "bg-[var(--bg-disabled)] text-[var(--text-disabled)] border-[var(--border-soft)] shadow-none",
  ghost: "bg-transparent text-[var(--text-disabled)] border-transparent shadow-none",
};

const SIZE_CLASSES: Record<ButtonSize, string> = {
  md: "h-[34px] px-3.5 text-[13px] rounded-[7.5px] gap-1.5",
  sm: "h-[28px] px-2.5 text-[12px] rounded-[6.5px] gap-1.5",
};

export function Button({
  variant = "secondary",
  size = "md",
  icon,
  trailingIcon,
  active = false,
  busy = false,
  disabled = false,
  disabledHint,
  className = "",
  type = "button",
  title,
  children,
  ...rest
}: ButtonProps) {
  const isDisabled = disabled || busy;
  const classes = [
    "inline-flex items-center justify-center font-semibold border whitespace-nowrap select-none transition-all duration-120 ease-out outline-none focus-visible:ring-2",
    SIZE_CLASSES[size],
    isDisabled
      ? `${DISABLED_CLASSES[variant]} cursor-not-allowed`
      : `${VARIANT_CLASSES[variant]} ${active && variant === "secondary" ? ACTIVE_SECONDARY_CLASSES : ""} cursor-pointer active:translate-y-[0.5px]`,
    className,
  ].join(" ");

  const buttonEl = (
    <button
      type={type}
      disabled={isDisabled}
      title={!isDisabled ? title : undefined}
      className={classes}
      {...rest}
    >
      {busy ? (
        <Loader2 className="h-3.5 w-3.5 animate-spin shrink-0" />
      ) : (
        icon && <span className="inline-flex shrink-0">{icon}</span>
      )}
      <span>{children}</span>
      {trailingIcon && <span className="inline-flex shrink-0">{trailingIcon}</span>}
    </button>
  );

  if (isDisabled && disabledHint) {
    return (
      <span title={disabledHint} className="inline-flex cursor-not-allowed">
        {buttonEl}
      </span>
    );
  }
  return buttonEl;
}
