import { Check, Minus } from "lucide-react";

export interface CheckboxProps {
  checked: boolean;
  indeterminate?: boolean;
  disabled?: boolean;
  onChange?: (checked: boolean) => void;
  title?: string;
  ariaLabel?: string;
}

export function Checkbox({
  checked,
  indeterminate = false,
  disabled = false,
  onChange,
  title,
  ariaLabel,
}: CheckboxProps) {
  const active = checked || indeterminate;
  return (
    <button
      type="button"
      role="checkbox"
      aria-checked={indeterminate ? "mixed" : checked}
      aria-label={ariaLabel}
      title={title}
      disabled={disabled}
      onClick={(e) => {
        e.stopPropagation();
        if (!disabled) onChange?.(!checked);
      }}
      className={[
        "inline-flex items-center justify-center w-4 h-4 rounded-[4.5px] border transition-all duration-120 shrink-0 outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]/35",
        disabled
          ? "bg-[var(--bg-disabled)] border-[var(--border-soft)] cursor-not-allowed"
          : active
            ? "bg-[var(--accent)] border-[var(--accent)] text-white hover:bg-[var(--accent-hover)] cursor-pointer"
            : "bg-[var(--bg-input)] border-[var(--border-control)] hover:border-[var(--accent)] hover:bg-[var(--accent-soft)] cursor-pointer",
      ].join(" ")}
    >
      {indeterminate && !checked ? (
        <Minus className="w-3 h-3 stroke-[2.6]" />
      ) : checked ? (
        <Check className="w-3 h-3 stroke-[2.8]" />
      ) : null}
    </button>
  );
}

export interface ToggleSwitchProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: string;
}

export function ToggleSwitch({ checked, onChange, label }: ToggleSwitchProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className="inline-flex items-center gap-2 h-[34px] px-1 rounded-[7px] cursor-pointer group outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]/30"
    >
      <span
        className={[
          "relative inline-flex items-center w-8 h-[18px] rounded-full transition-colors duration-150 shrink-0",
          checked
            ? "bg-[var(--accent)] group-hover:bg-[var(--accent-hover)]"
            : "bg-[var(--border-control)] group-hover:bg-[var(--border-control-hover)]",
        ].join(" ")}
      >
        <span
          className={[
            "inline-block w-[13px] h-[13px] rounded-full bg-white shadow-[0_1px_2px_rgba(0,0,0,0.3)] transition-transform duration-150",
            checked ? "translate-x-[16.5px]" : "translate-x-[2.5px]",
          ].join(" ")}
        />
      </span>
      <span
        className={[
          "text-[13px] transition-colors whitespace-nowrap",
          checked
            ? "text-[var(--text-ink)] font-medium"
            : "text-[var(--text-muted)] group-hover:text-[var(--text-ink)]",
        ].join(" ")}
      >
        {label}
      </span>
    </button>
  );
}
