import { forwardRef, type InputHTMLAttributes, type ReactNode } from "react";
import { Minus, Plus, X } from "lucide-react";

export interface TextInputProps
  extends Omit<InputHTMLAttributes<HTMLInputElement>, "onChange"> {
  value: string;
  onChange: (value: string) => void;
  onSubmit?: () => void;
  icon?: ReactNode;
  shortcutHint?: string;
  clearable?: boolean;
  containerClassName?: string;
}

export const TextInput = forwardRef<HTMLInputElement, TextInputProps>(function TextInput(
  {
    value,
    onChange,
    onSubmit,
    icon,
    shortcutHint,
    clearable = true,
    disabled = false,
    containerClassName = "",
    className = "",
    onKeyDown,
    ...rest
  },
  ref,
) {
  return (
    <div
      className={[
        "group relative flex items-center h-[34px] px-2.5 gap-2 rounded-[7.5px] border transition-all duration-120",
        disabled
          ? "bg-[var(--bg-disabled)] border-[var(--border-soft)] cursor-not-allowed"
          : "bg-[var(--bg-input)] border-[var(--border-control)] hover:border-[var(--border-control-hover)] focus-within:border-[var(--accent)] focus-within:ring-2 focus-within:ring-[var(--accent)]/25",
        containerClassName,
      ].join(" ")}
    >
      {icon && (
        <span className="inline-flex shrink-0 text-[var(--text-subtle)] group-focus-within:text-[var(--accent-text)] transition-colors">
          {icon}
        </span>
      )}
      <input
        ref={ref}
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && onSubmit) {
            e.preventDefault();
            onSubmit();
          }
          onKeyDown?.(e);
        }}
        className={[
          "w-full min-w-0 bg-transparent text-[13px] text-[var(--text-ink)] placeholder:text-[var(--text-subtle)] outline-none disabled:cursor-not-allowed disabled:text-[var(--text-disabled)]",
          className,
        ].join(" ")}
        {...rest}
      />
      {clearable && !disabled && value.length > 0 ? (
        <button
          type="button"
          onClick={() => onChange("")}
          aria-label="Clear"
          className="inline-flex items-center justify-center w-[18px] h-[18px] rounded-full bg-[var(--bg-hover)] text-[var(--text-muted)] hover:bg-[var(--bg-pressed)] hover:text-[var(--text-ink)] transition-colors shrink-0 cursor-pointer"
        >
          <X className="w-2.5 h-2.5 stroke-[2.5]" />
        </button>
      ) : shortcutHint && !disabled && value.length === 0 ? (
        <kbd className="inline-flex items-center justify-center h-[19px] px-1.5 rounded-[4.5px] bg-[var(--bg-surface-alt)] border border-[var(--border-line)] text-[10.5px] font-semibold text-[var(--text-subtle)] shrink-0 group-focus-within:opacity-0 transition-opacity">
          {shortcutHint}
        </kbd>
      ) : null}
    </div>
  );
});

export interface NumericStepperProps {
  value: number;
  min?: number;
  max?: number;
  suffix?: string;
  onChange: (value: number) => void;
}

export function NumericStepper({
  value,
  min = 1,
  max = 65535,
  suffix = "",
  onChange,
}: NumericStepperProps) {
  const clamp = (n: number) => Math.max(min, Math.min(max, Math.floor(n)));
  const canDec = value > min;
  const canInc = value < max;

  return (
    <div className="inline-flex items-center h-[34px] rounded-[7.5px] border border-[var(--border-control)] bg-[var(--bg-input)] overflow-hidden focus-within:border-[var(--accent)] focus-within:ring-2 focus-within:ring-[var(--accent)]/25 transition-all">
      <button
        type="button"
        disabled={!canDec}
        onClick={() => onChange(clamp(value - 1))}
        aria-label="Decrease"
        className="inline-flex items-center justify-center w-[30px] h-full border-r border-[var(--border-soft)] text-[var(--text-ink)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-pressed)] disabled:text-[var(--text-disabled)] disabled:cursor-not-allowed cursor-pointer transition-colors"
      >
        <Minus className="w-3.5 h-3.5" />
      </button>
      <div className="inline-flex items-center px-2.5 gap-1">
        <input
          type="number"
          min={min}
          max={max}
          value={value}
          onChange={(e) => {
            const parsed = Number.parseInt(e.target.value, 10);
            if (!Number.isNaN(parsed)) onChange(clamp(parsed));
          }}
          className="w-12 text-center text-[13px] font-semibold text-[var(--text-ink)] tabular-nums bg-transparent outline-none [appearance:textfield] [&::-webkit-outer-spin-button]:appearance-none [&::-webkit-inner-spin-button]:appearance-none"
        />
        {suffix && (
          <span className="text-[12.5px] text-[var(--text-subtle)] select-none">{suffix}</span>
        )}
      </div>
      <button
        type="button"
        disabled={!canInc}
        onClick={() => onChange(clamp(value + 1))}
        aria-label="Increase"
        className="inline-flex items-center justify-center w-[30px] h-full border-l border-[var(--border-soft)] text-[var(--text-ink)] hover:bg-[var(--bg-hover)] active:bg-[var(--bg-pressed)] disabled:text-[var(--text-disabled)] disabled:cursor-not-allowed cursor-pointer transition-colors"
      >
        <Plus className="w-3.5 h-3.5" />
      </button>
    </div>
  );
}
