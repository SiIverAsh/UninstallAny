import { useCallback, useEffect, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { X } from "lucide-react";

export interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: string;
  icon: ReactNode;
  iconTone: "accent" | "danger";
  footerLeft?: ReactNode;
  footerRight: ReactNode | ((requestClose: () => void) => ReactNode);
  children: ReactNode;
}

const EXIT_MS = 140;

export function Modal({
  open,
  onClose,
  title,
  icon,
  iconTone,
  footerLeft,
  footerRight,
  children,
}: ModalProps) {
  const [closing, setClosing] = useState(false);

  const requestClose = useCallback(() => {
    if (closing) return;
    setClosing(true);
    window.setTimeout(() => {
      setClosing(false);
      onClose();
    }, EXIT_MS);
  }, [closing, onClose]);

  useEffect(() => {
    if (!open) return;
    setClosing(false);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        requestClose();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, requestClose]);

  if (!open) return null;

  const dialog = (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
    >
      <div
        onClick={requestClose}
        className={[
          "fixed inset-0 bg-[var(--backdrop)] backdrop-blur-[3px]",
          closing ? "animate-modal-backdrop-out" : "animate-modal-backdrop",
        ].join(" ")}
      />
      <div
        className={[
          "relative z-10 w-full max-w-[560px] rounded-[12px] bg-[var(--bg-popover)] border border-[var(--border-line)] shadow-[var(--shadow-modal)] overflow-hidden",
          closing ? "animate-modal-panel-out" : "animate-modal-panel",
        ].join(" ")}
      >
        <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--border-soft)]">
          <div className="flex items-center gap-3 min-w-0">
            <div
              className={[
                "inline-flex items-center justify-center w-9 h-9 rounded-full shrink-0",
                iconTone === "danger"
                  ? "bg-[var(--danger-bg)] text-[var(--danger-text)]"
                  : "bg-[var(--accent-pale)] text-[var(--accent-text)]",
              ].join(" ")}
            >
              {icon}
            </div>
            <h2 className="text-[18px] font-semibold text-[var(--text-ink)] truncate">
              {title}
            </h2>
          </div>
          <button
            type="button"
            onClick={requestClose}
            aria-label="Close"
            className="inline-flex items-center justify-center w-7 h-7 rounded-full text-[var(--text-subtle)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-ink)] transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="px-6 py-4 max-h-[64vh] overflow-y-auto">{children}</div>

        <div className="flex items-center justify-between gap-3 px-6 py-3.5 bg-[var(--bg-surface-alt)] border-t border-[var(--border-soft)]">
          <div className="flex items-center gap-2">{footerLeft}</div>
          <div className="flex items-center gap-2">
            {typeof footerRight === "function" ? footerRight(requestClose) : footerRight}
          </div>
        </div>
      </div>
    </div>
  );

  if (typeof document !== "undefined") {
    return createPortal(dialog, document.body);
  }
  return dialog;
}
