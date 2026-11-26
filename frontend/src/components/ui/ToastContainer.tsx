import { useCallback, useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { AlertTriangle, Check, Info, X } from "lucide-react";
import type { ToastItem } from "@/types/domain";

const EXIT_MS = 160;

function SingleToast({
  toast,
  onDismiss,
}: {
  toast: ToastItem;
  onDismiss: (id: number) => void;
}) {
  const [hovered, setHovered] = useState(false);
  const [remaining, setRemaining] = useState(1);
  const [exiting, setExiting] = useState(false);

  const triggerExit = useCallback(() => {
    setExiting((already) => {
      if (already) return true;
      window.setTimeout(() => onDismiss(toast.id), EXIT_MS);
      return true;
    });
  }, [onDismiss, toast.id]);

  useEffect(() => {
    if (exiting) return;
    let elapsed = 0;
    let last = performance.now();
    const timer = window.setInterval(() => {
      const now = performance.now();
      const dt = now - last;
      last = now;
      if (!hovered) {
        elapsed += dt;
        const next = Math.max(0, 1 - elapsed / toast.durationMs);
        setRemaining(next);
        if (elapsed >= toast.durationMs) {
          window.clearInterval(timer);
          triggerExit();
        }
      }
    }, 40);
    return () => window.clearInterval(timer);
  }, [exiting, hovered, toast.durationMs, triggerExit]);

  const meta = {
    success: {
      border: "border-[var(--success-border)]",
      well: "bg-[var(--success-bg)] text-[var(--success-text)]",
      bar: "bg-[var(--success-text)]/70",
      icon: <Check className="w-3.5 h-3.5 stroke-[2.6]" />,
    },
    info: {
      border: "border-[var(--accent-border)]",
      well: "bg-[var(--accent-pale)] text-[var(--accent-text)]",
      bar: "bg-[var(--accent)]/80",
      icon: <Info className="w-3.5 h-3.5" />,
    },
    warning: {
      border: "border-[var(--warning-border)]",
      well: "bg-[var(--warning-bg)] text-[var(--warning-text)]",
      bar: "bg-[var(--warning-text)]/70",
      icon: <AlertTriangle className="w-3.5 h-3.5" />,
    },
    error: {
      border: "border-[var(--danger-border)]",
      well: "bg-[var(--danger-bg)] text-[var(--danger-text)]",
      bar: "bg-[var(--danger)]/80",
      icon: <AlertTriangle className="w-3.5 h-3.5" />,
    },
  }[toast.kind];

  return (
    <div
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      className={[
        "relative w-[320px] max-w-[calc(100vw-36px)] rounded-[10px] bg-[var(--bg-popover)] border shadow-[var(--shadow-toast)] overflow-hidden",
        exiting ? "animate-toast-out pointer-events-none" : "animate-toast-in",
        meta.border,
      ].join(" ")}
    >
      <div className="flex items-center gap-2.5 px-3 py-2.5">
        <span
          className={[
            "inline-flex items-center justify-center w-6 h-6 rounded-full shrink-0",
            meta.well,
          ].join(" ")}
        >
          {meta.icon}
        </span>
        <span className="flex-1 min-w-0 text-[12.5px] font-semibold text-[var(--text-ink)] leading-snug">
          {toast.message}
        </span>
        <button
          type="button"
          onClick={triggerExit}
          aria-label="Dismiss"
          className="inline-flex items-center justify-center w-5 h-5 rounded-full text-[var(--text-subtle)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-ink)] transition-colors cursor-pointer shrink-0"
        >
          <X className="w-3 h-3" />
        </button>
      </div>
      <div className="h-[2px] w-full bg-transparent">
        <div
          className={["h-full transition-[width] duration-75 ease-linear", meta.bar].join(" ")}
          style={{ width: `${remaining * 100}%` }}
        />
      </div>
    </div>
  );
}

export function ToastContainer({
  toasts,
  onDismiss,
}: {
  toasts: ToastItem[];
  onDismiss: (id: number) => void;
}) {
  if (toasts.length === 0) return null;
  const overlay = (
    <div className="fixed right-4 bottom-[48px] z-[60] flex flex-col gap-2 pointer-events-none">
      {toasts.map((toast) => (
        <div key={toast.id} className="pointer-events-auto">
          <SingleToast toast={toast} onDismiss={onDismiss} />
        </div>
      ))}
    </div>
  );
  if (typeof document !== "undefined") {
    return createPortal(overlay, document.body);
  }
  return overlay;
}
