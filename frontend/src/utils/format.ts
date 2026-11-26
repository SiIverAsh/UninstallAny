import type { AppRecord, Language } from "@/types/domain";
import { t } from "@/i18n/messages";

export function formatBytes(bytes: number): string {
  const KIB = 1024;
  const MIB = KIB * KIB;
  const GIB = MIB * KIB;
  if (bytes >= GIB) return `${(bytes / GIB).toFixed(1)} GB`;
  if (bytes >= MIB) return `${(bytes / MIB).toFixed(1)} MB`;
  if (bytes >= KIB) return `${Math.floor(bytes / KIB)} KB`;
  return `${bytes} B`;
}

export function formatInstallDate(raw: string): string {
  if (/^\d{8}$/.test(raw)) {
    return `${raw.slice(0, 4)}-${raw.slice(4, 6)}-${raw.slice(6, 8)}`;
  }
  return raw;
}

export function formatExpiry(
  lang: Language,
  unixMs: number,
): { tone: "warning" | "neutral"; label: string } {
  const now = Date.now();
  if (unixMs <= now) {
    return {
      tone: "warning",
      label: t(lang, "Retention reached", "已到保留期"),
    };
  }
  const days = Math.ceil((unixMs - now) / 86_400_000);
  return {
    tone: "neutral",
    label:
      lang === "zh"
        ? `距最近保留期 ${days} 天`
        : `Next retention date in ${days}d`,
  };
}

export function sourceBadgeMeta(
  lang: Language,
  app: AppRecord,
): { label: string; hint: string; tone: "accent" | "success" | "warning" | "neutral" } {
  if (app.system_component) {
    const label = t(lang, "System", "系统组件");
    return { label, hint: label, tone: "warning" };
  }
  if ("WindowsRegistry" in app.id) {
    return { label: "Win32", hint: "Windows Registry", tone: "accent" };
  }
  if ("WindowsPackage" in app.id) {
    return { label: "MSIX", hint: "Windows MSIX", tone: "success" };
  }
  const manager = app.id.Package.manager;
  switch (manager) {
    case "macos-bundle":
      return { label: "App", hint: "macos-bundle", tone: "accent" };
    case "homebrew-cask":
      return { label: "Homebrew", hint: "homebrew-cask", tone: "success" };
    case "homebrew-formula":
      return { label: "Brew", hint: "homebrew-formula", tone: "success" };
    case "apple-pkg-receipt":
      return {
        label: t(lang, "Installer", "安装包"),
        hint: "apple-pkg-receipt",
        tone: "neutral",
      };
    case "flatpak":
    case "flatpak-user":
    case "flatpak-system":
      return { label: "Flatpak", hint: manager, tone: "accent" };
    case "snap":
      return { label: "Snap", hint: "snap", tone: "warning" };
    case "dpkg":
      return { label: "DEB", hint: "dpkg", tone: "accent" };
    case "rpm":
      return { label: "RPM", hint: "rpm", tone: "accent" };
    case "pacman":
      return { label: "Pacman", hint: "pacman", tone: "accent" };
    case "appimage":
      return { label: "AppImage", hint: "appimage", tone: "success" };
    case "desktop":
      return { label: "Desktop", hint: "desktop", tone: "neutral" };
    default:
      return { label: manager, hint: manager, tone: "neutral" };
  }
}

const GLYPH_STYLES = [
  "bg-blue-500/15 text-blue-400 border-blue-400/25",
  "bg-emerald-500/15 text-emerald-400 border-emerald-400/25",
  "bg-violet-500/15 text-violet-400 border-violet-400/25",
  "bg-amber-500/15 text-amber-400 border-amber-400/25",
  "bg-sky-500/15 text-sky-400 border-sky-400/25",
  "bg-rose-500/15 text-rose-400 border-rose-400/25",
] as const;

export function glyphClasses(name: string): string {
  let hash = 0;
  for (let i = 0; i < name.length; i++) {
    hash = (hash * 31 + name.charCodeAt(i)) >>> 0;
  }
  return GLYPH_STYLES[hash % GLYPH_STYLES.length]!;
}

export function glyphLetter(name: string): string {
  const match = name.match(/[A-Za-z0-9\u4e00-\u9fa5]/);
  return match ? match[0].toUpperCase() : "?";
}

export function isMacPlatform(): boolean {
  if (typeof navigator === "undefined") return false;
  return /Mac|iPhone|iPad/i.test(navigator.platform || navigator.userAgent);
}
