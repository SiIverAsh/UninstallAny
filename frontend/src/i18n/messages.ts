import type {
  Category,
  Confidence,
  Language,
  MatchKind,
  OfficialOutcome,
  OperationKind,
  RecoveryState,
} from "@/types/domain";

export function detectInitialLanguage(): Language {
  if (typeof navigator !== "undefined" && navigator.language.toLowerCase().startsWith("zh")) {
    return "zh";
  }
  return "en";
}

export function t(lang: Language, en: string, zh: string): string {
  return lang === "zh" ? zh : en;
}

export function categoryLabel(lang: Language, category: Category): string {
  switch (category) {
    case "File":
      return t(lang, "File", "文件");
    case "Directory":
      return t(lang, "Directory", "目录");
    case "Shortcut":
      return t(lang, "Shortcut", "快捷方式");
    case "Registry":
      return t(lang, "Registry", "注册表");
    case "Startup":
      return t(lang, "Startup", "启动项");
    case "Service":
      return t(lang, "Service", "服务");
    case "ScheduledTask":
      return t(lang, "Scheduled task", "计划任务");
    case "Firewall":
      return t(lang, "Firewall", "防火墙");
    case "FileAssociation":
      return t(lang, "File association", "文件关联");
    case "ShellExtension":
      return t(lang, "Shell extension", "Shell 扩展");
    case "Com":
      return "COM";
  }
}

export function confidenceLabel(lang: Language, confidence: Confidence): string {
  switch (confidence) {
    case "High":
      return t(lang, "High confidence", "高置信度");
    case "Medium":
      return t(lang, "Medium confidence", "中置信度");
    case "Low":
      return t(lang, "Low confidence", "低置信度");
  }
}

export function evidenceLabel(lang: Language, evidence: MatchKind): string {
  switch (evidence) {
    case "ExactIdentity":
      return t(lang, "Exact identity match", "精确标识匹配");
    case "PublisherAndApp":
      return t(lang, "Publisher and application match", "发行商与应用名同时匹配");
    case "AppName":
      return t(lang, "Application name match", "应用名匹配");
    case "FuzzyName":
      return t(lang, "Fuzzy name match", "应用名模糊匹配");
    case "RuleHint":
      return t(lang, "Rule hint", "规则线索");
  }
}

export function operationLabel(lang: Language, op: OperationKind): string {
  switch (op) {
    case "inventory":
      return t(lang, "Reading installed applications…", "正在枚举已安装应用…");
    case "scan":
      return t(lang, "Scanning leftovers…", "正在扫描残留…");
    case "prepare_uninstall":
      return t(lang, "Checking official uninstallers…", "正在核查官方卸载程序…");
    case "uninstall":
      return t(lang, "Running uninstall queue…", "正在处理卸载队列…");
    case "backups":
      return t(lang, "Reading quarantine…", "正在读取隔离区…");
    case "prepare_restore":
      return t(lang, "Checking backup records…", "正在检查备份记录…");
    case "restore":
      return t(lang, "Restoring selected batch…", "正在还原所选批次…");
    case "cleanup":
      return t(lang, "Quarantining and backing up…", "正在隔离和备份…");
    case "expiry_preview":
      return t(lang, "Checking expired files…", "正在检查到期文件…");
    case "purge_expired":
      return t(lang, "Removing selected expired files…", "正在清理所选到期文件…");
    case "preferences":
      return t(lang, "Saving settings…", "正在保存设置…");
    case "audit_export":
      return t(lang, "Exporting audit log…", "正在导出操作日志…");
  }
}

export function recoveryLabel(lang: Language, state: RecoveryState): string {
  switch (state) {
    case "Applied":
      return t(lang, "Recoverable", "可还原");
    case "Restored":
      return t(lang, "Restored", "已还原");
    case "Purged":
      return t(lang, "Purged", "已清理");
    case "Staged":
      return t(lang, "Pending", "待确认");
    case "NeedsReview":
      return t(lang, "Needs review", "需要复核");
  }
}

export function officialOutcomeMeta(
  lang: Language,
  outcome: { Ok: OfficialOutcome } | { Err: string },
): { tone: "success" | "warning" | "neutral" | "danger"; label: string } {
  if ("Err" in outcome) {
    return { tone: "danger", label: t(lang, "Needs attention", "需要处理") };
  }
  const value = outcome.Ok;
  if (value === "Completed") {
    return { tone: "success", label: t(lang, "Completed", "已完成") };
  }
  if (value === "NeedsRestart") {
    return { tone: "warning", label: t(lang, "Restart needed", "需要重启") };
  }
  if (value === "Cancelled") {
    return { tone: "neutral", label: t(lang, "Cancelled", "已取消") };
  }
  if ("Failed" in value) {
    return {
      tone: "danger",
      label: `${t(lang, "Failed", "失败")} · ${value.Failed}`,
    };
  }
  return {
    tone: "warning",
    label: `${t(lang, "Completion unverified", "无法确认完成")} · ${value.Unverified}`,
  };
}
