import { Check, Copy, Download, Folder } from "lucide-react";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { NumericStepper, TextInput } from "@/components/ui/Inputs";
import {
  ChipButton,
  DiagnosticsBlock,
  SegmentedControl,
} from "@/components/ui/Primitives";
import { t } from "@/i18n/messages";
import { useApp } from "@/store/AppContext";

const RETENTION_PRESETS = [7, 14, 30, 90] as const;

export function SettingsPage() {
  const {
    lang,
    setLang,
    theme,
    setTheme,
    retention,
    savedRetention,
    setRetention,
    ruleText,
    savedRuleText,
    setRuleText,
    exportDestination,
    setExportDestination,
    exportResult,
    preferenceWarnings,
    status,
    isBusy,
    isRunning,
    saveRetention,
    saveRules,
    exportAudit,
    copyText,
  } = useApp();

  const retentionDirty = retention !== savedRetention;
  const rulesDirty = ruleText !== savedRuleText;
  const ruleLines = ruleText.length === 0 ? 0 : ruleText.split("\n").length;
  const ruleBytes = new TextEncoder().encode(ruleText).length;

  return (
    <div className="flex flex-col h-full min-h-0 animate-page-enter">
      <h1 className="text-[22px] font-semibold tracking-[-0.015em] text-[var(--text-ink)] shrink-0">
        {t(lang, "Settings", "设置")}
      </h1>

      <div className="mt-3 flex-1 min-h-0 overflow-y-auto pr-0.5">
        <div className="max-w-[740px] space-y-3 pb-4">
          {/* Appearance Theme */}
          <section className="p-[18px] rounded-[10px] bg-[var(--bg-surface)] border border-[var(--border-line)] shadow-[var(--shadow-card)] flex flex-wrap items-center justify-between gap-4">
            <div className="min-w-0">
              <h2 className="text-[14.5px] font-semibold text-[var(--text-ink)]">
                {t(lang, "Appearance", "外观主题")}
              </h2>
              <p className="text-[12.5px] text-[var(--text-muted)] mt-1">
                {t(
                  lang,
                  "Choose dark or light interface surface colors.",
                  "切换深色或浅色界面配色方案。",
                )}
              </p>
            </div>
            <div className="w-[196px] shrink-0">
              <SegmentedControl
                value={theme}
                onChange={setTheme}
                options={[
                  { value: "dark", label: t(lang, "Dark", "深色") },
                  { value: "light", label: t(lang, "Light", "浅色") },
                ]}
              />
            </div>
          </section>

          {/* Display Language */}
          <section className="p-[18px] rounded-[10px] bg-[var(--bg-surface)] border border-[var(--border-line)] shadow-[var(--shadow-card)] flex flex-wrap items-center justify-between gap-4">
            <div className="min-w-0">
              <h2 className="text-[14.5px] font-semibold text-[var(--text-ink)]">
                {t(lang, "Display language", "显示语言")}
              </h2>
              <p className="text-[12.5px] text-[var(--text-muted)] mt-1">
                {t(
                  lang,
                  "Switch interface text immediately without restarting.",
                  "立即切换界面语言，无需重启应用。",
                )}
              </p>
            </div>
            <div className="w-[196px] shrink-0">
              <SegmentedControl
                value={lang}
                onChange={setLang}
                options={[
                  { value: "en", label: "English" },
                  { value: "zh", label: "简体中文" },
                ]}
              />
            </div>
          </section>

          {/* Quarantine Retention */}
          <section className="p-[18px] rounded-[10px] bg-[var(--bg-surface)] border border-[var(--border-line)] shadow-[var(--shadow-card)]">
            <div className="flex items-center gap-2">
              <h2 className="text-[14.5px] font-semibold text-[var(--text-ink)]">
                {t(lang, "Quarantine retention", "隔离保留期")}
              </h2>
              {retentionDirty && (
                <Badge tone="warning">{t(lang, "Unsaved", "未保存")}</Badge>
              )}
            </div>
            <p className="text-[12.5px] text-[var(--text-muted)] mt-1">
              {t(
                lang,
                "Applies to future backups. Expired items remain available for restore.",
                "新设置适用于后续备份。到期的隔离项仍可还原。",
              )}
            </p>
            <div className="my-3 border-t border-[var(--border-soft)]" />
            <div className="flex flex-wrap items-center gap-2">
              {RETENTION_PRESETS.map((days) => (
                <ChipButton
                  key={days}
                  selected={retention === days}
                  onClick={() => setRetention(days)}
                >
                  {lang === "zh" ? `${days} 天` : `${days}d`}
                </ChipButton>
              ))}
              <NumericStepper
                value={retention}
                min={1}
                max={65535}
                suffix={t(lang, "days", "天")}
                onChange={setRetention}
              />
              {retentionDirty && (
                <Button variant="ghost" onClick={() => setRetention(savedRetention)}>
                  {t(lang, "Reset", "还原")}
                </Button>
              )}
              <Button
                variant="primary"
                icon={<Check className="w-3.5 h-3.5" />}
                busy={isRunning("preferences")}
                disabled={isBusy || !retentionDirty}
                onClick={() => void saveRetention()}
              >
                {t(lang, "Apply", "应用")}
              </Button>
            </div>
          </section>

          {/* Custom Rules */}
          <section className="p-[18px] rounded-[10px] bg-[var(--bg-surface)] border border-[var(--border-line)] shadow-[var(--shadow-card)]">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <h2 className="text-[14.5px] font-semibold text-[var(--text-ink)]">
                  {t(lang, "Custom rules", "自定义规则")}
                </h2>
                {rulesDirty && (
                  <Badge tone="warning">{t(lang, "Unsaved", "未保存")}</Badge>
                )}
              </div>
              <span className="text-[11.5px] text-[var(--text-subtle)] tabular-nums">
                {lang === "zh"
                  ? `${ruleLines} 行 · ${ruleBytes} B`
                  : `${ruleLines} lines · ${ruleBytes} B`}
              </span>
            </div>
            <p className="text-[12.5px] text-[var(--text-muted)] mt-1">
              {t(
                lang,
                "Paste your TOML rules. Leave it blank to use the built-in rules only.",
                "在这里粘贴 TOML 规则。清空并保存即可只使用内置规则。",
              )}
            </p>
            <div className="my-3 border-t border-[var(--border-soft)]" />
            <textarea
              value={ruleText}
              disabled={isBusy}
              rows={6}
              spellCheck={false}
              onChange={(e) => setRuleText(e.target.value)}
              placeholder={`# [[rules]]\n# app_match = "..."`}
              className="w-full rounded-[8px] border border-[var(--border-control)] bg-[var(--bg-input)] px-3 py-2.5 font-mono text-[12px] text-[var(--text-ink)] placeholder:text-[var(--text-subtle)] outline-none focus:border-[var(--accent)] focus:ring-2 focus:ring-[var(--accent)]/25 transition-all resize-y"
            />
            <div className="mt-3 flex items-center justify-between gap-2">
              <div>
                {status?.kind === "rules_saved" && (
                  <Badge tone="success" icon={<Check className="w-3 h-3" />}>
                    {lang === "zh"
                      ? `${status.count} 条自定义规则`
                      : `${status.count} custom rules`}
                  </Badge>
                )}
              </div>
              <div className="flex items-center gap-2">
                {rulesDirty && (
                  <Button
                    variant="ghost"
                    onClick={() => setRuleText(savedRuleText)}
                  >
                    {t(lang, "Revert", "撤回修改")}
                  </Button>
                )}
                <Button
                  variant="primary"
                  icon={<Check className="w-3.5 h-3.5" />}
                  busy={isRunning("preferences")}
                  disabled={isBusy || !rulesDirty}
                  onClick={() => void saveRules()}
                >
                  {t(lang, "Save rules", "保存规则")}
                </Button>
              </div>
            </div>
          </section>

          {/* Audit Log Export */}
          <section className="p-[18px] rounded-[10px] bg-[var(--bg-surface)] border border-[var(--border-line)] shadow-[var(--shadow-card)]">
            <h2 className="text-[14.5px] font-semibold text-[var(--text-ink)]">
              {t(lang, "Audit log", "操作日志")}
            </h2>
            <p className="text-[12.5px] text-[var(--text-muted)] mt-1">
              {t(
                lang,
                "Export a new JSON Lines file. Records can include local app names and paths.",
                "导出新的 JSON Lines 文件。日志可能包含本机应用名称和路径。",
              )}
            </p>
            <div className="my-3 border-t border-[var(--border-soft)]" />
            <div className="flex items-center gap-2">
              <TextInput
                value={exportDestination}
                onChange={setExportDestination}
                onSubmit={() => {
                  if (!isBusy && exportDestination.trim()) void exportAudit();
                }}
                disabled={isBusy}
                icon={<Folder className="w-3.5 h-3.5" />}
                placeholder={t(
                  lang,
                  "Absolute path to a new .jsonl file",
                  "新 .jsonl 文件的绝对路径",
                )}
                containerClassName="flex-1"
              />
              <Button
                variant="primary"
                icon={<Download className="w-3.5 h-3.5" />}
                busy={isRunning("audit_export")}
                disabled={isBusy || !exportDestination.trim()}
                disabledHint={t(
                  lang,
                  "Enter an absolute path for the new .jsonl file.",
                  "请输入新的 .jsonl 文件绝对路径。",
                )}
                onClick={() => void exportAudit()}
              >
                {t(lang, "Export log", "导出日志")}
              </Button>
            </div>
            {exportResult && (
              <div className="mt-3 space-y-2">
                <div className="flex items-center justify-between gap-2 px-3 py-2 rounded-[8px] bg-[var(--bg-surface-alt)] border border-[var(--border-soft)]">
                  <div className="flex items-center gap-2 min-w-0">
                    <Badge tone="success" icon={<Check className="w-3 h-3" />}>
                      {lang === "zh"
                        ? `已导出 ${exportResult.report.written} 条记录`
                        : `${exportResult.report.written} records exported`}
                    </Badge>
                    <span
                      title={exportResult.path}
                      className="text-[12px] font-mono text-[var(--text-muted)] truncate"
                    >
                      {exportResult.path}
                    </span>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    icon={<Copy className="w-3 h-3" />}
                    onClick={() =>
                      copyText(exportResult.path, t(lang, "export path", "导出路径"))
                    }
                  >
                    {t(lang, "Copy path", "复制路径")}
                  </Button>
                </div>
                <DiagnosticsBlock
                  warnings={exportResult.report.warnings}
                  label={
                    lang === "zh"
                      ? `${exportResult.report.warnings.length} 条诊断信息`
                      : `${exportResult.report.warnings.length} diagnostics`
                  }
                />
              </div>
            )}
          </section>

          <DiagnosticsBlock
            warnings={preferenceWarnings}
            label={
              lang === "zh"
                ? `${preferenceWarnings.length} 条诊断信息`
                : `${preferenceWarnings.length} diagnostics`
            }
          />
        </div>
      </div>
    </div>
  );
}
