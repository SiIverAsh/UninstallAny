import { useEffect, useState } from "react";
import { AlertTriangle, RotateCcw, Shield, Trash2 } from "lucide-react";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Checkbox } from "@/components/ui/Controls";
import { Modal } from "@/components/ui/Modal";
import { DiagnosticsBlock, Notice } from "@/components/ui/Primitives";
import { t } from "@/i18n/messages";
import { useApp } from "@/store/AppContext";

export function ConfirmationModal() {
  const {
    lang,
    modal,
    setModal,
    isBusy,
    approveUninstall,
    approveCleanup,
    approveRestore,
    approvePurgeExpired,
  } = useApp();

  const [expirySelected, setExpirySelected] = useState<Set<string>>(() => new Set());

  useEffect(() => {
    if (modal?.kind === "expiry") {
      setExpirySelected(new Set());
    }
  }, [modal]);

  if (!modal) return null;

  const close = () => setModal(null);

  if (modal.kind === "uninstall") {
    return (
      <Modal
        open
        onClose={close}
        title={t(lang, "Review official uninstall", "确认运行官方卸载")}
        icon={<AlertTriangle className="w-4 h-4" />}
        iconTone="danger"
        footerRight={(requestClose) => (
          <>
            <Button variant="secondary" onClick={requestClose}>
              {t(lang, "Cancel", "取消")}
            </Button>
            <Button
              variant="danger"
              icon={<Trash2 className="w-3.5 h-3.5" />}
              disabled={isBusy || modal.intents.length === 0}
              onClick={() => void approveUninstall(modal.ticket)}
            >
              {t(lang, "Start uninstall", "开始卸载")}
            </Button>
          </>
        )}
      >
        <p className="text-[13px] text-[var(--text-muted)] mb-3">
          {t(
            lang,
            "The official uninstallers will run in order. A failed app will not stop the rest.",
            "将依次运行官方卸载程序。单项失败后会继续处理其余应用。",
          )}
        </p>
        <div className="space-y-2.5">
          {modal.intents.map((intent, idx) => (
            <div
              key={idx}
              className="p-3.5 rounded-[9px] bg-[var(--bg-surface-alt)] border border-[var(--border-line)] space-y-1"
            >
              <div className="flex items-center gap-2">
                <span className="text-[13.5px] font-semibold text-[var(--text-ink)]">
                  {intent.application}
                </span>
                {intent.quiet && (
                  <Badge tone="accent">{t(lang, "Quiet uninstall", "静默卸载")}</Badge>
                )}
              </div>
              <div className="text-[12.5px] text-[var(--text-muted)] font-mono break-all">
                {intent.method}
              </div>
              {intent.notice && (
                <div className="text-[12px] text-[var(--warning-text)]">{intent.notice}</div>
              )}
            </div>
          ))}
        </div>
        {modal.warnings.length > 0 && (
          <div className="mt-3">
            <DiagnosticsBlock
              warnings={modal.warnings}
              label={
                lang === "zh"
                  ? `${modal.warnings.length} 条警告`
                  : `${modal.warnings.length} warnings`
              }
            />
          </div>
        )}
      </Modal>
    );
  }

  if (modal.kind === "cleanup") {
    return (
      <Modal
        open
        onClose={close}
        title={t(lang, "Confirm cleanup", "确认清理")}
        icon={<Shield className="w-4 h-4" />}
        iconTone="accent"
        footerRight={(requestClose) => (
          <>
            <Button variant="secondary" onClick={requestClose}>
              {t(lang, "Cancel", "取消")}
            </Button>
            <Button
              variant="primary"
              icon={<Shield className="w-3.5 h-3.5" />}
              disabled={isBusy || modal.items.length === 0}
              onClick={() => void approveCleanup(modal.planId, modal.items)}
            >
              {t(lang, "Quarantine selected items", "隔离所选项目")}
            </Button>
          </>
        )}
      >
        <p className="text-[13px] text-[var(--text-muted)]">
          {lang === "zh"
            ? `将处理 ${modal.items.length} 个所选项目。文件进入隔离区，注册表项在删除前备份。`
            : `${modal.items.length} selected items will be processed. Files go to quarantine and registry entries are backed up before deletion.`}
        </p>
        {modal.hasHighRisk && (
          <div className="mt-3">
            <Notice tone="danger">
              {t(
                lang,
                "Your selection includes high-risk items. Review their effect before continuing.",
                "所选项目含高风险项。请在继续前核对影响。",
              )}
            </Notice>
          </div>
        )}
        <div className="mt-3 rounded-[9px] bg-[var(--bg-surface-alt)] border border-[var(--border-line)] divide-y divide-[var(--border-soft)] max-h-[260px] overflow-y-auto">
          {modal.targets.map((target, idx) => (
            <div
              key={idx}
              title={target}
              className="px-3.5 py-2 text-[12.5px] font-mono text-[var(--text-ink)] truncate"
            >
              {target}
            </div>
          ))}
        </div>
      </Modal>
    );
  }

  if (modal.kind === "restore") {
    return (
      <Modal
        open
        onClose={close}
        title={t(lang, "Confirm restore", "确认还原")}
        icon={<RotateCcw className="w-4 h-4" />}
        iconTone="accent"
        footerRight={(requestClose) => (
          <>
            <Button variant="secondary" onClick={requestClose}>
              {t(lang, "Cancel", "取消")}
            </Button>
            <Button
              variant="primary"
              icon={<RotateCcw className="w-3.5 h-3.5" />}
              disabled={isBusy || modal.entries.length === 0}
              onClick={() => void approveRestore(modal.ticket)}
            >
              {t(lang, "Restore batch", "还原此批次")}
            </Button>
          </>
        )}
      >
        <p className="text-[13px] text-[var(--text-muted)]">
          {t(
            lang,
            "Items return to their original locations. Existing objects are preserved.",
            "项目将回到原位置。已有的同名对象会保留。",
          )}
        </p>
        {modal.warnings.length > 0 && (
          <div className="mt-3">
            <DiagnosticsBlock
              warnings={modal.warnings}
              label={
                lang === "zh"
                  ? `${modal.warnings.length} 条诊断信息`
                  : `${modal.warnings.length} diagnostics`
              }
            />
          </div>
        )}
        <div className="mt-3 rounded-[9px] bg-[var(--bg-surface-alt)] border border-[var(--border-line)] divide-y divide-[var(--border-soft)] max-h-[275px] overflow-y-auto">
          {modal.entries.map((entry) => (
            <div key={entry.id} className="px-3.5 py-2.5">
              <div
                className="text-[12.5px] font-semibold text-[var(--text-ink)] truncate"
                title={entry.target}
              >
                {entry.target}
              </div>
              <div
                className="text-[11.5px] text-[var(--text-subtle)] font-mono truncate mt-0.5"
                title={entry.backup}
              >
                {entry.backup}
              </div>
            </div>
          ))}
        </div>
      </Modal>
    );
  }

  const allCount = modal.entries.length;
  const selCount = expirySelected.size;
  return (
    <Modal
      open
      onClose={close}
      title={t(lang, "Expired quarantine files", "到期隔离文件")}
      icon={<AlertTriangle className="w-4 h-4" />}
      iconTone="danger"
      footerLeft={
        allCount > 0 ? (
          <Badge tone={selCount > 0 ? "danger" : "neutral"}>
            {lang === "zh"
              ? `已选 ${selCount} / ${allCount} 项`
              : `${selCount} / ${allCount} selected`}
          </Badge>
        ) : null
      }
      footerRight={(requestClose) => (
        <>
          <Button variant="secondary" onClick={requestClose}>
            {t(lang, "Cancel", "取消")}
          </Button>
          <Button
            variant="danger"
            icon={<Trash2 className="w-3.5 h-3.5" />}
            disabled={isBusy || selCount === 0}
            onClick={() => void approvePurgeExpired(modal.ticket, Array.from(expirySelected))}
          >
            {t(lang, "Permanently remove selected files", "永久清理所选文件")}
          </Button>
        </>
      )}
    >
      {modal.warnings.length > 0 && (
        <div className="mb-3">
          <DiagnosticsBlock
            warnings={modal.warnings}
            label={
              lang === "zh"
                ? `${modal.warnings.length} 条诊断信息`
                : `${modal.warnings.length} diagnostics`
            }
          />
        </div>
      )}
      {allCount === 0 ? (
        <p className="text-[13px] text-[var(--text-muted)]">
          {t(
            lang,
            "No expired files are eligible for permanent removal.",
            "没有符合永久清理条件的到期文件。",
          )}
        </p>
      ) : (
        <>
          <Notice tone="danger">
            {t(
              lang,
              "Select the expired quarantine copies to remove permanently. Restoring those copies will be unavailable.",
              "请选择要永久清理的到期备份。执行后将失去这些备份的还原能力。",
            )}
          </Notice>
          <div className="flex items-center justify-between mt-3 mb-1.5">
            <span className="text-[12px] text-[var(--text-muted)]">
              {lang === "zh" ? `共 ${allCount} 个到期备份` : `${allCount} expired copies`}
            </span>
            <div className="flex items-center gap-1">
              <Button
                variant="ghost"
                size="sm"
                disabled={selCount === allCount}
                onClick={() => setExpirySelected(new Set(modal.entries.map((e) => e.id)))}
              >
                {t(lang, "Select all", "全选")}
              </Button>
              <Button
                variant="ghost"
                size="sm"
                disabled={selCount === 0}
                onClick={() => setExpirySelected(new Set())}
              >
                {t(lang, "Clear", "清空")}
              </Button>
            </div>
          </div>
          <div className="rounded-[9px] bg-[var(--bg-surface-alt)] border border-[var(--border-line)] divide-y divide-[var(--border-soft)] max-h-[240px] overflow-y-auto">
            {modal.entries.map((item) => {
              const checked = expirySelected.has(item.id);
              const toggle = () => {
                setExpirySelected((prev) => {
                  const next = new Set(prev);
                  if (next.has(item.id)) next.delete(item.id);
                  else next.add(item.id);
                  return next;
                });
              };
              return (
                <div
                  key={item.id}
                  onClick={toggle}
                  className={[
                    "flex items-center gap-3 px-3.5 py-2.5 cursor-pointer transition-colors",
                    checked ? "bg-[var(--danger-bg)]" : "hover:bg-[var(--bg-hover)]",
                  ].join(" ")}
                >
                  <Checkbox checked={checked} onChange={toggle} />
                  <div className="min-w-0 flex-1">
                    <div className="text-[12.5px] font-semibold text-[var(--text-ink)] truncate">
                      {item.target}
                    </div>
                    <div className="text-[11.5px] text-[var(--text-subtle)] font-mono truncate">
                      {item.backup}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </>
      )}
    </Modal>
  );
}
