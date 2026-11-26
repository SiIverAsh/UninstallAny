import { Sidebar } from "@/components/layout/Sidebar";
import { StatusBar } from "@/components/layout/StatusBar";
import { ConfirmationModal } from "@/components/modals/ConfirmationModal";
import { Notice } from "@/components/ui/Primitives";
import { ToastContainer } from "@/components/ui/ToastContainer";
import { t } from "@/i18n/messages";
import { ApplicationsPage } from "@/pages/ApplicationsPage";
import { QuarantinePage } from "@/pages/QuarantinePage";
import { ReviewPage } from "@/pages/ReviewPage";
import { SettingsPage } from "@/pages/SettingsPage";
import { AppProvider, useApp } from "@/store/AppContext";

function WorkspaceShell() {
  const { lang, page, status, clearStatus, toasts, dismissToast } = useApp();

  return (
    <div className="h-screen w-screen flex flex-col overflow-hidden bg-[var(--bg-page)] text-[var(--text-ink)]">
      <div className="flex-1 min-h-0 flex overflow-hidden">
        <Sidebar />
        <main className="flex-1 min-w-0 min-h-0 flex flex-col px-6 py-5 overflow-hidden">
          {status?.kind === "error" && (
            <div className="mb-3 shrink-0">
              <Notice
                tone="danger"
                onDismiss={clearStatus}
                dismissLabel={t(lang, "Dismiss", "关闭提示")}
              >
                {status.message}
              </Notice>
            </div>
          )}
          <div className="flex-1 min-h-0">
            {page === "applications" && <ApplicationsPage />}
            {page === "quarantine" && <QuarantinePage />}
            {page === "settings" && <SettingsPage />}
            {page === "review" && <ReviewPage />}
          </div>
        </main>
      </div>
      <StatusBar />
      <ConfirmationModal />
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />
    </div>
  );
}

export default function App() {
  return (
    <AppProvider>
      <WorkspaceShell />
    </AppProvider>
  );
}
