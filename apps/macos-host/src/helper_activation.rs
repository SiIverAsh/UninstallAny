use serde::Serialize;
use uninstallany_core::{AppRecord, AuditEvent, Cancellation, Error, Result};
use uninstallany_macos::{PrivilegedHelperServiceState, SystemHelperActivation};
use uuid::Uuid;

const ACTION: &str = "macos_helper_registration";
const PREVIEW_NOTICE: &str = "This confirmation only requests registration of the signed system \
    helper. macOS may require administrator approval. Uninstalling the selected application \
    requires a fresh review and separate confirmation.";

/// Information shown before requesting system helper registration.
#[derive(Serialize)]
pub(crate) struct HelperActivationPreviewPayload {
    ticket: Uuid,
    application: String,
    path: Option<String>,
    notice: &'static str,
}

/// The service state observed after the registration request.
#[derive(Serialize)]
pub(crate) struct HelperActivationReportPayload {
    status: &'static str,
    notice: &'static str,
    audit_warning: Option<String>,
}

/// Owns one reviewed registration request until it is confirmed or discarded.
pub(crate) struct HelperActivationTicket {
    id: Uuid,
    plan: SystemHelperActivation,
}

impl HelperActivationTicket {
    /// Associates the native registration preview with a session ticket.
    pub(crate) fn new(plan: SystemHelperActivation) -> Self {
        Self {
            id: Uuid::new_v4(),
            plan,
        }
    }

    /// Identifies this single-use registration review.
    pub(crate) fn id(&self) -> Uuid {
        self.id
    }

    /// Projects the registration review without exposing its native authority.
    pub(crate) fn preview(&self) -> HelperActivationPreviewPayload {
        let app = self.plan.application();
        HelperActivationPreviewPayload {
            ticket: self.id,
            application: app.name.clone(),
            path: display_path(app),
            notice: PREVIEW_NOTICE,
        }
    }

    /// Returns the audit event for the registration review shown to the user.
    pub(crate) fn audit_preview(&self) -> AuditEvent {
        registration_event(self.id, &audit_target(self.plan.application()), "reviewed")
    }

    /// Consumes the confirmed preview and records the observed service state.
    pub(crate) fn run(
        self,
        cancel: &Cancellation,
        record: &impl Fn(&AuditEvent) -> Result<()>,
    ) -> Result<HelperActivationReportPayload> {
        let Self { id, plan } = self;
        let target = audit_target(plan.application());
        let event = |status| registration_event(id, &target, status);
        let state = match cancel.check() {
            Err(error) => Err(error),
            Ok(()) => {
                // Registration persists beyond this session, so its intent
                // must be durable before requesting the change from macOS.
                record(&event("starting"))?;
                cancel.check().and_then(|()| plan.register(cancel))
            }
        };
        match state {
            Ok(state) => {
                let (status, notice) = service_status(state);
                let audit_warning = record(&event(status)).err().map(|error| {
                    format!("Could not record the helper registration result: {error}")
                });
                Ok(HelperActivationReportPayload {
                    status,
                    notice,
                    audit_warning,
                })
            }
            Err(error) => {
                let status = if matches!(error, Error::Cancelled) {
                    "cancelled"
                } else {
                    "needs_review"
                };
                match record(&event(status)) {
                    Ok(()) => Err(error),
                    Err(audit_error) => Err(Error::Rejected(format!(
                        "Helper registration: {error}. Could not record its result: {audit_error}"
                    ))),
                }
            }
        }
    }
}

fn service_status(state: PrivilegedHelperServiceState) -> (&'static str, &'static str) {
    match state {
        PrivilegedHelperServiceState::Enabled => (
            "enabled",
            "The macOS helper is enabled. Refresh the application list and review the uninstall again.",
        ),
        PrivilegedHelperServiceState::RequiresApproval => (
            "requires_approval",
            "Approve the helper in macOS System Settings, then refresh the application list and review the uninstall again.",
        ),
        PrivilegedHelperServiceState::NotRegistered => (
            "not_registered",
            "macOS still reports the helper as unregistered. Check its state before requesting registration again.",
        ),
        PrivilegedHelperServiceState::NotFound => (
            "not_found",
            "The signed helper or its launch definition is missing from this installation.",
        ),
    }
}

fn display_path(app: &AppRecord) -> Option<String> {
    app.install_location
        .as_deref()
        .map(|path| path.display().to_string())
}

fn audit_target(app: &AppRecord) -> String {
    display_path(app).unwrap_or_else(|| app.name.clone())
}

fn registration_event(id: Uuid, target: &str, status: &str) -> AuditEvent {
    let mut event = AuditEvent::new(target.into(), ACTION, status);
    event.batch_id = Some(id);
    event.operation_id = Some(id);
    event
}
