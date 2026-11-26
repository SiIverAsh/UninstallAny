use std::{
    io,
    num::NonZeroU16,
    sync::{Arc, Mutex, mpsc},
    thread,
};

use serde::Serialize;
use tauri::{AppHandle, Emitter, async_runtime};
use uninstallany_core::{AppId, Cancellation, Error};
use uuid::Uuid;

#[cfg(feature = "macos-privileged-helper")]
use crate::helper_activation::{HelperActivationPreviewPayload, HelperActivationReportPayload};
use crate::{
    dto::{
        BackupInventoryPayload, ChangeReportPayload, ExpiryReviewPayload, InventoryPayload,
        LoadedPreferencesPayload, OfficialRow, RestoreReviewPayload, UninstallReviewPayload,
    },
    session::Session,
};

const WORKER_STOPPED: &str = "The macOS background worker has stopped.";
const WORKER_BUSY: &str = "A macOS operation is already running.";
const PROGRESS_EVENT: &str = "uninstallany://progress";

type Reply<T> = async_runtime::Sender<Result<T, String>>;

pub(crate) enum Operation {
    Inventory(Reply<InventoryPayload>),
    Review(Vec<AppId>, Reply<UninstallReviewPayload>),
    Uninstall(Uuid, AppHandle, Reply<Vec<OfficialRow>>),
    Cleanup(Uuid, Vec<usize>, Reply<ChangeReportPayload>),
    Backups(Reply<BackupInventoryPayload>),
    ReviewRestore(Uuid, Reply<RestoreReviewPayload>),
    Restore(Uuid, Reply<ChangeReportPayload>),
    ReviewExpiry(Reply<ExpiryReviewPayload>),
    PurgeExpired(Uuid, Vec<Uuid>, Reply<ChangeReportPayload>),
    SetRetention(NonZeroU16, Reply<u16>),
    #[cfg(feature = "macos-privileged-helper")]
    ReviewHelperActivation(AppId, Reply<HelperActivationPreviewPayload>),
    #[cfg(feature = "macos-privileged-helper")]
    RunHelperActivation(Uuid, Reply<HelperActivationReportPayload>),
}

enum Job {
    Preferences(Reply<LoadedPreferencesPayload>),
    Operation(ActiveOperation, Operation),
}

struct ActiveOperation {
    slot: Arc<Mutex<Option<Cancellation>>>,
    cancellation: Cancellation,
}

impl Drop for ActiveOperation {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.slot.lock() {
            *slot = None;
        }
    }
}

#[derive(Clone, Serialize)]
struct Progress {
    done: usize,
    total: usize,
}

/// Bridges async IPC to a single owner of the engine and confirmation plans.
pub(crate) struct Host {
    jobs: mpsc::SyncSender<Job>,
    active: Arc<Mutex<Option<Cancellation>>>,
}

impl Host {
    pub(crate) fn start() -> io::Result<Self> {
        // The frontend requests preferences and inventory together at startup.
        let (jobs, incoming) = mpsc::sync_channel(2);
        thread::Builder::new()
            .name("macos-uninstall-worker".into())
            .spawn(move || worker(incoming))?;
        Ok(Self {
            jobs,
            active: Arc::new(Mutex::new(None)),
        })
    }

    pub(crate) async fn load_preferences(&self) -> Result<LoadedPreferencesPayload, String> {
        let (reply, mut response) = async_runtime::channel(1);
        self.send(Job::Preferences(reply))?;
        response
            .recv()
            .await
            .ok_or_else(|| WORKER_STOPPED.to_string())?
    }

    pub(crate) async fn run<T>(
        &self,
        operation: impl FnOnce(Reply<T>) -> Operation,
    ) -> Result<T, String> {
        let active = self.reserve()?;
        let (reply, mut response) = async_runtime::channel(1);
        self.send(Job::Operation(active, operation(reply)))?;
        response
            .recv()
            .await
            .ok_or_else(|| WORKER_STOPPED.to_string())?
    }

    pub(crate) fn cancel(&self) -> Result<bool, String> {
        let slot = self.active.lock().map_err(|_| WORKER_STOPPED.to_string())?;
        if let Some(cancellation) = slot.as_ref() {
            cancellation.cancel();
        }
        Ok(slot.is_some())
    }

    fn reserve(&self) -> Result<ActiveOperation, String> {
        let mut slot = self.active.lock().map_err(|_| WORKER_STOPPED.to_string())?;
        if slot.is_some() {
            return Err(WORKER_BUSY.into());
        }
        let cancellation = Cancellation::default();
        *slot = Some(cancellation.clone());
        Ok(ActiveOperation {
            slot: Arc::clone(&self.active),
            cancellation,
        })
    }

    fn send(&self, job: Job) -> Result<(), String> {
        self.jobs.try_send(job).map_err(|error| match error {
            mpsc::TrySendError::Full(_) => WORKER_BUSY.into(),
            mpsc::TrySendError::Disconnected(_) => WORKER_STOPPED.into(),
        })
    }
}

fn worker(incoming: mpsc::Receiver<Job>) {
    let mut session = uninstallany_macos::open()
        .map_err(|error| format!("Could not open the macOS backend: {error}"))
        .map(Session::new);
    for job in incoming {
        match job {
            Job::Preferences(reply) => {
                let result = call(&mut session, |session| {
                    session.load_preferences(&Cancellation::default())
                });
                let _ = reply.blocking_send(result);
            }
            Job::Operation(active, operation) => {
                let cancel = &active.cancellation;
                match operation {
                    Operation::Inventory(reply) => {
                        let result =
                            call(&mut session, |session| session.list_applications(cancel));
                        finish(active, reply, result);
                    }
                    Operation::Review(apps, reply) => {
                        let result = call(&mut session, |session| {
                            session.review_uninstall(apps, cancel)
                        });
                        finish(active, reply, result);
                    }
                    Operation::Uninstall(ticket, app, reply) => {
                        let result = call(&mut session, |session| {
                            session.run_uninstall(ticket, cancel, |done, total| {
                                // Progress has no effect on the operation's authority or outcome.
                                let _ =
                                    app.emit_to("main", PROGRESS_EVENT, Progress { done, total });
                            })
                        });
                        finish(active, reply, result);
                    }
                    Operation::Cleanup(plan, items, reply) => {
                        let result = call(&mut session, |session| {
                            session.apply_cleanup(plan, &items, cancel)
                        });
                        finish(active, reply, result);
                    }
                    Operation::Backups(reply) => {
                        let result = call(&mut session, |session| session.list_backups(cancel));
                        finish(active, reply, result);
                    }
                    Operation::ReviewRestore(batch_id, reply) => {
                        let result = call(&mut session, |session| {
                            session.review_restore(batch_id, cancel)
                        });
                        finish(active, reply, result);
                    }
                    Operation::Restore(ticket, reply) => {
                        let result =
                            call(&mut session, |session| session.run_restore(ticket, cancel));
                        finish(active, reply, result);
                    }
                    Operation::ReviewExpiry(reply) => {
                        let result = call(&mut session, |session| session.review_expiry(cancel));
                        finish(active, reply, result);
                    }
                    Operation::PurgeExpired(ticket, items, reply) => {
                        let result = call(&mut session, |session| {
                            session.purge_expired(ticket, items, cancel)
                        });
                        finish(active, reply, result);
                    }
                    Operation::SetRetention(days, reply) => {
                        let result =
                            call(&mut session, |session| session.set_retention(days, cancel));
                        finish(active, reply, result);
                    }
                    #[cfg(feature = "macos-privileged-helper")]
                    Operation::ReviewHelperActivation(app, reply) => {
                        let result = call(&mut session, |session| {
                            session.review_helper_activation(&app, cancel)
                        });
                        finish(active, reply, result);
                    }
                    #[cfg(feature = "macos-privileged-helper")]
                    Operation::RunHelperActivation(ticket, reply) => {
                        let result = call(&mut session, |session| {
                            session.run_helper_activation(ticket, cancel)
                        });
                        finish(active, reply, result);
                    }
                }
            }
        }
    }
}

fn call<S, T>(
    session: &mut Result<S, String>,
    task: impl FnOnce(&mut S) -> uninstallany_core::Result<T>,
) -> Result<T, String> {
    match session {
        Ok(session) => task(session).map_err(message),
        Err(error) => Err(error.clone()),
    }
}

fn finish<T>(active: ActiveOperation, reply: Reply<T>, result: Result<T, String>) {
    // Release the slot before the frontend's post-operation inventory refresh.
    drop(active);
    let _ = reply.blocking_send(result);
}

fn message(error: Error) -> String {
    match error {
        Error::Cancelled => "Operation cancelled".into(),
        error => error.to_string(),
    }
}
