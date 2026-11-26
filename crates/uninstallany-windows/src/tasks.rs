use std::{ffi::OsString, io, os::windows::ffi::OsStringExt, path::Path};

use uninstallany_core::{Access, Cancellation, Category, Proposal, Result, Risk, Scan, Target};
use windows::Win32::System::{
    Com::{CLSCTX_INPROC_SERVER, CoCreateInstance},
    TaskScheduler::{
        IExecAction, IRegisteredTask, ITaskFolder, ITaskService, TASK_ACTION_EXEC,
        TASK_ACTION_TYPE, TASK_ENUM_HIDDEN, TaskScheduler,
    },
    Variant::VARIANT,
};
use windows::core::{BSTR, IUnknown, Interface};

use super::{
    highrisk::ComApartment,
    uninstall::{RegisteredScope, registered_image},
};

const MAX_FOLDERS: i32 = 512;
const MAX_TASKS: i32 = 4_096;

/// Queries local Task Scheduler registrations visible to the current token.
pub(super) fn discover_tasks(scope: &RegisteredScope, cancel: &Cancellation) -> Result<Scan> {
    cancel.check()?;
    let _apartment = ComApartment::initialize()?;
    // SAFETY: the apartment is active and the CLSID selects the system scheduler.
    let scheduler: ITaskService =
        unsafe { CoCreateInstance(&TaskScheduler, None::<&IUnknown>, CLSCTX_INPROC_SERVER) }
            .map_err(windows_error)?;
    let local = VARIANT::default();
    // SAFETY: these empty variants select the local service and the current token.
    unsafe { scheduler.Connect(&local, &local, &local, &local) }.map_err(windows_error)?;
    // SAFETY: the scheduler is connected and the root folder path is valid.
    let root = unsafe { scheduler.GetFolder(&BSTR::from("\\")) }.map_err(windows_error)?;
    let mut pending = vec![root];
    let mut discovery = TaskDiscovery {
        scope,
        cancel,
        folders_left: MAX_FOLDERS - 1,
        tasks_left: MAX_TASKS,
        unreadable: 0,
        limited: false,
        scan: Scan::default(),
    };

    while let Some(folder) = pending.pop() {
        cancel.check()?;
        discovery.read_tasks(&folder)?;
        discovery.queue_folders(&folder, &mut pending)?;
    }
    if discovery.limited {
        discovery.scan.warnings.push(format!(
            "Task Scheduler discovery reached its limit of {MAX_FOLDERS} folders or {MAX_TASKS} tasks"
        ));
    }
    if discovery.unreadable > 0 {
        discovery.scan.warnings.push(format!(
            "could not inspect {} Task Scheduler folders or registrations",
            discovery.unreadable
        ));
    }
    Ok(discovery.scan)
}

struct TaskDiscovery<'a> {
    scope: &'a RegisteredScope,
    cancel: &'a Cancellation,
    folders_left: i32,
    tasks_left: i32,
    unreadable: usize,
    limited: bool,
    scan: Scan,
}

impl TaskDiscovery<'_> {
    fn queue_folders(
        &mut self,
        folder: &ITaskFolder,
        pending: &mut Vec<ITaskFolder>,
    ) -> Result<()> {
        // SAFETY: both interfaces remain in the active apartment, and flags must be zero.
        let folders = unsafe {
            folder
                .GetFolders(0)
                .and_then(|folders| folders.Count().map(|count| (folders, count)))
        };
        let Ok((folders, count)) = folders else {
            self.unreadable += 1;
            return Ok(());
        };
        let entries = take_budget(count, &mut self.folders_left, &mut self.limited);
        for index in 1..=entries {
            self.cancel.check()?;
            // SAFETY: the index is one-based and no larger than the reported count.
            let child = unsafe { folders.get_Item(&VARIANT::from(index)) };
            let result = child.map_err(windows_error).and_then(|child| {
                // SAFETY: this is a live folder from the current apartment.
                let path = scheduler_path(unsafe { child.Path() }.map_err(windows_error)?)?;
                Ok(path.map(|_| child))
            });
            match result {
                Ok(Some(child)) => pending.push(child),
                Ok(None) => {}
                Err(_) => self.unreadable += 1,
            }
        }
        Ok(())
    }

    fn read_tasks(&mut self, folder: &ITaskFolder) -> Result<()> {
        // SAFETY: hidden tasks are included only in this read of a live folder.
        let tasks = unsafe {
            folder
                .GetTasks(TASK_ENUM_HIDDEN.0)
                .and_then(|tasks| tasks.Count().map(|count| (tasks, count)))
        };
        let Ok((tasks, count)) = tasks else {
            self.unreadable += 1;
            return Ok(());
        };
        let entries = take_budget(count, &mut self.tasks_left, &mut self.limited);
        for index in 1..=entries {
            self.cancel.check()?;
            // SAFETY: the index is one-based and no larger than the reported count.
            let task = unsafe { tasks.get_Item(&VARIANT::from(index)) };
            match task
                .map_err(windows_error)
                .and_then(|task| task_proposal(&task, self.scope))
            {
                Ok(Some(proposal)) => self.scan.proposals.push(proposal),
                Ok(None) => {}
                Err(_) => self.unreadable += 1,
            }
        }
        Ok(())
    }
}

fn take_budget(count: i32, remaining: &mut i32, limited: &mut bool) -> i32 {
    let entries = count.clamp(0, *remaining);
    *remaining -= entries;
    *limited |= count > entries;
    entries
}

fn task_proposal(task: &IRegisteredTask, scope: &RegisteredScope) -> io::Result<Option<Proposal>> {
    // SAFETY: this is a live registered task from the active apartment.
    let Some(path) = scheduler_path(unsafe { task.Path() }.map_err(windows_error)?)? else {
        return Ok(None);
    };
    // SAFETY: these calls read the task definition and its action collection.
    let actions = unsafe {
        task.Definition()
            .and_then(|definition| definition.Actions())
    }
    .map_err(windows_error)?;
    let mut count = 0;
    // SAFETY: count is a writable output for this action collection.
    unsafe { actions.Count(&mut count) }.map_err(windows_error)?;
    if count != 1 {
        return Ok(None);
    }
    // SAFETY: the sole action has one-based index 1.
    let action = unsafe { actions.get_Item(1) }.map_err(windows_error)?;
    let mut kind = TASK_ACTION_TYPE::default();
    // SAFETY: kind is a writable output for this action.
    unsafe { action.Type(&mut kind) }.map_err(windows_error)?;
    if kind != TASK_ACTION_EXEC {
        return Ok(None);
    }
    let executable: IExecAction = action.cast().map_err(windows_error)?;
    let mut program = BSTR::new();
    // SAFETY: program is an empty BSTR output initialized by this getter.
    unsafe { executable.Path(&mut program) }.map_err(windows_error)?;
    if program.contains(&u16::from(b'%')) {
        // Expansion can differ under the task principal, so use literal paths only.
        return Ok(None);
    }
    let program = OsString::from_wide(&program);
    let program = Path::new(&program);
    if !program.is_absolute() {
        return Ok(None);
    }
    let Some(image) = registered_image(program, scope)? else {
        return Ok(None);
    };
    Ok(Some(Proposal {
        target: Target::Reference(format!("Scheduled task {path} — {}", image.path.display())),
        category: Category::ScheduledTask,
        evidence: image.evidence,
        reason: image.reason("the task's sole executable is in the verified application directory"),
        risk: Risk::High,
        access: Access::ReadOnly("task configuration and restore are not implemented".into()),
    }))
}

fn scheduler_path(path: BSTR) -> io::Result<Option<String>> {
    let path = String::try_from(path).map_err(io::Error::other)?;
    let Some(relative) = path.strip_prefix('\\') else {
        return Ok(None);
    };
    if relative.split('\\').any(|part| {
        part.is_empty() || matches!(part, "." | "..") || part.chars().any(char::is_control)
    }) {
        return Ok(None);
    }
    let reserved = relative.split('\\').next().is_some_and(|part| {
        part.eq_ignore_ascii_case("Microsoft") || part.eq_ignore_ascii_case("Windows")
    });
    Ok((!reserved).then_some(path))
}

fn windows_error(error: windows::core::Error) -> io::Error {
    io::Error::other(format!("Task Scheduler returned {}", error.code()))
}
