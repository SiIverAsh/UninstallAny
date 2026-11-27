use std::{collections::BTreeMap, io::Write};

use uninstallany_core::{Cancellation, Engine, Journal, PlatformBackend, RecoveryState};
use uuid::Uuid;

use crate::{CliResult, Terminal, report_changes, visible, warnings};

struct Batch {
    first_target: String,
    recoverable: usize,
    pending: usize,
}

/// Lists local backup batches or restores one explicitly reviewed batch.
pub(crate) fn restore<P: PlatformBackend, J: Journal>(
    engine: &Engine<P, J>,
    batch: Option<Uuid>,
    terminal: &mut Terminal,
    cancel: &Cancellation,
) -> CliResult<()> {
    cancel.check()?;
    let Some(batch) = batch else {
        list_batches(engine, terminal, cancel)?;
        #[cfg(target_os = "linux")]
        show_snap_snapshots(terminal, cancel)?;
        return Ok(());
    };

    let plan = engine.prepare_restore(batch)?;
    cancel.check()?;
    warnings(terminal, plan.warnings())?;
    let locale = terminal.locale();
    if plan.entries().len() == 0 {
        let label = locale.text("Batch", "批次");
        let description = locale.text("has no recoverable objects.", "没有可还原的项目。");
        return Err(format!("{label} {batch} {description}").into());
    }

    let heading = locale.text("Restore batch", "还原批次");
    writeln!(terminal.out, "{heading} {batch}")?;
    for entry in plan.entries() {
        writeln!(terminal.out, "  {}", visible(&entry.target))?;
    }
    if !terminal.confirm(locale.text("Restore these objects?", "要还原这些项目吗？"))? {
        writeln!(
            terminal.out,
            "{}",
            locale.text("Restore cancelled.", "已取消还原。")
        )?;
        return Ok(());
    }

    cancel.check()?;
    let report = engine.restore(plan.confirm()?, cancel)?;
    report_changes(terminal, &report)
}

#[cfg(target_os = "linux")]
fn show_snap_snapshots(terminal: &mut Terminal, cancel: &Cancellation) -> CliResult<()> {
    let locale = terminal.locale();
    let history = match uninstallany_linux::snap_snapshot_history(cancel) {
        Ok(history) => history,
        Err(error @ uninstallany_core::Error::Cancelled) => return Err(error.into()),
        Err(error) => {
            let description = locale.text(
                "Could not list recorded Snap snapshots:",
                "无法列出已记录的 Snap 快照：",
            );
            return warnings(terminal, &[format!("{description} {error}")]).map_err(Into::into);
        }
    };
    warnings(terminal, &history.warnings)?;
    if history.snapshots.is_empty() {
        return Ok(());
    }
    writeln!(
        terminal.out,
        "{}",
        locale.text("Recorded Snap data snapshots:", "已记录的 Snap 数据快照：")
    )?;
    let hint = locale.text("check with", "查看命令");
    for snapshot in history.snapshots {
        cancel.check()?;
        writeln!(
            terminal.out,
            "  {}  {}  ({hint} `snap saved --id={}`)",
            snapshot.set_id,
            visible(&snapshot.instance),
            snapshot.set_id,
        )?;
    }
    Ok(())
}

fn list_batches<P: PlatformBackend, J: Journal>(
    engine: &Engine<P, J>,
    terminal: &mut Terminal,
    cancel: &Cancellation,
) -> CliResult<()> {
    let inventory = engine.backups()?;
    cancel.check()?;
    warnings(terminal, &inventory.warnings)?;
    let locale = terminal.locale();

    let mut batches = BTreeMap::new();
    for item in inventory.items {
        let (recoverable, pending) = match item.state {
            RecoveryState::Applied => (1, 0),
            RecoveryState::Staged | RecoveryState::NeedsReview => (0, 1),
            RecoveryState::Restored | RecoveryState::Purged => continue,
        };
        let batch = batches.entry(item.batch_id).or_insert_with(|| Batch {
            first_target: item.target,
            recoverable: 0,
            pending: 0,
        });
        batch.recoverable += recoverable;
        batch.pending += pending;
    }

    if batches.is_empty() {
        writeln!(
            terminal.out,
            "{}",
            locale.text("No local backup batches.", "没有本地备份批次。")
        )?;
        return Ok(());
    }
    let recoverable = locale.text("recoverable", "项可还原");
    let pending = locale.text("pending", "项待处理");
    for (id, batch) in batches {
        writeln!(
            terminal.out,
            "{id}  {} {recoverable}, {} {pending}  {}",
            batch.recoverable,
            batch.pending,
            visible(&batch.first_target),
        )?;
    }
    Ok(())
}
