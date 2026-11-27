use std::{
    io::{self, StdoutLock, Write},
    sync::mpsc::{self, RecvTimeoutError},
    thread,
    time::Duration,
};

use uninstallany_core::{Cancellation, ChangeReport, ChangeResult};

use crate::{CliResult, locale::Locale, visible};

pub(crate) struct Terminal {
    pub(crate) out: StdoutLock<'static>,
    cancel: Cancellation,
    locale: Locale,
}

impl Terminal {
    pub(crate) fn new(cancel: Cancellation, locale: Locale) -> Self {
        Self {
            out: io::stdout().lock(),
            cancel,
            locale,
        }
    }

    pub(crate) fn locale(&self) -> Locale {
        self.locale
    }

    pub(crate) fn prompt(&mut self, prompt: &str) -> io::Result<Option<String>> {
        self.check_cancelled()?;
        write!(self.out, "{prompt} ")?;
        self.out.flush()?;
        let (send, receive) = mpsc::sync_channel(1);
        // Console reads may restart after Ctrl+C. Keep the main thread cancellable.
        thread::Builder::new()
            .name("cli-input".into())
            .spawn(move || {
                let mut line = String::new();
                let result = io::stdin()
                    .read_line(&mut line)
                    .map(|size| (size != 0).then(|| line.trim().to_owned()));
                let _ = send.send(result);
            })?;
        loop {
            self.check_cancelled()?;
            match receive.recv_timeout(Duration::from_millis(100)) {
                Ok(answer) => {
                    self.check_cancelled()?;
                    return answer;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::other(
                        self.locale.text("input closed", "输入已关闭"),
                    ));
                }
            }
        }
    }

    pub(crate) fn confirm(&mut self, prompt: &str) -> io::Result<bool> {
        let choices = self.locale.text("[y/N]", "[y/是，回车选否]");
        let answer = self.prompt(&format!("{prompt} {choices}"))?;
        Ok(answer.is_some_and(|text| is_confirmation(self.locale, &text)))
    }

    fn check_cancelled(&self) -> io::Result<()> {
        self.cancel
            .check()
            .map_err(|error| io::Error::new(io::ErrorKind::Interrupted, error))
    }
}

fn is_confirmation(locale: Locale, answer: &str) -> bool {
    answer.eq_ignore_ascii_case("y")
        || answer.eq_ignore_ascii_case("yes")
        || (locale == Locale::Chinese && answer == "是")
}

pub(crate) fn warnings(terminal: &mut Terminal, messages: &[String]) -> io::Result<()> {
    let label = terminal.locale().text("Warning:", "提示");
    for message in messages {
        writeln!(terminal.out, "{label} {}", visible(message))?;
    }
    Ok(())
}

pub(crate) fn report_changes(terminal: &mut Terminal, report: &ChangeReport) -> CliResult<()> {
    let locale = terminal.locale();
    let mut incomplete = false;
    writeln!(
        terminal.out,
        "{} {}",
        locale.text("Batch:", "批次"),
        report.batch_id
    )?;
    for item in &report.items {
        let target = visible(&item.target);
        let (label, reason) = match &item.result {
            ChangeResult::Applied => (locale.text("Cleaned:", "已清理"), None),
            ChangeResult::Restored => (locale.text("Restored:", "已还原"), None),
            ChangeResult::Purged => (locale.text("Purged:", "已清除"), None),
            ChangeResult::Skipped(reason) => (locale.text("Skipped:", "已跳过"), Some(reason)),
            ChangeResult::NeedsReview(reason) => {
                (locale.text("Needs review:", "待复核"), Some(reason))
            }
        };
        if let Some(reason) = reason {
            incomplete = true;
            writeln!(terminal.out, "{label} {target} ({})", visible(reason))?;
        } else {
            writeln!(terminal.out, "{label} {target}")?;
        }
    }
    if incomplete {
        return Err(locale
            .text(
                "Some items were skipped or need review. See the results above.",
                "部分项目已跳过或需要复核，请查看上面的结果。",
            )
            .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chinese_confirmation_keeps_the_default_negative() {
        assert!(is_confirmation(Locale::Chinese, "是"));
        assert!(is_confirmation(Locale::Chinese, "yes"));
        assert!(!is_confirmation(Locale::Chinese, ""));
        assert!(!is_confirmation(Locale::Chinese, "否"));
        assert!(!is_confirmation(Locale::English, "是"));
    }
}
