#![forbid(unsafe_code)]

mod locale;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod restore;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod terminal;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod uninstall;

use std::{env, error::Error, io, io::Write, process::ExitCode};

#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::io::IsTerminal;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use uninstallany_core::Cancellation;
use uuid::Uuid;

use crate::locale::Locale;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use crate::terminal::{Terminal, report_changes, warnings};

type CliResult<T> = Result<T, Box<dyn Error>>;

const USAGE_EN: &str = "\
Usage: uninstallany <command>

  list [search]       List installed apps, optionally by name
  uninstall <app>     Review uninstall and cleanup by name or absolute path
  restore [batch-id]  List backup batches or review and restore one batch
  --help              Show this help
  --version           Show the version";

const USAGE_ZH: &str = "\
用法  uninstallany <命令>

  list [关键词]      列出已安装的应用，可按名称筛选
  uninstall <应用>   按名称或绝对路径审阅卸载与清理
  restore [批次 ID]  列出备份，或审阅并还原指定批次
  --help             显示帮助
  --version          显示版本";

#[derive(Debug, PartialEq)]
enum Command<'a> {
    Help,
    Version,
    List(Option<&'a str>),
    Uninstall(&'a str),
    Restore(Option<Uuid>),
}

impl<'a> Command<'a> {
    fn parse(args: &'a [&'a str], locale: Locale) -> CliResult<Self> {
        match args {
            [] | ["--help" | "-h" | "help"] => Ok(Self::Help),
            ["--version" | "-V"] => Ok(Self::Version),
            ["list"] => Ok(Self::List(None)),
            ["list", search] if !search.trim().is_empty() => Ok(Self::List(Some(search.trim()))),
            ["uninstall", app] if !app.trim().is_empty() => Ok(Self::Uninstall(app)),
            ["restore"] => Ok(Self::Restore(None)),
            ["restore", batch] => Uuid::parse_str(batch)
                .map(|id| Self::Restore(Some(id)))
                .map_err(|_| {
                    locale
                        .text(
                            "Use the batch ID shown by `uninstallany restore`.",
                            "请输入 `uninstallany restore` 显示的批次 ID。",
                        )
                        .into()
                }),
            _ => Err(locale
                .text(
                    "Invalid command or arguments. Run `uninstallany --help`.",
                    "命令或参数无效。请运行 `uninstallany --help` 查看用法。",
                )
                .into()),
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn changes_system(&self) -> bool {
        matches!(self, Self::Uninstall(_) | Self::Restore(Some(_)))
    }
}

fn main() -> ExitCode {
    let locale = Locale::from_environment();
    let cancelled = locale.text("Cancelled.", "已取消。");
    match run(locale) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if let Some(error) = error.downcast_ref::<io::Error>() {
                if error.kind() == io::ErrorKind::BrokenPipe {
                    return ExitCode::SUCCESS;
                }
                if error.kind() == io::ErrorKind::Interrupted {
                    let _ = writeln!(io::stderr(), "{cancelled}");
                    return ExitCode::from(130);
                }
            }
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            if matches!(
                error.downcast_ref(),
                Some(uninstallany_core::Error::Cancelled)
            ) {
                let _ = writeln!(io::stderr(), "{cancelled}");
                return ExitCode::from(130);
            }
            let _ = writeln!(
                io::stderr(),
                "{} {}",
                locale.text("Error:", "错误"),
                visible(&error.to_string())
            );
            ExitCode::FAILURE
        }
    }
}

fn run(locale: Locale) -> CliResult<()> {
    let arguments = env::args_os()
        .skip(1)
        .map(|value| {
            value.into_string().map_err(|_| {
                locale.text(
                    "Arguments must be valid Unicode.",
                    "参数必须是有效的 Unicode 文本。",
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let arguments: Vec<_> = arguments.iter().map(String::as_str).collect();
    match Command::parse(&arguments, locale)? {
        Command::Help => writeln!(io::stdout(), "{}", locale.text(USAGE_EN, USAGE_ZH))?,
        Command::Version => writeln!(io::stdout(), "uninstallany {}", env!("CARGO_PKG_VERSION"))?,
        command => run_workflow(command, locale)?,
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run_workflow(command: Command<'_>, locale: Locale) -> CliResult<()> {
    if command.changes_system() && !(io::stdin().is_terminal() && io::stdout().is_terminal()) {
        return Err(locale
            .text(
                "Uninstall and restore require an interactive terminal for confirmation.",
                "卸载和还原需要在交互终端中确认。",
            )
            .into());
    }
    let cancel = Cancellation::default();
    let signal = cancel.clone();
    ctrlc::set_handler(move || signal.cancel())?;
    let mut terminal = Terminal::new(cancel.clone(), locale);

    #[cfg(target_os = "macos")]
    let mut engine = uninstallany_macos::open()?;
    #[cfg(target_os = "linux")]
    let mut engine = uninstallany_linux::open()?;
    if command.changes_system() {
        warnings(&mut terminal, &engine.restore_preferences()?.warnings)?;
    }

    match command {
        Command::List(filter) => uninstall::list(&engine, filter, &mut terminal, &cancel),
        Command::Uninstall(app) => uninstall::uninstall(&engine, app, &mut terminal, &cancel),
        Command::Restore(batch) => restore::restore(&engine, batch, &mut terminal, &cancel),
        Command::Help | Command::Version => Ok(()),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn run_workflow(_: Command<'_>, locale: Locale) -> CliResult<()> {
    Err(locale
        .text(
            "This CLI currently supports macOS and Linux.",
            "此命令行工具支持 macOS 和 Linux。",
        )
        .into())
}

// Native app metadata and diagnostics are untrusted terminal content.
fn visible(text: &str) -> String {
    text.chars()
        .map(|ch| {
            if ch.is_control() || matches!(ch, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
                '\u{fffd}'
            } else {
                ch
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_commands_and_rejects_unattended_uninstall() -> CliResult<()> {
        let locale = Locale::English;
        assert_eq!(
            Command::parse(&["list", "editor"], locale)?,
            Command::List(Some("editor"))
        );
        assert_eq!(
            Command::parse(&["restore"], locale)?,
            Command::Restore(None)
        );
        assert!(Command::parse(&["uninstall", "Editor", "--yes"], locale).is_err());
        assert!(Command::parse(&["restore", "unknown"], locale).is_err());
        Ok(())
    }

    #[test]
    fn native_text_cannot_emit_terminal_control_sequences() {
        assert_eq!(visible("应用\x1b[2J\n"), "应用�[2J�");
    }
}
