use std::{
    collections::HashSet,
    io::{self, Write},
    path::Path,
};

use uninstallany_core::{
    Access, AppId, AppRecord, Cancellation, Category, CleanupAttempt, CleanupPlan, Confidence,
    Engine, Error, Journal, MatchKind, OfficialOutcome, PlatformBackend, Risk,
};

use crate::{CliResult, Terminal, locale::Locale, report_changes, visible, warnings};

enum ApplicationSelection<'a> {
    Catalogued(&'a AppRecord),
    Portable(&'a Path),
    Cancelled,
}

pub(crate) fn list<P: PlatformBackend, J: Journal>(
    engine: &Engine<P, J>,
    filter: Option<&str>,
    terminal: &mut Terminal,
    cancel: &Cancellation,
) -> CliResult<()> {
    let locale = terminal.locale();
    let mut inventory = engine.inventory(false, cancel)?;
    warnings(terminal, &inventory.warnings)?;
    let filter = filter.map(str::to_lowercase);
    if let Some(filter) = filter {
        inventory.applications.retain(|app| {
            app.name.to_lowercase().contains(&filter)
                || native_package_id(app).is_some_and(|id| id.to_lowercase().contains(&filter))
        });
    }
    if inventory.applications.is_empty() {
        writeln!(
            terminal.out,
            "{}",
            locale.text(
                "No matching installed applications.",
                "未找到匹配的已安装应用。"
            )
        )?;
        return Ok(());
    }
    inventory
        .applications
        .sort_by_cached_key(|app| app.name.to_lowercase());
    for app in &inventory.applications {
        cancel.check()?;
        write_application(&mut terminal.out, app, locale)?;
    }
    Ok(())
}

pub(crate) fn uninstall<P: PlatformBackend, J: Journal>(
    engine: &Engine<P, J>,
    query: &str,
    terminal: &mut Terminal,
    cancel: &Cancellation,
) -> CliResult<()> {
    let locale = terminal.locale();
    let selected = locale.text("Selected application:", "选中的应用：");
    let cancelled = locale.text("Uninstall cancelled.", "已取消卸载。");
    let inventory = engine.inventory(false, cancel)?;
    warnings(terminal, &inventory.warnings)?;
    let app = match select_application(&inventory.applications, query, terminal, cancel)? {
        ApplicationSelection::Catalogued(app) => app,
        ApplicationSelection::Portable(path) => {
            let plan = engine.scan_portable(path, cancel)?;
            writeln!(
                terminal.out,
                "{} {}",
                locale.text("Portable application directory:", "便携应用目录："),
                visible(&path.to_string_lossy())
            )?;
            return cleanup(engine, plan, terminal, cancel);
        }
        ApplicationSelection::Cancelled => {
            writeln!(terminal.out, "{cancelled}")?;
            return Ok(());
        }
    };
    if !app.official_uninstall_available {
        writeln!(terminal.out, "{selected}")?;
        write_application(&mut terminal.out, app, locale)?;
        let preview = engine.inspect_residuals(&app.id, cancel)?;
        warnings(terminal, preview.warnings())?;
        show_leftovers(&preview, terminal)?;
        return Err(locale
            .text(
                "No supported uninstall is available for this application.",
                "此应用没有受支持的卸载方式。",
            )
            .into());
    }
    let prepared = engine.prepare_uninstall(&app.id, cancel)?;
    let reviewed_app = prepared.application();
    if reviewed_app.name != app.name
        || reviewed_app.version != app.version
        || reviewed_app.publisher != app.publisher
        || reviewed_app.install_location != app.install_location
    {
        return Err(locale
            .text(
                "The application changed. Review the installed applications again.",
                "应用信息已变化。请重新查看已安装应用。",
            )
            .into());
    }
    let intent = prepared.intent();
    writeln!(terminal.out, "{selected}")?;
    write_application(&mut terminal.out, reviewed_app, locale)?;
    writeln!(
        terminal.out,
        "{} {}",
        locale.text("Uninstall method:", "卸载方式："),
        visible(&intent.method)
    )?;
    if !intent.notice.is_empty() {
        writeln!(terminal.out, "{}", visible(&intent.notice))?;
    }
    if !terminal.confirm(locale.text("Start uninstall?", "开始卸载？"))? {
        writeln!(terminal.out, "{cancelled}")?;
        return Ok(());
    }

    let report = engine.run_uninstall(prepared.confirm()?, cancel)?;
    warnings(terminal, &report.warnings)?;
    if let Some(batch_id) = report.application_backup_batch {
        writeln!(
            terminal.out,
            "{} {batch_id}",
            locale.text("Application quarantine batch:", "应用隔离批次：")
        )?;
    }
    match report.outcome {
        OfficialOutcome::Completed => writeln!(
            terminal.out,
            "{}",
            locale.text("Uninstall complete.", "卸载完成。")
        )?,
        OfficialOutcome::NeedsRestart => {
            return Err(locale
                .text(
                    "Restart required to finish uninstalling.",
                    "重启后才能完成卸载。",
                )
                .into());
        }
        OfficialOutcome::Cancelled => return Err(Error::Cancelled.into()),
        OfficialOutcome::Failed(code) => {
            let message = match locale {
                Locale::English => format!("Uninstaller failed (exit code {code})."),
                Locale::Chinese => format!("卸载程序失败（退出码 {code}）。"),
            };
            return Err(message.into());
        }
        OfficialOutcome::Unverified(code) => {
            if let Some(preview) = report.cleanup {
                warnings(terminal, preview.warnings())?;
                show_leftovers(&preview, terminal)?;
            }
            let message = match locale {
                Locale::English => {
                    format!("Could not verify uninstall completion (exit code {code}).")
                }
                Locale::Chinese => format!("无法确认卸载是否完成（退出码 {code}）。"),
            };
            return Err(message.into());
        }
    }
    if let Some(plan) = report.cleanup {
        cleanup(engine, plan, terminal, cancel)?;
    }
    Ok(())
}

fn select_application<'a>(
    apps: &'a [AppRecord],
    query: &'a str,
    terminal: &mut Terminal,
    cancel: &Cancellation,
) -> CliResult<ApplicationSelection<'a>> {
    let locale = terminal.locale();
    let path = Path::new(query);
    let matches = matching_applications(apps, query);
    match matches.as_slice() {
        [] if path.is_absolute() => return Ok(ApplicationSelection::Portable(path)),
        [] => {
            return Err(locale
                .text(
                    "No exact application match. Use `uninstallany list` to find its name.",
                    "未找到完全匹配的应用。运行 `uninstallany list` 查看应用名称。",
                )
                .into());
        }
        [app] => return Ok(ApplicationSelection::Catalogued(app)),
        _ => {}
    }

    writeln!(
        terminal.out,
        "{}",
        locale.text("Multiple applications matched:", "找到多个匹配的应用：")
    )?;
    for (index, app) in matches.iter().enumerate() {
        write!(terminal.out, "{}. ", index + 1)?;
        write_application(&mut terminal.out, app, locale)?;
    }
    loop {
        cancel.check()?;
        let Some(input) = terminal.prompt(locale.text(
            "Application number [Enter to cancel]:",
            "输入应用编号，直接按回车取消：",
        ))?
        else {
            return Ok(ApplicationSelection::Cancelled);
        };
        if input.is_empty() {
            return Ok(ApplicationSelection::Cancelled);
        }
        if let Some(app) = displayed_index(&input).and_then(|index| matches.get(index)) {
            return Ok(ApplicationSelection::Catalogued(app));
        }
        writeln!(
            terminal.out,
            "{}",
            locale.text(
                "Choose a displayed application number.",
                "请选择列表中的应用编号。"
            )
        )?;
    }
}

fn matching_applications<'a>(apps: &'a [AppRecord], query: &str) -> Vec<&'a AppRecord> {
    let path = Path::new(query);
    if path.is_absolute() {
        return apps
            .iter()
            .filter(|app| app.install_location.as_deref() == Some(path))
            .collect();
    }
    let query_name = query.to_lowercase();
    apps.iter()
        .filter(|app| {
            app.name.to_lowercase() == query_name || native_package_id(app) == Some(query)
        })
        .collect()
}

fn write_application(out: &mut impl Write, app: &AppRecord, locale: Locale) -> io::Result<()> {
    write!(out, "{}", visible(&app.name))?;
    if let Some(id) = native_package_id(app) {
        write!(out, " | {}", visible(id))?;
    }
    for detail in [&app.version, &app.publisher].into_iter().flatten() {
        write!(out, " | {}", visible(detail))?;
    }
    if let Some(path) = &app.install_location {
        write!(out, " | {}", visible(&path.to_string_lossy()))?;
    }
    if !app.official_uninstall_available {
        write!(
            out,
            " | {}",
            locale.text("uninstall unavailable", "不支持卸载")
        )?;
    }
    writeln!(out)
}

fn native_package_id(app: &AppRecord) -> Option<&str> {
    match &app.id {
        AppId::Package { manager, id } if matches!(manager.as_str(), "dpkg" | "rpm") => Some(id),
        _ => None,
    }
}

fn cleanup<P: PlatformBackend, J: Journal>(
    engine: &Engine<P, J>,
    mut plan: CleanupPlan,
    terminal: &mut Terminal,
    cancel: &Cancellation,
) -> CliResult<()> {
    let locale = terminal.locale();
    loop {
        cancel.check()?;
        warnings(terminal, plan.warnings())?;
        show_leftovers(&plan, terminal)?;
        let Some(selected) = select_leftovers(&plan, terminal, cancel)? else {
            return Ok(());
        };
        let count = selected.len();
        let prompt = match locale {
            Locale::English => format!("Clean {count} selected item(s)?"),
            Locale::Chinese => format!("清理选中的 {count} 项残留？"),
        };
        if !terminal.confirm(&prompt)? {
            writeln!(
                terminal.out,
                "{}",
                locale.text("Residual cleanup skipped.", "已跳过残留清理。")
            )?;
            return Ok(());
        }
        match engine.apply_cleanup_preview(plan, &selected, cancel)? {
            CleanupAttempt::Reported(report) => return report_changes(terminal, &report),
            CleanupAttempt::RetryableBeforeApply {
                plan: returned,
                error,
            } => {
                if matches!(error, Error::Cancelled) {
                    return Err(error.into());
                }
                writeln!(
                    terminal.out,
                    "{} {}",
                    locale.text("Cleanup could not start:", "无法开始清理："),
                    visible(&error.to_string())
                )?;
                plan = *returned;
            }
        }
    }
}

fn show_leftovers(plan: &CleanupPlan, terminal: &mut Terminal) -> io::Result<()> {
    let locale = terminal.locale();
    if plan.candidates().next().is_none() {
        return writeln!(
            terminal.out,
            "{}",
            locale.text("No residual candidates found.", "未发现可能的残留。")
        );
    }
    writeln!(
        terminal.out,
        "{}",
        locale.text("Residual scan:", "残留扫描结果：")
    )?;
    for item in plan.candidates() {
        let selection = match &item.access {
            Access::Allowed if item.default_selected() => {
                locale.text("recommended", "推荐").to_owned()
            }
            Access::Allowed => locale.text("optional", "可选").to_owned(),
            Access::ReadOnly(reason) => format!(
                "{} {}",
                locale.text("read-only:", "只读："),
                visible(reason)
            ),
        };
        let risk = if item.risk == Risk::High {
            locale.text(", high risk", ", 高风险")
        } else {
            ""
        };
        writeln!(
            terminal.out,
            "{}. {} [{}, {}{risk}, {selection}]",
            item.id + 1,
            visible(&item.target.display()),
            category_label(item.category, locale),
            confidence_label(item.confidence, locale),
        )?;
        if locale == Locale::Chinese {
            let evidence = match item.evidence {
                MatchKind::ExactIdentity => "精确标识",
                MatchKind::PublisherAndApp => "发行商和应用名称匹配",
                MatchKind::AppName => "应用名称匹配",
                MatchKind::FuzzyName => "名称近似",
                MatchKind::RuleHint => "规则线索",
            };
            writeln!(terminal.out, "   匹配依据  {evidence}")?;
        }
        writeln!(terminal.out, "   {}", visible(&item.reason))?;
    }
    Ok(())
}

fn category_label(category: Category, locale: Locale) -> &'static str {
    let (english, chinese) = match category {
        Category::File => ("File", "文件"),
        Category::Directory => ("Directory", "目录"),
        Category::Shortcut => ("Shortcut", "快捷方式"),
        Category::Registry => ("Registry", "注册表"),
        Category::Startup => ("Startup", "启动项"),
        Category::Service => ("Service", "服务"),
        Category::ScheduledTask => ("Scheduled task", "计划任务"),
        Category::Firewall => ("Firewall", "防火墙"),
        Category::FileAssociation => ("File association", "文件关联"),
        Category::ShellExtension => ("Shell extension", "Shell 扩展"),
        Category::Com => ("COM", "COM"),
    };
    locale.text(english, chinese)
}

fn confidence_label(confidence: Confidence, locale: Locale) -> &'static str {
    let (english, chinese) = match confidence {
        Confidence::Low => ("Low confidence", "低置信度"),
        Confidence::Medium => ("Medium confidence", "中置信度"),
        Confidence::High => ("High confidence", "高置信度"),
    };
    locale.text(english, chinese)
}

fn select_leftovers(
    plan: &CleanupPlan,
    terminal: &mut Terminal,
    cancel: &Cancellation,
) -> CliResult<Option<Vec<usize>>> {
    let locale = terminal.locale();
    let writable: HashSet<_> = plan
        .candidates()
        .filter(|item| item.access == Access::Allowed)
        .map(|item| item.id)
        .collect();
    if writable.is_empty() {
        return Ok(None);
    }
    let recommended: Vec<_> = plan
        .candidates()
        .filter(|item| item.default_selected())
        .map(|item| item.id)
        .collect();
    loop {
        cancel.check()?;
        let Some(input) = terminal.prompt(locale.text(
            "Item numbers (1,3), r for recommended [Enter to skip]:",
            "输入编号（如 1,3），输入 r 或“推荐”选择推荐项，直接按回车跳过：",
        ))?
        else {
            return Ok(None);
        };
        if input.is_empty() {
            return Ok(None);
        }
        if input.eq_ignore_ascii_case("r") || (matches!(locale, Locale::Chinese) && input == "推荐")
        {
            if !recommended.is_empty() {
                return Ok(Some(recommended));
            }
            writeln!(
                terminal.out,
                "{}",
                locale.text(
                    "There are no recommended items. Choose item numbers.",
                    "没有推荐项。请选择要清理的编号。",
                )
            )?;
        } else if let Some(selected) = parse_item_numbers(&input)
            .filter(|selected| selected.iter().all(|id| writable.contains(id)))
        {
            return Ok(Some(selected));
        } else {
            writeln!(
                terminal.out,
                "{}",
                locale.text(
                    "Choose distinct numbers for writable items.",
                    "请选择可清理的项目，每个编号只能输入一次。",
                )
            )?;
        }
    }
}

fn displayed_index(text: &str) -> Option<usize> {
    text.trim().parse::<usize>().ok()?.checked_sub(1)
}

fn parse_item_numbers(input: &str) -> Option<Vec<usize>> {
    let mut seen = HashSet::new();
    input
        .split(',')
        .map(|part| displayed_index(part).filter(|id| seen.insert(*id)))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{AppId, AppRecord, matching_applications, parse_item_numbers};

    #[test]
    fn numbers_use_display_order_and_reject_invalid_selections() {
        assert_eq!(parse_item_numbers("1, 3"), Some(vec![0, 2]));
        for input in ["0", "1,1", "1,", "1,a"] {
            assert_eq!(parse_item_numbers(input), None, "{input}");
        }
    }

    #[test]
    fn absolute_selection_matches_install_location_even_if_another_app_uses_it_as_a_name() {
        let path = "/example/Tools/Editor";
        let item = |name: &str, install_location: Option<PathBuf>| AppRecord {
            id: AppId::Package {
                manager: "example".into(),
                id: name.into(),
            },
            name: name.into(),
            publisher: None,
            version: None,
            install_location,
            size_bytes: None,
            install_date: None,
            system_component: false,
            official_uninstall_available: true,
        };
        let apps = [item(path, None), item("Editor", Some(path.into()))];
        let matched: Vec<_> = matching_applications(&apps, path)
            .into_iter()
            .map(|app| app.name.as_str())
            .collect();
        assert_eq!(matched, ["Editor"]);
        assert!(matching_applications(&apps[..1], path).is_empty());
    }
}
