# Tauri 桌面宿主

## macOS

`uninstallany-macos-host` 将现有 Web 前端接到 Rust 核心和 macOS 后端。
桌面端从同一个本地窗口处理应用列表、卸载确认、自动残留扫描和可选清理。
当前支持有已验证厂商卸载器的应用，以及通过隔离守卫的独立应用包。

卸载完成并经后端核实后，自动扫描残留。
发现候选项时显示清理预览，用户可选中项目并确认清理，也可关闭预览直接结束。
没有候选项时直接显示卸载结果，并保留扫描诊断。
清理只接受当前会话中预览的编号和用户选中的候选项，执行前重新验证并将文件移入可还原的隔离区。
清理开始前，选择无效、取消或已记录的复核读取错误可在原清单仍有效时重新确认。
重新确认会再次检查目标和归属。
需要撤销时，可从已有的隔离区界面预览并确认还原。
设置页可将本地操作日志导出到用户自有目录内一个新的 `.jsonl` 绝对路径，已有文件会保留。
隔离保留期默认 14 天，可通过现有设置页保存为 1 至 65,535 天。
修改后的天数用于新备份，已有备份沿用记录中的到期时间。
更改天数后，待确认的卸载需重新生成预览，已生成的残留清单仍可确认清理。
到期备份仍保留在隔离区，用户可以单独预览、勾选并确认永久清理。
部分删除或结果待复核时，界面会显示实际数量，审计记录保留逐项结果。

读取偏好失败时，应用列表会说明原因并停用新的卸载和清理。
刷新列表会重试读取偏好。
备份与审计记录可用时，隔离区仍可核验及还原已有备份。

本入口使用普通权限。
Homebrew cask 和仅有 Installer 安装收据的条目仍可识别。
这两种来源暂未开放通用卸载。
设置页可保存自定义 TOML 规则。规则作为之后扫描中的只读线索。[规则写法](../../docs/custom-rules.md)

签名构建可启用 `--features macos-privileged-helper`，接入系统级独立应用的隔离和还原。
该功能要求签名应用及同一 Developer ID 团队签名的助手、正确的启动描述文件，以及已注册并获批的系统服务。
卸载和还原各自需要用户确认及系统授权。
普通开发构建使用本地隔离流程，系统隔离只接受通过路径和应用归属守卫的目标。

从仓库根目录启动需要 Rust 1.90+ 和已构建的 `frontend/dist`。

```sh
cargo run --locked --manifest-path apps/macos-host/Cargo.toml
```

### 签名助手的首次启用

启用签名助手的构建提供两个独立的 Tauri 命令，供前端的专用确认入口接入。
现有卸载弹窗只处理卸载，当前 Web 前端还没有接入启用确认。

1. `review_system_helper_activation` 接收 `{ appId }`，返回 `ticket`、所选应用和启用说明。
   只有自身符合本地守卫、需要助手且助手尚未注册的目标可以生成预览。
2. 在明确的启用确认后，`run_system_helper_activation` 接收 `{ ticket }` 并消耗票据。
   返回的 `status` 区分 `enabled`、`requires_approval`、`not_registered` 和 `not_found`。
   若写入结果审计失败，`audit_warning` 保留该诊断。
3. 需要管理员批准时，等待 macOS 系统设置中的批准。
   刷新应用列表后，重新预览并确认所选应用的卸载。

启用记录与卸载记录独立。
启用只提交 Service Management 注册请求，应用仍留在原路径。

## Windows

Windows 宿主使用同一个 Web 前端，连接原生 Windows 后端。
应用列表覆盖注册表登记的传统应用和当前用户的 MSIX 应用。
确认后逐项调用已核验的 Win32、MSI 或 MSIX 原生卸载入口。
核实原安装登记或包已消失后，桌面端会展示残留清单。
取消后停止调度新操作。已经启动的原生卸载继续由 Windows 等待完成，随后跳过残留扫描。
用户再次确认后，文件会移入隔离区，受支持的注册表项会先备份再清理。
隔离区可预览并确认文件和注册表备份的还原。

### 开发前置条件

使用 Rust 1.90 或更新版本的 MSVC 工具链，例如 x64 的 `x86_64-pc-windows-msvc`。
Microsoft C++ Build Tools 需启用「使用 C++ 的桌面开发」，系统需提供 Microsoft Edge WebView2 Runtime。
[Tauri Windows 前置条件](https://v2.tauri.app/start/prerequisites/#windows) · [Tauri Rust 工具链说明](https://v2.tauri.app/start/prerequisites/#rust)

前端构建可沿用项目 CI 使用的 Node.js 24 和 pnpm 12.16.1。
从仓库根目录用普通权限终端执行以下命令，使用 Cargo 默认输出目录。

```powershell
pnpm --dir frontend install --frozen-lockfile
pnpm --dir frontend build
cargo build --locked --release --manifest-path apps/macos-host/Cargo.toml --bin uninstallany-desktop
.\apps\macos-host\target\release\uninstallany-desktop.exe
```

### 提权边界

桌面宿主以普通用户权限运行。
原生卸载明确需要管理员权限时，独立助手只处理受支持的机器级 MSI，并要求单次确认。
后端核对桌面端和助手的固定安装路径、访问权限和进程身份。
普通开发产物 `uninstallany-desktop.exe` 和便携 ZIP 使用无需助手的卸载路径。
服务、计划任务、防火墙规则、文件关联、COM 和 Shell 扩展保持高风险、只读。

### Windows x64 MSI 预览安装包

在本地可用 `scripts/package_windows_installer.py --unsigned-preview` 将预构建桌面程序、助手和 WebView2 加载器封装为专用 VM 验收的未签名 MSI。
它由 Windows Installer 执行每机安装，把 `UninstallAny.exe`、`UninstallAnyHelper.exe` 和 `WebView2Loader.dll` 放入固定的 `ProgramFiles64Folder\UninstallAny`，并为安装目录和文件设置显式 ACL。
安装完成后由用户以普通权限启动桌面端，桌面端仅在需要调用助手时请求 UAC。
Windows「设置 → 应用」负责卸载 UninstallAny 自身的 MSI，用户数据保留。
离线使用前须为目标系统准备 x64 WebView2 Runtime，MSI 不下载运行时。[Microsoft WebView2 离线部署](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/distribution#offline-deployment)

公开发行须签名并核验两个 EXE 和最终 MSI。原生 Windows 构建、安装、卸载和助手 UAC 仍待实机验证。[Windows MSI 预览打包和验收步骤](../../docs/windows-mvp-verification.md#windows-x64-msi-预览安装包) · [Microsoft SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool)
