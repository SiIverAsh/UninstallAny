# UninstallAny

[English](README.md) | **简体中文**

UninstallAny 是一款用 Rust 编写的跨平台开源应用卸载与残留清理工具。它会先调用软件自带的官方卸载程序，再自动帮你找出残留的文件和配置；清理的内容会先放进本地隔离区，万一误删也能一键还原。

---

## 项目功能

### 统一管理各平台已安装应用
- **跨平台支持**：同时支持 **Windows**、**macOS** 和 **Linux**。
  - **Windows**：支持传统 Win32 / MSI 软件（涵盖 32 位和 64 位）、微软商店（MSIX）应用，以及绿色便携软件目录。
  - **macOS**：支持独立 `.app` 应用、自带厂商卸载器的软件、Homebrew Cask、Apple Installer（`.pkg`）安装记录，以及便携版 `.app`。
  - **Linux**：支持 Flatpak（用户级与系统级）、Snap、AppImage、便携目录，安装配套系统助手后还支持 Debian/Ubuntu（`dpkg`）、Fedora（`rpm`）和 Arch Linux（`pacman`）原生包。
- **高效浏览与批量操作**：支持按应用名或发行商搜索，按名称、占用大小、安装日期或发行商排序，显示应用图标，可按需切换显示系统组件，也支持多选后排队批量卸载。
- **绿色便携软件扫描**：直接指定某个便携软件的独立目录，就能像已安装软件一样预览并清理。

### 先走官方卸载，再清残留
- **标准两步流程**：先启动软件自身的卸载程序或系统包管理器，卸载完成后自动扫描遗留数据。
- **清晰的残留清单**：扫描残留文件、目录、缓存、偏好设置、日志、快捷方式、启动项和 Windows 注册表项。每条残留都会标明类别、匹配原因、置信度和风险等级，确认后再动手。
- **强制移除（Windows）**：当某些老旧软件的卸载程序丢失或失效时，可以直接使用强制移除来清理失效登记和残留文件。

### 隔离区备份与一键还原
- **本地隔离区**：清理文件和目录时不会直接彻底删除，而是移入本地隔离区（默认保留 14 天，可在设置中自由调整）。
- **自动备份**：清理 Windows 注册表项前会自动导出 `.reg` 备份；卸载 Linux Snap 应用前会自动创建原生快照。
- **随时一键反悔**：在隔离区按批次一键还原到原位置，且不会覆盖后来新建的同名文件。备份到期后，再由你手动确认彻底清除。

### 自定义规则、操作日志与多端形态
- **自定义 TOML 规则**：内置 Chrome/Chromium、Firefox、VS Code、Zotero 等常见软件规则，也支持在设置里粘贴自己的 TOML 规则扩展扫描范围，写法见 [docs/custom-rules.md](docs/custom-rules.md)。
- **操作日志导出**：自动记录卸载、清理和还原历史，可在设置里导出为结构化的 `.jsonl` 文件。
- **桌面端与命令行**：提供桌面界面（macOS 和 Windows 默认使用 Tauri + React 界面，全平台也提供原生 Rust `egui` 界面），同时为 macOS 和 Linux 提供交互式命令行工具（`list`、`uninstall`、`restore`），用法见 [docs/cli.md](docs/cli.md)。
- **中英双语界面**：内置简体中文与英文，随时切换。

---

## 项目优点

- **默认可反悔，不怕误删**：每一步都有清晰预览，文件进隔离区、注册表先备份，真删错了点一下就能恢复原样。
- **守住系统底线，不乱动个人文件**：自动保护系统核心目录、个人文件夹（桌面、文档、下载等）和共享文件；高风险项默认不勾选，决定权始终在你手里。
- **完全离线，干净无打扰**：不收集遥测数据、没有广告弹窗、不偷偷联网检查更新，也没有任何捆绑推广，断网也能正常使用。
- **轻量快速，原生体验**：核心引擎采用纯 Rust 编写（`uninstallany-core` 零 `unsafe` 代码）并直接对接系统原生接口，安装包精简（控制在 15 MB 以内），启动快、内存占用低。
- **最小权限运行**：日常以普通用户身份运行，只有卸载系统级软件时才通过独立的小型助手按需申请管理员授权，用完即止。
- **统一的跨平台架构**：Windows、macOS、Linux 共用同一套核心引擎，不管是桌面端还是命令行，扫描逻辑、确认流程和还原体验都保持一致。

---

## 如何贡献

欢迎任何形式的贡献——修复 Bug、补充常见软件的残留规则、在不同系统上实测反馈、优化界面交互或完善文档，都非常欢迎。

### 你可以帮上忙的地方
- **提交问题与反馈**：遇到未能识别的应用、奇怪的软件残留，或某个发行版上的兼容问题，欢迎提 Issue。
- **补充残留扫描规则**：为常用软件编写简洁准确的 TOML 规则（参考 [docs/custom-rules.md](docs/custom-rules.md)）。
- **参与代码与体验改进**：优化各平台后端、桌面端 UI、CLI 交互、多语言文案或补充自动化测试。

### 仓库结构

| 目录 | 说明 |
| --- | --- |
| `crates/uninstallany-core` | 跨平台核心引擎：规则解析、确认流程、隔离区与日志状态 |
| `crates/uninstallany-windows` | Windows 后端（Win32/MSI/MSIX、注册表、快捷方式、可选 MSI 助手） |
| `crates/uninstallany-macos` | macOS 后端（`.app`、Homebrew Cask、`.pkg` 收据、Library 扫描） |
| `crates/uninstallany-linux` | Linux 后端（Flatpak、Snap、AppImage、`dpkg`、`rpm`、`pacman`） |
| `crates/uninstallany-unix` | Unix 通用文件操作、隔离与目录体积计算 |
| `crates/uninstallany-gui` | 原生 Rust 桌面端（`egui/eframe`） |
| `crates/uninstallany-cli` | macOS / Linux 交互式命令行工具 |
| `apps/macos-host` | macOS 与 Windows 的 Tauri 桌面宿主 |
| `frontend/` | Tauri 桌面端使用的 React + TypeScript + Tailwind CSS 前端 |
| `packaging/` 与 `scripts/` | 系统包卸载助手（`dpkg`、`rpm`、`pacman`）及发行打包脚本 |
| `docs/` | 架构设计、CLI 说明、自定义规则、打包与测试文档 |

### 本地开发环境

**环境要求**
- **Rust**：主工作区需要 `1.85+`，Tauri 宿主（`apps/macos-host`）需要 `1.90+`。
- **Node.js 24 与 pnpm**：修改前端或构建 Tauri 桌面端时需要。
- **Python 3.11+**：运行发行打包脚本及其单元测试时需要。
- **平台额外依赖**：
  - **Linux（构建 GUI）**：`libssl-dev`、`libwayland-dev`、`libxcb-render0-dev`、`libxcb-shape0-dev`、`libxcb-xfixes0-dev`、`libxkbcommon-dev`。
  - **Windows（构建 Tauri 桌面端）**：MSVC C++ Build Tools 与 WebView2 Runtime。

**本地构建与运行**

```bash
# 运行原生 Rust 桌面端（Windows / macOS / Linux）
cargo run --locked -p uninstallany-gui

# 运行命令行工具（macOS / Linux）
cargo run --locked -p uninstallany-cli -- list

# 构建前端并运行 Tauri 桌面端（macOS / Windows）
pnpm --dir frontend install --frozen-lockfile
pnpm --dir frontend build
cargo run --locked --manifest-path apps/macos-host/Cargo.toml
```

**提交前本地检查**

```bash
# Rust 代码格式、静态检查与测试
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked

# 如果修改了前端或 Tauri 宿主
pnpm --dir frontend build
cargo test --locked --manifest-path apps/macos-host/Cargo.toml

# 如果修改了打包脚本
python3 -B -m unittest discover -s scripts -p 'test_*.py'
```

### 提交 Pull Request
1. Fork 本仓库，并从 `main` 创建新的开发分支。
2. 保持改动聚焦、附带必要的测试；如果涉及真实卸载或清理流程的实测，建议在可回滚的虚拟机快照中进行，避免影响日常主力机。
3. 在本地跑通上述格式、检查与测试命令。
4. 提交 PR，简要说明改动内容、原因以及你的验证方式。

### 更多文档
- [架构设计](docs/architecture.md)
- [命令行使用说明](docs/cli.md)
- [自定义残留扫描规则](docs/custom-rules.md)
- [离线发行打包说明](docs/release-packaging.md)
