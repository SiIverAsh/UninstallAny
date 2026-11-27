# UninstallAny

**English** | [简体中文](README.zh-CN.md)

UninstallAny is a clean, offline, cross-platform app uninstaller and leftover cleaner built with Rust. It runs each app's official uninstaller first, finds leftover files and settings automatically, and puts cleaned items into a local quarantine so you can undo mistakes in one click.

---

## Features

### Manage All Your Apps in One Place
- **Cross-platform support**: Works across **Windows**, **macOS**, and **Linux**.
  - **Windows**: Traditional Win32 & MSI apps (32-bit and 64-bit), Microsoft Store (MSIX) apps, and portable app folders.
  - **macOS**: Standalone `.app` bundles, apps with vendor uninstallers, Homebrew casks, Apple Installer (`.pkg`) receipts, and portable `.app` bundles.
  - **Linux**: Flatpak (user & system), Snap, AppImage, portable folders, plus native `dpkg` (Debian/Ubuntu), `rpm` (Fedora), and `pacman` (Arch Linux) packages via optional system helpers.
- **Fast browsing & batch actions**: Search by name or publisher, sort by name, size, install date, or publisher, view app icons, toggle system components, and uninstall multiple apps in a queue.
- **Portable app scanning**: Point UninstallAny at any standalone app folder to review and clean it just like an installed app.

### Official Uninstall First, Clean Leftovers Second
- **Standard uninstall workflow**: Launches the app's official uninstaller or native package manager first, then automatically scans for leftover data.
- **Clear leftover breakdown**: Finds leftover files, folders, caches, preferences, logs, shortcuts, startup items, and Windows registry entries—displaying each item's category, match reason, confidence level, and risk level before you approve cleanup.
- **Force Removal (Windows)**: Clean up broken entries and leftover files when an app's official uninstaller is missing or fails to run.

### Quarantine & One-Click Restore
- **Safe local quarantine**: Cleaned files and folders are moved into a local quarantine (kept for 14 days by default, adjustable in Settings) instead of being permanently deleted right away.
- **Automatic backups**: Windows registry entries are exported as `.reg` backups before removal, and Snap removals automatically save a native `snapd` snapshot first.
- **Easy undo**: Restore any cleanup batch back to its original locations in one click without overwriting newer files. When quarantine backups expire, review and clear them on your own schedule.

### Custom Rules, Audit Logs & Flexible Interfaces
- **Custom TOML rules**: Ships with built-in rules for popular apps (such as Chrome/Chromium, Firefox, VS Code, and Zotero) and lets you add your own TOML rules in Settings. See [docs/custom-rules.md](docs/custom-rules.md).
- **Local audit log export**: Keeps a local history of uninstall, cleanup, and restore actions that can be exported to `.jsonl`.
- **Desktop GUI & CLI**: Use the desktop app (Tauri + React UI on macOS & Windows, native Rust `egui` UI across platforms including Linux) or the interactive CLI (`list`, `uninstall`, `restore`) on macOS & Linux. See [docs/cli.md](docs/cli.md).
- **Bilingual UI**: Switch between English and Simplified Chinese anytime.

---

## Key Advantages

- **Undoable by default**: Every uninstall and cleanup shows a clear preview first. Files go to quarantine and registry keys are backed up beforehand, so an accidental cleanup is never permanent.
- **Respects your system and personal files**: Automatically protects OS directories, personal folders (Documents, Desktop, Downloads, etc.), and shared files. High-risk items stay unchecked by default so you stay in control.
- **100% offline & zero clutter**: No telemetry, no ads, no background update nags, and no bundled software. Everything runs locally on your machine.
- **Fast and lightweight**: Built around a shared Rust core (`uninstallany-core` with zero `unsafe` code) and native platform APIs—compact release packages (under 15 MB), quick startup, and low memory use.
- **Least-privilege design**: Runs under your normal user account. Administrator approval is only requested on demand for the specific system action you confirm, through small isolated helpers.
- **Clean cross-platform architecture**: One shared core handles scanning rules, confirmation, quarantine, and restore across Windows, macOS, and Linux, keeping behavior consistent on every platform.

---

## How to Contribute

Contributions of all kinds are welcome—whether it's fixing a bug, adding leftover rules for a popular app, testing on your OS, improving the UI, or polishing docs.

### Ways to Help
- **Report issues & share real-world cases**: Let us know if an app isn't detected properly or leaves unusual leftovers on your system.
- **Add leftover rules**: Contribute clean, well-documented TOML rules for common apps (see [docs/custom-rules.md](docs/custom-rules.md)).
- **Improve code & UX**: Work on platform backends, desktop UI, CLI experience, translations, or test coverage.

### Repository Layout

| Path | Description |
| --- | --- |
| `crates/uninstallany-core` | Platform-independent engine, rules, confirmation, quarantine, and audit logic |
| `crates/uninstallany-windows` | Windows backend (Win32/MSI/MSIX, registry, shortcuts, optional MSI helper) |
| `crates/uninstallany-macos` | macOS backend (`.app` bundles, Homebrew casks, `.pkg` receipts, Library scan) |
| `crates/uninstallany-linux` | Linux backend (Flatpak, Snap, AppImage, `dpkg`, `rpm`, `pacman`) |
| `crates/uninstallany-unix` | Shared Unix filesystem, quarantine, and bundle-size helpers |
| `crates/uninstallany-gui` | Native Rust desktop GUI (`egui/eframe`) |
| `crates/uninstallany-cli` | Interactive terminal CLI for macOS & Linux |
| `apps/macos-host` | Tauri desktop host for macOS & Windows |
| `frontend/` | React + TypeScript + Tailwind CSS web UI for the Tauri desktop host |
| `packaging/` & `scripts/` | System package helpers (`dpkg`, `rpm`, `pacman`) and release packaging scripts |
| `docs/` | CLI guide, custom cleanup rules, and offline release packaging |

### Local Development Setup

**Prerequisites**
- **Rust**: `1.85+` for the main workspace (`1.90+` for `apps/macos-host`).
- **Node.js 24 & pnpm**: Required when working on `frontend/` or the Tauri desktop app.
- **Python 3.11+**: Required for running release packaging scripts and their tests.
- **Platform extras**:
  - **Linux (GUI)**: `libssl-dev`, `libwayland-dev`, `libxcb-render0-dev`, `libxcb-shape0-dev`, `libxcb-xfixes0-dev`, `libxkbcommon-dev`.
  - **Windows (Tauri desktop)**: MSVC C++ Build Tools and WebView2 Runtime.

**Build & Run**

```bash
# Run the native Rust desktop GUI (Windows / macOS / Linux)
cargo run --locked -p uninstallany-gui

# Run the CLI (macOS / Linux)
cargo run --locked -p uninstallany-cli -- list

# Build the web frontend and launch the Tauri desktop app (macOS / Windows)
pnpm --dir frontend install --frozen-lockfile
pnpm --dir frontend build
cargo run --locked --manifest-path apps/macos-host/Cargo.toml
```

**Run Checks Before Opening a PR**

```bash
# Format, lint, and test the Rust workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked

# If you touched the frontend or Tauri host
pnpm --dir frontend build
cargo test --locked --manifest-path apps/macos-host/Cargo.toml

# If you touched packaging scripts
python3 -B -m unittest discover -s scripts -p 'test_*.py'
```

### Submitting a Pull Request
1. Fork the repository and create a new branch from `main`.
2. Keep changes focused and well-tested. When testing real uninstall or cleanup behavior, use a disposable VM or snapshot rather than your daily machine.
3. Run the relevant formatting, lint, and test checks above.
4. Open a pull request explaining what changed, why, and how you tested it.

### Further Reading
- [CLI Guide](docs/cli.md)
- [Custom Cleanup Rules](docs/custom-rules.md)
- [Offline Release Packaging](docs/release-packaging.md)
