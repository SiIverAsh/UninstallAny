# 离线发行打包与验收

发行脚本使用 Python 3.11+、Rust 工具链和已有的 Cargo 依赖缓存。
从项目根目录执行，默认构建本机目标。
Cargo 的 `--offline --locked` 阻止联机获取依赖和修改锁文件。

```console
python3 scripts/package_release.py
```

Windows 上也可使用 `py -3 scripts/package_release.py`。
脚本把归档和 SHA-256 校验文件放入 `target/dist/UninstallAny-<版本>-<平台>-<架构>/`。
同一发布目录已存在时，可通过 `--output-dir` 选择新的输出目录。
脚本验证完整压缩归档，大小严格低于 15,000,000 字节时才生成正式输出。

## 目标和格式

| 平台 | Rust 目标 | 交付物 |
| --- | --- | --- |
| macOS 13+ | `aarch64-apple-darwin`、`x86_64-apple-darwin` | 含 `UninstallAny.app` 的 ZIP |
| Windows 10/11 x64 | `x86_64-pc-windows-msvc`、`x86_64-pc-windows-gnullvm` | 含图形子系统 `UninstallAny.exe` 的 ZIP |
| Linux GNU arm64/x64 | `aarch64-unknown-linux-gnu`、`x86_64-unknown-linux-gnu` | 含可执行文件 `uninstallany` 的 tar.gz |

打包工具接收可信的预编译发布二进制，并按指定目标核对架构和可执行格式。
macOS 打包需要在 macOS 上执行。默认制作供本地使用的临时签名应用包。
带系统级助手的发行包由发布者选择 Developer ID 签名。
[Apple 分发打包指南](https://developer.apple.com/documentation/xcode/packaging-mac-software-for-distribution)

### macOS 桌面预览包

macOS 默认从 `apps/macos-host` 构建 `uninstallany-desktop`，并嵌入已有的 `frontend/dist`。
打包沿用仓库里的资源路径和内容安全策略。需要打包已有发布二进制时，可显式传入 `--binary`。

```sh
python3 -B scripts/package_release.py --target aarch64-apple-darwin \
  --output-dir target/dist/macos-tauri-preview
```

该预览包含 Apple Silicon 的 `.app` 和 SHA-256 校验文件，使用本地临时签名。
预览提供普通权限的卸载、残留清理与还原。公开发行的 Developer ID 签名、公证和系统级助手需另行准备。

### macOS 系统级助手

为 macOS 目标提供 `--macos-signing-identity` 时，打包脚本启用 Tauri 宿主的 `macos-privileged-helper` 特性，从同一次 Cargo 构建取得桌面端和助手。
脚本为嵌套助手和外层应用分别做 Hardened Runtime 签名，再核对标识及 Developer ID 要求。
LaunchDaemon 配置随应用包封装，安装后通过 macOS 的 Service Management 注册。
如使用 `--binary`，需提供同一目标及同一构建的 `--macos-helper-binary`，并在构建桌面程序时启用 `macos-privileged-helper`。

```console
python3 scripts/package_release.py --target aarch64-apple-darwin \
  --macos-signing-identity "Developer ID Application: Publisher Name (TEAMID)" \
  --macos-notary-profile "uninstallany-release"
```

`--macos-notary-profile` 使用发布者已建立的 Keychain 公证配置。
启用后，脚本提交签名应用，将获准票据附加到 `.app`，重新归档并检查最终归档中的票据。
省略公证配置可生成签名 ZIP，公开发行前仍需完成公证。
签名时间戳和公证属于发行过程。应用功能在用户设备上使用本机数据和系统接口。
[Apple Developer ID 签名](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac/) · [Apple 公证流程](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)

默认本地归档使用固定的成员顺序、文件时间戳和权限。
Developer ID 安全时间戳和公证票据随实际发行生成，归档以配套的 SHA-256 文件为准。
目标系统提供图形驱动、字体和运行库。
归档包含桌面程序、平台元数据和使用说明。
Linux 的 glibc 兼容范围取决于实际链接环境，建议在最低目标发行版环境构建并验收。

### Windows x64 桌面预览包

Windows 默认从 `apps/macos-host` 构建 `uninstallany-desktop.exe`，并嵌入已有的 `frontend/dist`。
系统需预装 WebView2 Runtime。
MSVC 构建静态链接 WebView2 加载器，gnullvm 构建从本次 Cargo 输出取得配套的 x64 `WebView2Loader.dll` 并随 ZIP 交付。
解压时保留包内文件在同一目录，以普通用户启动后使用。
需要从现有二进制打包时可传入 `--binary`，并为动态链接的 Tauri 二进制显式传入 `--windows-loader`。
机器级 MSI 提权助手通过独立 MSI 安装包交付。[Windows MSI 打包与验收](windows-mvp-verification.md#windows-x64-msi-预览安装包)

## 发布包验收

1. 用生成的 `.sha256` 核对归档，解压后检查程序与可执行权限。
   macOS 可以通过 `codesign --verify --strict UninstallAny.app` 检查本地签名。
2. 在目标平台干净测试机断网启动，观察运行库、字体和显卡是否兼容。
   核对应用列表、残留预览、隔离与还原流程。
3. 按[架构文档的离线和性能方案](architecture.md#离线和性能)记录冷启动、空闲内存和下载包大小。
   Windows 和 Linux 的交叉检查结果不能替代目标平台的打包和运行验收。

打包工具回归测试使用 Python 标准库。

```console
python3 -B -m unittest discover -s scripts -p 'test_*.py'
```
