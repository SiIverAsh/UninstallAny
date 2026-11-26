# 自定义残留扫描规则

在桌面端设置的「自定义规则」中粘贴 TOML 内容，再选择「保存规则」。
保存通过校验后，新的扫描会同时使用内置与自定义规则。
清空自定义规则文本并保存即可恢复为仅使用内置规则。
内容保存在本机的应用设置中。
规则解析与扫描可以离线执行。

## 示例

以下规则为 macOS 上精确匹配 Bundle ID 的应用检查一个特定缓存目录。

~~~toml
version = 1

[[rules]]
id = "example-editor-cache"
scope = "macos"
app_match = { kind = "macos_bundle", id = "org.example.Editor" }
root_id = "macos_caches"
relative_path = "Example Studio/EditorCache"
evidence = "示例编辑器使用的额外缓存位置。"
~~~

只展示实际找到、经过平台路径检查且尚未出现在普通扫描结果中的对象。
单独由规则发现的对象是低置信度、只读的线索。
普通扫描独立发现的同一对象沿用原有证据、风险与权限。
应用归属、保护路径与实际执行仍由平台守卫验证。

## 内置规则来源

- Chrome 和 Chromium 的缓存规则采用项目文档所述的默认缓存位置。[Chromium 用户目录说明](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md#user-cache-directory)
- Firefox 的规则使用 `org.mozilla.firefox`，检查默认用户资料和资料缓存目录。[Mozilla 用户资料说明](https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data) · [Firefox 目录实现](https://searchfox.org/firefox-main/source/toolkit/xre/nsXREDirProvider.cpp#1234)
- Visual Studio Code 的规则使用 `com.microsoft.VSCode`，检查默认的用户设置目录 `Code/User`。[Microsoft 应用标识](https://www.microsoft.com/de-de/techwiese/blog/visual-studio-code-02-installation.aspx) · [VS Code 设置目录说明](https://code.visualstudio.com/docs/configure/settings#_user-settingsjson-location)
- Zotero 的规则使用 `org.zotero.zotero`，检查默认资料目录 `Zotero/Profiles`。[Zotero 应用清单](https://raw.githubusercontent.com/zotero/zotero/main/app/mac/Contents/Info.plist) · [Zotero 资料目录说明](https://www.zotero.org/support/kb/profile_directory)

## 字段

| 字段 | 规则 |
| --- | --- |
| `version` | 当前版本为 `1`。 |
| `rules` | `[[rules]]` 条目数组。整个 UTF-8 文档最大 64 KiB，每份最多 128 条。 |
| `id` | 文档内唯一，最多 64 字节，使用小写英文字母、数字、连字符或下划线。 |
| `scope` | 平台，取 `windows`、`macos` 或 `linux`。 |
| `app_match` | 应用识别条件，见下表。 |
| `root_id` | 平台后端解析的当前用户根目录，见下表。必须与平台一致。 |
| `relative_path` | 单个字面相对路径，使用正斜杠逐段分隔。最多 12 段、共 384 字节。 |
| `evidence` | 说明这条规则指向该位置的原因。最多 320 字节。 |

绝对路径、空路径段、`.`、`..`、设备名、Windows 数据流、通配符和变量表达式会被拒绝。
未知字段、命令、脚本与 URL 也会使文档校验失败。

## 应用识别条件

| `kind` | 平台 | 字段 |
| --- | --- | --- |
| `windows_uninstall_code` | Windows | `code` 为卸载注册表键的完整 GUID。 |
| `windows_package` | Windows | `full_name` 为完整 MSIX 包名，含版本及体系结构。 |
| `macos_bundle` | macOS | `id` 为完整 Bundle ID，也可匹配已关联到应用包的 Homebrew cask。 |
| `linux_package` | Linux | `manager` 取 `dpkg`、`rpm`、`pacman`、`flatpak-user`、`flatpak-system` 或 `snap`。`id` 为该来源的完整标识。 |
| `publisher_and_name` | 任意 | `publisher` 与 `name` 都必须完整匹配，过短或过泛的名称会被拒绝。 |

Linux 标识示例包括 `vlc:amd64`（dpkg）、`vlc.x86_64=3.0.21-1.fc41`（RPM）、`chromium`（pacman）以及 `app/org.videolan.VLC/x86_64/stable`（Flatpak）。
Flatpak 的用户与系统安装采用不同的 `manager`。

## 允许的根目录

| `root_id` | 含义 |
| --- | --- |
| `windows_roaming_app_data` | Windows 当前用户漫游应用数据。 |
| `windows_local_app_data` | Windows 当前用户本地应用数据。 |
| `macos_application_support` | 当前用户的 `Library/Application Support`。 |
| `macos_caches` | 当前用户的 `Library/Caches`。 |
| `macos_preferences` | 当前用户的 `Library/Preferences`。 |
| `linux_config` | 当前用户的 XDG 配置目录。 |
| `linux_data` | 当前用户的 XDG 数据目录。 |
| `linux_cache` | 当前用户的 XDG 缓存目录。 |
