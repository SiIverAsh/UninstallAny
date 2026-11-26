# UninstallAny 第一阶段架构设计

Windows 10 和 11 优先实现。Rust 核心库负责生成清理计划、执行安全检查、隔离和还原。
桌面端采用 egui/eframe，通过独立 Rust 核心调用平台后端。
官方卸载和残留清理各有一次明确确认。清理默认为 dry-run，确认后也只能执行计划中已审查且仍符合安全条件的对象。

## 技术选型

| 维度 | Tauri | egui/eframe |
| --- | --- | --- |
| 发布体积与离线安装 | 系统已有 WebView 时应用包可以很小。对缺 WebView2 的 Windows，Tauri 文档估计捆绑离线安装器增加约 127 MB，固定运行时增加约 180 MB，下载式安装需要网络。 | 原生渲染，无 WebView 运行时。二进制大小取决于渲染器、字体及依赖，仍依赖目标系统的图形驱动及相应系统库。 |
| 跨平台 | Windows 使用 WebView2，macOS 使用 WKWebView，Linux 使用 WebKitGTK。网页渲染与运行时随系统变化。 | Windows、macOS、Linux 共用 Rust UI。渲染器兼容、中文输入与字体回退、键盘导航和辅助功能需逐平台验证。 |
| 开发与维护 | Web 生态可复用表格与国际化组件，需要维护前端构建、Rust 命令接口和 IPC 边界。 | 共用 Cargo 工具链，集成路径较短。长表虚拟化、排序、复选和无障碍交互要在桌面端实现并验收。 |

先验证单一 `glow` 渲染器，避免同时打包两种渲染后端。
在 Windows 无 3D 加速虚拟机或远程桌面上验证 OpenGL 能力，若启动受阻，再实测单一 `wgpu` 配置的取舍。
阶段三用同一真实列表验证体积、内存和启动时间。框架文档提供依赖与分发信息，数值以实测为准。
[Tauri Windows 安装包](https://v2.tauri.app/distribute/windows-installer/) · [Tauri 进程模型](https://v2.tauri.app/concept/process-model/) · [eframe 功能选项](https://docs.rs/eframe/latest/eframe/#feature-flags) · [egui glow 渲染器源码](https://github.com/emilk/egui/blob/main/crates/egui_glow/src/painter.rs)

Rust 核心优先用标准库、`serde` 和 `tracing`。用 `windows` 绑定专用系统 API，`winreg` 可用于普通只读枚举，前提是能明确控制视图。
macOS 用 `plist` 读结构化元数据。文件枚举可用 `walkdir` 辅助非特权发现，路径授权和写入由原生句柄实现。
规则文件采用 TOML。首个 workspace 按实际阶段添加 crate 和依赖，工具链及 MSRV 在阶段二建立时锁定。

## 模块与接口

| 模块 | 职责 |
| --- | --- |
| `uninstallany-core` | 独立 library crate。定义应用、证据、计划、结果和日志事件，编排卸载队列、扫描、确认、守卫、隔离和还原。核心无 UI 依赖。 |
| `uninstallany-platform` | 按目标 OS 编译后端。实现平台信任根、对象身份与句柄、注册表视图、包管理适配器和平台权限判断。 |
| `uninstallany-helper` | 临时提权进程。复用核心安全策略和平台守卫，收窄到一项原生操作，返回可核对的结果。 |
| `uninstallany-gui` | 展示清单与结果、接收确认和取消。桌面端提供搜索、名称／大小／日期／发行商排序、批量选择及系统组件切换。缺失值单独显示，稳定排序。 |

以下名称是接口契约。实际 Rust 签名在阶段二依据平台句柄生命周期确定。

| 接口 | 输入与输出 | 权限边界 |
| --- | --- | --- |
| `PlatformBackend` | 枚举得到 `InventoryReport`，从应用记录构建 `UninstallIntent`，调用官方卸载得到 `UninstallOutcome`，在给定扫描根内返回证据与候选。 | 官方卸载入口消费已确认的具体意图。发现接口只读。支持取消和增量发送结果。 |
| `FileStore` | 从可信根打开并检查对象、枚举限定目录、比较对象身份、无覆盖地移动或还原隔离对象。 | 写入目标由后端解析为已校验的句柄操作。目录枚举器返回的字符串不能直接写入。 |
| `RegistryStore` | 显式视图的读、定向快照与 `.reg` 导出、有限键／值变更与还原。 | 仅 Windows 提供。读写按当前用户 SID、hive、逻辑视图及逐段键名定域，供核心单元测试替换为 fake。 |
| 平台专项适配器 | 启动项、服务、任务、防火墙、包管理器各返回有类型的身份、能力与结果。 | 没有已验证备份、还原语义或权限模型的操作仅供发现。 |
| 快照证据入口 | 后续的安装前后快照 diff 可提供 `Evidence`，用于生成同一种候选。 | 快照、右键入口和启动项管理仍走核心计划、守卫及确认流程。 |

文件和注册表测试可注入模拟错误。核心也注入时钟与操作日志存储，以便验证保留期、确认失效和崩溃恢复。
所有作业使用有限的后台工作线程，分批返回结果。目录、记录和任务边界检查取消令牌，取消停止排队或扫描，不强杀已运行的官方卸载器，也不截断正在提交的一项变更。
桌面端后台持有核心会话和未执行的计划，视图只收到预览数据。
界面的确认绑定在该会话中生成的具体计划，执行和还原仍由核心验证。

## 数据结构

| 类型 | 关键字段与约束 |
| --- | --- |
| `AppRecord` / `AppId` | 平台、来源、范围（当前用户 SID/UID、系统、包安装实例）和原生标识构成稳定身份。名称、版本、发行商、位置、大小、日期可缺失并记录来源。保留安装类型、系统组件标记和卸载能力。 |
| `UninstallIntent` / `UninstallOutcome` | 精确 `AppId`、适配器、命令或原生操作、作用范围、预期权限及提示。结果区分成功、待重启、取消、失败和完成状态不明。 |
| `Target` | 类型化地址。文件含可信根与相对组件、卷与对象身份，注册表含 hive、视图、键与可选值名，服务／任务／包使用原生标识。显示文本不能当地址回传。 |
| `Candidate` | 稳定候选 ID、目标、应用身份、证据及来源、置信度、风险等级、共享检查、守卫状态和可读原因。 |
| `CleanupPlan` | 不可变计划 ID、摘要、用户与设备范围、策略版本、候选快照和生成时间。确认绑定计划与选中 ID，任何内容变更或许可过期都要重新预览。 |
| `BackupRecord` / `AuditEvent` | 操作与候选 ID、原始身份、备份定位、完整性信息、状态、时间和错误。日志另含动作、结果、用户范围及可显示的原因。 |

文件路径用平台原生表示保存，避免显示转码造成身份碰撞。
结果的错误码与原因用于桌面界面的中英文消息。每项 I/O 失败要提供对象、操作和可采取的动作。

## 卸载、清理与还原流程

```text
枚举应用 → 预览官方卸载意图 → 用户确认 → 运行官方卸载器
  ├─ 确认成功，重查应用状态 → 自动只读扫描
  ├─ 待重启或完成状态不明 → 记录，暂停自动清理并提示复核
  └─ 失败、缺失或取消 → 报告，可另行预览扫描或强制移除

便携目录 / 手动扫描 → 只读扫描 → 证据匹配 → 安全守卫 → dry-run 清单
  → 选择候选 → 确认本次精确计划 → 按项复验 → 隔离或备份后变更 → 结果报告
  → 选择批次还原 → 预检冲突和权限 → 按项还原 → 还原报告
```

启动官方卸载器会修改系统。确认界面先显示应用、卸载方式、权限请求和其原生操作范围，说明隔离区只能还原本工具处理的残留。
强制移除单独确认，仅清理可验证归属的残留及精确的第三方 `Uninstall` 叶键，展示程序或包仍可能已安装。
同一批次的官方卸载串行，每个应用各自记录、重查与生成计划。某项失败继续下一个，取消停止后续调度。
重叠目标合并展示。跨应用所有权无法排除时按共享项保留。

dry-run 允许读取、生成计划以及向工具自己的状态目录写入审计事件，禁止启动卸载器、发起提权、写目标或生成真实目标备份。
所有写入口在核心与后端校验确认状态。确认只授权当前用户、当前设备和具体目标，不能向计划外扩张。
写前重新定位并核对目标、上级、范围、归属和守卫。目标改变、身份缺失、权限不足或无法可靠备份时标明原因并跳过。

## 安全守卫

### 文件与目录

1. 由系统 API 解析已知目录、用户重定向目录和本地卷。扫描根是发现范围，只有应用专属且通过策略的子项可能进入执行清单。
2. 在解析前拒绝原始路径中的 `..`、相对路径、设备命名、网络路径和 Windows ADS 等不支持的形式。从可信根持有的目录句柄逐段按 no-follow 语义打开，依据实际卷和对象身份确定规范位置和策略归属。
3. 任意中间组件是 symlink、junction、挂载点或未知重解析点即停止。末端若是受支持的链接类型，只在链接本身有独立归属证据时考虑隔离，绝不打开其目标。多硬链接、未知卷或身份不可靠的对象保留。
4. 守卫对规范位置及对象身份校验保护范围，按路径组件判断祖先与后代。Windows 动态保护 Windows 目录及 System32、系统管理的包目录、Program Files/ProgramData 根和公共目录。macOS 保护 `/System` 等系统树，Linux 保护 `/usr/bin`、系统库和其它系统根。各平台都保护卷根、用户家目录和桌面、文档、下载根、重定向后的实际位置，以及隔离区、日志目录和程序本身。桌面／开始菜单仅开放已核实归属的精确快捷方式。
5. 目录候选展开检查，识别应用专属文件、共享文件及无法归属的内容。不移动未经逐项审查的整棵目录。目录整体隔离依赖能够防止新增未授权子项被带走的原生条件和验证，条件缺失时仅隔离已审核的子项并保留目录。
6. 写时重用经过检查的对象与父目录身份，通过原生句柄移动，避免“先检查路径再按旧字符串操作”的竞态。Windows 候选方案是从父句柄使用 `NtCreateFile` 单组件打开并检查重解析点，再使用句柄与 `FILE_RENAME_INFO` 执行同卷、无覆盖重命名。祖先竞争、短路径、共享标志、目录竞争及原生句柄语义是阶段二验证门槛。

[Windows Known Folders](https://learn.microsoft.com/en-us/windows/win32/shell/known-folders) · [Windows 重解析点](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points-and-file-operations) · [NtCreateFile](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile) · [FILE_RENAME_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info) · [Linux 路径查找](https://docs.kernel.org/filesystems/path-lookup.html)

### 注册表与高风险对象

- 仅接受规范化的原生 hive、视图、用户与逐段键名。拒绝合并视图 `HKCR`、注册表符号链接、别名归属不明和无法验证的访问。黑名单覆盖 `HKLM\SYSTEM`、Microsoft/Windows 自带项、系统策略与共享注册表区域。UI 和规则库不能修改这条边界。
- 系统管理容器本身受保护。策略只为特定用途声明精确的第三方对象类型，例如已经核验的 `Uninstall` 叶键或 `Run` 的单个应用值。删除容器、递归删除、内置组件或所有权不明对象没有授权路径。
- 启动项、服务、计划任务、防火墙、文件关联、Shell 扩展、COM/CLSID 识别和执行能力独立。其中可能改变系统行为的项标为高风险，始终不预选。无法整项恢复的类别仅展示，服务与任务也不通过直接删底层注册表实现。
- 删除前从原 hive／视图读取精确对象，保存可读 `.reg` 与包含原始值类型、数据、目标身份及必要安全元数据的内部快照，并写入操作日志。单值导出只覆盖该值。阶段二验证类型和视图往返、叶键权限可恢复性、事务冲突语义及并发更改。备份、限制范围或冲突检测不能可靠实现时禁用对应写能力。
- 一键还原通过应用内部的原生接口回放本次备份，保留原有视图与用户范围。存在新版本或第三方修改时报告冲突，避免导入整个父键覆盖无关值。用户不能把任意导入的 `.reg` 或日志当成执行授权。

[Microsoft 注册表写入与删除](https://learn.microsoft.com/en-us/windows/win32/sysinfo/writing-and-deleting-registry-data) · [注册表符号链接](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/d5ce9dcc-1f90-4f5a-b076-cc1d2c9b4195) · [reg export](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg-export) · [注册表函数](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-functions)

### 隔离、日志与最小权限

- 每个支持写入的卷使用本工具控制的私有隔离区，机器级操作使用系统保护的位置。保留期默认 14 天，可配置。到期标记为可清理，永久清理隔离内容仍需确认。阶段二采用同卷移动，隔离目录无法安全建立或需要跨卷时保留源对象。
- 每项操作先持久化意图和备份信息，再变更，再记结果。文件在移动前记录源与唯一隔离位置的预期身份，同卷移动本身落入隔离区。注册表在删除前持久化备份并验证可读。写前记录或备份失败时保持目标原样，写后结果记录失败时标记待恢复并停止继续变更。
- 上次退出留下未完成操作时，启动后核对原对象、隔离对象和记录状态。只在身份与状态明确时补记结果或幂等恢复，冲突和不确定项留给用户复核。还原也检查当前父目录和身份，禁止覆盖新对象。必要时可先显示冲突并保留备份。
- 审计事件记录时间、对象、动作、结果、备份位置、权限及诊断码。备份和审计文件本地留存并限制访问，避免把注册表原始值及卸载参数中的敏感数据写入日志。阶段五提供用户触发的导出，明确路径和应用名称也可能含个人信息。
- 主程序以普通用户运行。需要权限时，由安装在受保护位置的独立 helper 接受一次结构化请求，向用户展示目标、具体动作和提权原因。helper 验证连接对端身份、登录会话、请求有效期和确认范围，并独立重跑同一守卫。Windows 采用限定本地登录会话与调用者的 IPC 权限。通过其他管理员凭据完成 UAC 时仍绑定发起者，避免误操作管理员自身的 `HKCU`。无法可靠绑定时跳过。
- helper 只执行编译期允许的原生操作。用户可写的规则、配置、日志和 IPC 数据不能扩大权限或充当提权授权。官方卸载器按系统正常机制处理自己的权限提示，helper 禁止代为执行任意命令。

[Windows 命名管道的安全与访问权限](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)

## 扫描与匹配

| 依据 | 置信度与范围 |
| --- | --- |
| 精确 Bundle ID、MSI ProductCode、包引用，或经后端核实归属的安装位置 | 高。位置必须与应用记录和实际身份一致。通用根、共享目录和缺乏归属证明的内容不能从父项继承高置信度。 |
| 独立验证的发行商与应用名均严格匹配 | 中，优先于仅名称匹配。 |
| 完整应用名按平台规则严格匹配 | 中，需用户选中。 |
| 模糊或仅弱证据 | 低，只作为候选，默认不选。 |

匹配前过滤过短与常见泛名作为名称证据，包括 `Common`、`Microsoft`、`Data`、`Update`。
共享目录默认保留。只有归属核查能排除其它应用、用户数据和未知子项时，才可考虑对目录整体生成可执行项。
置信度只描述归属证据，执行许可还取决于风险、路径与权限。只有高置信度、普通风险且已通过守卫的项目默认勾选。

内置与用户 TOML 规则共用有版本的声明式 schema，包含 `app_match`、`scope`、`root_id`、`relative_path` 和 `evidence`。
桌面端导入方式、字段说明与示例见 [自定义残留扫描规则](custom-rules.md)。
`root_id` 来自平台有限枚举。相对路径拒绝穿越、设备名和过宽模式。禁止命令、脚本、URL 和动态加载。
用户规则只能补充证据或缩小范围，经验证的后端证据决定置信度，守卫决定能否执行。

## 平台后端

### Windows

- 对 HKLM、HKCU 的逻辑 `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` 查询适用的 32 位与 64 位视图，通过视图标志访问 WOW64 数据，去重共享视图并保留实际来源。读取 `DisplayName`、`DisplayVersion`、`Publisher`、`InstallLocation`、`UninstallString`、`QuietUninstallString`、`EstimatedSize`、`InstallDate`。MSI 日期可能反映最近维护日期。识别 `WindowsInstaller=1` 与 `SystemComponent=1`，系统组件默认隐藏。
- MSI 用已核验 ProductCode 和安装上下文调用系统 `msiexec /x`，设置禁止自动重启，按模式选择静默和解释返回码。Win32 首选可验证的 `QuietUninstallString`，否则审查普通命令，显式指定本地可执行文件并保持参数语义。拒绝有歧义的未引用路径、shell／解释器链、PATH 搜索或不能证明来源的命令。包管理、脚本包装器、异步启动器的完成语义需要适配并实测。无法判断子进程状态时返回待复核。
- 当前用户的 UWP/MSIX 用 Windows `PackageManager` 枚举并按完整包名卸载，通过系统 API 处理，系统包、预配包或来源不明的包单独标记。WindowsApps 目录属于受保护范围。
- 便携版由用户指定目录并预览。按授权范围发现 Program Files、Program Files (x86)、ProgramData、AppData、LocalAppData、Temp、开始菜单与桌面中的候选。注册表发现覆盖应用专属 `Software` 键、App Paths、Run/RunOnce，并按能力扩展至服务、任务、防火墙、文件关联、Shell 扩展与 COM/CLSID。系统路径从已知目录 API 等原生机制获取。快捷方式仅解析和核对目标，不执行。

[注册表备用视图](https://learn.microsoft.com/en-us/windows/win32/winprog64/accessing-an-alternate-registry-view) · [MSI 卸载注册表字段](https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key) · [MSI 命令行](https://learn.microsoft.com/en-us/windows/win32/msi/standard-installer-command-line-options) · [MSI 退出码](https://learn.microsoft.com/en-us/windows/win32/msi/error-codes) · [CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw) · [PackageManager](https://learn.microsoft.com/en-us/uwp/api/windows.management.deployment.packagemanager)

### macOS

- 发现 `/Applications` 与 `~/Applications` 的 `.app`，取 `Info.plist` 的 Bundle ID。读取 `pkgutil` receipts 与 Homebrew cask 元数据，标记共享文件、关联来源和重复应用。先使用可验证的厂商卸载器或 cask 的常规卸载，具有完整归属的手动安装 `.app` 可走隔离计划。
- receipts 用于归属与发现。`pkgutil --forget` 只处理收据，不能代替卸载。Homebrew 默认避开可能涉及共享文件的 `--zap`。确认授权后才扫描映射到用户与系统 Library 的 Application Support、Caches、Preferences、Logs、Containers、Group Containers、Saved Application State、LaunchAgents 和 LaunchDaemons。共享容器及 launchd 条目需要可验证归属与恢复语义。

[Apple Bundle ID](https://developer.apple.com/documentation/bundleresources/information-property-list/cfbundleidentifier) · [Apple 卸载应用](https://support.apple.com/en-ie/102610) · [Homebrew cask zap](https://docs.brew.sh/Cask-Cookbook#stanza-zap)

### Linux

- 枚举 dpkg、rpm、pacman 的已安装包，以及 Flatpak、Snap。AppImage 从有限目录或手动选择发现。`.desktop` 仅用作只读元数据与归属线索。按包管理器、安装实例和原生包身份关联条目，包管理器所拥有的文件交由该管理器处理。
- 包卸载通过原生命令，使用具体包 ID 与安装范围。依赖或关联项随原生事务展示和确认，禁止默认级联清理、purge 或 autoremove。扫描 XDG 或系统配置指定的用户路径，以及有限的 `/etc`、`/opt`、systemd 和 autostart 路径，核对包归属、挂载边界与用户数据。
- Flatpak 默认卸载精确 ref 后扫描应用数据并隔离。`--delete-data` 还会删除权限存储中的记录。保留这个需求为单独选项，只有能通过精确 ref 限定范围、排除共享应用 ID、事先备份文件及权限并验证可还原时才开放。

[dpkg-query](https://manpages.debian.org/bookworm/dpkg/dpkg-query.1.en.html) · [RPM](https://rpm.org/docs/latest/man/rpm.8) · [pacman](https://man.archlinux.org/man/pacman.8.en) · [Flatpak uninstall](https://docs.flatpak.org/en/latest/flatpak-command-reference.html#flatpak-uninstall) · [Snap 数据快照](https://snapcraft.io/docs/how-to-guides/manage-snaps/create-data-snapshots/) · [Desktop Entry Specification](https://specifications.freedesktop.org/desktop-entry/latest-single/)

UninstallAny 的安装、启动、规则解析、扫描和清理在断网下可用。不加入遥测、广告、更新请求、远程规则加载、在线字体或第三方捆绑推广。
应用发起的官方卸载由各发行商或系统包管理器执行，确认界面说明外部程序的行为由其自身决定，断网可用性按适配器验证。

## 验收计划

### 核心单元测试

- 路径守卫覆盖 `..`、相似前缀、用户目录重定向、短名和大小写别名、根／祖先保护、链接末端与中间链接、挂载、硬链接及扫描后对象置换。
- 注册表 fake 覆盖系统黑名单、32/64 位同名键、链接、不同用户、单值 vs 父键、缺备份、快照冲突及还原失败。原生语义另在 Windows VM 验证。
- 匹配评分覆盖精确身份、发行商与应用名、严格名称、模糊、泛名和共享目录。同发行商两款应用、单个无主文件或不可读目录存在时，保持共享目录。
- dry-run 用 fake 验证目标写入、进程启动、提权和隔离均为零。变更计划、目标身份变化、过期确认、取消和模拟单项失败均有回归测试。
- 在备份前后、变更前后和结果写入前注入中断，复核源、隔离对象、审计记录、幂等恢复、空间不足与还原冲突。

### 手动虚拟机检查清单

| 步骤 | 操作与通过条件 |
| --- | --- |
| 1. 准备 | 建立 Windows 10/11 x64 干净快照。准备普通用户与独立管理员。安装一个 MSI、一个 Win32 EXE、同发行商双应用和可测的 MSIX，再放入便携样本并配置失效卸载项。覆盖 HKCU/HKLM、两种注册表视图及存在/缺失静默入口。 |
| 2. 枚举与预览 | 对照系统应用列表和注册表读数，检查系统组件默认隐藏、来源和字段语义。预置兄弟应用、受保护目录、正常数据与链接目标标记。执行 dry-run，核对快照确认目标无变化。 |
| 3. 官方卸载与队列 | 分别验证 MSI、EXE、MSIX 的正常行为和确认边界。模拟取消、待重启、缺失、命令异常及另一个作业的失败，检查队列继续且仅在确认成功后自动扫描。 |
| 4. 安全与权限 | 验证 junction、目标置换、名称过泛、共享目录、跨卷、锁文件、权限错误、UAC 拒绝及使用其它管理员身份的行为。检查标记、保护对象和隔离目标均符合预期。若无法证实某类安全语义，该类写入口保持关闭。 |
| 5. 还原与恢复 | 确认文件移动前已记录隔离意图，注册表删除前已有可读备份和日志。核对目标路径、视图、内容、元数据及标记。重复运行并验证冲突不覆盖、中断可恢复，过期批次仍遵守清理确认。 |
| 6. 平台扩展 | macOS 13+ 检查手动 `.app`、cask、pkg receipts、APFS 跨卷和 launchd 条目。Linux 覆盖 Ubuntu/Debian、Fedora、Arch，检查 Flatpak 用户／系统双安装、Snap、AppImage、XDG 路径和挂载边界。 |

### 离线和性能

- 每个平台与架构分别测量用户实际获取的完整正式发行件。统计 GUI、helper、字体及所有随包附带运行时，总大小目标 `< 15,000,000` 字节。关闭网络的新环境应能完成安装并启动。
- 每个基准环境至少执行 10 次独立冷启动。从 OS 创建进程到首帧显示且可操作，报告 p50 和 p95，验收目标 p95 `< 1 s`。应用首批枚举和完整枚举耗时分开报告。
- 等初次后台作业完成并稳定 30 秒后，采样 60 秒。内存包含整个应用进程树，记录平台对应的私有驻留内存或物理占用口径、典型值和峰值，空闲峰值目标 `< 60,000,000` 字节。
- 记录 OS 版本、架构、CPU、内存、图形配置、发行物和样本量。阶段三测 Windows 基线，阶段四复测 macOS 与 Linux，阶段五用实际发行包复验。

## 分阶段交付

| 阶段 | 交付与确认条件 |
| --- | --- |
| 一 | 架构、安全边界、流程、平台选型与验收方案。确认后进入阶段二。 |
| 二 | 建立 Rust workspace 和核心库，交付 Windows MVP、mock 单测及 Windows 验证。主路径覆盖 Win32/MSI 枚举、官方卸载、便携扫描、dry-run、隔离、注册表备份与还原。验证当前用户 MSIX 适配。精确启用已验证的能力，待验证的范围在阶段末单列。 |
| 三 | 接入 egui 桌面端，完成搜索、排序、批量队列、进度与取消、中英界面和 Windows 性能实测。 |
| 四 | 接入 macOS 与 Linux 后端，落实包管理适配、路径语义、隔离和多系统验收。 |
| 五 | 交付内置和自定义规则库文档、日志导出与离线打包。逐项验收尚未开放的 Windows 扩展能力，不把只读发现计为已支持清理。 |

### 已完成

模块与接口契约、目标数据模型、卸载与清理流程、安全守卫、框架对比、跨平台适配范围和测试方案已形成。

### 未完成

阶段一仅交付架构与验收方案。实现与验证状态以各阶段交付记录为准。

### 已知风险

Windows 文件与注册表竞态、特权 helper 的身份绑定、第三方卸载器实际完成条件、共享数据归属、无覆盖恢复语义及渲染器兼容均需实机验证。
只开放满足相应原生条件、备份条件和复验条件的实际写入口。

### 需要确认的决定

1. 阶段三采用 egui/eframe，先测 `glow`，按 Windows 实测选择单一渲染器。
2. 阶段二接受这些安全边界。隔离限同卷，不能安全移动的目录保留目录本身，隔离到期后由用户确认永久清理，高风险项在恢复能力验证前仅展示。
3. 阶段四默认保留 Flatpak 数据供隔离，`--delete-data` 待权限及文件备份都能完整恢复后再开放。
