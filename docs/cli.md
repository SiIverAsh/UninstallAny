# UninstallAny CLI

CLI 支持 macOS 和 Linux。
解压后，在普通用户的终端运行 `./uninstallany` 可查看用法。
界面语言按 `LC_ALL`、`LC_MESSAGES`、`LANG` 的顺序取第一个非空设置，`zh` 系列显示简体中文，其他语言环境显示英文。
两种界面使用同样的命令。中文界面也可输入 `是` 确认，并以中文显示匹配依据的类型。
后端提供的卸载方式、诊断和具体匹配说明保留原文。

```sh
./uninstallany list
./uninstallany list editor
./uninstallany uninstall "Example Editor"
./uninstallany restore
./uninstallany restore BATCH_ID
```

`list` 显示已装应用。`list` 后可加名称关键词。
`uninstall` 接收完整应用名称或绝对安装路径。遇到多个匹配时会要求选定具体应用。
Debian 包也可使用列表中的完整标识，例如 `./uninstallany uninstall example:amd64`。
先确认卸载方式。后端核实卸载完成后，会自动列出残留、置信度和依据。
用逗号分隔的编号选择清理项，也可输入 `r` 选择推荐项。中文界面也接受 `推荐`。直接按 Enter 保留残留。
清理前需再次确认，成功的隔离操作会显示批次 ID。
将 `.app` 或 AppImage 移入隔离区后，CLI 会立即显示应用备份批次。
随后确认清理的残留加入同一批次，`restore` 会先处理应用备份，再处理残留。
旧版本已生成的批次仍可分别还原。

对于未出现在清单中的便携应用，可传入其专属目录的绝对路径，例如 `./uninstallany uninstall "$HOME/Tools/Example Editor"`。
CLI 会使用平台守卫扫描该目录并展示清单。可以选择符合条件的项目并确认隔离，直接按 Enter 保留原状。
macOS 上也可指定独立便携 `.app` 的绝对路径。通过完整性和归属检查的应用包可作为一项进入隔离预览。

`restore` 显示本地隔离批次。
加上完整批次 ID 后会展示可恢复对象，并在完成单独确认后执行还原。
卸载和还原需要交互终端。Ctrl+C 请求取消，已经完成的变更会保留在结果和备份中。
发布商卸载程序可能继续运行，CLI 会保留无法核实的结果。

macOS 复用已核验的发布商卸载器和独立 `.app` 隔离流程。
符合条件的 Homebrew cask 可通过同一条 `uninstall` 命令卸载。
CLI 使用已安装的 Homebrew 运行时，复核本地收据和单个应用包，并限制原生卸载进程的写入范围与联网能力。
包含独立卸载脚本、安装器或其他实际卸载动作的 cask 只能查看残留预览。
原生卸载移除应用包及其安装记录，随后可另行选择隔离残留。
仅有 `.pkg` 收据的应用也可查看只读残留预览。
Linux 支持按已核实的安装身份卸载 Flatpak，以及创建快照后卸载 Snap。
Flatpak 卸载后，可另行选择隔离 `~/.var/app/<应用 ID>` 下符合条件的专属数据目录。
该目录可能含个人文件，需手动选择并再次确认。
只有卸载前后目录一致、可见的 Flatpak 安装中已无其他应用、当前会话也无运行实例时，才开放隔离。
Flatpak 会将历史 ID 的数据目录提供给改名后的应用，安装列表无法完整显示这类数据依赖。
目录会整体移入隔离区，可用 `restore` 还原到原位置。Flatpak 的权限记录会保留。
此类目录备份支持还原，当前继续保留在隔离区。
[Flatpak 历史 ID 迁移实现](https://github.com/flatpak/flatpak/blob/main/common/flatpak-run.c#L3163-L3246)
Linux 上也可卸载列表中的独立 AppImage。确认前关闭应用，卸载只把选中的 AppImage 文件移入隔离区。
卸载前后都能核实为直接指向该 AppImage 的用户应用启动器，可在残留清单中另行确认隔离。
按名称发现的配置、缓存和启动项会列为只读线索。
Linux 上按 Ctrl+C 会停止后续步骤，已经启动的包管理器事务由原生工具完成。
如果在 Snap 创建快照时取消，CLI 会保留已完成的快照并停止发起移除。
Snap 卸载前会记录已核实的快照编号，`restore` 会列出这些记录。
发起移除前会复核已安装的修订号。若快照记录失败或修订号无法核对，会停止移除。
用 `snap saved --id=编号` 核对快照是否仍在及其对应的实例。
快照数据由 snapd 保管，恢复前须重新安装对应 Snap，再按原生流程操作。
[Snap 快照文档](https://snapcraft.io/docs/how-to-guides/manage-snaps/create-data-snapshots/)
Debian 和 Ubuntu 安装配套的 [dpkg 助手](release-packaging.md#debian-和-ubuntu-卸载助手) 后，可以卸载符合条件的单个包。
助手通过当前会话的 PolicyKit 认证请求管理员批准，并在 dpkg 锁内核对包身份和版本，预演后才调用原生移除。
dpkg 会保留已登记的配置文件，可能按包自身的脚本更新系统状态。
卸载完成后会自动扫描残留，按包名匹配的条目只提供查看。
重新安装 Debian 包使用原生包管理器。
Arch Linux 安装配套的 `uninstallany-pacman-helper` 后，也可用 `uninstall` 移除符合条件的单个包。
可在源码目录 `packaging/arch-pacman-helper` 中使用 Arch Linux 的 `makepkg` 构建助手。
助手在持有 libalpm 事务锁时复核包身份、安装记录与依赖关系。包自己的卸载脚本和系统钩子仍按原生规则运行。
卸载完成后可查看按包名匹配的残留。重新安装 pacman 包使用系统包管理器。
CLI 使用各平台的普通用户后端，需要管理员审批的操作由对应的系统流程处理。
Snap 需要授权时，由当前会话的 PolicyKit 认证代理处理。

## 从源码构建

在 macOS 或 Linux 的仓库根目录构建并查看帮助。

```sh
cargo build --release --locked -p uninstallany-cli
./target/release/uninstallany --help
```

已有 Cargo 依赖缓存时可加 `--offline`。

仓库内的打包脚本可离线生成 CLI 归档和 SHA-256 校验文件。

```sh
python3 -B scripts/package_release.py --cli
```

归档位于 `target/dist`，包内有可执行文件和本说明。
