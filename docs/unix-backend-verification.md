# macOS 和 Linux 后端验收

先运行工作区检查，再在普通账号的 macOS 13+ 或 Linux 测试机中检查原生行为。
真实卸载与清理试验使用可回滚快照、专用账号及测试应用。

```console
cargo fmt --all --check
cargo clippy --offline --locked --workspace --all-targets -- -D warnings
cargo test --offline --locked --workspace
```

从项目根目录构建并启动桌面端。

```console
cargo run --offline --locked --release -p uninstallany-gui
```

## macOS

1. 在系统与用户 Applications 目录各放一个测试包。对照 Bundle ID、显示名和版本。
   安装一份测试 pkg 和一个 Homebrew cask，检查来源标记与重复 Bundle ID 下的残留归属。
   用虚拟机中的副本模拟 `env: null`、同版快照和受信暂存链接，核对已有链接证据可确认应用位置。
   在复核期间改变配置内容或打乱快照、配置和收据的时间顺序，核对归属仍无法确认。
   对照可用的安装日期，缺少可靠日期或大小时应显示空值。
2. 选择具有已验证厂商卸载器的测试应用，审阅原生动作后确认。
   核对原应用路径消失后才进入残留扫描。
   如果厂商卸载器同时移除 Applications 下的一级套件目录，核对后端仍能确认原路径消失并生成预览。
   如果原套件目录被替换为文件或符号链接，核对后端拒绝把它判定为已经消失。
   如果厂商卸载器只重命名或把原应用包移到普通目录，核对报告保留「无法确认完成」，残留只能查看。
   如果厂商卸载器将原应用包移入当前账号的废纸篓，核对后端在可读且文件身份相符时打开残留预览。
   在确认清理前从废纸篓恢复应用或清空废纸篓，核对旧预览无法执行。
   如果无关应用的元数据无法读取，核对原应用仍可确认已卸载，残留预览保留读取警告，归属不明的条目保持只读。
   在用户 Applications 放入无后台服务且归当前用户所有的独立应用，从应用列表选择卸载。
   用 Bundle ID 配对但主程序缺失的伴随卸载器复核普通整包隔离，并检查确认窗口说明原因。
   在确认前修复该卸载器，核对旧的整包计划会退出并要求重新审阅。
   在守卫允许的 `/Applications` 下放入当前用户拥有的一级套件目录和独立应用，核对普通卸载只隔离选中的应用包。
   确认窗口应显示应用包路径和隔离动作。第一次确认只移动应用包，随后自动展示残留预览。
   关闭残留预览应保留所有残留。重新执行时，仅所选残留在第二次确认后进入隔离区。
   已启用签名助手时，从应用列表选择受支持的 `/Applications` 独立应用，核对预览显示系统路径和管理员授权原因。
   拒绝管理员授权或模拟回执不明确时，核对后端不会开放可清理的残留清单；若回执不明确，按操作编号查询隔离状态。
   在用户家目录的私有工具目录放入便携 `.app`，通过指定目录预览整包。
   对照应用运行时的限制，以及关闭应用后重新扫描的结果。
   在主应用退出后保留一个系统能识别的包内应用，核对卸载和残留隔离仍被拦截。
   对照未选中的应用、Homebrew cask 和 pkg 安装收据。
3. 在测试应用的 Library 范围添加配置、缓存、日志和 Saved Application State 样本。
   在独占沙盒中添加 Library 和 Documents 样本，核对隔离候选来自限定的 Library 子路径。
   在沙盒 `Data/Library/Application Support/<Bundle ID>` 放入数据库及伴随文件，卸载后核对该目录以一个默认不勾选的候选项展示，并且可以整体还原。
   添加嵌套应用或符号链接后重新生成预览，核对整目录选项不再可用，普通文件仍受单项隔离守卫约束。
   在同一个 Application Support 父目录下放入其他命名的目录和文件，核对它们不会成为可清理项。
   在专属子目录放入超过扫描深度或条数上限的样本，核对预览提示扫描范围受限。
   在用户、系统和沙盒的 `Preferences/ByHost` 放入样本，核对精确命名的普通文件进入清单，系统项保持只读。
   将 Bundle ID 改为其他标识，把主机 UUID 改成非标准格式，或把样本换成符号链接，核对这些文件无法选择清理。
   用非沙盒 WKWebView 应用写入本地网站数据，卸载后核对 `~/Library/WebKit/<Bundle ID>/WebsiteData` 出现在残留清单中且默认不勾选。
   用第三方沙盒 WKWebView 应用核对 `~/Library/Containers/<Bundle ID>/Data/Library/WebKit/WebsiteData`，并对照具名存储、其他应用沙盒和授权拒绝的情况。
   确认隔离后核对同级命名存储和父目录仍存在，并验证网站数据目录可还原。
   在 `~/Library/HTTPStorages/<Bundle ID>` 准备 `httpstorages.sqlite` 与可选的 `-wal`、`-shm` 文件。
   核对卸载后整个目录只出现一次，默认不勾选，并能整体隔离及还原。
   把数据库换成链接、去掉主数据库或添加无关文件，核对目录只可查看。
   在用户 `Library/Logs/DiagnosticReports` 放入所选应用和其他应用的 `.ips` 崩溃报告样本。
   核对只有首行标识精确匹配的崩溃报告可选，默认不勾选，并验证隔离还原。
   验证同 Bundle ID 的歧义、共享容器、已注册启动服务和系统级服务的只读行为。
   安装 Bundle ID 不同、显示名仅有分隔符差异的两个应用，核对仅按名称命中的偏好文件不可选，精确匹配所选 Bundle ID 的文件仍按原守卫审核。
   在残留预览后添加同名应用，核对执行前重扫会拒绝受冲突影响的名称匹配项。
   对于标签与 Bundle ID 不同、程序直接指向应用包内 Mach-O 文件的用户启动项，核对注册仍存在时阻止整包隔离，未注册时只列为只读残留。
   应用仍运行时，核对用户 Library 文件、沙盒数据和用户 LaunchAgent 保持只读。
   在预览后启动应用并执行，核对执行前复核阻止隔离。
   在 Tauri 桌面端复核残留清单时取消，核对隔离区没有新增备份，且原清单仍可重新选择并确认。
   确认重试会重新核验归属和身份，清单有效期从首次预览开始计算。
   在逐项处理开始后取消，核对已完成的项目仍可还原，原清单只能使用一次。
   在一批残留开始隔离后，将应用恢复到原安装位置且保持关闭，核对后续项目被跳过，已隔离的项目仍可还原。
4. 对可写项执行隔离与还原。在原位置放置冲突标记，重试还原后确认占位对象保持原样。
   如测试机有第二个卷，验证缺少同卷私有隔离区或卷关闭文件所有权检查时的处理。
   在测试副本中模拟对象已经移回、结果尚未写入时中断，重新读取隔离区核对恢复状态及补记日志。
   核对原目录或对象身份发生变化时，后端不会补记成功。
   在测试副本的隔离应用包中移走 `Contents/Info.plist`，核对原备份记录仍显示为待复核，且还原和到期清理均不提供该对象。
   如果批次出现待复核结果，核对剩余未执行的条目逐项标为已跳过。
   在同时选中普通和系统隔离项的过期清理中，也要核对停写状态会阻止后续特权清理。
   日志可写时核对导出保留这些跳过事件、批次编号和已有的备份位置。
   跳过事件写入失败时，结果仍显示已跳过，并附上日志写入错误。

桌面列表为已识别的应用包统计同一卷上普通文件的逻辑长度。
统计优先处理第三方应用，每次列表刷新共享 400 毫秒及 15 万个目录项的预算。
后端在文件系统调用之间检查取消和预算，结果以逐项观测到的元数据为准。
统计前复核 Bundle ID，返回大小前再次核对应用目录身份。
符号链接的目标和嵌套挂载点在统计范围之外，未完整统计的包保留空值。
列表大小表示应用包内文件的逻辑字节总和，磁盘实际占用和预计可回收空间需另行计算。

桌面列表的发行商来自当前架构主程序通过离线检查的 Developer ID 应用签名证书。
后端复核 Bundle ID 与 Team ID，并提取证书主题中的名称。
发行商补全优先用于第三方应用，每次刷新最多检查 32 个应用，并在检查之间使用 150 毫秒的预算。
未获得可靠 Developer ID 名称时，保留发行商空值。
该字段仅用于列表展示、搜索和排序，清理匹配继续使用独立的核验清单。
[Apple Developer ID 证书](https://developer.apple.com/help/account/certificates/create-developer-id-certificates) · [签名证书链接口](https://developer.apple.com/documentation/security/kseccodeinfocertificates)

手动选择的便携 `.app` 和用户目录中的独立套件成员可以进入整包预览。
用户 Applications 中的独立 `.app` 可从卸载入口进入可还原的整包隔离。
直属 `/Applications` 且通过普通权限路径守卫的应用也可走此流程。
`/Applications` 的一级套件目录若归当前用户所有且符合路径守卫，可用普通权限隔离其中的独立应用包。
同级应用和套件目录保留在原位。签名助手的适用范围仍是直属系统应用。
有已验证的厂商卸载器时优先展示厂商动作。整包隔离确认只授权移动应用包。
确认原位置已空出后自动扫描残留，文件和目录由用户另行选择并确认。
应用包隔离记录进入原有备份和审计，可按原位置还原。
整包移动复核应用运行状态、安装收据、后台项目及目录身份。
移动前在收据检查之后复核可归属的用户 LaunchAgent。
在 Homebrew、安装收据或启动项复核期间取消，可在改名提交前停止隔离。
改名一旦开始，后端继续核对目录身份、同步和记录结果，随后响应取消并停止残留扫描。
可在执行复核期间取消，核对原应用路径未移动、报告为已取消且不存在可还原备份。
用户 plist 的程序直接指向核实过的包内 Mach-O 文件时，按实际标签核对注册状态。
选择隔离 plist 仍要求应用命名空间，以及文件名与标签完全匹配。
预配置的应用目录属于 root 时，仅接受具有 sticky bit、当前账号可写且 ACL 符合守卫的目录。
普通管理员组共享写入且没有 sticky bit 的系统 Applications 目录依然只读。
[Apple 文件权限说明](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AuthenticationAndAuthorizationGuide/Permissions/Permissions.html) · [AppKit 应用运行状态](https://developer.apple.com/documentation/appkit/nsrunningapplication/runningapplications(withbundleidentifier:))

厂商卸载器需要匹配固定位置与名称、应用标识和同一 Developer ID Team。
按应用名称构成的伴随卸载器可在同级目录、`Contents/Helpers` 或 `Contents/Resources` 中识别。
两个应用内目录也支持固定的 `Uninstaller.app` 名称。
应用位于 Applications 下的一级套件目录时，也会检查同级的 `Uninstall.app` 和 `Uninstaller.app`。
这些名称仍需通过同样的 Bundle ID、签名、属主和路径核验。
启动入口仅接受唯一通过独立身份核验的候选。
启动前重新核验签名、磁盘对象和路径权限。
签名核验先对相同的代码对象设置离线验证，再读取证书与签名详情。
伴随卸载器的主程序声明无效、主程序缺失或包内候选的元数据损坏时，已有的整包隔离守卫仍可独立审核所选应用。
通过守卫后，确认窗口说明厂商动作不能使用，并显示可还原的整包隔离范围。
执行隔离前会重新查找厂商卸载器。已恢复的有效厂商动作需要重新确认。
无法解释的签名错误、权限错误、对象变化和多个通过核验的候选均会阻止隔离回退。
同级伴随应用的 `Info.plist` 无法读取时，仍按应用枚举不完整处理。
[Apple 签名状态码](https://developer.apple.com/documentation/security/code-signing-services-result-codes?language=objc)
启动前取消会跳过该程序。
等待进程仍在运行时，取消只结束本工具启动的等待进程。
未观测到正常退出时，厂商程序可能继续运行，报告标为「无法确认完成」。
已观测到正常退出时，后端立即核验原应用路径与已持有的可执行文件身份。
路径仍在使用或原程序仍有链接且缺少废纸篓证明时，后端最多等待两秒复核后台移除。
取消会停止后续等待、扫描和未启动的队列项目，已确认的卸载结果仍会保留。
原生结果已取得时，卸载结果或完成核验的审计写入失败会保留已核实的结果和错误信息。
此时本次操作不会发出可执行的残留清理清单。
系统仍报告同一厂商卸载器正在运行时，后端拒绝再启动一份。
启动厂商卸载器前，后端持有经过签名和文件身份核验的原应用包及主可执行文件描述符。
厂商退出后，原应用位置空出且主可执行文件的链接数为零时，进入可清理的残留扫描。
主可执行文件仍有链接时，也可由 macOS 查到当前账号的废纸篓，再核对同卷的原应用包和主可执行文件仍在其中。
废纸篓只用于核验来源，不作为清理目标。程序不会创建废纸篓或申请额外权限。
在生成预览和迁移每个选中对象前，重新核验原路径空出并且原应用仍位于废纸篓。
从废纸篓移出且原可执行文件仍有链接时，该证据无法继续授权清理。
清空废纸篓后，只有原应用路径仍空出且已持有的原可执行文件链接数归零，才能继续清理。
这项检查只核验原文件，其他卷上的独立副本仍由已有的重复安装扫描范围决定是否可见。
[Apple 文件链接语义](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/unlink.2.html) · [Apple 系统目录 API](https://developer.apple.com/documentation/foundation/filemanager/url(for:in:appropriatefor:create:)) · [Apple 废纸篓权限](https://developer.apple.com/videos/play/wwdc2019/701/?time=1995)
残留扫描独立检查重复安装和枚举警告，用于决定各项能否清理。
厂商卸载器正常退出后仍无法核实原位置或主可执行文件时，报告保留「无法确认完成」。
此时后端可用卸载前核实的应用标识和 App Groups 生成只读残留清单，包括应用包元数据已损坏的情况。
核心在独立核验阶段降为「无法确认完成」时，也保留后端提供的只读残留证据。
由管理员组共同可写的 Applications 位置不符合此路径守卫。
Homebrew cask 支持识别和残留扫描。
识别使用本地安装快照与收据，多个已知应用目标分别参与归属核对。
符合便携应用目录范围的用户目录可作为 Homebrew 自定义 `--appdir`。
快照额外记录的实际目标也参与归属核对，多个目标指向不同路径时保留各自的只读线索。[Homebrew cask 选项](https://docs.brew.sh/Manpage#global-cask-options) · [Homebrew 目标记录实现](https://github.com/Homebrew/brew/blob/main/Library/Homebrew/cask/cask.rb#L729-L748)
已保存的目录配置按 `explicit`、`env`、`default` 的顺序解析。两个高优先级配置段均有记录且未覆写目录时，可采用 Homebrew 的 `/Applications` 默认目录。
没有显式目录且 `env` 为 `null` 时，Homebrew 会读取当前环境，无法从配置推断历史安装目录。
配置格式无效或旧快照的序列化目标缺少其他证据时，保留归属不确定状态。
[Homebrew 配置实现](https://github.com/Homebrew/brew/blob/main/Library/Homebrew/cask/config.rb#L56-L152) · [旧版快照加载器](https://github.com/Homebrew/brew/blob/5.1.0/Library/Homebrew/cask/cask_loader.rb#L335-L349)
`app` 参数内的空目标或 `null` 按源文件名解析。旧快照中的系统和架构变体也参与可能的归属核对。[Homebrew 目标选项解析](https://github.com/Homebrew/brew/blob/main/Library/Homebrew/cask/artifact/relocated.rb#L18-L65) · [Homebrew 平台变体格式](https://github.com/Homebrew/brew/blob/main/Library/Homebrew/cask/cask.rb#L649-L685)
缺少 `config.json` 时，可用同版收据和最新有效 JSON 快照定位 Homebrew 为某个 `app` 条目保留的暂存链接。路径以快照记录的 `only_path` 为准。[Homebrew 暂存路径](https://github.com/Homebrew/brew/blob/main/Library/Homebrew/cask/artifact/relocated.rb#L52-L65) · [Homebrew 移动后的记录](https://github.com/Homebrew/brew/blob/main/Library/Homebrew/cask/artifact/moved.rb#L139-L186)
配置结构有效、没有 `explicit.appdir` 且明确记录 `env: null` 时，也可以沿用这套暂存链接核验。
此时还要求配置文件写入时间介于快照和收据之间，且核验前后读取到相同的受信配置字节。
[Homebrew 快照与收据写入](https://github.com/Homebrew/brew/blob/main/Library/Homebrew/cask/installer.rb#L147-L198) · [Homebrew 配置写入](https://github.com/Homebrew/brew/blob/main/Library/Homebrew/cask/installer.rb#L350-L358)
后端只读取链接文本，并独立核验确切的应用位置、目录身份和 `Info.plist`。收据、快照和链接所在目录必须通过独占权限核验。
复核收据和快照时，后端从通过权限检查的文件描述符读取内容和修改时间。
重新读取的字节哈希必须与最初解析的记录一致。
旧版基础快照若重复收据中的相同 `app` 源和目标参数，可沿用已核验的暂存链接目标。
快照的显式目标若有记录，还须与暂存链接目标一致，才能沿用这份归属证据。
有安装器或安装钩子的快照不沿用这项推断。
重复源、不同声明和平台或语言变体继续独立审核，空的 artifact 列表不能独立证明 cask 的应用归属。
多个条目引用同一暂存来源、链接悬空、版本不一致或 Caskroom 允许其他用户写入时，仍保留归属不确定状态。[Homebrew Caskroom 权限](https://github.com/Homebrew/brew/blob/main/Library/Homebrew/cask/caskroom.rb#L162-L176)
另外核对收据文件晚于快照写入，暂存和元数据均没有同版本 `.upgrading` 备份。[Homebrew 安装顺序](https://github.com/Homebrew/brew/blob/main/Library/Homebrew/cask/installer.rb#L189-L199) · [Homebrew 升级备份](https://github.com/Homebrew/brew/blob/main/Library/Homebrew/cask/installer.rb#L644-L684)
归属复核也检查标准 Applications 目录之外的已知 cask 应用路径。
不同目录的应用使用相同 Bundle ID，或已知目标的归属无法核实时，可能共享的用户 Library 条目保持只读。
已识别的其他应用若以显示名称或 Bundle ID 命中同一归一化名称，仅按名称匹配的残留保持只读。
这项检查包含系统应用和标准目录外已核实的 Homebrew 应用目标。
系统应用枚举不完整时，只限制名称匹配项。精确 Bundle ID 命中仍按原有归属和文件守卫审核。
Homebrew 枚举存在警告时，普通应用清单不提供卸载入口。无法解析应用位置时，诊断中会显示至少一个存在问题的 cask。
如果本地记录包含可能引入其他应用的安装前置或后置步骤，扫描仍保留明确记录的路径，同时把整体应用归属视为未核实。
Homebrew 的安装步骤可以移动目录或在应用目录中运行具有写权限的程序，因此单个 `app` 声明无法列出这些步骤产生的所有应用。
[Homebrew 安装步骤](https://docs.brew.sh/Cask-Cookbook#stanza-flight_steps)
厂商卸载在生成确认清单前和执行前分别复核 Homebrew 归属。
现有扫描清单会展示仍可观察的应用目标和所选 cask 安装收据中的字面卸载声明。
常规卸载和可选的 zap 声明分别标注，文件路径、服务和包收据模式均为只读参考。
脚本、钩子、通配模式及超出显示范围的内容以诊断提示。
清单只表明收据中的声明。应用尚无已核实的 Bundle ID 对应项时，名称推断的残留保持只读。
标准 Caskroom 中缺少两种记录的目录会给出诊断，并阻止无法确认归属的隔离。
其包归属检查也覆盖内外层应用包及指向同一对象的 APFS 路径写法。
Homebrew 会重新解析 cask 定义并读取可覆盖调用环境变量的配置。
在调用范围能独立约束之前，后端不开放 Homebrew 原生卸载。
[Homebrew 安装收据格式](https://github.com/Homebrew/brew/blob/main/Library/Homebrew/cask/tab.rb#L27-L39) · [Homebrew cask 加载器](https://docs.brew.sh/rubydoc/Cask/CaskLoader.html#load_prefer_installed-class_method) · [Homebrew 环境配置读取](https://github.com/Homebrew/brew/blob/main/bin/brew#L115-L165)
Apple Installer 收据与能够确认的现存包文件用于归属判断和只读展示。
完整应用清单并行读取应用包和 Homebrew 信息，以及 Installer 收据。
两路共用取消信号，结束后合并结果和诊断，再按应用名称排序。
后端查询启动卷和当前用户家目录两个收据范围，并对所选收据使用同一范围查询安装位置和载荷。
同一个包 ID 可以在两个范围内各显示一条，家目录收据在名称后显示 `(~)`。
单独打开某条收据时只查询它所在的收据范围，启动卷也只读取该条目的详情。
普通应用和 Homebrew 的逐项查找继续使用应用包与 cask 的归属关系，整包隔离时另行检查 Installer 收据。
应用清单、逐项查找及按路径扫描先核对完整的 cask 归属关系。
判断卸载入口是否可用时，先检查普通隔离资格。生成卸载预览时仍优先核验厂商卸载器。
普通隔离预览在完成应用和后台项目检查后，使用同一份新读取的 Homebrew 清单核对额外目标冲突和直接归属。
实际隔离会重新读取归属证据。
家目录收据的版本、日期和载荷查询输出格式仍需实机核对。
文件清单超过预览上限时，后端显示通过路径核验的部分条目，并提示预览受限。
只有查询在传输和时间限制内成功结束时才展示这些条目。
可使用声明支持家目录安装的测试包核对显示和只读行为。[Apple 安装范围说明](https://developer.apple.com/library/archive/documentation/DeveloperTools/Reference/DistributionDefinitionRef/Chapters/Distribution_XML_Ref.html) · [pkgutil 手册](https://keith.github.io/xcode-man-pages/pkgutil.1.html)
普通权限整包隔离在同一超时预算内比较两轮收据证据，覆盖收据标识、应用定位文件、安装位置和相关 BOM 文件清单。
两轮证据不一致时，应用包保留并提示收据在核验期间发生变化。
收据没有统一的厂商卸载语义。

启动已核验的厂商卸载器前，后端查询启动卷收据。
应用的 Info.plist 和主程序必须同时出现在同一包版本的文件归属结果和载荷清单中。
载荷查询前后会对比收据元数据，记录有限数量的路径供卸载后参考。
核实原应用已移除后，后端核对仍存在、位于 Applications 或系统 Library 收据探查范围内的普通文件和目录。
这些路径在自动扫描中保持只读，即使厂商卸载器已移除收据。
直接收据预览和卸载后预览都能读取收据所列的系统框架、音频插件、Java 虚拟机和偏好设置面板。
这两处从 Applications 或 Library 根目录逐层打开候选路径，拒绝符号链接和其下的挂载边界。
专用系统预览不会把新增目录加入普通应用扫描或隔离范围。
[Apple 框架安装指南](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFrameworks/Tasks/InstallingFrameworks.html) · [Apple 音频插件位置](https://support.apple.com/en-asia/102239) · [Oracle JDK 安装文档](https://docs.oracle.com/en/java/javase/17/install/installation-jdk-macos.html)
预览只表明路径曾在收据中列出，当前对象可能已经更换。
查询格式异常、超时或超过限额时会给出诊断，厂商卸载仍可按确认继续。
需在 macOS 13 及较新版本上，用带厂商卸载器的测试 pkg 核对该流程，以及取消和收据被移除时的结果。
可在测试包中加入框架目录、音频组件和指向其他位置的链接，核对前两项以只读结果出现，链接被跳过。
[pkgutil 手册](https://keith.github.io/xcode-man-pages/pkgutil.1.html)

对归属明确、文件名与标签完全匹配的用户 LaunchAgent，仅当用户和 GUI 域均能确认没有对应注册时提供隔离。
启动厂商卸载器前，后端核对用户 LaunchAgent 指向的应用内可执行文件，并记录可确认的 plist。
确认原安装已卸载后，仅当该 plist 指纹保持一致且服务仍未注册时，该启动项才可进入可选清单。
程序归属明确但文件名或标签不符合清理要求时，内容保持一致的 plist 可列为只读残留。
厂商卸载整个套件目录也适用。新增、被替换或归属未核实的启动项保持只读。
执行和还原均会再次检查 launchd 状态。
普通权限隔离和残留扫描会检查 Bundle ID 及 AppKit 可见的包内应用。
发现运行中的应用或包内组件时，保留只读候选。
执行前复核预览绑定的应用身份，包括手动选择的 `.app`。
普通应用的每项残留在隔离前再查询 Bundle ID，并比较运行中组件的应用包路径与已确认的路径哈希。
这次逐项路径哈希比较要求路径拼写一致，且适用于应用包来源。
已卸载应用的每项文件残留还会在备份记录落盘后复核原安装位置。
这项检查从持有的父目录描述符查询旧名称，并复核父目录仍是该位置指向的目录。

用户 `Library/Logs/DiagnosticReports` 的独立 `.ips` 也可进入残留清单。
后端读取有界前缀并解析完整首行，仅接受类型 `309` 的崩溃报告和精确匹配的第三方 Bundle ID。
确认前把首行内容核对到同一个文件身份，受限的读取或检查会提示覆盖范围。
符合隔离条件的报告标为高风险，默认不勾选。
[Apple 崩溃报告格式](https://developer.apple.com/documentation/xcode/interpreting-the-json-format-of-a-crash-report)
原位置若被恢复的应用、符号链接或其他对象占用，该项会被跳过并记录原因。
逐项复核是隔离前的状态观测，其他位置的安装仍由整批残留重扫负责检查。
AppKit 结果随主运行循环更新，独立后台进程或复核后启动的应用可能未被观察到。
[Apple AppKit 应用查询](https://developer.apple.com/documentation/appkit/nsworkspace/runningapplications)
用户和符合条件的应用沙盒中，`Preferences/ByHost` 下精确匹配 Bundle ID 和主机 UUID 的普通 `.plist` 可单独确认隔离。
系统 `Preferences/ByHost` 中的匹配项为只读，用户偏好文件种类与身份在隔离前再次核对。
应用沙盒中的 `Data/Library/Application Support` 作为只读位置展示。
核实卸载后，如果沙盒目录和专属子目录的名称均与第三方应用的 Bundle ID 拼写完全一致，并通过整棵目录树核验，可以将专属子目录整体隔离。
此项可能包含用户数据，标为高风险，默认不勾选。
整目录无法通过核验时，可单独审阅通过文件守卫的普通文件，文件项同样标为高风险。
父级目录下直接存放的数据及其他名称的子目录仍不可选。
扫描不跟随符号链接。隔离和还原前重新检查应用是否正在运行。
[Apple Application Support 文档](https://developer.apple.com/documentation/foundation/url/applicationsupportdirectory) · [Apple 文件系统指南](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/AccessingFilesandDirectories/AccessingFilesandDirectories.html)
后台项目声明的 Bundle ID 可用于发现，共享或冲突的声明会阻止隔离。
当前实现依赖 `launchctl print` 的服务缺失退出码 113，跨 macOS 版本行为需验证。
应用内声明的后台项目保持只读，与整个签名包一起展示。
这类应用的手动整包隔离需要厂商先处理后台注册。
后端也读取应用 Info.plist 的 `SMPrivilegedExecutables` 声明，核对旧式系统助手和对应 daemon 的位置及身份。
旧式助手仍在系统中或归属存在歧义时，整包隔离需要先复核。
[Apple 后台项目的应用包布局](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos)

应用仍在磁盘上时，扫描可读取当前架构主程序已签名声明的 App Group 标识。
启动厂商卸载器前，还可按预览中的签名哈希核对并暂存这些标识。
普通隔离和签名助手隔离也在移动应用包前读取签名中的标识。
确认卸载完成后，残留预览可显示仍存在的同名共享容器。
扫描只匹配容器父目录中的同名条目，共享容器始终只读。
仅凭名称与 Bundle ID 相似的共享容器以低置信度展示。
`/Library` 中存在的 Containers、Group Containers 与 Saved Application State 也纳入只读发现。
[Apple App Groups entitlement](https://developer.apple.com/documentation/BundleResources/Entitlements/com.apple.security.application-groups) · [Apple 共享容器授权说明](https://developer.apple.com/documentation/xcode/accessing-app-group-containers)

### 特权预检

macOS 13+ 的 `privileged-inspection` 是可选后端特性。
启用后由 Apple 工具链生成客户端静态库和 `OUT_DIR/UninstallAnyPrivilegedHelper`。
助手二进制的包内位置为 `Contents/MacOS/UninstallAnyPrivilegedHelper`。
同名的 daemon 配置位于 `Contents/Library/LaunchDaemons`。
客户端和 daemon 需要同一 Developer ID Team、各自的签名标识和 Hardened Runtime。
带助手的签名发行包可通过打包脚本的 `--macos-signing-identity` 生成。
系统级助手在用户确认后通过 Service Management 注册。注册前核对应用、嵌套助手和 launchd 配置。
在接入独立启用确认的签名宿主中，用需助手的独立应用生成启用预览，并核对确认后的状态与系统设置一致。
注册后核对应用仍在原位置，原启用票据无法重用，也无法用于执行卸载。
等待助手获批后重新预览卸载，核对助手在这次确认中仍独立校验目标和管理员授权。
系统可要求管理员在设置中单独批准 daemon，此时后端报告等待批准。
桌面上的服务启用入口仍待接入。隔离、还原或到期处理各有独立确认和管理员授权。
有应用需要此助手时，应用列表可显示目录权限不合格、助手缺失、未注册或等待系统批准的原因。
[Apple Service Management](https://developer.apple.com/documentation/servicemanagement/smappservice)

预检使用系统级 Mach 服务名与双向 XPC 签名要求。
客户端先确认系统已批准该服务运行。
客户端先等待已认证的探测回复，再发送一个直属 `/Applications` 的应用名及其 Bundle ID。
助手根据系统提供的用户和审计会话限制连接，并使用目录描述符检查属主、卷、ACL 和实际文件身份。
预检结果仅提供对象身份和拒绝原因。
[Apple XPC 对端签名要求](https://developer.apple.com/documentation/foundation/nsxpclistener/setconnectioncodesigningrequirement%28_%3A%29)

可选的授权校验入口使用上次成功预检得到的根身份摘要。
助手只为同一已认证连接和审计会话签发一次性挑战，并绑定动作、路径、Bundle ID 和 120 秒期限。
客户端在此之后传入一份空授权引用。
在发起系统认证前，助手独立核验启动数据卷上的应用、清单及主可执行文件，并查询 Apple Installer 收据和相关 BOM 项。
检查使用本机 `pkgutil` 的只读命令，共享 30 秒时限，并比较两轮收据证据以发现同包 ID 的收据变动。
收据声明了应用或其中的文件、查询超时或证据不一致时，助手会中止本次请求。
通过收据检查后，助手用专用的非共享、零缓存管理员规则发起系统认证。
助手会在认证前后复核目标身份，处理后销毁本次授权。
认证后通过已核验的目录描述符检查整个应用包。
检查限制为 48 层及 100,000 项，拒绝可被普通账号修改的对象、非本地 APFS 卷、ACL、硬链接及特殊文件。
对符号链接只检查链接自身。
校验成功只表示本次授权已核对并消耗。
[Apple Authorization Services 概念](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/02authconcepts/authconcepts.html) · [Apple 授权引用传输](https://developer.apple.com/documentation/security/authorizationmakeexternalform%28_%3A_%3A%29)

#### 特权隔离事务

助手内部按已认证用户和操作 UUID 划分私有隔离区。
隔离位置为 `/private/var/db/io.github.siiverash.uninstallany.privileged-helper/<uid>/<uuid>/`。
记录先于移动落盘，包含审阅时的对象身份、原始位置和准备时间。
隔离和还原均要求原位与隔离区位于同一个本地 APFS 卷，并通过排他重命名拒绝覆盖已有对象。
发生连接中断时，可重新建立签名连接查询同一操作，核对日志、原位和隔离对象。
无法确认对象身份、持久化标记或当前状态时，返回待复核结果。
[Apple XNU 的 `renameatx_np` 接口](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/syscalls.master)

还原入口先提供只读预览，展示同一已认证用户的隔离对象和原位置。
预览经用户确认后，助手以单独的管理员权限完成一次认证，提示中显示实际还原位置。
助手持有隔离记录锁，在写入还原意图和最终移动前复核预览指纹。
原位置已被占用时保留现有对象和隔离备份。
还原完成标记提供操作时间。若系统中断，仅凭对象身份确认已回到原位时，完成时间留空。
回执丢失或状态不明确时，调用方按原操作编号查询，后续重试需重新预览并确认。
[Apple Authorization Services 任务说明](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/03authtasks/authtasks.html)

系统级隔离为应用列表中选定的独立应用提供单项只读卸载预览。
签名助手已启用且已核对清单中的应用身份时，卸载确认后由助手单独请求管理员授权。
只有回执确认隔离、日志落盘并独立确认原位置已空出后，才生成可供选择的残留预览。
应用包已经隔离成功时，即使用户在执行期间取消，仍完成原位置核验，残留扫描响应取消。
无法验证回执时，结果提供助手操作编号，由原有备份清单和还原入口核对。
助手已启用时，可在现有的「扫描目录」入口输入该应用的完整路径。
桌面后端先核对重复标识、已知归属、运行情况和厂商卸载路径，再向助手请求单项预览。
从「扫描目录」发起时，整包隔离标为高风险，需要勾选并确认后才请求管理员授权。
预览采用当时已保存的保留期。本地日志导出包含预览、执行开始和结果，成功时带隔离位置。
预览仅接受受保护的 `/Applications` 下直属的、经过 Developer ID 签名验证的完整应用包。
如果 `/Applications` 对组可写但缺少 sticky bit，助手拒绝预览和移动，以防确认后应用路径被替换。
遇到此类拒绝或助手不可用时，「扫描目录」通过当前应用清单中的准确位置和 Bundle ID 查找残留。
应用包在该清单中只读。可以选择的残留限定为通过普通权限守卫的用户 Library 文件和目录。
树内包含符号链接、嵌套 `.app` 或无法校验的对象时，维持只读。
助手核对 Installer 收据、标准 Caskroom、应用声明、系统 launchd 磁盘记录和当前进程的可执行文件路径。
标准 Caskroom 必须在所检查的受保护位置确认为空或不存在。
预览指纹绑定系统目录、应用包身份和签名，用户确认后需要独立完成管理员授权。
助手在授权前后复核预览，移动前再次核对标准 Caskroom、后台记录和运行中的进程。
隔离成功时，日志提供操作编号、原位置、备份位置和完成时间。
回执中断后可用同一编号查询隔离结果，再按需要重新预览。
[Apple 代码签名深入说明](https://developer.apple.com/library/archive/technotes/tn2206/) · [Apple XNU 进程查询实现](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/proc_info.c)

系统管理员并发修改以及应用包内已有的写入句柄可改变目录树，现有静态检查无法冻结这些写入。
进程和 launchd 检查覆盖当前观察的可执行文件和系统级磁盘记录。
应用列表的卸载入口还在请求助手前检查可归属的用户 LaunchAgent。授权期间新注册的用户任务、间接加载和动态注册仍可能在该范围之外。
Installer 检查覆盖可查询的启动卷收据。安装脚本产生的数据可以超出 BOM，收据查询格式和耗时也需在支持的 macOS 版本上核对。
Homebrew 可以使用自定义前缀、应用路径或脚本。此入口适用于用户能确认是手动独立安装的应用。已知包管理应用仍走对应适配器。
签名部署和原生验证仍待完成。
[Apple 部署指南](https://www.apple.com/ca/education/docs/l521219b_osx_deployment_guide_030513.pdf) · [Homebrew 安装手册](https://docs.brew.sh/Installation) · [Homebrew Cask Cookbook](https://docs.brew.sh/Cask-Cookbook)

### 隔离保留与清理

普通备份的隔离对象无法核对时，列表保留有效清单的操作编号、原位置和隔离位置，并标记待复核。
普通隔离和还原发现路径竞态时，回滚到先前位置后仍会同步两端目录并核对对象位置和身份。
回滚或同步无法证实时，本项标为待复核并停止本批次后续写操作。
已观测到的隔离异常会按备份编号记录并进入日志导出。
重启后如果无法核实隔离对象，已记录的异常继续显示为待复核，完整且身份一致的隔离对象仍可还原。
Unix 后端在写入隔离及审计记录前同步状态路径的父目录，也覆盖继承中断操作所留下的目录。
macOS 私有隔离和审计存储会拒绝包含扩展 ACL 允许权限的目录或记录。
[Apple 文件系统权限与 ACL](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)

系统级备份可由同一有效用户按页查询，重启后可从助手的私有记录重建列表。
清单展示隔离、还原、待复核或正在处理等状态，并提示目录中无法识别的记录。
跨页期间发生目录变更时，助手要求从第一页重新查询。每个条目的状态以该条记录被读取时为准。
新系统级备份默认保留 14 天，调用方可传入现有偏好中的保留天数。
助手在移动前把保留天数和到期时间写入隔离记录，后来修改的偏好只影响新备份。
系统级到期预览要求备份仍处于隔离状态、具有持久化完成标记且期限已到。
旧记录仍可查询和还原。缺少到期时间的记录继续保留。
带助手的签名版会在服务已启用时，把系统级备份加入现有桌面隔离区。
桌面后端分别核对两种备份的操作编号。编号冲突时保留普通备份条目，并提示检查系统级记录。
缺少到期时间的旧备份在桌面列表中显示为待复核，其还原仍可通过助手接口完成。
系统级到期处置先预览单个备份，显示其隔离位置和仍待处置的条目数。
开始前需要用户再次确认，并通过单独的管理员权限授权永久移除这份备份。
助手持锁保存完整条目清单，排他移入私有待处置目录，再持久化与清单绑定的提交记录。
移除限定于清单中的条目，并通过目录描述符核对每项的身份和位置。
待处置目录内的备份停止接受还原。中断后可重新预览剩余条目，确认后继续。
出现新条目、身份变化或无法核对提交记录时，助手保留剩余对象并报告待复核。
完成后保留原隔离记录、操作编号和清理完成时间。
桌面日志导出以同一备份编号关联系统级隔离、还原及到期清理的预览、执行开始和结果。
导出保留已写入日志的预览、跳过、回执不确定及到期清理待继续状态。
同一备份在同一毫秒内的记录按隔离、还原和到期清理的阶段排序，每个阶段内先显示预览，再显示开始和结果。
桌面后端在开始记录落盘后才向助手提交操作。
回执丢失或结果无法核对时，报告保留备份编号。
到期清理中断时，结果记录采用助手回报的暂存路径。
[Apple XNU 的目录相对操作](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/syscalls.master) · [Apple 文件持久化说明](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fcntl.2.html)

专属缓存或日志目录通过有界目录树、同卷身份和所有权校验后可以整体隔离。
用户顶层 Saved Application State 中的专属目录也可使用这套隔离逻辑。
候选目录必须字面匹配已核实的第三方 Bundle ID 和 `.savedState` 后缀，并通过重复归属和目录树检查。
窗口和会话信息可能保留未结束的工作，因此整目录候选标为高风险，默认不勾选。
应用运行时保持其状态目录只读，隔离和还原前会重新查询进程状态。
系统级状态目录保持只读，沙盒内的状态继续按限定范围展示单项文件。
隔离区支持恢复已移动的目录和文件。
本地 APFS 上已隔离的应用包、专属缓存、日志、状态或沙盒专属 Application Support 目录可进入到期清理预览。
[Apple 的 AppKit 状态恢复指南](https://developer.apple.com/documentation/AppKit/restoring-your-app-s-state-with-appkit)

WebKit 应用的默认网站数据目录也使用同一套可还原隔离逻辑。
用户目录中，扫描匹配第三方 Bundle ID 字面对应的 `Library/WebKit/<Bundle ID>/WebsiteData`。
核实卸载后，也匹配所选应用沙盒内的 `Data/Library/WebKit/WebsiteData`，按列出的实际名称逐级核对路径。
目录可能含有站点本地存储和数据库，因此标为高风险，默认不勾选。
只有归属已核实且应用停止时才提供可清理的 WebKit 数据项。隔离和还原前会重新检查应用状态。
全局 WebKit 数据、具名存储、上级目录和其他应用的沙盒仍在此次清理范围之外。
[WebKit 默认网站数据路径实现](https://github.com/WebKit/WebKit/blob/main/Source/WebKit/UIProcess/WebsiteData/Cocoa/WebsiteDataStoreCocoa.mm#L537-L555)
macOS 14 及更新版本可能要求授权读取其他应用的沙盒。访问遭拒时，目录读取错误会保留在扫描诊断中。
[Apple 沙盒文件访问说明](https://developer.apple.com/documentation/security/accessing-files-from-the-macos-app-sandbox)

确认清理后，后端先将整棵目录移入待处置位置，再记录提交凭证并逐项复核和删除。
如果普通权限目录已移入待处置位置，但删除尚未提交且整个备份仍核对一致，备份清单会显示实际隔离路径，可重新选择还原或到期清理。
还原与到期清理用同一备份编号的独占锁，并在取得锁后重新核对处置凭证、目录指纹和目标位置。
一旦删除已提交，即使尚未移除目录项，备份也只可预览剩余的处置操作。
中断后可重新预览并确认清理，后端只处理原清单中身份仍匹配的剩余目录项。
出现新目录项或身份变化时，该备份会停在待复核状态。
HFS+ 上的目录保留在隔离区，因为其目录硬链接不满足递归删除所需的归属条件。
[Apple APFS 目录硬链接说明](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/FAQ/FAQ.html)

macOS 单个文件或终端链接的到期清理也会先暂存，再提交删除。
提交凭证绑定原备份指纹、隔离目录身份和暂存对象的元数据。
提交前中断可还原或重新确认清理。提交后中断仅可重新确认清理。
暂存名称已消失时，只有提交凭证有效且仍能核实原隔离目录，才可同步并补记清理结果。
链接只作为单个目录项移除，保留其指向的对象。

## Linux

1. 分别用 Debian/Ubuntu、Fedora 和 Arch 系快照核对已安装包来源。
   使用标签区分原生包、当前用户与系统 Flatpak、Snap、AppImage 和桌面入口。
2. 为同一 Flatpak 应用分别准备 user 与 system 安装，核对预览中的安装范围。
   卸载后检查用户文件、权限和另一安装实例。核对残留扫描和隔离确认之间的边界。
3. 分别验证默认路径与自定义 XDG 路径。检查 config、cache、data、autostart、systemd 和发行包所有权。
   系统目录、用户文档根目录、标为共享的目录以及其它包拥有的文件应保持原样。
4. 核对没有权限承载或无法确认恢复语义的包卸载入口。任何确认都应绑定到原生包标识和安装范围。

当前 Linux 原生写入支持指定范围和完整引用的 Flatpak 卸载，以及先创建 Snap 快照再卸载指定实例。
Snap 快照由 snapd 保存与恢复，桌面端的隔离区还原覆盖本工具隔离的残留文件。
dpkg、rpm 和 pacman 包可枚举，写入需等待能限制依赖删除的提权执行路径。
已核对的 PackageKit 发布记录显示，APT 后端的依赖删除开关是在后续版本中补齐的。
[PackageKit 发布记录](https://github.com/PackageKit/PackageKit/blob/main/NEWS)

## 文件安全与恢复

- 在扫描前及扫描后分别替换测试文件和父目录，核对执行前身份复验、跳过与诊断。
- 用中间符号链接指向保护目录，验证扫描与执行均不穿过它。
  对末端测试链接，检查隔离和还原针对链接本身，目标文件保持原样。
- 在 Linux 测试 bind mount，在两个平台分别测试跨设备目标。核对系统不回退到复制后删除。
- 检查 quarantine 的访问权限、本地日志、备份保留期及还原冲突。
  在文件已经移动而操作回执尚未落盘时终止测试进程，重启后根据隔离对象身份重新核对。

Rust 交叉检查只能验证目标平台的源码编译。
实际系统包管理、权限、隔离与还原以对应测试机的原生结果为准。
