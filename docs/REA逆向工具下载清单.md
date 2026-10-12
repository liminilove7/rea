# REA 逆向工具下载清单

整理日期：2026 年 10 月 12 日。按 Windows x64 工作机优先整理，Linux 和 macOS 工具单列。目标是把安装包、便携包和必要依赖集中保存，后续按目标类型取用。

**先准备 Node.js、一个原生分析引擎，再配齐 Windows 常用辅助工具。** REA 并不要求安装全部逆向软件：JavaScript、Electron 和 .NET 的静态分析不需要 Hopper、Ghidra 或 IDA；原生二进制深度分析才需要选择引擎。

REA 接入要求以本地项目 `6afcc9e7` 的文档和源码为依据；本地 `package.json` 版本为 6.1.0。[npm 官方登记](https://registry.npmjs.org/rea-agents/latest)在整理时返回最新发布版 6.4.0。发行版和本地源码的功能以各自实际 CLI/MCP 契约为准，不能仅凭版本号认定行为完全一致。

## Windows 优先下载组合

以普通 Windows EXE 分析为起点，先收齐以下工具：

- [ ] Node.js 24.18.0 x64，包含 npm。
- [ ] Ghidra 12.1.4 PUBLIC ZIP。
- [ ] Eclipse Temurin 完整 JDK 21 x64。
- [x] x64dbg 便携目录，已确认 x64dbg 和 x32dbg 入口存在。
- [x] Detect It Easy Windows x64 完整发布包，已确认本机 3.09 可用。
- [x] 二进制查看工具：本机已有 Hex Editor Neo 7.31.00.8528；HxD 保留为备选。
- [ ] 7-Zip x64。
- [ ] Sysinternals Suite。
- [ ] Wireshark，保留对应抓包依赖的安装材料。

有 IDA Pro 授权时，可用 IDA Pro、对应 Hex-Rays 反编译器、Python 和匹配的 ida-pro-mcp 替代上述 Ghidra/JDK 组合。分析 DLL、复杂 Windows 原生目标时，优先评估 IDA 路线或手工工具：当前 REA 的 Windows Ghidra 接口有严格的目标限制。

## 本机 Detect It Easy

已确认本机 **Detect It Easy 3.09 x64 便携版** 位于 `D:\安装包\DIE\die_win64_portable_3.09_x64`。保留整个目录中的数据库和 Qt 运行库。

- 图形界面：`D:\安装包\DIE\die_win64_portable_3.09_x64\die.exe`。
- 命令行：`D:\安装包\DIE\die_win64_portable_3.09_x64\diec.exe`。

2026 年 10 月 12 日使用命令行 JSON 模式静态检查 `C:\Windows\System32\whoami.exe`，退出码为 0，标准错误为空。结果报告 PE64、Microsoft Linker 和 Visual C/C++ 等指纹，原始 JSON 保存于 `D:\安装包\DIE\REA验证\whoami-die.json`。指纹识别结果属于工具判断，不独立证明完整构建环境。

```powershell
& 'D:\安装包\DIE\die_win64_portable_3.09_x64\diec.exe' --json 'D:\samples\program.exe'
```

用实际样本路径替换示例。该发行包的 `--help` 会显示帮助弹窗；JSON 分析模式已验证可输出到标准输出。DIE 作为外部辅助工具使用，不作为 REA 原生分析 provider 注册。

## 本机 x64dbg

已确认本机 x64dbg 位于用户提供的 `snapshot_2024-07-09_23-55` 目录中。保存完整 `release` 目录及其依赖和插件。

- 64 位入口：`D:\安装包\Assemble\X64DBG\snapshot_2024-07-09_23-55\release\x64\x64dbg.exe`。
- 32 位入口：`D:\安装包\Assemble\X64DBG\snapshot_2024-07-09_23-55\release\x32\x32dbg.exe`，已确认存在。

```powershell
& 'D:\安装包\Assemble\X64DBG\snapshot_2024-07-09_23-55\release\x64\x64dbg.exe'
```

本次确认文件位置，未启动调试器或开展真实调试会话。x64dbg 作为外部动态调试工具使用，不作为 REA 原生分析 provider 注册。

## 本机二进制查看工具

已确认用户提供的 Hex Editor Neo 入口存在，文件版本和产品版本均为 **7.31.00.8528**，PE 机器类型为 x64。

程序路径：`C:\Users\admin\AppData\Local\HHD Software\Hex Editor Neo\HexFrame.exe`。

```powershell
& 'C:\Users\admin\AppData\Local\HHD Software\Hex Editor Neo\HexFrame.exe'
```

本机的二进制查看工具项已具备。后续可使用这个入口查看文件字节，HxD 保留为同类备选。本次只核对文件及版本，未启动编辑器或修改样本。

## 本机 GhidraMCP 归档

已检查 `D:\安装包\Assemble\Ghidra\GhidraMCP-6.0.0\GhidraMCP`，内容是 [bethington/ghidra-mcp 6.0.0](https://github.com/bethington/ghidra-mcp/releases/tag/v6.0.0) 的 Ghidra 扩展，不是 Ghidra 本体。

| 本地材料 | 状态与要求 |
| --- | --- |
| `GhidraMCP\lib\GhidraMCP-6.0.0.jar` | 插件版本 6.0.0；随包 Maven 元数据记录编译目标 Ghidra 12.1.2、Java 21 |
| `D:\安装包\Assemble\Ghidra\GhidraMCP-6.0.0.zip` | 已找到完整插件 ZIP；上游发行说明支持在 Ghidra 的 Install Extensions 中选择该 ZIP 安装 |
| `D:\安装包\Assemble\Ghidra\ghidra_mcp_bridge-6.0.0-py3-none-any.zip` | 外层 ZIP 内包含同版本 `.whl`；后续需取出 wheel 安装，不能把外层 ZIP 当成 wheel |
| wheel 的依赖与入口 | 元数据声明 Python ≥3.10、`mcp>=1.28.1,<2.0.0`；入口 `bridge-mcp-ghidra`，默认 stdio；插件 HTTP 默认地址为 `http://127.0.0.1:8089` |

**用途：保留作独立 Ghidra MCP 接口。** 上游声明支持 Ghidra 项目的反编译、交叉引用、函数与变量改名、类型和注释修改，并提供 GUI/headless 方式。适合需要 AI 操作 Ghidra 项目时单独接入客户端；这些能力尚未在本机实际运行验证。

**与 REA 的关系：当前 REA 的 Ghidra provider 不读取这个插件。** REA 调用 Ghidra 的 `analyzeHeadless` 和自带 `ReaGhidraBridge.java`，使用自己的协议、目标准入和临时数据库生命周期。该扩展不能直接填入 `GHIDRA_INSTALL_DIR`，也不能直接替代 REA 的 provider。相关代码见 `src/ghidra/GhidraProviderClient.ts` 和 `src/ghidra/GhidraLauncher.ts`。

本次在 `D:\安装包\Assemble` 中未找到 Ghidra 的 `ghidraRun.bat` 或 `analyzeHeadless.bat`；当前 PATH 也未找到 `java`/`javac`，JDK 尚未定位。若要启用此插件，还需先定位 Ghidra 本体与 JDK。插件的已声明基线为 Ghidra 12.1.2；REA 的真实验证基线为 12.1.4，两者共同使用同一安装时需验证该扩展对 12.1.4 的兼容性。

现有 REA 与 IDA MCP 已完成真实分析验证。GhidraMCP 可作为补充，当前先归档即可。本次只检查包内容、元数据和项目接入代码，未安装扩展、运行桥接或修改客户端注册。

## REA 基础环境

| 工具 | 用途和优先级 | 应保存的包 | 官方入口 |
| --- | --- | --- | --- |
| Node.js 与 npm | REA 必需。源码开发固定 Node 24.18.0、npm 11.16.0；运行 REA 支持 22.x ≥22.19、24.x ≥24.11 或 26+ | Windows x64 MSI 或 ZIP。npm 随 Node 提供；需要源码开发时再核对 npm 的固定版本 | [下载页](https://nodejs.org/en/download)；[24.18.0 文件目录](https://nodejs.org/dist/v24.18.0/) |
| REA | CLI 和 MCP 主程序 | 固定版本 npm 包与对应版本源码；整理时 npm latest 为 6.4.0 | [项目仓库](https://github.com/morluto/rea)；[6.4.0 npm 包](https://registry.npmjs.org/rea-agents/-/rea-agents-6.4.0.tgz) |
| Python | 走 IDA MCP、Frida 或 Linux ELF 工具时需要；基础 JavaScript/Ghidra 路线不需要 | 与所选 IDAPython 和上游工具兼容的 64 位安装包。现代 ida-pro-mcp 声明 Python 3.11+；实际版本同时受 IDA 约束 | [Windows 下载](https://www.python.org/downloads/windows/) |
| uv | 采用上游现代 IDA 的 uv 工作流时准备 | Windows x64 发布包；对应系统发布包另存 | [官方 Releases](https://github.com/astral-sh/uv/releases) |
| HCLI | 可选的 Hex-Rays 独立管理工具，用于厂商下载、授权和插件管理；本清单的 REA/mrexodia 安装路线不要求它 | Windows x64 独立程序。安装 IDA 不代表 `hcli` 已安装或位于 PATH | [官方安装说明](https://hcli.docs.hex-rays.com/getting-started/installation/)；[官方 Releases](https://github.com/HexRaysSA/ida-hcli/releases) |
| Git | 获取源码、插件和固定提交时准备 | Git for Windows x64 安装包或便携包 | [Windows 下载](https://git-scm.com/downloads/win) |
| 7-Zip | 解压安装包、应用资源和归档材料；常用辅助 | Windows x64 安装包 | [官方下载](https://www.7-zip.org/download.html) |
| Chrome 或现有 Edge | 网页和浏览器运行时分析需要 Chrome 系浏览器的 CDP 接口 | 已有 Edge 可先用；下载 Chrome 时优先保存完整离线安装包 | [Chrome 官方入口](https://www.google.com/chrome/) |

## REA 原生分析引擎

Ghidra、IDA、Hopper 是按平台和目标选择的替代路线，不必全部安装。

| 工具 | 选择版本和下载内容 | REA 接入边界 | 官方入口 |
| --- | --- | --- | --- |
| Ghidra | **12.1.4**，下载 `ghidra_12.1.4_PUBLIC_20260921.zip`，约 543 MB；选运行发行包，跳过 Source code 压缩包 | REA 接纳 12.1.x。Linux/macOS 支持 x64/arm64，并需匹配的原生反编译组件；Windows x64 是实验性只读 P0 | [固定版本发布页](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build)；[PUBLIC ZIP](https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip) |
| Eclipse Temurin JDK | **完整 JDK 21 x64**，MSI 或 ZIP；选择 JDK，避免误下 JRE。21 的补丁版可按实际下载记录 | Ghidra 12.1 发行版声明 JDK 21+；REA 实测基线为 JDK 21。也可供 Android 路线使用，但系统包需分别保存 | [Temurin 21 下载](https://adoptium.net/temurin/releases/?version=21)；[Ghidra 版本说明](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/GhidraDocs/GettingStarted.md) |
| IDA Pro 与 Hex-Rays | 按授权下载 IDA 与目标架构对应的反编译器；REA 初始真实验证包含 Windows x64 IDA 9.3 | 商业授权。伪代码需要相应反编译器授权。REA 的 IDA 适配器提供只读分析；IDA Free 不能替代该上游接入路线 | [IDA 官方产品与获取入口](https://hex-rays.com/ida-pro) |
| mrexodia/ida-pro-mcp | GUI 接入保存 **legacy 1.4.0**；headless supervisor 接入按 REA 已验证提交 `c133c3853faa111a9b00ee615c013b720d0c4acd` 保存源码及依赖 | GUI 接入和现代 supervisor 是不同协议。legacy 1.4.0 的旧 idalib SSE 服务不能替代现代 supervisor。上游最新 main 和其他 IDA MCP 服务不能直接视为已兼容 | [legacy 1.4.0](https://github.com/mrexodia/ida-pro-mcp/releases/tag/1.4.0)；[supervisor 固定提交说明](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/README.md) |
| Hopper Disassembler | 按 macOS 或 Linux 下载厂商完整发行包。项目文档记录过 6.1.0-demo 的真实验证；新版本需验证实际接入 | 商业软件，Demo 有厂商限制。REA 当前支持 macOS/Linux 路线；Windows 工作机无需为本机路线下载 | [官方各平台下载](https://www.hopperapp.com/download.html) |

**Windows Ghidra 限制：** 当前本地源码只接纳原生、非托管、非 DLL 的 x86 或 x86-64 PE 应用；目标和临时目录需在固定本地 NTFS 卷上。它不提供 Windows 注释修改、GUI 控制或任意格式分析。Ghidra 自身 GUI 能打开的文件范围不等于 REA Windows 接口的范围。较早 REA npm 包还可能只支持 x86-64，见[项目 Windows P0 指南](windows-ghidra-p0.md)。

## Windows 手工逆向辅助工具

以下工具用于手工分析、补充证据和处理目标。它们不是 REA 原生分析引擎，也不是安装 REA 的前置条件。

| 工具 | 解决的问题 | 下载建议 | 官方入口 |
| --- | --- | --- | --- |
| x64dbg | EXE/DLL 动态调试、断点、寄存器、内存和导入重建 | 完整便携包；保留 x32dbg、x64dbg 及配套文件，分别用于 32/64 位目标 | [官方网站与下载](https://x64dbg.com/) |
| Detect It Easy | 判断文件类型、编译器、壳和打包特征 | Windows x64 完整应用发行包；不要仅下载 `db` 或 `db_extra` 数据库更新 | [官方 Releases](https://github.com/horsicq/Detect-It-Easy/releases) |
| HxD | 十六进制查看、搜索、比较及编辑副本 | 按需要选安装版或便携版 | [官方下载](https://mh-nexus.de/en/hxd/) |
| Sysinternals Suite | Windows 进程、文件、注册表、模块和网络行为线索 | 保存整个 Suite；常用 Process Monitor、Process Explorer、Strings、TCPView、Sigcheck | [微软官方下载](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) |
| WinDbg | Windows 崩溃转储、用户态调试和内核相关分析 | 按微软页面获取支持当前 Windows 的安装材料 | [微软安装入口](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/) |
| Resource Hacker | 查看 EXE/DLL 的图标、字符串、对话框等资源 | 官方安装版或 ZIP | [官方下载](https://www.angusj.com/resourcehacker/) |
| Dependencies | PE 导入和 DLL 依赖检查 | Windows x64 发布包，并保存其声明的运行库依赖 | [官方 Releases](https://github.com/lucasg/Dependencies/releases) |
| Wireshark | 网络抓包、协议分析和 PCAP/PCAPNG 查看 | Windows x64 安装包；按安装器要求准备 Npcap。REA 当前没有这里的 PCAP 原生解析接口，网页证据接入优先用 HAR | [官方下载](https://www.wireshark.org/download.html) |

## .NET 和 Electron

| 工具 | 用途 | 是否为 REA 必需 | 官方入口 |
| --- | --- | --- | --- |
| ILSpy | .NET C# 反编译和元数据浏览 | 手工辅助；REA 自身静态元数据/CIL 分析不要求它。下载发布二进制，并按该版说明准备运行库 | [官方 Releases](https://github.com/icsharpcode/ILSpy/releases) |
| dnSpyEx | .NET 反编译、调试和程序集检查 | 手工辅助；保存适合目标的 win64/win32 包及其依赖。不是 REA 内置调试接口 | [官方 Releases](https://github.com/dnSpyEx/dnSpy/releases) |
| .NET SDK 或 Desktop Runtime | 运行所选辅助工具，或编译验证恢复出的代码 | 按辅助工具需求下载。只运行工具时未必需要 SDK；REA 静态分析本身不要求 .NET SDK | [微软下载](https://dotnet.microsoft.com/en-us/download) |

Electron/JavaScript 的目录、ASAR、模块关系和 source map 静态分析使用 REA 与 Node.js 即可。浏览器运行时使用 Chrome 系 CDP；Node/Electron 的 V8 Inspector 路线也使用已有 Node/Electron，不需要另下原生反编译器。

## Android

| 工具 | 应保存的版本或包 | 用途和平台限制 | 官方入口 |
| --- | --- | --- | --- |
| jadx-headless-mcp | **0.7.1** 的 `jadx-headless-mcp-0.7.1-all.jar`，约 40.6 MB | **REA Android 接入必需**，配完整 JDK 17+。当前适配器支持 Linux/macOS，macOS arm64/JDK 21 有真实验证；Windows 原生接口不支持 | [0.7.1 发布页](https://github.com/1013503897/jadx-headless-mcp/releases/tag/v0.7.1)；[all.jar 直链](https://github.com/1013503897/jadx-headless-mcp/releases/download/v0.7.1/jadx-headless-mcp-0.7.1-all.jar) |
| JADX GUI | 对应系统的完整发布包 | 手工查看 Java/DEX。可在 Windows 手工使用，但不能替代上面的 headless JAR | [官方 Releases](https://github.com/skylot/jadx/releases) |
| Apktool | 配套启动脚本与同一版本的 JAR | 手工解码资源、Manifest 和 smali；不属于 REA Android 必需依赖 | [官方安装与下载说明](https://apktool.org/docs/install/) |
| Android Platform Tools | 对应系统的完整 ZIP，含 adb/fastboot | 需要连接设备、取包、日志或动态分析时准备；REA 离线 APK 静态分析不需要设备、模拟器或完整 Android Studio | [Android 官方下载](https://developer.android.com/tools/releases/platform-tools) |

Windows 工作机如需使用 REA Android 接口，应另备 Linux/macOS 环境，在该环境安装 REA/JDK 并运行分析。WSL 可作为准备 Linux 环境的方式，但不据此承诺每条真实 provider 工作流都已验证。

## 网络和动态插桩

| 工具 | 用途 | REA 接入或依赖要求 | 官方入口 |
| --- | --- | --- | --- |
| mitmproxy 与 mitmdump | HTTP/HTTPS 流量捕获和离线流量材料 | HAR 1.2 文件可直接交给 REA，不要求安装代理。REA 读取原生 `.mitm` 格式目前要求 **Linux mitmdump 12.2.3**；Windows 手工抓取材料可优先导出 HAR | [官网](https://www.mitmproxy.org/)；[官方安装说明](https://docs.mitmproxy.org/stable/overview/installation/) |
| Frida | 手工运行时插桩、函数调用和参数观察 | 按需保存 Python 包和对应平台/架构的 server 或 Gadget；客户端与目标端组件保持匹配。当前 REA 没有直接的 Frida provider | [官方安装说明](https://frida.re/docs/installation/) |

## Linux ELF 崩溃和固件

这一组有明确平台和版本要求，不应收成 Windows EXE 工具包。

| 工具或依赖组 | REA 要求 | 下载与部署注意 | 官方入口 |
| --- | --- | --- | --- |
| pwntools、pyelftools、Unicorn | **4.15.0、0.33、2.1.2**，三个版本都需匹配 | 在 Linux x64 的独立 Python 环境中保存完整依赖；用于 ELF 和记录的 core 分析。Windows wheel 不能替代 Linux 环境材料 | [pwntools 官方安装](https://docs.pwntools.com/en/stable/install.html)；[项目固定依赖说明](../third_party/pwntools/README.md) |
| GDB | 项目真实验证基线 **13.1** | 请求可选的 debugger mapping context 才需要；用目标 Linux 发行版的包源保存软件包与依赖 | [GDB 官方源码镜像](https://sourceware.org/gdb/) |
| pwndbg | 项目真实验证基线 **2026.09.15** | 保存源码/发行包、`gdbinit.py` 和其 Python 环境；仅查看记录的 core 基础事实时不需要它 | [固定版本 Releases](https://github.com/pwndbg/pwndbg/releases/tag/2026.09.15) |
| Binwalk | 接纳 **3.1.x**，报告解析实测 **3.1.0** | REA 固件区域识别。保存 Linux 发行材料或源码与构建依赖；GitHub Source code 本身未必是可直接运行的工具 | [3.1.0 官方发布](https://github.com/ReFirmLabs/binwalk/releases/tag/v3.1.0) |
| Unblob | 接纳 **26.6.x**，报告解析实测 **26.6.4** | REA 固件提取。还需按格式保存外部提取器，例如 ext 文件系统的 `debugfs`；保留其默认 sandbox 要求 | [26.6.4 官方发布](https://github.com/onekey-sec/unblob/releases/tag/26.6.4) |
| util-linux 的 prlimit | Binwalk/Unblob 接口必需 | 属于 Linux 系统依赖；按 Linux 发行版的软件包保存，通常位于 `/usr/bin/prlimit` | [项目固件前置条件](firmware-analysis.md#caller-supplied-tools) |

固件当前真实验证范围为 Linux x64。Hopper 的 Linux 路线另需 Python 3、Xvfb、X11/XTEST 和相应共享库，具体按[安装指南](installation.md#launcher-paths-and-troubleshooting)准备。Linux 程序行为捕获还需要原生 PTY；安装上述静态引擎不会自动获得 Windows 的对应运行时功能。

需要重编译原生恢复代码、构建 REA 源码或执行真实工具验证时，再备 [Visual Studio Build Tools 与 Windows SDK](https://visualstudio.microsoft.com/downloads/) 或 Linux/macOS 对应编译工具链。普通用户使用已发布 REA 包不需要为了 Windows Ghidra 接口自己编译 native addon。

## 统一存放方式

可以把下面的目录作为下载库，例如放在 `D:\ReverseTools`。这是归档建议，各工具实际安装目录可以不同。

```text
D:\ReverseTools\
  00_说明与版本记录\
  01_基础环境\         Node、Python、uv、Git、7-Zip
  02_原生静态分析\     Ghidra、JDK、IDA、IDA_MCP
  03_Windows动态分析\  x64dbg、Sysinternals、WinDbg
  04_文件与资源\       DetectItEasy、HxD、Dependencies、ResourceHacker
  05_NET与Electron\    ILSpy、dnSpyEx、所需.NET运行库
  06_网络与插桩\       Wireshark、抓包依赖、mitmproxy、Frida
  07_Android\          JADX_GUI、JADX_HEADLESS、Apktool、PlatformTools
  08_Linux专用\        pwntools环境、GDB、pwndbg、Binwalk、Unblob、Hopper
  09_REA发行包\        固定版本npm包、源码、依赖材料
```

每个工具目录保留完整原始包、官方来源说明、版本、OS/架构、下载日期和 SHA-256。便携工具保留整个目录；不要只摘出一个 EXE。商业工具的安装材料和授权按账户实际权限保存。

**集中归档与完全离线安装是两回事。** REA 的 `.tgz`、插件源码 ZIP 或一个 Python 主包不包含所有传递依赖。若还需要离线部署，必须在相同 OS/架构上额外准备 npm 依赖缓存、完整 Python wheels、Linux 软件包依赖和工具运行库；仅保存上述直链包不足以完成离线安装。Git 子模块内容也不会因为保存主仓库 ZIP 就自动齐全。

## 固定包与校验

以下哈希分别来自 Node 官方 `SHASUMS256.txt`、Ghidra 官方发布页，以及 JADX 发布资产与 REA 固定源码记录。

| 文件 | SHA-256 |
| --- | --- |
| [node-v24.18.0-x64.msi](https://nodejs.org/dist/v24.18.0/node-v24.18.0-x64.msi) | `e30cd4ca15529583afe0efc978f1ae3ab3a93c2400c222d0752d17900552ebb3` |
| [node-v24.18.0-win-x64.zip](https://nodejs.org/dist/v24.18.0/node-v24.18.0-win-x64.zip) | `0ae68406b42d7725661da979b1403ec9926da205c6770827f33aac9d8f26e821` |
| [ghidra_12.1.4_PUBLIC_20260921.zip](https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip) | `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db` |
| [jadx-headless-mcp-0.7.1-all.jar](https://github.com/1013503897/jadx-headless-mcp/releases/download/v0.7.1/jadx-headless-mcp-0.7.1-all.jar) | `6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75` |

Node 的[原始校验清单](https://nodejs.org/dist/v24.18.0/SHASUMS256.txt)可一起保存。下载后在 PowerShell 中按实际文件路径校验，例如：

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath 'D:\ReverseTools\02_原生静态分析\ghidra_12.1.4_PUBLIC_20260921.zip'
```

## 下载后接入 REA

已安装 REA 时先检查需要的引擎：

```powershell
node --version
npm --version
rea --version
rea doctor --provider ghidra --json
# 选择 IDA 路线时改为：
rea doctor --provider ida --json
```

Ghidra 路径设置按[REA 安装指南](installation.md#ghidra)，IDA 接入按[IDA provider 指南](ida-provider.md)。`doctor` 检查前置条件和配置，不等于已完成真实二进制分析，也不证明当前聊天已连接 MCP。

需要注册客户端时运行 `rea setup`，先阅读计划再按提示确认；下载清单本身不安装软件或修改客户端配置。已有可用注册无需重复 setup。REA 不会自动替你安装或升级 Node、npm、Java、Ghidra、IDA 及这些辅助工具。

## REA 要求的项目依据

- [总体目标和支持范围](../README.md#what-you-can-analyze)
- [基础环境与引擎安装](installation.md)
- [Windows Ghidra P0](windows-ghidra-p0.md)
- [IDA 协议与真实验证范围](ida-provider.md)
- [Android 引擎要求](android-analysis.md)
- [固件引擎要求](firmware-analysis.md)
- [ELF 固定依赖](binary-diagnostics.md)
- [记录的崩溃与可选调试上下文](recorded-crashes.md)
- [HAR 与 mitmproxy 文件接入](web-network-captures.md)
- [.NET 静态分析与外部辅助工具](managed-code-analysis.md)
