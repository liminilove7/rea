# AION Classic 客户端离线分析

日期：2026-10-10。来源：`F:\SOFTWARE\永恒之塔\aionclassic2`，重点为 `bin64`。工作区：`F:\RVE-Workspace\cases\aionclassic2-2026-10-10`。

本轮完成了目录盘点、PE 结构检查、核心文件副本及哈希校验、数据资源解包、二进制 XML/对话转换和配置解码。未启动游戏客户端、附加游戏进程或修改客户端原件。**EXE/DLL 的保护尚未移除，未生成脱壳后的可执行文件。**

## 版本与模块

| 模块 | 文件版本 | 结构观察 |
| --- | --- | --- |
| Aion.bin | 1926.1027.0901.7252 | AMD64 PE；入口 RVA `0x5ee000`；`.taggant` 入口、异常/随机节名、仅一个可见导入，强烈提示保护层 |
| Game.dll | 1926.1027.0901.7252 | AMD64 PE；入口 RVA `0x141a000`；相似保护结构；导出 CreateGameInstance、CryModuleGetMemoryInfo |
| CrySystem.dll | 1926.1027.0901.7252 | AMD64 PE；入口 RVA `0x77b000`；相似保护结构；仍能读到 27 个导出 |
| ScriptDLL64.dll | 1926.1027.0812.7208 | 标准 `.text/.rdata/.data/.pdata/.rsrc/.reloc`；可见 79 个 KERNEL32 导入；导出 GetInterface，适合先静态分析 |

上述入口地址是当前文件入口，不是已经恢复的原始 OEP。正常节表也不能证明完全没有局部混淆。具体保护器名称和版本尚未用可工作的签名引擎确认。

其余引擎组件包括 Cry3DEngine、CryAnimation、CryEntitySystem、CryPhysics、CryScriptSystem、CrySoundSystem、XRenderD3D9；媒体支持文件包含 Bink 和 FMOD，CEF 位于独立子目录。模块用途由名称及导入/导出结构推断，尚未追踪全部调用链。

四个核心文件已复制到 `samples`，副本 SHA-256 与原件一致：

| 文件 | SHA-256 |
| --- | --- |
| Aion.bin | `17c8de936526f119e16c1923ba5922d3a524698f04c01562fc878424653cda1e` |
| Game.dll | `834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786` |
| CrySystem.dll | `8705aeef77411a28e178832f2f242128b0b018b9546f58878c9e69df8f4e9061` |
| ScriptDLL64.dll | `ea42f2e51de3d46b14e958f11c4f33dc9e78a92cf62765c6a42f0cb79584ca27` |

## 资源与数据

客户端共 3,244 个文件、2,073 个 `.pak`。其中 2,064 个以 `AF B4 FC FB` 开头，8 个以 `04 00 00 00` 开头，1 个是普通 ZIP。扩展名相同不代表同一种格式。

数据提取范围为 `data` 下的 PAK、`L10N/CHS/CHS.pak`、`L10N/CHS/Data/Data.pak`，另含 `bin32/bin32.pak` 的 Lua 文件。没有把整个客户端的贴图、模型、声音、视频全量解压。

- 187 个数据包，索引 31,039 个内部条目。
- 21,626 个文本类数据文件完成提取，逐一通过原包记录的长度和 CRC32 校验。
- 4,280 个二进制 XML 完成转换，输出可由 XML 解析器重新读取。
- 16,682 个编码对话文件完成转换。6 个旧文件采用单字节编码，编码根据区域路径推断并通过严格解码；其中 3 个源文件存在“UTF-16 BOM + 单字节正文”的异常。保留对应 `.decoded.bin`，便于回溯字节而不依赖字符集判断。
- `system.cfg` 解码得到 88 项 `key=value` 设置；原文件未覆盖。

资源包变体的目录标志与 ZIP 对应，但内容仍有变换；仅改 ZIP 标识不足以提取。当前选中的数据使用公开格式中的第二套变换参数，提取正确性以每个条目的长度/CRC 结果确认。格式参考：[PAK codec](https://github.com/giordanidev/aion-pak-manager/blob/main/backend/parse/pak-codec.ts)、[解包实现](https://github.com/giordanidev/aion-pak-manager/blob/main/backend/core/unpak.ts)、[Gibbed.Aion 二进制 XML](https://github.com/gibbed/Gibbed.Aion)、[对话格式](https://github.com/giordanidev/aion-pak-manager/blob/main/backend/parse/html-crypt.ts)。

## 可直接使用的数据表

以下路径都相对于工作区 `exports/decoded`。数量是根节点下的记录数，不能视为服务器当前实际启用的数量。

| 数据 | 路径 | 记录数 |
| --- | --- | ---: |
| 物品 | `data/items/items/client_items.xml` | 56,923 |
| 技能 | `data/skills/skills/client_skills.xml` | 7,160 |
| 技能学习 | `data/skills/skills/client_skill_learns.xml` | 7,360 |
| NPC | `data/npcs/npcs/client_npcs.xml` | 30,424 |
| 任务 | `data/Quest/Quest/quest.xml` | 4,696 |
| 中文物品名称 | `L10N/CHS/Data/Data/Strings/client_strings_item.xml` | 65,523 |
| 中文物品名称补充 | `L10N/CHS/Data/Data/Strings/client_strings_item2.xml` | 17,290 |
| 中文技能文本 | `L10N/CHS/Data/Data/Strings/client_strings_skill.xml` | 16,970 |
| 中文任务文本 | `L10N/CHS/Data/Data/Strings/client_strings_quest.xml` | 13,339 |
| 显示等本机配置 | `system.cfg` | 88 |

物品表包含 `id/name/desc/weapon_type/icon_name/price/min_damage/max_damage` 等字段；技能表含目标、类型、图标、效果等字段；NPC 表含模型、体积、移动速度等字段；任务表含等级、种族、职业与奖励等声明。

`desc` 等字段通常是本地化键，可关联语言表的 `name`，再读 `body`。已验证示例：物品 100000001 的 `STR_SWORD_CIRCULOUS` 对应“瑟库拉斯之剑”；技能 1 的描述键对应“基础长剑修炼”。这些是客户端静态声明，不是服务器权威规则或运行时数据。

`data/China` 中还有区域变体表，已分别导出。未验证客户端的覆盖/加载顺序，不自动把区域表覆盖到通用表。

`LocalVersion.xml` 的实际内容不是普通 XML，尚未还原其格式；准确构建标识目前来自 PE 版本资源。`bin64/config.ini` 的地址配置仅说明文件中的声明，本次未连接或验证任何服务端。

## 文件位置与复现

- `reports/client-inventory.json`：全目录路径、大小和修改时间。
- `reports/pe-modules.json`：47 个 bin64 根目录 PE 文件的头、节、导入/导出、版本和哈希。
- `reports/resource-packages.json`：全部 PAK 的头尾特征。
- `reports/data-archive-index.json`：187 个数据包的内部文件目录。
- `reports/data-extraction.json`、`data-summary.json`：每项提取、CRC、XML 验证结果。
- `reports/dialog-decoding.json`：对话文件转换、字符集推断和异常说明。
- `exports/raw`：解包后的原始数据；`exports/decoded`：XML/对话/配置的可读版本。
- 关键报告备份在 `D:\RVE\.codex\local\aion-report-backup`；大资源和样本目前在 F:。

分析脚本在 `D:\RVE\.codex\local`：`inspect_aion.py`、`aion_pak.py`、`extract_aion_data.py`、`decode_aion_dialogs.py`。Python PE 解析依赖仅安装在该目录下的 `python-libs` 中。

## 后续边界

主程序脱壳需要进一步识别保护器并选择动态分析环境，当前等待用户选择。资源提取本身不等于 EXE/DLL 脱壳。没有启动 AION、加载其保护组件、禁用保护、安装驱动或配置任何自动启动项。

F: 为可拔出的 exFAT 移动盘，Windows 查询的 HealthStatus 为 Warning；这不是硬件故障诊断。分析中不要拔盘，保存并退出工具后再安全弹出。拔盘不会结束进程；一键关闭入口留在 D:，即使 F: 不在也可运行。

## 2026-10-10 程序本体深度分析补充

### 样本范围与结论

本轮严格针对 `F:\SOFTWARE\永恒之塔\aionclassic2\bin64` 的本机文件。对四个主要模块的工作副本重新计算 SHA-256，并与该目录的源文件逐一核对，全部一致。未执行游戏、连接服务器或加载保护驱动。

结论分为三层：

1. **已验证的静态事实**：入口跳转、第一层解码算法、导出函数、C++ RTTI、虚表地址、名称到函数的配对表、属性分派和读取指令。
2. **有代码证据的语义解释**：CXGame 全局对象、玩家实体解析链、属性快照与缓存、组件字段用途。仍缺运行时交叉验证。
3. **尚未完成**：完整 EXE/DLL 脱壳、原始入口 OEP 确认、导入表重建、可运行重建文件、实时对象地址/属性值验证。不得将本轮的 4 KB 解码结果标成“完整脱壳”。

本轮深入四个主模块；此前的 47 个 bin64 根目录 PE 清单仍有效，但不表示所有模块的函数都已逐一分析。

| 文件 | PE 版本 | SHA-256 |
|---|---|---|
| Aion.bin | 1926.1027.0901.7252 | `17c8de936526f119e16c1923ba5922d3a524698f04c01562fc878424653cda1e` |
| Game.dll | 1926.1027.0901.7252 | `834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786` |
| CrySystem.dll | 1926.1027.0901.7252 | `8705aeef77411a28e178832f2f242128b0b018b9546f58878c9e69df8f4e9061` |
| ScriptDLL64.dll | 1926.1027.0812.7208 | `ea42f2e51de3d46b14e958f11c4f33dc9e78a92cf62765c6a42f0cb79584ca27` |

### 地址的含义

以下没有特别标明的模块地址均为 **RVA（模块内相对地址）**。运行时地址应为 `实际加载基址 + RVA`，本轮未观察实际加载基址。PE 中 Aion.bin 的首选基址为 `0x140000000`，其余三个模块为 `0x180000000`；不能将其假定为 ASLR 后的实际地址。

`对象 + 0x119C` 是对象成员偏移，`Game.dll + 0xD647C0` 是模块内位置，两者不是同一类“偏移”。JSON 每个地址尽量同时记录 RVA、首选 VA、文件偏移、所属节。没有文件原始数据支撑的零初始化区域，文件偏移记为 null。

### 保护入口与第一层还原

三个受保护模块的 PE 导入目录目前均仅显示 `kernel32.dll!lstrcpy`。它们存在类似的跳转与解码结构，原始代码、字符串和 RTTI 仍有大量可读部分；不能笼统认为整个文件都被加密。保护器品牌和版本未确认。

| 模块 | 文件入口 RVA | 入口跳转链中的另外两处 | 第一层解码桩 RVA | 被解码区 RVA | 解码后继续地址 | 下一跳 RVA |
|---|---|---|---|---|---|---|
| Aion.bin | `0x5EE000` | `0x5EE00A → 0x5F000F` | `0x5E2000` | `0x149000` | `0x149014` | `0x14A835` |
| Game.dll | `0x141A000` | `0x141A00A → 0x141C00F` | `0x13C1000` | `0xE26000` | `0xE26014` | `0xE277D5` |
| CrySystem.dll | `0x77B000` | `0x77B00A → 0x77D00F` | `0x762000` | `0x2BE000` | `0x2BE014` | `0x2BF7F1` |

解码桩通过 call/pop 取得自身位置，计算目标缓冲区；随后对 0x1000 字节、共 1024 个小端 uint32 执行：

```text
明文 DWORD = ((原 DWORD XOR xor_key) + add_key) mod 2^32
```

| 模块 | xor_key | add_key |
|---|---|---|
| Aion.bin | `0x76145AC7` | `0x6D21FE52` |
| Game.dll | `0x4AEA85EB` | `0x25DCB9BB` |
| CrySystem.dll | `0x0C55E334` | `0x66768119` |

关键依据：桩内 `mov ebx,0x1000`、`shr ecx,2`、`xor dword ptr [rsi],eax`、`add dword ptr [rsi],ebx`、每轮地址增加 4。上述两个密钥来自实际压栈立即数。脚本核验这些关键指令后才变换数据。

三个 4 KB 结果均已保存为独立 `.bin`，源 PE 未修改。逆变换逐字节匹配源数据，解码区 `+0x14` 出现有效的直接跳转；下一跳在原文件中可读，开始保存寄存器并计算保护器上下文地址。逆变换验证证明字节变换可复现，不等于重建程序可运行。

产物：`exports/protection-stage1/`。JSON 包括每份输出的 SHA-256。第一层区域包含数据，顺序反汇编产生的 `add [rax],al` 等文本不是已执行路径；应以 `entry-chain` 和明确分支为准。下一阶段仅导出入口窗口，尚未还原完整控制流或原始导入解析。

### 模块接口、全局对象和类

| 模块 | 项目 | RVA | 证据/含义 |
|---|---|---|---|
| Game.dll | CreateGameInstance | `0x33A8A0` | 导出；`lea rax,[…]; ret`，完整函数 8 字节 |
| Game.dll | CXGame 静态对象 | `0xD647C0` | 上述函数返回其地址；不是从此地址读一个对象指针 |
| Game.dll | CXGame 静态初始化代码 | `0x33AAF0` | 写入三张与 RTTI 一致的虚表 |
| Game.dll | CXGame 主虚表 | `0x820678` | 对象 +0；RTTI 子对象位移 0 |
| Game.dll | IConsoleSink 子对象虚表 | `0x820660` | 对象 +8；RTTI 与初始化写入一致 |
| Game.dll | IInputEventListener 子对象虚表 | `0x820648` | 对象 +0x10；RTTI 与初始化写入一致 |
| Game.dll | Player 构造代码 | `0x4F87E0` | 调用基类构造并写入 Player 虚表，初始化大量成员 |
| Game.dll | Player 虚表 | `0x841CD8` | RTTI 名字 `.?AVPlayer@@` |
| CrySystem.dll | CreateSystemInterface | `0x10FE80` | 导出；检查输入结构 +0x838，必要时分配 0x3610 字节并构造 |
| ScriptDLL64.dll | GetInterface | `0x6E21B0` | 保存 RCX 并返回固定对象地址，完整函数 15 字节 |
| ScriptDLL64.dll | 输入指针存储槽 | `0x103F710` | GetInterface 写入；处于 .data 的零初始化范围 |
| ScriptDLL64.dll | IScriptDLLImpl 对象 | `0xDAE450` | GetInterface 返回地址 |
| ScriptDLL64.dll | IScriptDLLImpl 虚表 | `0xA97118` | 文件中对象首指针与 RTTI 对应，识别到 10 个连续槽 |

`CXGame` 的继承关系包含 `IXGame → IGame`，以及位移分别为 8、16 的 `IConsoleSink`、`IInputEventListener`。`Player` 的 RTTI 基类链包含 `CharacterObject → GameObject → IEntityContainer`，此次观察到的基类成员位移均为 0。

ScriptDLL64 的 GetInterface 可还原为以下简化语义（参数类型尚未恢复）：

```text
*(ScriptDLL64_base + 0x103F710) = input_pointer;
return ScriptDLL64_base + 0xDAE450;
```

其虚表 slot 0 的 RVA 为 `0x6E04D0`，返回常数 `0x28`，目前不能断言这是版本号还是大小。slot 2/3/4/5/9 分别返回其他静态结构地址，slot 6/7/8 是跳转包装函数；详细槽位和汇编见 `ScriptDLL64.dll.interface.json`。

RTTI 扫描识别数：Aion.bin 94 个类型描述符（91 个关联到虚表候选）；Game.dll 876（712）；CrySystem.dll 850（414）；ScriptDLL64.dll 18,905（18,901）。这是按 MSVC x64 结构校验的静态恢复结果，不等于业务类总数。合并的可执行/可写节会降低仅靠节标志识别虚表边界的可靠性，关键类另外使用写入代码交叉核对。

### 玩家相关解析链

`CXGame` 主虚表字节偏移 `+0x1E0`（slot 60）指向 `Game.dll + 0x2B720`。该叶函数：

1. 从 `Game.dll + 0xD6CB08` 读取 16 位 ID，零值直接失败。
2. 从 `Game.dll + 0x94C7B0` 读取系统对象指针，空值直接失败。
3. 经该对象虚表 `+0x30` 以 ID 查找实体。系统对象的精确动态类型尚未验证。
4. 调用者将实体传给 `Game.dll + 0x4F9810`；该函数通过实体虚表 `+0xB8` 取得容器，再通过容器虚表 `+0x50`、接口编号 2 取得组件指针。

`GetPlayerPos` 和玩家属性快照函数都使用这条链，因此它是“本地玩家实体/组件解析链”的强静态证据。实际 ID、系统指针、组件指针和动态 RTTI 仍需在运行时确认；此处没有提供一个伪造的固定玩家堆地址。

### 属性绑定、分派和字段

已完整提取两段连续的“函数名指针 + 实现指针”表：

- `0x6CE6B0` 至 `0x6CEC40`（结束地址不含），89 项。
- `0x6CEDA0` 至 `0x6CEF50`（结束地址不含），27 项。

共 116 项；不是全程序所有脚本接口的总数。其他表和不连续项目未据此排除。相邻两项每项 16 字节，通过名称字符串、实现 RVA 和函数代码共同验证。

`Game.dll + 0xA2530` 将字符串参数分类：`player → 1`、`target → 2`、`party1…party6 → 3…8`、`summon → 9`。`Game.dll + 0xA2830` 按分类和属性 selector 读取数据。下表仅描述 **player 分支**，快照缓冲区起始位置为调用者的 `rbp-0x80`。

| 属性 | 实现 RVA | selector | 快照内偏移 | 宽度 | 在有效玩家组件存在时的数据来源 |
|---|---|---:|---|---:|---|
| UnitHP | `0xA17A0` | 0 | `+0x40` | 4 | 组件 `+0x119C`，按有符号值读取，负数夹到 0 |
| UnitHPMax | `0xA1800` | 1 | `+0x3C` | 4 | 全局缓存 `Game.dll+0xD71BB4` |
| UnitMP | `0xA1860` | 2 | `+0x48` | 4 | 全局缓存 `Game.dll+0xD71BC0` |
| UnitMPMax | `0xA18C0` | 3 | `+0x44` | 4 | 全局缓存 `Game.dll+0xD71BBC` |
| UnitClassID | `0xA1590` | 4 | `+0xA4` | 4 | 全局缓存 `Game.dll+0xD71C1C`；包装函数另外检查值小于 12 |
| UnitLevel | `0xA1680` | 5 | `+0x18` | 2 | 全局缓存 `Game.dll+0xD71B90`；零扩展读取 |
| UnitGender | `0xA16E0` | 6 | `+0x160` | 4 | 组件 `+0x22C` |

这份全局缓存起始 RVA 为 `0xD71B78`。`0x368E50` 先将其中 0xC8 字节复制到快照，再使用组件 `+0x119C` 覆盖快照生命值。快照偏移 `+0x40` 不能写成“Player+0x40 是血量”。无组件时另有选中记录回退分支；不同分类的 target/party/summon 也有不同支持范围，不能将表格直接套用到所有实体。

`UnitIsDead` 位于 `0xA1740`，走 `0xA27B0` 取得对象，随后检查 `+0xAB4`、`+0xAB0` 和 `+0x2C0` 的组合条件；并不是简单判断上述生命值是否等于零。完整状态枚举尚未命名。

属性定位证据链为：名称字符串 → 配对表中的实现地址 → 包装函数传入 selector → 0xA2830 的跳转表 → 快照字段 → 0x368E50 的填充来源。七项 selector、共同分派目标及主要地址均已另做二进制核对。

### 位置相关接口

- `GetPlayerMapPosition`：`Game.dll + 0xA10A0`。参数分类为 player 后，按顺序读取 `Game.dll+0xD65FEC`、`+0xD65FF0`、`+0xD65FF4` 的三个 float，转换为脚本数值返回。可称为该接口的位置缓存；坐标单位、轴方向及与世界坐标的关系未运行验证。
- `GetPlayerPos`：`Game.dll + 0x96300`。通过上述实体链取得组件，再经组件 `+8` 指针和被指对象虚表 `+8` 取得三分量向量；随后还有数值处理和格式化路径。没有将其粗略标成“人物 X/Y/Z 固定偏移”。完整人工核对的函数窗口为 `0x96300…0x96510`，跨多个 PE 展开信息片段。
- `UnitObjectID`：`0xA1190`；`UnitName`：`0xA1250`。名称和实现映射已确认，字符串对象内部布局尚未完整恢复。

### 工具结果、验证与限制

尝试本地 IDA 8.3 的命令行批处理后，日志出现 `Python3TargetDLL value is not set`、`No module named 'imp'`、`License not yet accepted, cannot run in batch mode`。本轮未修改注册表配置或运行其绿化程序，未声称 IDA 分析成功，未生成有效 IDA 数据库。

实际完成分析使用本项目私有目录中的 pefile 2024.8.26 与 Capstone 5.0.6。Capstone 仅安装到 `.codex/local/python-libs`，未改变系统 Python 包集。汇编语义和 `aion_static_notes.c` 为人工还原，不能当作 Hex-Rays 反编译结果或原始源码。

16 项离线检查全部通过：导出短函数字节、主虚表对应槽、七个属性 selector/分派调用、四份样本与源文件哈希一致、三个第一层解码结果的逆变换及入口跳转。这些检查不覆盖实时属性值、动态类型、游戏登录或重建程序运行。

PE 异常目录的 3,686 / 29,842 / 8,107 / 59,320 条范围是展开信息代码范围计数，不是完整且唯一的高级语言函数数量。叶函数可能没有条目，一个函数也可能包含多个片段。通用导出窗口和保护数据的线性反汇编不应全部视为可达代码。

### 本轮交付文件

主目录：`F:\RVE-Workspace\cases\aionclassic2-2026-10-10\reports\binary`。
同名备份：`D:\RVE\.codex\local\aion-report-backup\binary`。

| 文件 | 内容 |
|---|---|
| `summary.json`、`*.native.json` | 样本哈希、PE 入口、导入导出、地址与汇编窗口 |
| `*.entry-chain.json` | 按实际直接跳转追踪的保护入口链 |
| `stage1-summary.json`、`*.stage1.json` | 解码范围、密钥、输出哈希、字节验证及解码数据窗口 |
| `*.stage2-entry.json` | 下一层入口原始字节的反汇编窗口 |
| `*.rtti.json` | 全量匹配到的类型描述符、定位结构和虚表候选 |
| `Game.dll.focus-classes.json` | CXGame、Player、GameSystem 的基类和虚表 |
| `Game.dll.script-bindings.json` | 两段表共 116 项名称/实现配对 |
| `Game.dll.property-map.json` | 七项属性的实现、selector、快照位移与来源 |
| `Game.dll.focus-functions.json` | 关键属性/实体/构造函数逐指令证据 |
| `Game.dll.target-xrefs.json`、`Game.dll.xref-functions.json` | 异常目录范围内的引用扫描及关联代码；不含全部叶函数 |
| `ScriptDLL64.dll.interface.json` | GetInterface 和十个接口虚表槽 |
| `aion_static_notes.c` | 带限制条件的手工伪代码，不可编译 |
| `verification.json` | 16 项离线核对结果 |

第一层二进制片段另外备份在 D: 的 `aion-report-backup/binary/protection-stage1`，拔掉 F: 后仍可阅读报告和这些小片段。原程序、大资源和大型工作副本继续放在 F:。

复现脚本在 `D:\RVE\.codex\local`：`analyze_aion_native.py`、`trace_aion_native.py`、`decode_aion_stage1.py`、`export_aion_findings.py`。其中 `ida_aion_batch.py` 保留为失败的工具尝试记录，不是本轮结果来源。

下一阶段应沿保护器后续初始化继续恢复 OEP/导入；动态验证仍需要明确的隔离运行环境。当前机器用于游戏，本轮保持离线；没有创建自动启动项或常驻监控。会话结束前另行执行本地进程清理并记录结果。

## 攻击速度实战第一课：从名称追到取值过程

用户此前观察到：攻速可能并非固定地址直接存放的最终值，而是在使用前经过隐藏计算。本轮把这条线索保留为待验证假设；当前证据还不能确认具体加密方式、隐藏地址或计算公式。

### 已证实的三类线索

| 字符串 | Game.dll RVA | 当前发现 |
|---|---|---|
| UTF-16 `attackDelay` | `0x774918` | 名称转换代码和两类枚举表引用 |
| UTF-16 `attack_delay` | `0x776A50` | 资源字段名与数据记录描述表 |
| UTF-16 `AttackSpeed` | `0x7F6AA8` | 另一组名称表引用；其运行时用途尚未关联 |

不要仅因为名字相近就将三者认作同一个内存字段。尤其不能把属性编号当成员偏移。

### 路径一：属性名称转换成编号

在 `Game.dll + 0x86450` 所在代码中，`0x868BD` 引用 `attackDelay`。字符串比较匹配后，`0x868D1` 设置 `eax=0x1D`，然后把 AX 写入输出位置。表 `0x94E2F0` 也存放该名称指针，其后 `0x94E2F8` 的值为 `0x1D`，两项证据相互印证。

这证明该转换上下文中的 `attackDelay` 属性编号为 **29**。不证明 `Player+29` 是攻速，也不证明整程序所有出现立即数 29 的位置都处理攻速。扫描得到的 73 处参数立即数候选中，许多明显用于长度、其他枚举或通用类型分派，不能全部计为攻速引用。

### 路径二：基础攻击间隔记录的读取

`0x6ECAE8` 是 `attack_delay` 名称指针；后续描述数据中出现位移 `0x1BE` 和宽度 `2`。相邻 `attack_range`、`hit_count` 记录也采用相似布局。

更直接的证据来自 `Game.dll + 0x396E80`：

```text
保存 EDX 中的查询 ID
调用 0xE7EC0 查询记录，参数之一为 0x210
如果找不到，经过 0xE7D30 取得备用查询参数后重试
如果仍找不到，返回 0
找到记录时，返回 zero_extend(uint16(record + 0x1BE))
```

关键指令为 `0x396EC6: movzx eax, word ptr [rax+0x1BE]`。这里的 RAX 是查询函数刚返回的记录指针，不是已经确认的角色对象基址。参数 0x210 的精确含义尚未恢复，不能仅凭数值断言它就是完整结构体大小。

目前提取到五个直接调用点：`0x1D90E8`、`0x1DA84D`、`0x1DC1BB`、`0x1DC1C6`、`0x3B25B0`。查询记录及调用者的上下文支持“物品/武器基础攻击间隔”的解释，但尚未证明它代表带全部加成后的最终攻速。

### 路径三：显示时的换算

`Game.dll + 0x1D90C0` 从输入记录 `+0xC` 取得 ID，调用上述读取函数，然后执行：

```asm
movzx eax, ax
movd xmm1, eax
cvtdq2ps xmm1, xmm1
divss xmm1, dword ptr [Game.dll + 0x8754A0]
```

`0x8754A0` 的 float32 原始字节为 `00 00 7A 44`，实际值为 **1000.0**。后面代码将结果转成 double 并传给格式化函数。因此，字段从类似毫秒的整数转换成秒数显示，是有指令和常数支撑的解释；这个函数本身不等于最终攻击调度器。

资源交叉核对：已解包的通用物品表中，8,188 项具有 `attack_delay` 字段。例如剑 `100000001` 为 1400、锤 `100100001` 为 1500、匕首 `100200001` 为 1200。与上面显示换算相结合，分别得到 1.4、1.5、1.2。这里演示的是基础资源值，不能据此推断实际战斗中一定按这些间隔攻击。

### 尚未坐实的计算路径

`0x3B25B0` 的调用者沿本地实体链获取组件，经组件 `+0x1010` 和另一个函数取得查询 ID，再读取基础间隔。其后另一段代码出现“基础间隔 / 常数 × 另一个记录值”的浮点运算，并写入某记录的 `+0x50`、`+0x54`；还会调用保护区域中的 `0x1244AE3`。

这是真实的后续数值处理线索，但该分支可能属于技能或其他计时子系统。尚不能把它命名为最终普通攻击公式，也不能因为调用进入保护区域，就断言攻速值经过加密。还需确认调用者、参数、写回对象和使用这些结果的代码。

### 本课练习与验证状态

先能回答四个问题，再进入动态修改：

1. 为什么 `0x1D` 是属性编号，而 `0x1BE` 才是当前记录内的成员位移？
2. 为什么 RAX 在读取前由查询函数返回，而不是一个固定全局玩家地址？
3. 为什么搜索界面显示的 1.4，可能找不到资源中的整数 1400？
4. 为什么找到基础间隔，仍不能声称找到了角色最终攻速？

脚本 `analyze_attack_speed.py` 可复现本课核心证据；六项核对（名称指针、属性编号、描述表位移/宽度、读取指令、1000.0 常数）全部通过。结果为 `attack-speed-lesson.json`，其余 `attack-delay-*` 文件保留候选、调用点及资源例子。

当前未知：最终攻击速度的具体保护表示、计算入口、加成组合、更新时机及运行时效果。没有修改原游戏字节、角色内存、攻速值或保护组件。
