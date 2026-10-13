# AION ScriptDLL64 接口与编译脚本登记

这是通过 REA MCP 实际分析同批 ScriptDLL64.dll 的记录，补充[持续机制分析](AION持续分析.md)。原始 PE/RTTI 辅助读取与 REA 返回的指令分别记录；没有原生加载或执行客户端 DLL。

样本 SHA-256：`ea42f2e51de3d46b14e958f11c4f33dc9e78a92cf62765c6a42f0cb79584ca27`，首选基址 `0x180000000`。该模块与 Game.dll、CrySystem.dll 即使 VA 相同也不能合并地址。首次指令请求包括数据库导入和自动分析，耗时约250秒；后续查询使用同一私有数据库。[真实请求及响应](../evidence/continuous/20261012-script-interface/) · [四模块原始 PE 入口](../evidence/continuous/original-four-module-entries.json)。

## GetInterface 返回的是静态接口对象

唯一具名导出 `GetInterface` 的 RVA 为 `6E21B0`。实际指令将传入的 RCX 保存到全局 `18103F710`，返回地址 `180DAE450`。没有新建对象的调用；不能把保存的外部参数仅凭类型猜成 Player。

原始地址 `DAE450` 的首个 QWORD 指向 `180A97118`。其前一槽的 locator `180C2C570` 具有有效 MSVC x64 RTTI、自引用 RVA 及类型名 **`.?AVIScriptDLLImpl@@`**，子对象偏移为0。该绑定确认了返回对象的具体类型。

证据：[GetInterface 指令](../evidence/continuous/20261012-script-interface/script-module-interface-export-instructions.normalized.json)、[接口对象原始前缀](../evidence/continuous/20261012-script-interface/original-interface-return-prefix.json)、[原始 RTTI 与虚表](../evidence/continuous/20261012-script-interface/original-script-interface-rtti.json)、[可复算脚本](../client/analysis-code/continuous/inspect-script-interface.py)。

当前连续代码指针候选从虚表 `+0` 到 `+0x48` 共十项，下一 QWORD 为0；十个目标均已取得 REA 指令。这个边界是原始指针连续范围，不是完整 C++ ABI 或所有运行时扩展的证明。

| 虚槽 | 目标 RVA | 已观察行为 |
| --- | --- | --- |
| `00` | `6E04D0` | 返回整数 `0x28`；已由 Game 调用方绑定为要求的接口版本值，见下文 |
| `08` | `6E04E0` | 遍历登记结构，并调用保存在 `103F710` 的外部对象虚方法 |
| `10` | `6E0660` | 返回 `103F838` 地址 |
| `18` | `6E0670` | 返回 `103F860` 地址 |
| `20` | `6E0680` | 返回 IDA 表示为 `Buffer+104h` 的地址，精确业务类型未知 |
| `28` | `6E0690` | 返回 `103F890` 地址 |
| `30` | `6E0630` | 用 `103F848` 调用 `926E70`；后者形成 `%squest\event_quest.xml` 并交给下一级处理 |
| `38` | `6E0640` | 用 `103F848` 调用 `929D90` |
| `40` | `6E0650` | 用 `103F848` 调用 `929D00` |
| `48` | `6E06A0` | 返回 `103F880` 地址 |

槽 `08` 的外部调用形态与登记结构访问已观察；Game 侧调用者类型及部分实现已在下文补证。先期对 `103F710` 的三次引用查询均返回 `unreadable_output`，失败原文保留；不能将读取失败当空引用或不存在调用。

证据：[槽08](../evidence/continuous/20261012-script-interface/script-interface-slot-08-instructions.normalized.json)、[任务文件路径消费者](../evidence/continuous/20261012-script-interface/script-interface-map-core-op-a-retry-instructions.normalized.json)、[外部参数引用失败](../evidence/continuous/20261012-script-interface/script-interface-caller-parameter-xrefs-third.mcp.json)。其余目标、原始 QWORD 与 Evidence 绑定由[接口语义核对](../evidence/continuous/script-interface-verification.json)复核。

## damage 名称已绑定到具体编译脚本

REA 按字面 `damage` 搜索取得41条字符串，其中包含 `LDF4a_Mob_MDamage`。辅助 ASCII 选择扫描得到173条候选，包含 RTTI、系统符号及不同关键词；二者选择范围和编码覆盖不同，数量不能互换。本例具名字符串的原始表示已核对为 UTF-16LE。

`LDF4a_Mob_MDamage` 的具体字符串引用进入初始化函数 `172F10`。该函数先为全局对象 `F70800` 写 CMonster 虚表和 `Monster` 表示，并调用树结构插入辅助函数 `6BF3E0`；随后：

- 在 `172F86` 获取 **CLDF4a_Mob_MDamage 虚表**，`172F99` 写入 `F70800`。
- 拷贝具体脚本名字到对象附近字段，再次登记到 `103F828` 指向的结构。
- 把 `F054B0` 地址写到该对象 `+0xA8`；后续补证已绑定该地址为共享 CMonster 对象，见下文。

证据：[REA 字符串结果](../evidence/continuous/20261012-script-interface/script-combat-name-query.normalized.json)、[名字引用](../evidence/continuous/20261012-script-interface/script-magic-damage-name-xrefs.normalized.json)、[构造与登记指令](../evidence/continuous/20261012-script-interface/compiled-magic-damage-script-registration-instructions.normalized.json)、[树插入辅助函数](../evidence/continuous/20261012-script-interface/compiled-script-registration-helper-instructions.normalized.json)、[原始 UTF-16/LEA/RTTI 绑定](../evidence/continuous/20261012-script-interface/original-magic-damage-script-binding.json)。

从构造函数实际 LEA 的原始字节可算出虚表 RVA `A527E8`；其 RTTI 类型名为 `.?AVCLDF4a_Mob_MDamage@@`。连续四个代码指针依次为 `6BF100/6BF0F0/6BF0F0/6BF100`，已分别查询两个实际目标：`6BF100` 直接返回，`6BF0F0` 将 EAX 清零后返回。**该具名类的这四个虚槽不是已经找到的通用魔法伤害计算函数。** 描述数据、其他函数以及外部实现仍可能承载行为，不能把这些短函数扩展成整个模块没有伤害逻辑。

`LDF4a_Mob_BStart_RangePDamage` 也取得了名字引用与对应初始化函数。它是另一个具体脚本名称，不能仅凭 PDamage 命名推导当前玩家物理/PVP结算公式。

证据：[方法A](../evidence/continuous/20261012-script-interface/compiled-script-method-a-instructions.normalized.json)、[方法B](../evidence/continuous/20261012-script-interface/compiled-script-method-b-instructions.normalized.json)、[物理脚本名称引用](../evidence/continuous/20261012-script-interface/script-physical-damage-name-xrefs-retry.normalized.json)、[对应构造](../evidence/continuous/20261012-script-interface/compiled-physical-damage-script-registration-instructions.normalized.json)、[描述字段引用失败](../evidence/continuous/20261012-script-interface/compiled-magic-damage-descriptor-xrefs-retry.mcp.json)。

当前还保存了 `Tahabata|Taha|IDDF2|IDDF1` 的 REA 搜索结果，包含16条符合该查询的具名字符串。它只是该表示中的候选集，不能证明整个客户端没有某个 Boss 行为，也不能把旧服务端的塔哈巴塔强化规则直接迁入这些客户端脚本。

## 共享 CMonster 的初始化来源

对 `F054B0` 的直接 REA 引用请求仍失败，因此另用 Capstone 5.0.7 解码原始 PE 的59,320个异常表代码范围，并把候选函数重新交给 REA。这不是运行时跟踪，也不能替代失败的上游引用结果。67个范围没有完整解码；无异常表的叶函数、寄存器推导、加密/RVA引用不在该候选扫描的完整覆盖内。

扫描得到26,027个选定目标的 RIP 相对引用候选，其中 `F054B0` 为3,895条 LEA和一条直接 MOV。这个数量是引用指令数，不能称为3,895个已经审计完成的脚本。`103F710` 有707条读取候选，登记结构 `103F828` 有21,420条候选。对同一目标的对齐完整 QWORD 扫描没有匹配；这仅是该表示的结果，不证明没有其他引用。

REA 实际读取的初始化函数 `1C5060` 清零 `F054B8` 起的0xA0字节，在 `1C5091` 将 **CMonster 虚表**写到 `F054B0`，写入 UTF-16 的 `Monster` 名字，并交给 `6BF3E0` 登记。原始 LEA 和 RTTI 独立绑定为 **`.?AVCMonster@@`**，虚表 `A4D148`。原始指针单元 `97B388` 指向 `1C5060`；它说明原文件保存了初始化指针，尚不能证明受保护装载器执行了它。

另一个取得实际指令的初始化函数 `1040` 建立 `C1Skill_Bs_Ev15s_UseSk1S`，也将 `F054B0` 写入其对象 `+0xA8`。结合已核对的 MDamage 构造，证明该地址为多个编译脚本共享，**不是 MDamage 独有的伤害公式块**。它的连续四个虚槽与 MDamage 相同，均落到 `6BF100/6BF0F0` 两个短返回函数。`+0xA8` 呈父对象链接形态，但语义继承、回退调用和所有消费者仍需要证据。

证据：[原始扫描完整候选及缺口](../evidence/continuous/20261012-script-descriptors/original-descriptor-reference-candidates.json)、[CMonster 初始化](../evidence/continuous/20261012-script-descriptors/shared-descriptor-initialize.normalized.json)、[另一脚本共享链接](../evidence/continuous/20261012-script-descriptors/first-script-constructor-shared-descriptor.normalized.json)、[原始 RTTI/虚表/初始化指针](../evidence/continuous/20261012-script-descriptors/original-shared-script-parent-object.json)、[候选扫描复算](../client/analysis-code/continuous/inspect-script-descriptor-references.py)、[原始对象复算](../client/analysis-code/continuous/inspect-script-parent-object.py)、[九项 REA 指令锚点与26,027条原字节核对](../evidence/continuous/script-descriptors-verification.json)。

## Game 的 NpcScriptMgr 接入与版本校验

同批 Game.dll 的实际 REA 字符串查询发现 `ScriptDLL64.dll`、`GetInterface` 和初始化错误文本，引用进入 `074C60/074CD0`。Game 初始化 `044C20` 在 `046128` 调用 `074CD0`；返回零就输出失败信息并退出。`074C60` 构造模块名并调用保护入口 `18124A742`，把结果存到 `938AF0`，失败会报告无法装载 ScriptDLL。

`074CD0` 用具名 `GetInterface` 调用保护入口 `18124AD87`，然后在 `074D3D` 将 **Game的 `938A90` 地址放入 RCX**，`074D44` 调用返回的函数，结果保存在 `938AF8`。返回接口第一虚槽的结果必须等于 **0x28**，不等会报告 interface version mismatch。这把前文 ScriptDLL `6E04D0` 的返回值绑定为调用方要求的接口版本值，不能继续仅标作未定用途常量。

原始 Game 对象首指针指向虚表 `772C60`，有效 RTTI类型名为 **`.?AVNpcScriptMgr@@`**。结合 ScriptDLL 的 GetInterface 存储指令，可静态连接 `Game NpcScriptMgr → ScriptDLL IScriptDLLImpl → 保存的外部调用者接口`。这个关系由具名查找及调用形态支持；当前保护入口实际 API 目标、进程所装载文件和运行时修补仍未采集，不能把两个模块的相同VA直接合并。

Game 随后调用返回接口 `+8`，失败会报告 NpcScriptMgr 初始化错误；成功时读取 `+10/+18/+20/+28/+48`，存到自己的 `938AC8/938AD0/938AE0/938AE8/938AD8`。根据已经取得的 ScriptDLL 槽体，对应目标依次为该模块 `103F838/103F860/103F824/103F890/103F880`；所有地址分别属于各自模块。

证据：[Game 名称查询](../evidence/continuous/20261012-game-script-binding/game-script-module-names.normalized.json)、[模块装载函数](../evidence/continuous/20261013-game-script-binding/game-script-loader.normalized.json)、[工厂调用及版本检查](../evidence/continuous/20261013-game-script-binding/game-script-interface-factory.normalized.json)、[Game 初始化消费者](../evidence/continuous/20261013-game-script-binding/game-script-init-error-consumer.normalized.json)、[NpcScriptMgr 原始 RTTI和14个槽候选](../evidence/continuous/20261013-game-script-binding/original-game-script-caller-rtti.json)、[独立复算](../client/analysis-code/continuous/inspect-game-script-caller.py)。

## 外部调用在该客户端适配器中的实际行为

ScriptDLL 的 `6E04E0` 遍历 `103F828`，将节点 `+0x20` 的脚本对象放入 RDX，调用外部接口第一虚槽。Game 对应 `0750F0` 先调用脚本对象第一虚槽，再读取对象 `+8` 的 UTF-16名字，连同对象指针登记进 NpcScriptMgr `+8` 的容器。第二虚槽 `075180` 则查询 `this+0x28` 的整数键，并使用脚本名字维护 `this+0x18` 结构与链表。这是对象/名称的登记过程，不能直接称为攻击结算。

另外，ScriptDLL 的函数 `6C2270/6C30C0` 成对调用外部 `+0x40/+0x48`；`923970` 调用 `+0x50/+0x58`。原始 NpcScriptMgr 的这四个槽已绑定并取得实际代码：

| Game NpcScriptMgr 虚槽 | 实际目标 RVA | 该样本指令行为 |
| --- | --- | --- |
| `40`、`48`、`58` | `02CF80` | 清零EAX并返回，没有填充传入的对象输出 |
| `50` | `00C9F0` | 直接返回，没有写输出，也没有显式设置返回值 |

因此，**这些已核对的客户端外部槽没有提供完整的对象查询/操作实现**。`+0x40` 路径会获得零返回值并走调用方失败分支；`+0x50` 的裸返回不能擅自解释成返回零。无论函数名是否含伤害或 Boss，这些静态事实都不能证明该客户端适配器执行了当前官方服务器的NPC伤害计算。其他调用入口、运行时替换及后台实现仍须分别核验。

证据：[ScriptDLL 的成对调用A](../evidence/continuous/20261012-script-descriptors/external-consumer-first.normalized.json)、[成对调用B](../evidence/continuous/20261012-script-descriptors/external-consumer-second.normalized.json)、[另一对调用](../evidence/continuous/20261012-script-descriptors/external-consumer-last.normalized.json)、[Game 第一槽登记](../evidence/continuous/20261013-game-script-binding/game-caller-register-script.normalized.json)、[第二槽登记](../evidence/continuous/20261013-game-script-binding/game-caller-register-secondary.normalized.json)、[清零返回体](../evidence/continuous/20261013-game-script-binding/game-caller-short-return-retry.normalized.json)、[裸返回体](../evidence/continuous/20261013-game-script-binding/game-caller-zero-return.normalized.json)、[双模块接口语义核对](../evidence/continuous/game-script-binding-verification.json)。最后一个工作文件名曾用 zero-return，实际结果只有返回；这里以指令为准，不据工作标签命名语义。

Game 的 `0010A0` 初始化了 `938A98/938AA8/938AB8` 三个容器，并登记清理入口 `6B2A30`。已读名称查询 `075300` 使用 `this+0x18` 的树，命中时将节点 `+0x40` 的值写给调用者输出。`0755D0` 形成 `Data\\Quest\\Quest.XML` 路径，交给 `075820` 解析 `quests/quest` 表示，再调用 `0761A0` 消费子节点并按ID写入 `938AB8`。首次指令请求失败后，实际 dossier 取得伪代码和汇编；失败仍保留，没有将失败覆盖或当成空函数。这里补证的是任务文件、名称和容器的消费，尚未审计所有节点处理器或把它命名为伤害计算。

证据：[容器初始化](../evidence/continuous/20261013-game-script-binding/game-primary-registry-initialize-retry.normalized.json)、[清理入口](../evidence/continuous/20261013-game-script-binding/game-primary-registry-lifetime.normalized.json)、[名称查询](../evidence/continuous/20261013-game-script-binding/game-caller-script-name-lookup.normalized.json)、[Quest 文件消费者](../evidence/continuous/20261013-game-script-binding/game-script-quest-map-read-retry.normalized.json)、[Quest 解析实际 dossier](../evidence/continuous/20261013-game-script-binding/game-quest-parser-analysis.normalized.json)。

## 接下来仍需证据的部分

静态外部调用者类型、已选虚槽和共享 CMonster 的初始化已补证，Game 与 ScriptDLL 的预期装载/调用链已连接。父链接所有消费者、全部脚本业务语义、保护解析后的实际装载文件、运行时对象和当前官方服务器结算仍未完成审计。记录中的原客户端来源路径本机不存在，尚未取得新的可运行根目录。
