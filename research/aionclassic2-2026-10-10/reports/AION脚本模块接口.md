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
| `00` | `6E04D0` | 返回整数 `0x28`；其业务名称/兼容版本语义尚未绑定 |
| `08` | `6E04E0` | 遍历登记结构，并调用保存在 `103F710` 的外部对象虚方法 |
| `10` | `6E0660` | 返回 `103F838` 地址 |
| `18` | `6E0670` | 返回 `103F860` 地址 |
| `20` | `6E0680` | 返回 IDA 表示为 `Buffer+104h` 的地址，精确业务类型未知 |
| `28` | `6E0690` | 返回 `103F890` 地址 |
| `30` | `6E0630` | 用 `103F848` 调用 `926E70`；后者形成 `%squest\event_quest.xml` 并交给下一级处理 |
| `38` | `6E0640` | 用 `103F848` 调用 `929D90` |
| `40` | `6E0650` | 用 `103F848` 调用 `929D00` |
| `48` | `6E06A0` | 返回 `103F880` 地址 |

槽 `08` 的外部调用形态与登记结构访问已观察，外部对象的实际实现还未取得。对 `103F710` 的三次引用查询均返回 `unreadable_output`，失败原文保留；不能将读取失败当空引用或不存在调用。

证据：[槽08](../evidence/continuous/20261012-script-interface/script-interface-slot-08-instructions.normalized.json)、[任务文件路径消费者](../evidence/continuous/20261012-script-interface/script-interface-map-core-op-a-retry-instructions.normalized.json)、[外部参数引用失败](../evidence/continuous/20261012-script-interface/script-interface-caller-parameter-xrefs-third.mcp.json)。其余目标、原始 QWORD 与 Evidence 绑定由[接口语义核对](../evidence/continuous/script-interface-verification.json)复核。

## damage 名称已绑定到具体编译脚本

REA 按字面 `damage` 搜索取得41条字符串，其中包含 `LDF4a_Mob_MDamage`。辅助 ASCII 选择扫描得到173条候选，包含 RTTI、系统符号及不同关键词；二者选择范围和编码覆盖不同，数量不能互换。本例具名字符串的原始表示已核对为 UTF-16LE。

`LDF4a_Mob_MDamage` 的具体字符串引用进入初始化函数 `172F10`。该函数先为全局对象 `F70800` 写 CMonster 虚表和 `Monster` 表示，并调用树结构插入辅助函数 `6BF3E0`；随后：

- 在 `172F86` 获取 **CLDF4a_Mob_MDamage 虚表**，`172F99` 写入 `F70800`。
- 拷贝具体脚本名字到对象附近字段，再次登记到 `103F828` 指向的结构。
- 把 `F054B0` 地址写到该对象 `+0xA8`，但该表示的生产者和业务结构尚未解析。

证据：[REA 字符串结果](../evidence/continuous/20261012-script-interface/script-combat-name-query.normalized.json)、[名字引用](../evidence/continuous/20261012-script-interface/script-magic-damage-name-xrefs.normalized.json)、[构造与登记指令](../evidence/continuous/20261012-script-interface/compiled-magic-damage-script-registration-instructions.normalized.json)、[树插入辅助函数](../evidence/continuous/20261012-script-interface/compiled-script-registration-helper-instructions.normalized.json)、[原始 UTF-16/LEA/RTTI 绑定](../evidence/continuous/20261012-script-interface/original-magic-damage-script-binding.json)。

从构造函数实际 LEA 的原始字节可算出虚表 RVA `A527E8`；其 RTTI 类型名为 `.?AVCLDF4a_Mob_MDamage@@`。连续四个代码指针依次为 `6BF100/6BF0F0/6BF0F0/6BF100`，已分别查询两个实际目标：`6BF100` 直接返回，`6BF0F0` 将 EAX 清零后返回。**该具名类的这四个虚槽不是已经找到的通用魔法伤害计算函数。** 描述数据、其他函数以及外部实现仍可能承载行为，不能把这些短函数扩展成整个模块没有伤害逻辑。

`LDF4a_Mob_BStart_RangePDamage` 也取得了名字引用与对应初始化函数。它是另一个具体脚本名称，不能仅凭 PDamage 命名推导当前玩家物理/PVP结算公式。

证据：[方法A](../evidence/continuous/20261012-script-interface/compiled-script-method-a-instructions.normalized.json)、[方法B](../evidence/continuous/20261012-script-interface/compiled-script-method-b-instructions.normalized.json)、[物理脚本名称引用](../evidence/continuous/20261012-script-interface/script-physical-damage-name-xrefs-retry.normalized.json)、[对应构造](../evidence/continuous/20261012-script-interface/compiled-physical-damage-script-registration-instructions.normalized.json)、[描述字段引用失败](../evidence/continuous/20261012-script-interface/compiled-magic-damage-descriptor-xrefs-retry.mcp.json)。

当前还保存了 `Tahabata|Taha|IDDF2|IDDF1` 的 REA 搜索结果，包含16条符合该查询的具名字符串。它只是该表示中的候选集，不能证明整个客户端没有某个 Boss 行为，也不能把旧服务端的塔哈巴塔强化规则直接迁入这些客户端脚本。

## 接下来仍需证据的部分

外部调用者接口实现、具体脚本描述数据的初始化及消费者、Game 与 ScriptDLL 的实际装载/调用绑定，以及当前运行时对象均未闭合。接口、构造和登记的明确结果已经归档；整个模块的所有脚本语义和当前官方服务器结算仍未完成审计。
