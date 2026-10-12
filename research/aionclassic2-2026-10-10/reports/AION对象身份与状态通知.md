# AION 对象身份、复位与状态通知取证

本记录补充[持续机制分析](AION持续分析.md)。主要证据来自 **Codex → REA 6.1.0 MCP → IDA 9.5 headless** 的真实查询；原始 PE 元数据读取和软件 CPU 仿真分别注明来源。当前工作没有建立整个客户端或当前官方后台的完整语义审计。

Game.dll SHA-256：`834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786`。地址均采用首选基址 `0x180000000`，不是游戏运行地址。[请求、响应与失败原文](../evidence/continuous/20261012-state-audit/) · [对象身份核对](../evidence/continuous/state-audit-verification.json) · [状态字段继续查询](../evidence/continuous/20261012-status-values/)。

## 相同偏移需要先确认对象

`581B40` 只有 `mov [rcx+2ECh],edx; ret`，单独观察容易误认为它直接覆盖角色反击资格。实际已读直接调用点是 `09BD56`：

1. `09BB5E` 调用 `5802E0`，返回值保存在 RDI。
2. `5802E0` 保存 RCX 到 RBX，调用基类初始化，再明确写入 **UI3DView 虚表**，最终返回 RBX。
3. `09BD53` 把 RDI 传回 RCX，再调用 `581B40`。

因此，这条已确认的构造与调用路径操作 UI3DView，不是 Player 的 `+0x2EC` 反击位。工作文件名中的 `cast` 是探索时的标签，不能覆盖实际构造指令。其他间接调用仍需独立追踪，不能从一个直接调用点推导全局不存在别的调用。

证据：[通用写入函数](../evidence/continuous/20261012-state-audit/ambiguous-state-setter-instructions.normalized.json)、[调用者与返回值流转](../evidence/continuous/20261012-state-audit/ambiguous-state-setter-caller-instructions.normalized.json)、[UI3DView 构造](../evidence/continuous/20261012-state-audit/model-widget-cast-instructions.normalized.json)。

另一个此前无法读取的候选 `116028`，属于带 BattlePassPathMap 虚表的 `115E90`；它以浮点表示初始化附近字段，不能并入 Player 状态。`29C9D0` 确属 DlgStart，但 `29CAF7` 写的是从 `this+0x4E8` 取得的成员指针。父函数读取过 Player，也不意味着成员写入属于 Player；这个成员的精确类型仍保留未知。

证据：[BattlePassPathMap 指令](../evidence/continuous/20261012-state-audit/missed-state-writer-116028-instructions.normalized.json)、[DlgStart 成员写入](../evidence/continuous/20261012-state-audit/missed-state-writer-29caf7-instructions.normalized.json)。

辅助读取在原始映像中验证了762个带有效 MSVC RTTI locator 的虚表候选，查询48个已选函数的绑定。该保护文件把含数据的节也标为可执行；首次只扫描非可执行节得到零个结果，已经保留并纠正这个错误前提。762是满足本脚本条件的候选数量，不是已审计的业务类数量。虚表属于 UI 类也不能自动排除其参数或成员指针指向 Player。

证据：[修正后的绑定](../evidence/continuous/20261012-state-audit/original-state-function-vtable-bindings.json)、[首次扫描记录](../evidence/continuous/20261012-state-audit/original-state-function-vtable-bindings-first-pass.json)、[可复算脚本](../client/analysis-code/continuous/inspect-function-vtables.py)。

## Player 复位引用中的异常元数据

Player 原始虚表 `841CD8+1F8` 指向 `0638E0`。该函数在 `0638FA` 调用 `4BB4C0`；基类复位已有证据会清整个 `+0x2EC`，并以64位零写入覆盖 `+0x324/+0x328`。`4BB4C0` 检查对象已有模式 `+0x2C0==7`，不能把它描述为一个接受显式“死亡/复活”参数的 setter，也不能只因渲染特效文本而给模式7命名。

两个数据引用 `8A1060`、`8A1070` 已经解析：它们是 **UNW_FLAG_CHAININFO 尾部的 RUNTIME_FUNCTION**，不是业务方法登记或实际调用点。

| UNWIND_INFO RVA | 原始头部 | unwind code 数量 | 尾部 RVA | 尾部三个 DWORD |
| --- | --- | --- | --- | --- |
| `8A1054` | `214e0400` | 4 | `8A1060` | `638E0 / 638F6 / 8A1040` |
| `8A106C` | `21000000` | 0 | `8A1070` | `638E0 / 638F6 / 8A1040` |

两个头部的版本均为1、flags均为4。按微软的 x64 异常展开格式，unwind code 槽按偶数补齐，CHAININFO 后跟三个相对映像地址；这里原始字节、尾部位置、起止地址和主展开地址均吻合。[微软 x64 异常处理格式](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)。

证据：[原始展开字节与解释](../evidence/continuous/20261012-state-audit/original-player-reset-unwind-xrefs.json)、[可复算读取](../client/analysis-code/continuous/inspect-player-reset-unwind.py)、[Player 复位包装](../evidence/continuous/20261012-state-audit/player-lifecycle-reset-wrapper-instructions.normalized.json)。

另外，原始字节搜索得到68个具有 `+0x1F8` 间接调用/跳转编码的候选。已读的 `3231E0` 使用 `lea rcx,[rbx+1F8]` 后直接 `call [rbx+1F8]`，属于成员回调形态；其他已读运动路径通过实体接口调用坐标相关方法。相同虚槽偏移不能证明同一接口或 Player 复位。候选搜索不覆盖所有机器编码、别名或保护分派，实际复位的全部调用者仍未知。

证据：[68个字节候选](../evidence/continuous/20261012-state-audit/original-reset-slot-call-candidates.json)、[成员回调指令](../evidence/continuous/20261012-state-audit/object-reset-status-loader-instructions.normalized.json)、[实体接口调用上下文](../evidence/continuous/20261012-state-audit/object-reset-actor-update-retry-instructions.normalized.json)。

## 当前客户端的 HP 通知与显示表示

当前消息登记将内部 ID3 命名为 **S_HIT_POINT**，路由从收到的载荷读取两个 DWORD：第一个传 EDX，第二个传 R8D，经 `4F9810` 取得本地 Player 后调用 `488F00`。内部 ID 不是已经识别的加密网络 opcode。

`488F00` 把 EDX 写到对象 `+0x11A4`，R8D 写到 `+0x11A0`。当对象 `+0x1190==0` 时，还把 EDX 写入 `+0x119C`，调用虚表 `+0x440` 通知。随后它向保护辅助函数 `18124E7DF` 传入 EDX、100、R8D，并将结果裁到至少1后保存低8位到 `+0x40`；输入 EDX 为0则写0。辅助函数的完整算术仍未解析，不能把“传入100”直接当成已经证明的全部百分比公式或上限裁剪。

结合具名 HP 消息与消费者，本地表示可区分如下：

| 字段 | 观察及解释 |
| --- | --- |
| `+0x11A4` | 收到的 HP 当前值，DWORD |
| `+0x11A0` | 与当前值配对的最大值表示，DWORD；作为保护比例函数的第三参数 |
| `+0x119C` | 显示/过渡值；只在 `+0x1190==0` 分支立即同步，UI读此槽 |
| `+0x40` | 低8位比例表示；0值与非0值分别处理，完整比例算术待查 |

`S_STATUS` 的 `42DD90→4FCB00` 同样从收到记录 `+0x40/+0x3C` 提供这对参数。`4FCB00` 另把记录 `+0xA4` 交给 `4B4AF0`，实际写对象 `+0x228`；该字段的业务名称尚未确定。它不是仅凭探索文件名就认定的“模式 setter”。

证据：[当前消息名称](../evidence/continuous/20261012-session-a/current-message-name-map.json)、[真实路由指令](../evidence/continuous/20261012-chain-value/skill-list-route-instructions.normalized.json)、[HP 值更新](../evidence/continuous/20261012-status-values/received-status-pair-consumer-retry-instructions.normalized.json)、[HP 更新伪代码与指令](../evidence/continuous/20261012-status-values/status-pair-object-consumer-dossier.normalized.json)、[收到完整状态](../evidence/continuous/20261012-state-audit/local-status-message-handler-retry-instructions.normalized.json)、[Player 消费者](../evidence/continuous/20261012-state-audit/local-status-player-object-consumer-instructions.normalized.json)、[字段228写入](../evidence/continuous/20261012-status-values/received-status-mode-consumer-instructions.normalized.json)。

另一对全局 DWORD **D71BCC/D71BC8 是飞行点数路径**：当前内部 ID245 明确登记为 `S_FLIGHT_POINT`，路由调用 `43F370`；该函数分别把载荷的第一个、第二个 DWORD 乘1000后写入它们。这一对也被 UI 消费，但不能当成 HP、DP 或伤害结果。乘1000已观察，当前运行时单位仍不能只从数值推导。

证据：[飞行点数更新](../evidence/continuous/20261012-status-values/status-value-received-update-instructions.normalized.json)、[界面读取 HP 与飞行值](../evidence/continuous/20261012-status-values/status-value-ui-primary-instructions.normalized.json)、[另一显示消费者](../evidence/continuous/20261012-status-values/status-value-script-consumer-instructions.normalized.json)。最后一个工作文件名含 `script`，实际返回内容展示界面对象调用，不能由文件名认定 Lua 接口。

这些路径证明客户端接收、保存和显示数值，尚未证明当前官方服务端的命中、PVP减伤、格挡伤害或生命结算公式。旧开源服务端模型继续作为独立对照。

原始 Player 虚表 `+0x440` 对应 `064620`，返回指令向全局 `D720C0` OR 入更新位，支持这是变化通知路径；基类槽为 `488E90`。另有 `01E120→4BB040`：后者写对象模式7，并向 `488F00` 传当前 HP 为0，再同步显示槽。这补充了“模式7与零HP的具体代码联系”，但没有因此把全部模式7调用或 `4BB4C0` 复位统一命名为死亡/复活。

证据：[原始状态更新虚槽](../evidence/continuous/20261012-status-values/original-status-update-slots.json)、[Player 更新通知](../evidence/continuous/20261012-status-values/player-hp-update-notification-instructions.normalized.json)、[零 HP 状态转换](../evidence/continuous/20261012-status-values/status-pair-lifecycle-caller-instructions.normalized.json)、[实际直接调用者](../evidence/continuous/20261012-status-values/hp-zero-player-state-direct-caller-instructions.normalized.json)、[状态语义核对](../evidence/continuous/status-values-verification.json)。

## 受保护时钟的离线 CPU 边界

使用独立 Python 环境中的 Capstone 5.0.7 与 Unicorn 2.1.4，对同哈希原始 PE 的映像副本做有界软件 CPU 仿真。样本没有作为本机 DLL 加载；映像、栈及返回地址均为仿真内存。工具版本来源：[Capstone](https://pypi.org/project/capstone/)、[Unicorn 2.1.4](https://pypi.org/project/unicorn/2.1.4/)。

已知 SkillItem 类型读取函数 `3A0000` 在构造的对象 `+0x58=21` 时，经2条指令返回21，校验映像映射及返回栈设置。这个小样例不校验整个保护器。

对时钟入口 `181244AE3`，三组明确记录的初始寄存器模式都经过299条指令，然后因无映射的指令取址失败。增强内存日志后确认：

- `181256113` 读取影子映像地址 `1810E4790` 的8字节，原始值字节为 `442408e916feffff`。
- 后续多段栈和算术变换在 `1812CAEF8` 执行 `ret 8`；返回栈字节为 `f3209c8e16feffff`，RIP最终为 `FFFFFE168E9C20F3`。
- 三个实验均没有写影子映像。第一次没有记录内存读取，第二次新增日志后结果一致；两次原始轨迹均保留。

这将静态难读的保护链缩小到具体数据依赖与失败位置，但没有取得时钟返回值。Windows loader、导入解析、TLS、线程环境与保护初始化都未提供；不能把这个失败说成真实游戏异常，也不能据此命名最终 API、宣称完整脱壳或采用某个时钟单位。当前 REA 对影子读取地址的引用查询返回空，指令查询失败；空引用不是没有运行时写入的证明。

证据：[仿真脚本](../client/analysis-code/continuous/emulate-protected-clock.py)、[首次轨迹与报告](../evidence/continuous/20261012-clock-emulation/report.json)、[带内存日志的报告](../evidence/continuous/20261012-clock-emulation-memory/report.json)、[首组完整轨迹](../evidence/continuous/20261012-clock-emulation-memory/clock-entry-state-0.trace.jsonl)、[REA 引用查询](../evidence/continuous/20261012-status-values/protected-clock-shadow-slot-xrefs.mcp.json)、[保留的指令读取失败](../evidence/continuous/20261012-status-values/protected-clock-shadow-slot-code-instructions.mcp.json)。

原始 PE、REA 分析和软件 CPU 仿真是三种不同证据来源。结论按可观察内容分别记录；完成这些核对不代表完整逆向已经完成。
