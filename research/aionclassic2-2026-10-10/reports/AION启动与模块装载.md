# AION 启动入口与模块装载

通过 REA MCP → IDA 9.5 headless 查询原始 Aion.bin。SHA-256 为 `17c8de936526f119e16c1923ba5922d3a524698f04c01562fc878424653cda1e`，首选基址 **0x140000000**，与三个 DLL 的 0x180000000 分开。[原始请求、响应及失败](../evidence/continuous/20261012-aion-bootstrap/) · [语义和原始字节核对](../evidence/continuous/bootstrap-verification.json)。

## 原始入口的有限页面变换

已取得原始入口链：`5EE000 → 5EE00A → 5F000F → 5E2000 → 5E2009`。`5E2003` 的 call 返回地址是 `5E2008`，原始字节为 CC；进入 `5E2009` 后将该返回地址取出并参与地址算术。

在这个原始输入条件下，目标 RVA 为：

`5E2009 - 499000 - 7307BA8 + 7307B9F = 149000`。

代码给下一级长度 `1000h`，再压入 `6D21FE52` 与 `76145AC7`。`5E204C` 将长度右移2，对每个 little-endian DWORD 先 XOR 后 ADD，递增4字节并循环。根据栈参数顺序，公式为 `((cipher XOR 76145AC7) + 6D21FE52) mod 2^32`；后续地址为 `149014`。

辅助算术复现这4096字节并通过逆变换逐字节核对。变换后页面 SHA-256 为 `345c8c5b2a9cee8ff449b35f8dc1530476907661031aeb8aba8cdd5c30fbbe4b`。保存的是公式、源字节核对、摘要和小段继续位置前缀，没有写新的二进制输出，也没有原生执行入口。

这是对历史第一层局部解析的真实 REA 指令补证；4096字节不等于完整脱壳、全部导入解析或已经恢复完整原始入口。

证据：[入口](../evidence/continuous/20261012-aion-bootstrap/aion-original-bootstrap-entry-retry-instructions.normalized.json)、[地址及栈参数](../evidence/continuous/20261012-aion-bootstrap/aion-protection-bootstrap-body-instructions.normalized.json)、[DWORD 变换](../evidence/continuous/20261012-aion-bootstrap/aion-protection-bootstrap-page-transform-instructions.normalized.json)、[算术复现](../evidence/continuous/20261012-aion-bootstrap/original-bootstrap-page-reproduction.json)、[可复算脚本](../client/analysis-code/continuous/inspect-aion-bootstrap-page.py)。

## CrySystem 工厂与 Game 初始化参数

`CrySystem.dll` 的字符串引用进入 `011764`。该函数在 `0118C3` 将具体模块名传入间接槽 `D3350`，保存返回值到 `135918`，并在失败分支形成 `CrySystem.dll Loading Failed` 消息。成功分支把这个返回值和具名导出 `CreateSystemInterface` 交给保护辅助函数 `553F8A`。

`011A21` 随后调用返回的函数指针，把结果保存到 `135920`。结合模块名、导出名、函数指针调用和错误消息，这是模块装载及导出查询的具体客户端路径；底层保护接口的最终 Windows API 地址仍未解析，实际加载目录与内存实例未捕获。

后续 `011B79` 把 `Game.dll` 名称放入初始化记录，在 `011BA2` 取上述系统对象，将该记录传给其虚表第一槽 `011BB1`。这证明 Game 名称进入系统初始化接口。这里没有直接按字符串调用 Game 的 `CreateGameInstance`，也不能只凭两个 DLL 名称就把各模块内的所有调用视为已连接。

证据：[装载、查询、工厂调用和初始化记录](../evidence/continuous/20261012-aion-bootstrap/aion-crysystem-loader-consumer-instructions.normalized.json)、[Game 名称引用](../evidence/continuous/20261012-aion-bootstrap/aion-game-module-name-xrefs-retry.normalized.json)、[具名工厂字符串](../evidence/continuous/20261012-aion-bootstrap/aion-crysystem-interface-name-query.normalized.json)、[原始四模块导出及入口](../evidence/continuous/original-four-module-entries.json)。

Game 的固定对象/系统指针与 CrySystem 计时器绑定见[持续报告](AION持续分析.md)；ScriptDLL64 的独立静态接口及编译脚本登记见[脚本模块接口](AION脚本模块接口.md)。未观察的运行时路径、保护状态及当前官方后台仍保留未知。

## 本机诊断的范围

对重复的 `unreadable_output` 保存失败后，执行 `rea doctor --provider ida --format json`。IDA 注册、Node、私有工作目录权限的显式检查通过；该诊断明确没有启动 IDA，不能解释全部上游运行时读取失败，也不替代真实查询。整体 `environment_healthy=false` 包括其他可选引擎与非本任务客户端登记，不能把它扩大成当前 IDA 读取链路不工作，也不能宣称全部可选环境已经齐备。[诊断原文](../evidence/continuous/ida-doctor-20261012.json)。
