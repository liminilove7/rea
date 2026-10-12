# AION 持续分析入口

## 从这里继续

- 当前工作改为持续逆向，不再按轮次交付，主记录为 [AION条件技能与施放机制分析](reports/AION持续分析.md)，新增原始结果见 `evidence/continuous/`。
- 已连接 `S_ATTACK` 收到标志→受击对象→`476770→4BC8D0` 资格设置→`61EE50` 操作检查→施放和 Socket 发送。Block 对应角色 `0x80/+0x2F8`，`4BCA40` 到期清除；成功通知的 `0x20` 标志决定前置连招保存，`3B2500` 按 delay_id 更新同组冷却。选项已追到提交与本地 opt 文件流，CrySystem 的计时器已取得实际 REA 指令。全局使用消耗、保护桩 API 和官方判定仍未知。
- GitHub main 与研究分支已归档报告、脚本和原始证据。已确认 `27E820` 返回 SkillItem，`+0x64` 来自技能添加通知并参与等级排序，绘制/施放对象身份已连接；完整 XML 中48条显式 prob1 均为0。详见主报告和 [来源核对](evidence/continuous/chain-object-verification.json)。
- 新增[对象身份与状态通知](reports/AION对象身份与状态通知.md)：`581B40` 已读直接调用链操作 UI3DView，不能当 Player 状态；复位引用 `8A1060/8A1070` 是 CHAININFO。HP 收到字段与显示字段分开，`D71BCC/D71BC8` 对应 S_FLIGHT_POINT。时钟入口的软件 CPU 实验读取原始影子地址 `1810E4790`，最终取址失败；不代表获得运行时 API 或完整脱壳。
- 已扩展实际 REA 查询到 [ScriptDLL64 的 IScriptDLLImpl 与编译脚本登记](reports/AION脚本模块接口.md) 和 [Aion.bin 入口/装载](reports/AION启动与模块装载.md)。累积991次分析/状态请求；十一个会话中十个正常关闭，原有 CrySystem 清理失败仍单独保留。系统第一虚槽已连接 Game 工厂、同步初始化与回调初始化；继续沿 ScriptDLL 外部接口、描述字段生产者和运行时保护解析查证。

- 历史第十一轮 IDA 9.5 归档见 [第十一轮报告](reports/AION_ROUND11_20261012.md)：39 次请求、29 成功、10 失败，14 项核对通过，见 [核对 JSON](evidence/round11/verification.json)。该阶段当时尚未找到实际施放资格；后续证据以持续报告为准。
- 优先续查 `2784E0 → 61EE50`、`13DF40/1E3660/2C4D60` 的关系调用上下文，以及 `283F40` 写入 `+0x870` 时间值的消费者。`39E770` 已确认递归关系查询，`39ECF0` 生成 `chainskill` 表示；不能直接当战斗激活状态。
- [第十轮核对结果](evidence/round10/verification.json)：23 次 REA 请求，17 成功、6 失败；15 项证据核对通过，失败原文保留。
- [四模块保护器指纹](evidence/round10/die-static/manifest.json)：前三模块报告 Obsidium/Oreans CodeVirtualizer 候选，准确版本未知。
- 下面的第九轮 HTML 和 Release 链接保留为原有下载归档；第十、十一轮及持续分析已同步到 main，最新结论使用持续 Markdown 报告。

- [最新图文报告](reports/mechanics/AION机制分析报告.html)，重点阅读第九轮续节；HTML需下载解压后在浏览器中打开。
- [第九轮结论和证据定位](evidence/round9/REA_AION_ROUND9_20261011.md)
- [完整分析记录](reports/AION_ANALYSIS.md)
- [分类下载与SHA256](DOWNLOADS.md)

## 样本与能力边界

Game.dll SHA256：834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786。
第九轮历史证据来自 REA 6.1.0 → IDA 8.3 离线数据库，619请求、581成功、38失败；80个识别入口取得指令不等于完整语义审计。第九轮39项关键指令与12个有限边界例子核对通过。HTML有49项浏览器检查通过。本机第十、十一轮已换用IDA 9.5，计数和证据分别保留。
参考服务端固定为 AionLightning 94fc8048e5fc198f000c0ca2176c65034c57cb39；并非当前官方后台。不能把客户端显示概率、固定源码模型、当前线上判定混为一谈。

## 优先入口

1. 继续追全局使用消耗及别名/批量状态写入。资格触发、检查、施放请求、成功连招状态已查通，27E820的 SkillItem 来源已确认；`+0x64` 与技能等级表示的推断、发送宽度及动作标志分开记录。不要把登记结构清理或 SkillItem `+0x6C` 倒计时当 Player 的反击次数扣减。counter_skill +768，chain_time +7A0，chain_skill_prob1/2 +7A4/+7A8。
2. 6BC748已由新指令确认是间接比较指针槽，而不是直接函数入口；原文件QWORD为0x081E47C3。追其解析/写入来源或运行时目标，继续保留Block/block大小写比较未知。
3. 057930、01B610、068810与480890的方向分类/状态时间，继续追实际消费者和1244AE3时间单位；716/1382不能直接叫毫秒或盾反窗口。368E50的快照+3BC也待追使用者。
4. RandomMoveLoc保留参数3的方向执行，以及移速相关虚表+18/+20/+478的具体实现。
5. 当前PVP参数实际消费：此前pvp_damage_ratio索引直接消费者是Quest，不能当伤害路径；430D20→0B5630这一分支证明收到整数转为战斗文字，尚未闭合当前结算公式。

## 本机复现环境

当前 REA 仓库为 `D:\REA`，Node 为 `C:\Program Files\nodejs\node.exe`。IDA 原安装目录为 `D:\安装包\IDA95`，英文目录入口为 `D:\IDA95`。独立 Python 3.12.13/MCP 环境为 `D:\安装包\IDA_MCP\.venv`，REA provider 配置为 `D:\安装包\IDA_MCP\rea-ida-mcp.json`。Codex 的 REA 注册已配置并备份。

当前样本为 `D:\REA\research\aionclassic2-2026-10-10\samples\Game.dll`，来源盘的 F: 路径是最初采集位置，不是本轮运行路径。使用新 headless 请求文件 `jobs-headless-counter.json`、`jobs-counter-follow.json`、`jobs-counter-consumers.json` 和 `jobs-registry-owners.json`；`jobs-first.json` 保留为旧 attached 预备请求的失败定位记录，不作为当前 headless 推荐首批。

REA 每批重新导入同哈希副本，当前 Game.dll 冷启动约 2 分钟。必须使用新的 output 目录；批处理脚本拒绝覆盖既有证据。结束时正常 `close_binary` 并关闭客户端；本轮五批关闭正常，成功 Evidence 关联的四个私有目录已移除。内部诊断的关闭响应和空库存也已保存。

第十一轮请求在 `client/analysis-code/rea-round11/`，证据在 `evidence/round11/`，复用第十轮批处理脚本并显式指定新输出目录。第十一轮四批关闭正常，三个成功批次可定位私有目录已移除；诊断也正常关闭并移除目录。首批反编译诊断发现就绪状态 true→false；因此建议先查询引用和指令，最后再取得 dossier，不将失败结果当空逻辑。两个健康返回缺字段错误原因仍未知。

辅助 DIE/原始 PE 读取与 REA 代码分析分开记源。本轮没有启动、附加或修改游戏，也没有新增自启、计划任务或后台监控。历史第九轮环境和脚本路径保留在原始归档中，换机不要照抄旧绝对路径。
