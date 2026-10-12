# AION客户端 / 服务端机制研究档案

## 下载入口

[按功能下载全部归档](DOWNLOADS.md) · [GitHub Release](https://github.com/liminilove7/rea/releases/tag/aion-research-20261011)

[下次续查入口与环境说明](CONTINUE_TOMORROW.md)

当前持续逆向见 [AION条件技能与施放机制分析](reports/AION持续分析.md) 和 [持续证据核对](evidence/continuous/verification.json)，后续不再按轮次交付。已连接收到的状态标志、受击玩家、资格计时、操作发送、成功连招标志、共享冷却与选项保存，并下探同批 CrySystem 的计时器。保护桩、运行时使用消耗和当前官方判定仍按证据保留未知。下面的编号记录为历史归档。

新增[对象身份与状态通知取证](reports/AION对象身份与状态通知.md)：排除 UI3DView 同偏移写入，识别 Player 复位引用中的异常展开元数据，连接 S_HIT_POINT 的对象/显示字段，并区分 S_FLIGHT_POINT。受保护时钟的离线 CPU 轨迹与明确失败边界也已保留。

另见[脚本模块接口](reports/AION脚本模块接口.md)与[启动和模块装载](reports/AION启动与模块装载.md)：十个 IScriptDLLImpl 虚槽、具体编译脚本登记，以及 CrySystem 工厂与 Game 初始化记录均取得 REA 指令。累计991次持续分析/状态请求，成功836、失败155；所有失败及未完成范围保留。

最新归档新增第九轮REA分析、原始响应与失败记录、49项HTML检查。整客户端及当前官方后台尚未完整破解。

历史第十一轮归档：39 次 REA 请求、29 成功、10 失败，14 项核对通过。确认登记容器清理与关系查询、连锁图构造、顺序调整及 `chain_skill_prob2` 的 UI 绘制消费者，见 [第十一轮报告](reports/AION_ROUND11_20261012.md) 和 [核对 JSON](evidence/round11/verification.json)。该阶段当时尚未闭合反击激活与施放链路，后续结果以持续分析报告为准。

本机已继续完成第十轮 IDA 9.5 实际分析：23 次 REA 请求、17 成功、6 失败，15 项证据核对通过。新增保护器指纹候选、间接比较槽纠正、条件登记与显示消费者追踪；结果见 [完整分析记录](reports/AION_ANALYSIS.md) 文末和 [第十轮核对 JSON](evidence/round10/verification.json)。此阶段新增内容尚未发布到上述 Release。

2026-10-12 的 Markdown 报告、分析脚本、第十/十一轮及持续分析原始响应已同步到 [GitHub main](https://github.com/liminilove7/rea/tree/main/research/aionclassic2-2026-10-10)，同时保留[研究分支](https://github.com/liminilove7/rea/tree/codex/aion-research-archive-20261011/research/aionclassic2-2026-10-10)。上面的 Release 和 HTML 仍为第九轮归档；最新结论请阅读持续分析 Markdown。新增归档不包含样本二进制。

## 阅读入口

- [图文机制报告与具体案例](reports/mechanics/AION机制分析报告.html)：塔哈巴塔强化、剑星巨剑/战戟对持盾角色、致命/命中/盾反前提、技能、神石与离线模型实验台。
- [REA与Codex教学](reports/REA与Codex逆向教学.html)
- [完整分析记录](reports/AION_ANALYSIS.md)
- [服务端对照](reports/AION_SERVER_COMPARISON_20261011.md)

GitHub网页只显示HTML源码；下载整个reports/mechanics目录后用浏览器打开HTML，即可离线查看图表和计算器，并打开相对证据链接。

## 按功能分类

| 目录 | 内容 |
| --- | --- |
| client | 客户端辅助分析/资源解析代码、文件索引、已解资源、第一层局部导出 |
| server | 固定开源服务端完整参考源码、分析脚本、提交/哈希溯源 |
| reports | 中文HTML、Markdown、可编辑报告代码与核对记录 |
| evidence | REA第七/八/九轮请求与结果、历史辅助静态证据归档 |
| tools | 静态识别工具包、IDA MCP接入源码、按功能工具入口、结束清理脚本 |
| samples | 较早已上传的四个客户端主模块，不重复更改 |

REA主项目仍在仓库根目录。当前记录未完成整个客户端或当前官方服务器语义审计。客户端显示概率与固定开源服务端判定分开，本文不把旧模型当当前线上机制。

所有归档经过CRC读取校验，早期文件SHA256见publication-manifest.json；本轮见round9-publication-manifest.json。文档使用“唯一品质”“英雄品质”；原始JSON英文标记保留便于对照。

## Release归档

大文件另存GitHub Release，文件名以前缀client/server/evidence/tools/reports分类。完整HTML目录请下载reports__complete-mechanics-report__round9.zip，解压后打开HTML，可保留所有证据链接。

