# 第九轮归档与下次续查

## 从这里继续

- [最新图文报告](reports/mechanics/AION机制分析报告.html)，重点阅读第九轮续节；HTML需下载解压后在浏览器中打开。
- [第九轮结论和证据定位](evidence/round9/REA_AION_ROUND9_20261011.md)
- [完整分析记录](reports/AION_ANALYSIS.md)
- [分类下载与SHA256](DOWNLOADS.md)

## 样本与能力边界

Game.dll SHA256：834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786。
本轮主要证据来自 REA 6.1.0 → IDA 8.3 离线数据库，619请求、581成功、38失败；80个识别入口取得指令不等于完整语义审计。39项关键指令与12个有限边界例子核对通过。HTML有49项浏览器检查通过。
参考服务端固定为 AionLightning 94fc8048e5fc198f000c0ca2176c65034c57cb39；并非当前官方后台。不能把客户端显示概率、固定源码模型、当前线上判定混为一谈。

## 优先入口

1. 条件技能实际控制更新、输入回调和施放判定：39D5D0→27FDE0已证明的是UI构建；继续追登记容器到真正消费者。counter_skill +768，chain_time +7A0，chain_skill_prob1/2 +7A4/+7A8。原始小写block与资源Block的比较规则仍未知。
2. 057930、01B610、068810与480890的方向分类/状态时间，继续追实际消费者和1244AE3时间单位；716/1382不能直接叫毫秒或盾反窗口。368E50的快照+3BC也待追使用者。
3. RandomMoveLoc保留参数3的方向执行，以及移速相关虚表+18/+20/+478的具体实现。
4. 当前PVP参数实际消费：此前pvp_damage_ratio索引直接消费者是Quest，不能当伤害路径；430D20→0B5630这一分支证明收到整数转为战斗文字，尚未闭合当前结算公式。

## 本机复现环境

REA仓库 D:\RVE；Node D:\nodejs\node.exe；Python C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe。
客户端 F:\SOFTWARE\永恒之塔\aionclassic2\bin64；样本 F:\RVE-Workspace\cases\aionclassic2-2026-10-10\samples\Game.dll。
复现请求/验证脚本在 client/analysis-code/rea-round9，原始REA响应与失败记录在 evidence__rea-round9.zip。脚本保留本机绝对路径，换电脑需按实际安装路径配置。run-rea-batch.mjs 使用已有REA构建、MCP客户端依赖和 .codex/local/rea-aion/ida-mcp.json；MIT接入源码与工具入口在 tools。
IDA须自行合法安装并确认许可；数据库可从同哈希样本重新建立，不随本次上传。start_ida_mcp.py仅在明确启动离线IDA分析时使用；历史stop-ida标记不随包分发，避免复现时立即退出。辅助PE读字节脚本不冒称REA反编译证据。
结束时保存结果、关闭本次会话，再显式运行本机 .codex/local/Enter-GameMode.ps1 -Close。无开机启动、计划任务、自动重启或后台监控；本轮未运行或附加游戏。
