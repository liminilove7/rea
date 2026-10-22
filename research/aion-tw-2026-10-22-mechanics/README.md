# AION TW 神石、强化、PVP 静态研究（2026-10-22）

打开 [中文图文报告与离线演算](AION-TW-机制分析.html)。本次资料来自当前台服归档，没有套用旧 Classic 的函数偏移和概率。

## 结果

- 神石：250候选，249关联到102技能；保留主/left原值及缺失，概率单位、触发口径及服务端判定未知。
- 普通强化：当前 Game.dll 计算函数与显示链经过 REA/IDA 核对，可复现客户端显示公式，不代表服务器概率。
- 其他强化：补解原items包28 XML；分别整理option、跳跃、累计和技能赋予。累计85关联技能207的PVP/PVE声明。
- PVP：3873物品含属性声明，96技能显式伤害ratio，52显式持续时间ratio；当前格式函数按输入十分之一显示百分比。完整伤害公式未知。
- 自动打怪/任务：提供[功能基础设计](combat-feature-plan.md)，未实现执行功能。

## 版本和来源

GitHub liminilove7/rea，研究分支 codex/aion-research-archive-20261011。2026-10-22 fetch检查时本地和远端均为 ee6943ff7941b5ccc675888b61fc1748bf145cec，见 [同步证据](sync-verification.json)。

输入来自 release aion-tw-offline-20261020：

- client__static-programs-20261020/bin56/Game.dll
- analysis__complete-static-study-20261020/aion-tw-20261019/resources
- resources__original-paks-20261020/data

Game.dll SHA256：b3043f0eaf225b3dc7ba320ac7671cc5b28cefbd637135943dc9e67c114ccae7。

用户确认只有客户端资源。没有启动游戏、读写游戏内存或执行网络战斗行为。神石RNG、强化成功判定和最终伤害没有冒充服务器已恢复。

## 复现

1. 将同一发布包解压到本仓库 _reference/github-releases/aion-tw-offline-20261020/，核对源SHA。
2. godstone/analyze_godstone.py、pvp/analyze_pvp.py 支持指定资源目录；强化 analyze_resources.py、build_evidence.py 补解原PAK、核验CRC。默认路径对应本次归档。
3. analysis-code/rea-session.mjs 使用真实 REA MCP 及用户已有 IDA，参数依次为原DLL、IDA配置JSON、证据目录、请求队列目录。实际工具名、参数与结果见 binary-evidence/requests.json；工具Schema按运行时目录读取。
4. 队列中创建 STOP 后关闭本次自有会话。不能关闭用户附加的GUI数据库。本次仅自有headless数据库，没有保存数据库到研究档案。
5. enchant/model_current_formula.py、model_option_display.py 校验资源算例；pvp/verify_binary_literals.py 核验PE字节和指令。
6. analysis-code/build-report.py 导出规范Evidence并生成总报告；analysis-code/verify-report.mjs 用本地Edge验证文档和计算器。

[结论台账](finding-ledger.json) 标记资源观察、代码推导和设计建议。[REA索引](binary-evidence/index.json) 提供ID、操作、参数、文件和SHA。辅助原字节和格式解析不冒充REA Evidence。完整MCP响应、工具目录、重复伪代码在本地保留并忽略提交，规范Evidence与复现脚本纳入档案。

检查针对研究资料与静态模型；没有修改REA运行时或修改器程序，也没有把文档验证当作游戏功能测试。
