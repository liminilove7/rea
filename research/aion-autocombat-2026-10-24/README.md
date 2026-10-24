# 自动战斗研究续接包 · 2026-10-24

本次归档包括最新 ImGui 修改器源码、可运行 Windows x64 包、REA→IDA 原始证据、图文报告、目标生命采样，以及用户提供的两轮 JSONL 实测日志。

**当前完成的是目标生命/死亡停止观察与普通攻击调用链的只读分析，尚未接入自动攻击执行器。** 既有速度实验功能保留；本轮没有新增游戏函数调用、自动输入、进程伪装、反检测或自启。

- [下载完整离线包与校验文件](DOWNLOADS.html)
- [实体、生命与技能调用链图文报告](analysis/aion-autocombat-20261021/实体与技能调用链进展.html#action-dispatch-20261024)
- [最新动作调用链分析](analysis/aion-action-20261024/runtime-action/action-analysis.html)
- [修改器源码及构建说明](source/modifier-imgui/README.txt)
- [两轮用户日志评审](analysis/aion-autocombat-20261024/health-implementation/live-user-review/review.json)
- [下次测试步骤](CONTINUE_NEXT_SESSION.txt)

客户端固定版本 Game.dll SHA256：b3043f0eaf225b3dc7ba320ac7671cc5b28cefbd637135943dc9e67c114ccae7。原客户端及资源另见 2026-10-19/20 发布附件；本包不重复包含游戏安装程序或商业 IDA/数据库。

验证：153 项程序检查、10 项实际 ImGui 渲染/交互检查；四组历史采样共 1,481 样本回放。两轮实机日志支持生产观察器的死亡停止路径，不能替代攻击执行器停手或服务器命中频率验证。

REA 原始 Evidence 与 MCP 输出保留来源路径、版本、错误和未知项。目录内脚本中的 D 盘工具/数据库路径属于原工作站，需要按实际环境调整；历史 PID/绝对内存地址不能复用。离线阅读无需启动游戏或 IDA。
