# 继续分析入口

本案例仅客户端。先从[图文报告](reports/AION_TW速度分析报告.html)及[结构化结论](provenance/findings.json)查看已确认与未知项。

1. 攻击间隔：Game.dll加载基址B+0x142DB40，uint16；RVA0x16D600请求门槛与上下文A+0x1E90；追额外写入者和保护计时来源。
2. 计时链：0x1819EDEA2 →0x1819FB376 →0x1819F239B →0x1819FEDD4 →0x1819FF314调用0x181A03A83。物理单位和最终来源尚未确认。
3. 对象定位：分类1的C、分类2的P、控制上下文A，不能直接视为同一指针；稳定本地玩家指针链尚待核对。
4. 移速：RVA0x8CA320通过虚表+0x260调用0x89ADB0，写C+0x38/+0x70C，维护平方+0x710和倒数+0x714。继续审运动接口、同步覆盖和实际效果。
5. S_ACTION子类型0x23写C+0x530/+0x532；cattack前缀分支算U/V×C+0x51C。动画倍率与服务器实际出手频率要分别验证。

完整研究ZIP带原始请求与jobs文件。复现脚本原路径为 `.codex/local/aion-tw-20261019`，辅助解码器要求父目录提供aion_pak.py、extract_aion_data.py及aion-format-tables.json，ZIP顶层已包含这三份依赖；实际运行前配置自己的路径和工具。
MCP接入源代码和依赖版本参考上一案例的tools/ida-mcp-bridge与本机既有环境；IDA须自行提供合法安装。不存在开机启动或自动重启。结束后保存并关闭本次会话，再按本机清单显式运行tools/Enter-GameMode.ps1 -Close。
