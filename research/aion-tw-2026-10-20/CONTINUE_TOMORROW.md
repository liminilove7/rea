# 明天无需运行游戏的静态续查

下载完整分析包、客户端静态程序包；资源原文另有PAK包，只要修改器则下载modifier包。完整分析包解压后打开 aion-tw-20261019/attack-speed-lab/攻速修改方案与后续计划.html，内含五阶段计划和实际界面。

1. 审 attack-speed-lab/AttackSpeedLab.cs：Profile→Target→Role.Resolve→Mutation→Session。检查三字段宽度、原值校验、部分失败还原、外部更新停止。历史运行脚本含旧PID和对象，只读作证据，不直接执行。
2. 静态追收到攻击路径 opcode36→7E8FD0→7DE090→8CABD0→29D7F0→29D9C0，候选记录C+1178。REA最新指令/伪代码在 runtime-20261019/attack-scroll-followup；先审完整性、唯一性、多段事件，再谈计数。
3. 请求门槛16D600，保护计时19EDEA2→19FB376→19F239B→19FEDD4→19FF314→1A03A83。单位与最终来源未闭合；C+1E90有非攻击写入，不能当命中计数。
4. 面板529F60受mask bit0x2控制→530650；6D6F90组装快照。实验期间实际mask未捕获，不将刷新假说当根因。
5. 正常9%卷轴让I/Mirror/V由1200到1092，U1200；到期恢复。三字段700仅支持用户感知出刀更快、还原变慢，服务器有效命中/DPS未证明。800掉血更快已被后续用户澄清替代。
6. 移速暂缓，实际私服服务端源码/配置尚未提供。公开AionLightning只作跨版本参考。

## 位置

Game.dll SHA256：b3043f0eaf225b3dc7ba320ac7671cc5b28cefbd637135943dc9e67c114ccae7
CryEntitySystem.dll SHA256：fbca87e5a639551bf7653d464e2863c49800e73c124ae4666ea9fb11d40bef7a
I=B+142DB40 u16；Mirror=B+142DC10 u32；V=C+532 u16。
C从B+F25C68管理器、+58句柄树、node+28实体、entity+380容器定位。历史B=3760000、C=73956000仅为旧值，同PID内C曾变化。

## 离线使用

不启动游戏也可阅读全部REA证据、模块、解码资源、报告和源码。合法IDA可对原始模块新建离线数据库；不分发商业IDA安装包、密钥或数据库。
REA主源码在仓库根；脚本保留原本机路径，换电脑先配置自己的输入与自备IDA路径。分析ZIP顶层附3份PAK/BXML辅助解码依赖。
EXE的self-test仅操作测试进程自身临时分配。静态阶段无需运行修改器。新GUI游戏内验证留待有条件时进行。
