AION Research Lab · ImGui frontend · 2026-10-20

运行发布包
1. 完整解压到可写目录；不要只复制 AionLab.exe。
2. preview.cmd：离线查看四个页面，不枚举或连接游戏。
3. start.cmd：常规模式，沿用既有目标路径、哈希、基线与还原校验。
4. architecture.html：界面、功能架构、实现位置及回家后的验收步骤。
发布包包含 .NET 8 x64 运行时。要求 Windows x64、D3D11 和系统微软雅黑字体。
源码构建需要 .NET 8 SDK：powershell -File build.ps1 -Publish
测试：powershell -File verify.ps1

本版范围
- ImGui.NET + Veldrid 的独立桌面窗口。
- 复用旧版攻速核心：只读检查、700–1200 间隔、单次应用、500 ms 校验、
  60 秒上限、手动/正常关闭时还原、JSONL 日志。
- 移速：草案界面与快照接口；应用/还原按钮禁用，没有移速写入实现。
- 怪物识别：列表布局与只读快照接口；没有实体扫描、实时识别或自动操作。
- 不引入反作弊规避、进程隐藏、驱动、注入或游戏内覆盖层。

当前配置仍指向旧环境：
D:\Workspace\AION_TW\DeuLuncher\bin56\aion.bin
本次没有修改目标路径或放宽模块哈希校验。在不同目录启动游戏会找不到目标。
先核对实际目录与版本，再审阅 Profile 的修改，不要直接套用到另一版本。
同旧版共用单实例互斥体，不能同时运行两个版本。
启动失败查看 last-command-error.txt；如果已有旧版或新版实例，第二个实例退出。

验证边界
自动测试只触及本进程分配的内存及模拟会话，不连接游戏。
UI 测试使用生产 ImGui/D3D11 渲染器、离屏帧缓冲和模拟输入。
自包含发布包已构建；再次执行该发布包的复测命令被自动审批拦截，尚未复测。
系统窗口捕获曾超时；不声称已完成真实鼠标点击、多 DPI、各种显卡兼容性验收。
本次没有验证游戏内动画、命中频率、移动速度或怪物识别效果。
正常关闭尝试还原；强制结束、断电、角色对象重建不能保证还原。

源码入口
Desktop.cs：窗口、字体、页面、事件。
Features.cs：会话生命周期、预留快照模型。
../modifier/AttackSpeedLab.cs：共享原有进程/对象校验及攻速事务。
ControllerTests.cs、RenderProbe.cs：离线验证。
packages.lock.json：固定依赖解析。
verification/：本次结果；历史旧版验证记录保持原样。
