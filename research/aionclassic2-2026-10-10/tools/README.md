# 工具按功能分类

| 功能 | 工具 | 本次内容 |
| --- | --- | --- |
| 分析编排 / 证据 | REA 6.1.0 | 本仓库根目录src、bridge、CLI/MCP；不重复打包node_modules |
| 静态格式 / 壳识别 | Detect It Easy 3.09 Windows x64 | static-inspection中本机现有便携ZIP（来源未独立验证），完整包上传、未启动工具 |
| 反汇编 / 反编译 | IDA Pro 8.3 | 仅记录版本与接入方法；本机包说明标记leaked，不再分发商业程序或密钥 |
| IDA MCP适配 | ida-pro-mcp 1.4.0 | ida-bridge中MIT源码、固定依赖和本机兼容改动记录 |
| 辅助资源 / 数学分析 | Python 3.12、Capstone、pefile | client/analysis-code；通过包管理器复现，不复制整个解释器环境 |
| 调试器候选 | x64dbg | 原工具清单保留路径；未用于本轮离线机制研究，不复制带有混合插件的安装目录 |
| 十六进制阅读 | HxD | 原工具清单保留路径；程序请从原作者获取 |
| 结束清理 | PowerShell脚本 | process-cleanup；含本机路径，其他机器先重新核对，不创建自启 |

下载与源码：
- REA：https://github.com/liminilove7/rea
- Detect It Easy：https://github.com/horsicq/Detect-It-Easy
- IDA：https://hex-rays.com/ida-pro （再分发限制：https://hex-rays.com/eula）
- IDA MCP：https://github.com/mrexodia/ida-pro-mcp
- x64dbg：https://github.com/x64dbg/x64dbg
- HxD：https://mh-nexus.de/en/hxd/

不包含ida.key、许可证/激活材料，不设置开机启动。持有游戏客户端不代表获得第三方商业工具再分发权。
