# AION TW 私服客户端研究档案 · 2026-10-19

这是独立于旧经典服案例的新版本文件夹。用户确认实际运行目录为 `D:\Workspace\AION_TW\DeuLuncher\bin56`，启动器为 `Aion(賽季beta1.0).exe`。目前只有客户端，没有对应服务端源码。

- [图文报告与离线演算台（HTML源码）](reports/AION_TW速度分析报告.html)
- [分类下载、文件范围与SHA256](DOWNLOADS.md)
- [续查入口](CONTINUE.md)
- [结构化结论](provenance/findings.json)

完整离线阅读请下载 `analysis__complete-study-package.zip`，解压后打开 `aion-tw-20261019/AION_TW速度分析报告.html`。此包保留全部原始相对证据链接。Git中的报告副本仅将两处较大JSON的链接改为下载指南；原报告和全部JSON在ZIP中逐字节保留。

## 按功能分类

| 目录 / 附件 | 内容 |
| --- | --- |
| reports | 中文报告、关键REA证据、浏览器检查、截图和离线场景 |
| analysis-code | REA请求/核对脚本、PAK/BXML辅助解析和报告构建代码 |
| provenance | 样本哈希、文件清单、结构化结论、核对记录和原PE常量 |
| client | 上传程序及原始PAK的逐文件SHA256；二进制在Release附件 |
| tools | 本机配置示例和显式结束清理脚本；不自动运行 |
| analysis__complete-study-package.zip | 238份REA请求结果（含11份失败）、完整入口清单、225份Evidence文件、解码资源及复现代码 |

## 已验证范围

主要样本Game.dll SHA256：`b3043f0eaf225b3dc7ba320ac7671cc5b28cefbd637135943dc9e67c114ccae7`。
REA 6.1.0 → IDA 8.3离线分析；完整导出44,646个识别入口，57个入口取得指令；不代表全客户端语义审计完成。34条关键指令、9个有限数值例子核对，另含输入/表/资源校验；281项静态检查和21项浏览器检查通过。

本轮没有执行/附加游戏、修改客户端或验证实际进程修改效果。攻击间隔、动画倍率、移动速度缓存分别记录；服务器是否接受及真实上限仍未知。启动器、Aion.bin、CrySystem.dll、ScriptDLL64.dll等并未完成全部语义审计。目录名和启动器beta标签不构成游戏机制版本证明。

## 环境与权利说明

REA主项目位于仓库根目录。脚本保留本机D盘路径，换位置需按实际安装环境配置；IDA及其Python/MCP依赖为另行提供的工具。此前MIT桥接源码位于同分支的 `research/aionclassic2-2026-10-10/tools`。
游戏程序和资源按用户明确要求备份，原权利归属保持；REA的MIT许可证不自动覆盖游戏文件。IDA商业程序、产品密钥、安装配置备份、.i64数据库和临时退出标记不在本次发布中。
