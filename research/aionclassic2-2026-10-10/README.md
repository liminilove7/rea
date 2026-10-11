# AION客户端 / 服务端机制研究档案

## 下载入口

[按功能下载全部归档](DOWNLOADS.md) · [GitHub Release](https://github.com/liminilove7/rea/releases/tag/aion-research-20261011)

[下次续查入口与环境说明](CONTINUE_TOMORROW.md)

最新归档新增第九轮REA分析、原始响应与失败记录、49项HTML检查。整客户端及当前官方后台尚未完整破解。

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

