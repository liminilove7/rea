# 当前客户端与分析代码

目标是F:\SOFTWARE\永恒之塔\aionclassic2\bin64，本机Game.dll SHA256为834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786。

仓库原samples目录已有Aion.bin、Game.dll、CrySystem.dll、ScriptDLL64.dll。用户选择仅bin64程序及分析所需资源。Release附件包含bin64程序、104份实际解析过的原始PAK、解码资源，未上传21.3GB完整客户端。程序包排除运行日志/崩溃输出，内置逐文件SHA256。

analysis-code保留历史辅助脚本原文，部分使用F:/与D:/绝对路径：复现前调整到自己的样本目录。早期Python/Capstone线性窗口不保证函数语义，后续REA→IDA证据在evidence。protection归档只有第一层局部导出，不能称完整脱壳。resources归档是已解析资源，不含游戏完整资源包。

## Release归档

大文件另存GitHub Release，文件名以前缀client/server/evidence/tools/reports分类。完整HTML目录请下载reports__complete-mechanics-report.zip，解压后打开HTML，可保留所有证据链接。

## Release归档

大文件另存GitHub Release，文件名以前缀client/server/evidence/tools/reports分类。完整HTML目录请下载reports__complete-mechanics-report.zip，解压后打开HTML，可保留所有证据链接。
