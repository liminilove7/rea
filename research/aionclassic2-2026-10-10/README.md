# AION Classic 本机版本：离线逆向学习记录

针对 2026-10-10 提供的 `aionclassic2/bin64` 样本。按用户要求上传四个主模块、分析结果与可复现的离线 Python 环境。样本是第三方程序，本目录不将其重新声明为 REA 的开源代码。

## 从攻击速度开始读

打开 [ANALYSIS.md](ANALYSIS.md)，阅读最后的“攻击速度实战第一课”。

- `attackDelay` 在已验证的名称转换上下文中对应编号 `0x1D`。
- `Game.dll + 0x396E80` 查询数据记录后读取 `uint16(record + 0x1BE)`。
- 一处显示函数把该值除以 `1000.0`。
- 这条链对应基础攻击间隔的读取与显示；最终角色攻速的计算、保护表示及运行时修改效果尚未确认。
- 用户报告以前发现过隐藏计算过程；当前保留为假设，不伪装为已经复现的结论。

精简机器可读证据：[reports/attack-speed-lesson.json](reports/attack-speed-lesson.json)。

## 包含内容

| 路径 | 内容 |
|---|---|
| `samples/` | Aion.bin、Game.dll、CrySystem.dll、ScriptDLL64.dll 原样副本 |
| `scripts/` | 五个静态分析/解码脚本，不启动被分析程序 |
| `reports/` | 关键 JSON、手工伪代码、完整二进制证据 ZIP |
| `exports/protection-stage1/` | 三个模块第一层各 4096 字节的独立解码结果 |
| `manifest.json` | 文件大小与 SHA-256 |
| `requirements.txt` | 精确固定的 Python 依赖版本 |

`binary-evidence.zip` 内含 RTTI、虚表、入口链、调用关系、汇编窗口和验证记录。原报告中的绝对路径属于历史证据，不代表换机后的文件位置。

完整客户端资源、F 盘其他目录、工具安装包、账号配置、Python 解释器及 IDA/调试器本体不包含在本目录中。资源表只提供本课相关的小规模示例与原分析说明；重新提取全部资源需要另备完整客户端。

## 复现环境

实测：Windows x64，Python 3.12；pefile 2024.8.26、Capstone 5.0.6。运行不需要 IDA。现有 IDA 8.3 的批处理尝试未成功，详情保留在报告中。

在此目录打开 PowerShell，使用已安装的 Python：

```powershell
python -m pip install --target .\scripts\python-libs -r .\requirements.txt
python .\scripts\verify_package.py
python .\scripts\analyze_attack_speed.py
```

包验证应全部通过；攻速脚本还会核验 Game.dll 的精确哈希和六项指令/常数证据。换版本不会静默套用旧偏移。

更完整的分析按以下顺序运行：

```powershell
python .\scripts\analyze_aion_native.py
python .\scripts\trace_aion_native.py
python .\scripts\decode_aion_stage1.py
python .\scripts\export_aion_findings.py
python .\scripts\analyze_attack_speed.py
```

默认从本目录的 `samples` 读取样本，向 `reports/binary` 与 `local-backup/binary` 写结果。要与另外的原始 bin64 目录核对，可设置进程环境变量：

```powershell
$env:AION_BIN64_DIR = 'F:\SOFTWARE\永恒之塔\aionclassic2\bin64'
python .\scripts\analyze_aion_native.py
```

`AION_CASE_DIR` 可覆盖整个案例目录，目录内须有 `samples`。默认只比较包内样本；设置 `AION_BIN64_DIR` 后才是与外部原件比较。分析输出中的 `matches_source` 必须结合此设置理解。

这些命令不添加开机启动、计划任务、驱动或后台服务。没有运行时内存写入、游戏自动化或反作弊修改功能。

## 结果边界

第一层解码不是完整脱壳；没有可运行的重建 EXE/DLL。RVA 不是运行时绝对地址，属性快照不是 Player 对象，基础间隔不是已验证的最终攻速。PE 展开信息范围可能只是函数片段；线性汇编窗口也可能包含数据。详细限制与证据来源见分析报告。
