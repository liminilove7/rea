# AION 1.9 剑星 PVP：后台公式与配装学习

本目录保存后台伤害公式的源码分析、装备证据和可重跑的计算模型。
分析日期：2026-10-10。以塔哈巴塔枪裸暴击 **598** 为入口，比较暴击、命中、攻击、盾防、武器防御及正常增益后的属性收益。

## 阅读入口

- [暴击、盾防与剑星 PVP](docs/暴击盾防与剑星PVP理解.md)：第10–18节包含598算例、精锐千夫＋15、完整物理伤害链、2500以上盾防命中表、魔石收益、两把合成枪、八职业条件分析和验证方案。
- [攻击速度与移动速度](docs/攻击速度与移动速度实现.md)：属性单位、上下限、网络请求校验和速度同步。
- [完整计算结果](analysis/pvp-damage-model.json)：名义概率、源码离散概率与指定条件下的魔石分配枚举。
- [暴击阈值表](analysis/pvp-critical-thresholds.csv)和[盾防/命中表](analysis/pvp-shield-accuracy.csv)。
- [装备XML证据](analysis/pvp-equipment-evidence.json)和[本机来源校验记录](analysis/study-materials-check.json)。

## 版本与验证范围

依据 [ZON3DEV/AionLightning 的 1.9.0 分支](https://github.com/ZON3DEV/AionLightning/tree/1.9.0)，固定提交为 `94fc8048e5fc198f000c0ca2176c65034c57cb39`。
文档源码链接均指向该提交，避免上游更新后行号和公式改变。
该源码混有1.9/2.1路径、默认配置2.1.0.12；分析属于此模拟器实现，尚未验证官方1.9规则、完整客户端兼容或实战对战。
校验记录保留上传前本机检查的上下文；它不是GitHub上重新运行过服务器的证明。

## 重跑计算模型

使用 Python 3.9 或更高版本，仅需标准库。在本目录运行：

```powershell
python scripts/analyze_pvp_damage.py
```

生成模型JSON和两张CSV，执行7项公式边界检查。此脚本不需要客户端或服务器进程。
模型区分名义百分比与源码 `Rnd.get(0,100)` 的101结果概率，但期望伤害仍省略逐阶段伤害取整、额外攻击、观察器效果、恢复与冷却；不是完整战斗模拟器。

## 重新提取装备证据

这一步额外需要上游源码，下载到本目录的 `server` 子目录并固定提交：

```powershell
git clone --branch 1.9.0 https://github.com/ZON3DEV/AionLightning.git server
git -C server checkout 94fc8048e5fc198f000c0ca2176c65034c57cb39
python scripts/analyze_pvp_equipment.py
```

脚本读取装备、套装和50级职业基础XML，更新装备证据JSON。它不会编译或启动服务端。
此上传目录仅包含学习文档、脚本和文本结果；客户端、DLL、下载归档、工具链与第三方服务端源码未随本次提交上传。
