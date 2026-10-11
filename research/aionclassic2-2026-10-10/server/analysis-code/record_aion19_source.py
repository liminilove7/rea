"""Record source provenance and bounded findings in the existing AION report."""
from pathlib import Path
import json,hashlib,shutil,xml.etree.ElementTree as ET

local=Path(__file__).parent
manifest=json.loads((local/'aion19-source-manifest.json').read_text(encoding='utf-8'))
root=Path(manifest['source_directory'])
def path(s):return root/'gameserver'/'src'/'org'/'openaion'/'gameserver'/s
def source(p):return p.read_text(encoding='utf-8-sig')
def lines(p,needle):return [i+1 for i,l in enumerate(source(p).splitlines()) if needle in l]
config=root/'gameserver'/'config'/'default.config'
random=path('skill/effect/RandomMoveLocEffect.java')
enchant=path('services/EnchantService.java')
rng=root/'commons'/'src'/'org'/'openaion'/'commons'/'utils'/'Rnd.java'
assert 'gameserver.version = 2.1.0.12' in source(config)
assert 'int success = 50;' in source(enchant)
assert 'if(Rnd.get(0, 100) < success)' in source(enchant)
assert '(max - min + 1)' in source(rng)
assert 'float lastSee = 0;' in source(random) and source(random).count('lastSee =')==1
assert 'float lastNonSee = 0;' in source(random)
skills=root/'gameserver'/'data'/'static_data'/'skills'/'skill_templates.xml'
examples=[]
for e in ET.parse(skills).getroot():
    if e.attrib.get('skill_id') in {'1424','1463','1544','1545','2278'}:
        examples.append({'attributes':e.attrib,'random_move_nodes':[{'tag':n.tag,'attributes':n.attrib} for n in e.iter() if 'randommove' in n.tag.lower()]})
findings={'scope':'Pinned AionLightning emulator only; not current official Classic server proof.','source_manifest_sha256':hashlib.sha256((local/'aion19-source-manifest.json').read_bytes()).hexdigest(),'source_commit':manifest['commit'],'version':{'default_config_value':'2.1.0.12','source_line':lines(config,'gameserver.version =')},'movement':{'direction_attribute':'FRONT/BACK strings, not proof of client reserved3 numeric mapping','source_path':str(random),'calculate_line':lines(random,'public void calculate'),'apply_line':lines(random,'public void applyEffect'),'back_branch_limitation':'lastSee and lastNonSee start at zero; lastSee is never subsequently assigned. The loop condition is initially false and the final BACK dash overwrites XY with the original XY. This is an observed implementation issue, not a retail rule.','matching_skill_ids':examples},'enchantment':{'source_path':str(enchant),'method_line':lines(enchant,'public static boolean enchantItem'),'start_success':50,'extra_success':'max(stone_level-target_level-qualityCap,0)*5','cap':95,'predicate':'Rnd.get(0,100) < success','predicate_line':lines(enchant,'if(Rnd.get(0, 100) < success)'),'rng_path':str(rng),'rng_line':lines(rng,'max - min + 1'),'nominal_outcomes':101,'nominal_cap_probability':'95/101, assuming uniform discrete outcomes; does not prove current Classic probability.'}}
serialized=json.dumps(findings,ensure_ascii=False,indent=2)
for dest in [root.parent/'AionLightning-1.9-reference-findings.json',local/'aion-report-backup'/'server-reference'/'reference-findings.json']:
    dest.write_text(serialized,encoding='utf-8')
marker='## 公开服务端参考源码：来源与版本边界'
report=local/'AION_ANALYSIS.md'
text=report.read_text(encoding='utf-8').split(marker)[0].rstrip()
addition=f'''

{marker}

2026-10-11，用户补充“之前也有服务端代码”，并要求从网上寻找AION 1.9服务端源码。本轮已查到旧学习材料所在的另一分支，同时下载并核对其引用的完整源码。此前本轮的客户端报告没有纳入这些材料；以下建立关联，避免重复寻找和混用版本。

### GitHub上之前保存了什么

在 [liminilove7/rea 的 docs/aion19-pvp-study-20261010 分支](https://github.com/liminilove7/rea/tree/docs/aion19-pvp-study-20261010/aion1.9)，提交 `82ef9e4c57fed2ce8592cfce567c50b8d29a1e24`，保存有攻速/移速实现笔记、PVP伤害与装备分析、可重跑Python模型、阈值CSV、来源哈希表。它不在当前analysis分支的目录里。

该目录的README明确说明第三方服务端源码没有随该提交上传，引用的是下面固定提交。旧校验记录证明当时检查过源文件和模型，不等于已经运行、验证了服务器兼容性。

### 已取得的源码与完整性

- 来源：[ZON3DEV/AionLightning，1.9.0分支](https://github.com/ZON3DEV/AionLightning/tree/1.9.0)。
- 固定提交：`{manifest['commit']}`；Git树：`{manifest['tree_sha']}`。
- 本机完整源码：`{root}`。
- 完整归档：`{manifest['archive_path']}`。
- 全部{manifest['git_blob_checks_passed']}个归档文件通过Git blob SHA-1逐项核对；去掉SVN历史副本后为{manifest['active_files_excluding_svn']}个文件，其中Java源码{manifest['java_files_excluding_svn']}个。
- 解包内容共{manifest['total_uncompressed_bytes']}字节；归档SHA-256为`{manifest['archive_sha256']}`。
- 完整来源清单：F盘sources/AionLightning-1.9-source-manifest.json；D盘.codex/local/aion19-source-manifest.json及aion-report-backup/server-reference/source-manifest.json。关键源码另备份在D盘server-reference/key-sources。

本轮仅取得、校验和阅读源码。打包完整性不证明可编译、可启动、协议兼容或规则正确；没有运行自带脚本、JAR或服务端进程。

### 版本边界必须先保留

仓库README把该分支标作1.9，但其 `gameserver/config/default.config` 第139行仍为 `gameserver.version = 2.1.0.12`。因此保留“标称1.9、实际混有其他版本实现”的约束。当前客户端Game.dll的版本和这份模拟器的协议、资源、公式尚未逐项匹配。

另找到 [rafabertholdo/AionGo](https://github.com/rafabertholdo/AionGo) 作为备选：其README称包含1.9的Go移植和Java21参考实现，同时承认Java部分有2.0协议残留。本轮只核实该项目公开说明，没有下载、审计或运行其完整代码，不把它列为已验证替代服务端。

### 与当前四条分析主线接起来的源码入口

| 问题 | 此源码的入口 | 下一步证据要求 |
|---|---|---|
| RandomMoveLoc位移 | skill/effect/RandomMoveLocEffect.java、skill/model/DashParam.java、world/World.java | 对照技能ID、效果参数、方向枚举和回包；不能把Java字段当C++偏移 |
| 属性与速度 | model/gameobjects/stats/PlayerGameStats.java、CreatureGameStats.java、Stat.java、modifiers/RateModifier.java | 追初始化/重算/上下限/同步，核对当前客户端收到的字段 |
| 攻击间隔与移动 | controllers/PlayerController.java、CreatureController.java、network/aion/clientpackets/CM_ATTACK.java、CM_MOVE.java | 区分收到请求的时间、最终属性和客户端动作表现 |
| 伤害与PVP | utils/stats/StatFunctions.java、controllers/attack/AttackUtil.java、skill/effect/DamageEffect.java | 旧PVP笔记可复用，但公式、取整和配置仍须限定到此提交 |
| 强化与神石 | services/EnchantService.java、model/items/GodStone.java、model/templates/item/GodstoneInfo.java、commons/utils/Rnd.java | 追随机判定与成功/失败写回，不能用本模拟器替代经典服概率 |
| 服务端到客户端同步 | network/aion/serverpackets/SM_EMOTION.java、SM_STATS_INFO.java、SM_ATTACK.java | 名称相似不证明与当前客户端消息编号或负载布局一致 |

### 两个已经读到的差异，说明为什么不能直接套用

`RandomMoveLocEffect` 使用字符串FRONT/BACK和整数value计算位置，再经DashParam与World.updatePosition更新位置。它给出了可读的执行逻辑，但没有证明当前客户端reserved3的1/2恰好映射这两个字符串。

此提交的BACK分支中，lastSee和lastNonSee初始为0，lastSee后续未被赋新值；循环条件初始不成立，末尾又以lastSee=0计算XY。这会覆盖前面计算的向后目的坐标，属于可见的实现问题。不能把有问题的模拟器分支解释成官方位移规则。

同时提取此服务端技能XML中的5条对应记录：1424为30/FRONT，1463为15/BACK，1544、1545、2278均为10/FRONT。五条value都与当前客户端的reserved2吻合，方向标签也与reserved3=1/2的资源候选一致。这增强了方向映射假设，但属于跨版本资源对照，还不能替代当前客户端执行消费者的代码证据。

强化入口 `EnchantService.enchantItem` 在服务端代码中调用Rnd并决定成功/失败：初始success=50，按石等级/装备等级/品质差增加，辅助剂另加配置值，随后封顶95，用 `Rnd.get(0,100) < success` 判定。Rnd的范围计算含max-min+1；若把101个整数结果视为均匀，封顶对应95/101，不能简单写成95%。这是**此模拟器**的判定代码，与第四课当前客户端提示公式明显不能直接等同。

这份源码使“判定端怎么写”成为可以阅读、复现和比较的问题；它仍不能证明正在玩的经典服后台恰好运行这份代码。后续应先建立版本对应关系，再把其结论接到当前二进制证据里。

### 状态回包给出的新攻速线索

另用 `trace_aion19_status_bridge.py` 按SM_STATS_INFO前段writeC/H/D/F/Q的实际宽度累计偏移，而不是凭字段名字排序。扣除前8字节元数据后，得到下面的模拟器字段位置：

| 模拟器源码字段 | 状态块内偏移 | 当前客户端已有证据 |
|---|---|---|
| POWER | +0x00 | 物理伤害提示读取该位置的uint16，名称仍为跨版本推断 |
| KNOWLEDGE | +0x08 | 魔法伤害提示读取该位置的uint16，同上 |
| MAXHP/当前HP | +0x3C/+0x40 | 当前客户端HP接收/组件/快照路径已确认 |
| MAXMP/当前MP | +0x44/+0x48 | 当前客户端MP接收路径已确认 |
| FLY_TIME/当前飞行时间 | +0x50/+0x54 | 当前客户端同步时乘1000；对应关系仍需版本核对 |
| ATTACK_RANGE | +0x64 | 当前客户端0x19B20会读取这里的float并加入技能射程 |
| ATTACK_SPEED | +0x68 | 当前客户端时间门槛路径会读取这里的uint16 |

当前客户端 `0x6A0B0` 路径在 `0x6A15E` 读取全局状态缓存+0x68（RVA 0xD71BE0），加上角色组件+0x1C88，与调用受保护函数0x1244AE3所得的计时候选比较；若当前值不大于两者之和则退出该路径。后续路径会构造请求、调用传输相关函数，并在 `0x6A350` 将本次计时值写回组件+0x1C88。另有0x5D140的时间补偿和0x14F92的动作检查使用同一个uint16。

这将“收到的状态字段 → 本地缓存 → 时间门槛读取者”接了起来。多处字段对齐使“该uint16是当前攻击间隔”的推断明显增强；尚不能只靠模拟器回包就确认当前版本的语义、单位、所有攻击路径和服务端认可规则。受保护计时函数的准确行为尚未解析。组件+0x1C88是时间戳候选，与间隔缓存是不同字段。

名称注册处的C_ATTACK内部编号为0x20，构造请求窗口出现其他字面字节；内部编号、传输操作码及加密前后表示尚未接通，不能把它们强行等同。证据保存在两盘binary/aion19-status-bridge.json，脚本含8项当前客户端指令核对及7项模拟器字段位置核对。
'''
text+='\n'+addition.strip()+'\n'
for dest in [report,local/'aion-report-backup'/'AION_ANALYSIS.md',Path(r'F:\RVE-Workspace\cases\aionclassic2-2026-10-10\reports\AION_ANALYSIS.md')]:
    dest.write_text(text,encoding='utf-8')
shutil.copy2(local/'aion19-source-discovery.json',root.parent/'AionLightning-1.9-source-discovery.json')
shutil.copy2(local/'aion19-source-discovery.json',local/'aion-report-backup'/'server-reference'/'source-discovery.json')
shutil.copy2(Path(__file__),root.parent/Path(__file__).name)
shutil.copy2(Path(__file__),local/'aion-report-backup'/'server-reference'/Path(__file__).name)
print(json.dumps({'matching_skill_examples':examples,'report_sha256':hashlib.sha256(report.read_bytes()).hexdigest(),'report_bytes':report.stat().st_size},ensure_ascii=False,indent=2))
