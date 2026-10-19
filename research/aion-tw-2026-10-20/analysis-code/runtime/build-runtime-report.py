"""Verify retained read-only observations and render an additive report section."""
from pathlib import Path
import hashlib, html, json, struct

root = Path(__file__).parent
case = root.parent
def load(name):
    return json.loads((root/name).read_text(encoding='utf-8-sig'))

baseline = load('baseline-readonly.json')
confirm = load('baseline-confirmation-readonly.json')
actor = load('character-fields-readonly.json')
mapping = load('entity-root-readonly.json')
panel = load('user-panel-observation.json')
c = actor['Character']
checks = []
def check(name, value):
    checks.append({'name': name, 'passed': bool(value)})
    if not value:
        raise RuntimeError(name)

check('Screenshot digest', hashlib.sha256((root/panel['Screenshot']).read_bytes()).hexdigest() == panel['SHA256'])
for name, capture in [('baseline', baseline), ('confirmation', confirm), ('character', actor), ('map', mapping)]:
    check(name+' successful and handle closed', capture['Failure'] is None and capture['HandleClosed'])
    check(name+' same process birth', capture['Pid'] == baseline['Pid'] and capture['StartedUtc'] == baseline['StartedUtc'])
    reads = capture.get('Observations', capture.get('Reads'))
    check(name+' every retained read succeeded', bool(reads) and all(x['Success'] and x['BytesRead'] == x.get('Requested', len(bytes.fromhex(x['Hex']))) for x in reads))

for capture in [baseline, confirm]:
    obs = {x['Name']: x for x in capture['Observations']}
    check('Attack interval bytes and panel', struct.unpack('<H', bytes.fromhex(obs['received_attack_interval']['Hex']))[0] == obs['received_attack_interval']['Value'] == 1200 and round(1200/1000, 1) == panel['DisplayedAttackSpeed'])
    check('Interval mirror agrees', obs['attack_interval_mirror']['Value'] == 1200)
    check('Movement mirror agrees', struct.unpack('<f', bytes.fromhex(obs['local_move_speed_mirror']['Hex']))[0] == panel['DisplayedMoveSpeed'] == c['Speed'])
    check('Module identity readback', capture['ModuleAfter']['MetadataMatched'] and capture['ModuleBefore']['OnDiskSHA256'] == actor['GameSHA256'])

check('Exact object ID maps to same local handle', mapping['FoundExactKey'] and mapping['Candidate']['Handle'] == actor['Candidate']['Key'] == 65535)
check('Character identity readback', actor['IdentityReadbackMatched'])
check('Category 1 and 2 equality is scoped', c['C'] == c['P'] and c['Category1And2SamePointer'])
check('Player vtable and setter match original static evidence', c['VtableRVA'] == '0xd53940' and c['SpeedSetterRVA'] == '0x89adb0')
sample_read = next(x for x in actor['Reads'] if x['Role'].startswith('C+0x70C'))
raw_speed, square, inverse = struct.unpack('<fff', bytes.fromhex(sample_read['Hex']))
check('Derived values decoded from raw bytes', raw_speed == c['Speed'] and square == c['Square'] and abs(inverse-c['Inverse']) < 1e-8)
check('Speed and float32 caches consistent', square == struct.unpack('<f', struct.pack('<f', raw_speed*raw_speed))[0] and inverse == struct.unpack('<f', struct.pack('<f', 1/raw_speed))[0])
check('Animation U/V values decoded', struct.unpack('<HH', bytes.fromhex(next(x['Hex'] for x in actor['Reads'] if x['Role'].startswith('C+0x530')))) == (c['U'], c['V']) == (1200,1200))
for filename, lines in {
    'engine-static/entity-get-insns.normalized.json': ['mov r8, [rcx+58h]', 'cmp [rax+20h], bx', 'mov rax, [rdx+28h]'],
    'engine-static/container-get-insns.normalized.json': ['mov rax, [rcx+380h]'],
    'game-static/type-get-annotated-insns.normalized.json': ['cmp edx, 2', 'ja loc_18011C95B', 'mov [r8], rcx', 'mov al, 1', 'mov qword ptr [r8], 0']
}.items():
    insns = load(filename)['instructions']
    for line in lines:
        check('REA instruction '+line, any(x.split(': ',1)[-1] == line for x in insns))

result = {'allPassed': True, 'checkCount': len(checks), 'checks': checks,
          'scope': 'Retained read-only evidence consistency; no server timing or modification claim',
          'inputs': [{'path': str(p.relative_to(root)), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(root.rglob('*.json')) if p.name not in {'runtime-verification.json','runtime-summary.json'} and not p.name.startswith('rea-tool-schemas')]}
(root/'runtime-verification.json').write_text(json.dumps(result, ensure_ascii=False, indent=2),encoding='utf8')
summary = {'method': 'REA static instructions plus auxiliary Win32 read-only observations, not an REA runtime memory provider',
           'pid': actor['Pid'], 'process_started_utc': actor['StartedUtc'], 'captured_utc': actor['CapturedAtUtc'],
           'module_base': actor['ModuleBase'], 'character': c, 'received_interval': 1200,
           'memory_written': False, 'remote_functions_invoked': False, 'atomic_snapshot': False,
           'unknowns': ['Pointers after relog/relaunch or entity recreation', 'Control context A identity and protected clock source/unit', 'Accepted server attack/movement rate and limits', 'Effects of local changes; no modification experiment performed'],
           'verification': {'passed': True, 'checks': len(checks)}}
(root/'runtime-summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf8')

base=int(actor['ModuleBase'],16)
component=int(c['C'],16)
rows=[('同步攻击间隔','B+0x142DB40',base+0x142DB40,'uint16','1200 → 面板1.2秒'),
      ('间隔镜像','B+0x142DC10',base+0x142DC10,'uint32','1200'),
      ('移速镜像','B+0x142DC14',base+0x142DC14,'float32','6.0'),
      ('角色面板移速','C/P+0x38',component+0x38,'float32',str(c['PanelSpeed'])),
      ('角色运动移速','C+0x70C',component+0x70c,'float32',str(c['Speed'])),
      ('平方缓存','C+0x710',component+0x710,'float32',str(c['Square'])),
      ('倒数缓存','C+0x714',component+0x714,'float32',str(c['Inverse'])),
      ('动画间隔U/V','C+0x530 / +0x532',component+0x530,'uint16 × 2','1200 / 1200'),
      ('动画系数','C+0x51C',component+0x51c,'float32',str(c['AnimationScale']))]
table=''.join(f'<tr><td>{label}<br><code>{offset}</code></td><td><code>{hex(address)}</code><br>{kind}</td><td>{value}</td></tr>' for label,offset,address,kind,value in rows)
fragment=f'''<section id="runtime"><h2>新增：截图与运行中只读核对</h2>
<p>角色面板为等级3斥候：攻击速度1.2，移动速度6.0。独立采样读到了原始间隔1200，随后确认角色移速及派生缓存。<strong>首次只读阶段补齐了当前玩家对象定位；该阶段尚未验证修改效果或服务器规则，后续试验另列于本节末尾。</strong></p>
<p>方法：REA → IDA分析离线副本；辅助Win32脚本仅以VM_READ和QUERY_LIMITED_INFORMATION权限读取游戏。没有调用游戏函数、写内存、注入或暂停游戏。原有静态阶段与本节运行中观察分开保存。</p>
<div class="cols"><div><img src="runtime-20261019/user-character-panel.png" alt="用户提供的角色面板，攻击速度1.2、移动速度6.0" style="width:100%;max-width:460px;height:auto"><p class="muted">截图原件保留哈希。截图与几次内存采样并非同一原子快照；首次模块采样与末次复核结果一致。</p></div><div>
<h3>当前进程的对象定位链</h3><pre>Game.dll 基址 B = {actor['ModuleBase']}
B+0x1416C00 → 对象ID {mapping['ObjectId']}
对象ID表 → 句柄 65535
实体系统 +0x58 的句柄表
  key(+0x20) = 65535
  value(+0x28) = {c['Entity']}
实体 +0x380 → 容器 {c['C']}
容器虚表+0x50 → Game.dll RVA 0x11C950
  分类1、分类2均返回容器自身
  因而当前玩家 C = P = {c['C']}
虚表+0x260 → RVA0x89ADB0 速度写入器</pre>
<p>实体查询函数是CryEntitySystem.dll RVA0x45F60，容器读取函数是该模块RVA0x19190。组件查询函数先前未被IDA识别，本轮仅新增21字节函数边界标记，核对原文件与运行中代码一致后由REA读取，未补丁修改字节。</p>
<p class="note">这些绝对地址只属于本次进程与当前实体。分类1/2同址的结论限于这个已验证玩家，不能外推所有实体；控制上下文A仍未证明与C同址。</p></div></div>
<table><thead><tr><th>字段及相对位置</th><th>本次绝对地址及类型</th><th>读取结果</th></tr></thead><tbody>{table}</tbody></table>
<p>组件采样UTC：{html.escape(actor['CapturedAtUtc'])}。模块基线UTC：{baseline['CapturedAtUtc']}；复核UTC：{confirm['CapturedAtUtc']}。读取前后核对了进程出生时间、路径与关键指针，未冻结目标，无法宣称原子一致性。</p>
<p>下一步用正常换武器、穿脱装备或获得移速效果做单因素对照，观察同步间隔、动画U/V及移速缓存怎样更新。当前只能确认客户端数值，尚不能承诺实际出手频率、服务器上限或修改后稳定生效。</p>
<p><a href="runtime-20261019/runtime-summary.json">本轮结构化结论</a> · <a href="runtime-20261019/character-fields-readonly.json">对象与字段原始读取记录</a> · <a href="runtime-20261019/baseline-readonly.json">首次模块基线</a> · <a href="runtime-20261019/baseline-confirmation-readonly.json">末次模块复核</a> · <a href="runtime-20261019/runtime-verification.json">{len(checks)}项证据一致性核对</a></p>
<p><a href="runtime-20261019/engine-static/entity-get-insns.evidence.json">REA实体查询证据</a> · <a href="runtime-20261019/engine-static/container-get-insns.evidence.json">REA容器读取证据</a> · <a href="runtime-20261019/game-static/type-get-annotated-insns.evidence.json">REA分类查询证据</a></p></section>'''
fragment=fragment.replace('辅助Win32脚本仅以VM_READ和QUERY_LIMITED_INFORMATION权限读取游戏。没有调用游戏函数、写内存、注入或暂停游戏。','首次只读阶段的辅助Win32脚本仅以VM_READ和QUERY_LIMITED_INFORMATION权限读取游戏，该阶段没有调用游戏函数、写内存、注入或暂停游戏；后续临时写入试验另列于本节末尾。')
for name in ['level4-fragment.html','weapon-removal-fragment.html','interval-trial-fragment.html','animation-trial-fragment.html','scroll-state-trials-fragment.html']:
    followup=root/name
    if followup.exists():
        fragment=fragment.removesuffix('</section>')+followup.read_text(encoding='utf8')+'</section>'
(root/'runtime-fragment.html').write_text(fragment,encoding='utf8')
print(json.dumps({'checks':len(checks),'allPassed':True,'component':c['C']},ensure_ascii=False))
