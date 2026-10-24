"""Audit REA evidence, independently check original PE bytes, summarize raw captures.
No game access. Preserves old report sections. Re-running updates only this section.
"""
import copy
import hashlib
import html
import importlib.util
import json
import pathlib
import struct

ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('audit', ROOT.parent / 'aion-autocombat-20261021/audit_evidence.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
spec = importlib.util.spec_from_file_location('probe', ROOT / 'capture_health_stop.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
pe = audit.PE(ROOT.parent / 'aion-tw-20261019/samples/Game.dll')
SHA = 'b3043f0eaf225b3dc7ba320ac7671cc5b28cefbd637135943dc9e67c114ccae7'
assert hashlib.sha256(pe.data).hexdigest() == SHA
checks = []


def check(label, address, observed, expected):
    checks.append(dict(label=label, rva=hex(address), observed=observed, expected=expected, passed=observed == expected))


# Displacements, immediates and branch destinations independently decoded from PE.
for rva, displacement, immediate in [(0x31f3e3, 0xafc, 18), (0x31f3ec, 0xaf8, 0),
                                    (0x31f3f5, 0x2c8, 7), (0x14454a, 0x2c8, 7),
                                    (0x144553, 0xafc, 18), (0x14455c, 0xaf8, 0)]:
    raw = pe.at(rva, 7)
    expected = b'\x83\xb8' + struct.pack('<I', displacement) + bytes([immediate])
    check('cmp dword [rax+field], immediate', rva, raw.hex(), expected.hex())
for rva, opcode, dest in [(0x31f3ea, 0x75, 0x31f3f5), (0x31f3f3, 0x75, 0x31f402),
                         (0x31f3fc, 0x74, 0x31f402), (0x144551, 0x74, 0x1445a6),
                         (0x14455a, 0x75, 0x144565), (0x144563, 0x75, 0x1445a6)]:
    raw = pe.at(rva, 2)
    check('conditional branch opcode/destination', rva,
          [raw[0], hex(rva+2+struct.unpack('<b', raw[1:])[0])], [opcode, hex(dest)])
for rva, dest in [(0x31f3d9, 0x320560), (0x144f8e, 0x144480), (0x8c5c09, 0x69cef0),
                  (0x13cac1, 0x867bc0), (0x144519, 0x14bd40), (0x31f448, 0x3205e0),
                  (0x31f4ab, 0x3205e0)]:
    raw = pe.at(rva, 5)
    check('direct call', rva, [raw[0], hex(rva+5+struct.unpack_from('<i', raw, 1)[0])], [0xe8, hex(dest)])
for table, name, function in [(0xb6aa00, 'UnitIsDead', 0x31f3d0),
                              (0xb6aa10, 'UnitHP', 0x31f430), (0xb6aa20, 'UnitHPMax', 0x31f490)]:
    st, fn = struct.unpack('<QQ', pe.at(table, 16))
    text = pe.at(st-pe.base, 64).split(b'\0')[0].decode('ascii')
    check('name/function descriptor pair (registration traversal not audited)', table,
          [text, hex(fn-pe.base)], [name, hex(function)])
raw = pe.at(0x9278f0, 7)
dest = 0x9278f0 + 7 + struct.unpack_from('<i', raw, 3)[0]
check('death diagnostic LEA', 0x9278f0, [raw[:3].hex(), hex(dest)], ['488d15', '0xd57ab0'])
check('death diagnostic text', dest, pe.at(dest, 128).split(b'\0')[0].decode('ascii'),
      '[TeleportToNPC] TELEPORT_TO_NPC_CONDITION_FAIL_ACTION_STATUS : ACT_STATE_DEAD')

evidence = []
for d in sorted(ROOT.glob('rea-health-2026-10-24T11-*')):
    for f in sorted(d.glob('*.evidence.json')):
        w = json.loads(f.read_text('utf-8'))
        e = w['data']
        assert w['ok'] and e['subject']['digest']['sha256'] == SHA
        evidence.append(dict(file=str(f.relative_to(ROOT)).replace('\\', '/'),
                             sha256=hashlib.sha256(f.read_bytes()).hexdigest(),
                             id=e['evidence_id'], operation=e['operation'], parameters=e['parameters']))


def dead(values):
    return values['state2c8'] == 7 or (values['stateafc'] == 18 and values['flagaf8'] != 0)


def summarize(name, user):
    f = ROOT / name
    d = json.loads(f.read_text('utf-8'))
    anchor = d.get('anchor')
    transitions, last = [], None
    counts = dict(samples=len(d['samples']), sameIdentity=0, deadPredicateTrue=0,
                  selectedDead=0, missing=0, rebound=0, unstable=0)
    replay = []
    for s in d['samples']:
        o = s.get('anchorObject')
        same = bool(anchor and o and all(o[k] == anchor[k] for k in ('handle', 'entity', 'character', 'identifier')))
        v = o['values'] if o else None
        stable = bool(s.get('stable') and o and o.get('stable'))
        dc = dead(v) if same and stable else None
        counts['sameIdentity'] += bool(same)
        counts['deadPredicateTrue'] += dc is True
        counts['selectedDead'] += dc is True and s['selectedBefore'] == anchor['handle']
        counts['missing'] += o is None
        counts['rebound'] += bool(o and not same)
        counts['unstable'] += not s.get('stable', False)
        assessment = probe.gate(s, anchor)
        must_stop = (not s.get('stable') or not same or s.get('selectedBefore') != anchor['handle']
                     or (stable and (v['byte40'] == 0 or dc)))
        replay.append(dict(elapsed=s['elapsed'], passed=not assessment['attackAuthorized'] and
                          (not must_stop or assessment['stopCandidate'])))
        row = dict(elapsed=round(s['elapsed'], 3), utc=s['utc'], selected=s.get('selectedBefore'),
                   resolvedIdentifier=o.get('identifier') if o else None, sameAnchor=same,
                   byte40=v['byte40'] if v else None, state2c8=v['state2c8'] if v else None,
                   stateafc=v['stateafc'] if v else None, flagaf8=v['flagaf8'] if v else None,
                   amount135c=v['amount135c'] if v else None, reference1358=v['reference1358'] if v else None,
                   clientDeadPredicate=dc, stable=s.get('stable'), stopReasons=assessment['reasons'])
        signature = {k: val for k, val in row.items() if k not in ('elapsed', 'utc')}
        if signature != last:
            transitions.append(row)
            last = signature
    assert all(r['passed'] for r in replay)
    return dict(file=name, sha256=hashlib.sha256(f.read_bytes()).hexdigest(), anchor=anchor,
                userObservation=user, counts=counts, handleClosed=d.get('handleClosed'),
                transitions=transitions, stopOnlyReplayPassed=len(replay),
                replayLimit='Exercises observation/stop policy only; no real attack actuator was connected.')


series = [
    summarize('health-stop-kill-series.json', '用户纠正为NPC击杀；确认倒地零血。目标栏清空是否自动，用户不能确定。'),
    summarize('health-stop-player-kill-series.json', '用户确认由本人击杀、尸体仍选中，随后告知消失。'),
    summarize('health-stop-quest-kill-series.json', '用户拟用带任务物品怪物验证保留尸体，之后回答尸体消失或目标改变；具体原因未确认。预检目标是灰毛布拉斯，但连续采样起点已变为亞希爾瀾號船員；本表只跟踪后者，不能归属于预检怪物，也未证实任务物品或拾取权限。')]
series[2]['preflightMismatch'] = dict(preflightFile='health-stop-quest-selection-check.json',
    preflightName='灰毛布拉斯', preflightIdentifier=2155088366,
    capturedName=series[2]['anchor']['name'], capturedIdentifier=series[2]['anchor']['identifier'],
    interpretation='Target changed before continuous capture; no same-target continuity or quest-loot claim.')

# Relevant failure cases absent from a successful run must stay fail-closed.
base = json.loads((ROOT / 'health-stop-selected-baseline.json').read_text('utf-8'))
sample, anchor = base['samples'][0], base['anchor']
cases = []
def fault(name, mutate, fresh=True):
    row = copy.deepcopy(sample)
    mutate(row)
    g = probe.gate(row, anchor, fresh)
    cases.append(dict(name=name, passed=g['stopCandidate'] and not g['attackAuthorized'], reasons=g['reasons']))
fault('expired sample', lambda r: None, False)
fault('read failure', lambda r: r.update(stable=False, error='injected read failure'))
fault('selection changed mid-sample', lambda r: r.update(selectedAfter=0))
fault('same name/handle, identifier reused', lambda r: r['anchorObject'].update(identifier=1))
fault('different component at same entity', lambda r: r['anchorObject'].update(character='0x10000'))
fault('invalid indicator must not clamp to alive', lambda r: r['anchorObject']['values'].update(byte40=255))
fault('zero indicator before death flag', lambda r: r['anchorObject']['values'].update(byte40=0, state2c8=1, stateafc=17, flagaf8=1))
fault('death flag despite nonzero indicator', lambda r: r['anchorObject']['values'].update(byte40=100, state2c8=7))
assert all(c['passed'] for c in checks + cases)
result = dict(inputSha256=SHA, provider='REA MCP → IDA attached GUI, read-only', newReaQueries=len(evidence),
              evidence=evidence, originalPeChecks=checks, captures=series, failurePolicyChecks=cases,
              sourceScriptSha256=hashlib.sha256((ROOT/'capture_health_stop.py').read_bytes()).hexdigest(),
              clientDeathPredicate='u32(C+0x2C8)==7 || (u32(C+0xAFC)==18 && u32(C+0xAF8)!=0)',
              conclusions=[
                  'The client death predicate is shared by the UnitIsDead-associated routine, an ACT_STATE_DEAD diagnostic branch, and selected action eligibility checks.',
                  'Two distinct death predicate branches occur in the captured lifecycle: AFC=18 with AF8 nonzero first, then state2C8=7.',
                  'Zero health indication, client death predicate, deselection and disappearance are different sampled events.',
                  'Entity handles and component addresses were reused; names or one pointer alone are insufficient identity.',
                  'UnitHP/UnitHPMax route through selector-dependent UI snapshots; target selector 2 returns unavailable for HP cases 0/1 in 3205E0. A named API alone does not guarantee target exact HP.'
              ],
              limits=['Client semantic death is not independently verified server state.',
                      'No hostile/faction, attack range/LOS, self-health, skill invocation, actuator shutdown or server acceptance validation.',
                      'No permanent-corpse/loot-rights conclusion from the task-item attempt.',
                      '250ms sampling cannot establish exact transition times or general latency.',
                      'No attack execution: replay tests are not evidence that an automated attack stopped in game.',
                      'H arithmetic/rounding and exact server monster HP remain unknown.'],
              gameWrites=0, targetCalls=0, automaticInputs=0, productionModifierChanged=False)
(ROOT/'health-stop-findings.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')

def table(s):
    rows = []
    for t in s['transitions']:
        rows.append('<tr>' + ''.join('<td>'+html.escape(str(t[k]))+'</td>' for k in
            ('elapsed','selected','resolvedIdentifier','sameAnchor','byte40','state2c8','stateafc','flagaf8','clientDeadPredicate')) + '</tr>')
    return '<div class="scroll"><table><thead><tr><th>相对秒</th><th>选中句柄</th><th>对象ID</th><th>原对象</th><th>生命指示</th><th>2C8</th><th>AFC</th><th>AF8</th><th>客户端死亡</th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div>'

links = ''.join('<li><a href="../aion-autocombat-20261024/'+e['file']+'">'+html.escape(e['file'])+'</a></li>' for e in evidence)
experiments = ''.join('<h3>'+html.escape(s['anchor']['name'])+' · 对象 '+str(s['anchor']['identifier'])+'</h3><p>'+html.escape(s['userObservation'])+'</p><p>采样 '+str(s['counts']['samples'])+' 次；同一对象死亡判定真 '+str(s['counts']['deadPredicateTrue'])+' 次；其中仍被选中 '+str(s['counts']['selectedDead'])+' 次。稳定性异常 '+str(s['counts']['unstable'])+' 次。</p>'+table(s) for s in series)
section = '''<!-- HEALTH-STOP-EVIDENCE-BEGIN -->
<style>#health-stop-evidence-20261024 .scroll{max-width:100%;overflow-x:auto}#health-stop-evidence-20261024 pre{overflow-x:auto}#health-stop-evidence-20261024 a{overflow-wrap:anywhere}</style>
<section id="health-stop-evidence-20261024"><h2>2026-10-24 · 生命状态与停止条件：静态判定＋三轮只读实测</h2>
<p><b>已补齐当前版本的客户端死亡判定与目标失效证据。</b>这证明可以构建停止观察器，不等于已实现自动战斗，也不证明服务器死亡事件或精确生命值。</p>
<p>本轮新增 REA 查询 <b>''' + str(len(evidence)) + '''</b> 次；原始 PE 核对 <b>''' + str(len(checks)) + '''</b> 项通过。三轮各120秒，只读采样；无游戏写入、自动输入或游戏函数调用。</p>
<svg viewBox="0 0 1000 150" role="img" aria-label="生命归零、死亡判定、目标清空、实体消失是独立阶段" style="width:100%;max-width:1000px;background:#10253a;border-radius:12px"><g fill="#163953" stroke="#62b5db"><rect x="15" y="25" width="210" height="95" rx="10"/><rect x="270" y="25" width="210" height="95" rx="10"/><rect x="525" y="25" width="210" height="95" rx="10"/><rect x="780" y="25" width="205" height="95" rx="10"/></g><g fill="#eef8ff" text-anchor="middle" font-family="Microsoft YaHei,sans-serif" font-size="19"><text x="120" y="65">生命指示归零</text><text x="120" y="95">先停止尝试</text><text x="375" y="65">客户端判定死亡</text><text x="375" y="95">尸体可能仍选中</text><text x="630" y="65">目标栏清空</text><text x="630" y="95">不代表此前没死</text><text x="882" y="65">实体消失或复用</text><text x="882" y="95">旧身份永久失效</text><text x="247" y="80">→</text><text x="502" y="80">→</text><text x="757" y="80">→</text></g></svg>
<p>图示是本次观察到的阶段，不承诺所有场景都按同一时序。采样间隔约250毫秒，不是精确游戏事件时钟。</p>
<h3>客户端死亡判定：两条分支都必须保留</h3>
<pre>ClientDead(C) = u32(C + 0x2C8) == 7
             || (u32(C + 0xAFC) == 18 &amp;&amp; u32(C + 0xAF8) != 0)</pre>
<p><code>UnitIsDead</code> 名称/函数描述符位于 RVA B6AA00，函数 RVA 31F3D0。它与 RVA 9271C0 内的 <code>ACT_STATE_DEAD</code> 提示分支、RVA 144480 的部分动作资格排除使用同一判定。描述符原字节已核对；完整脚本接口注册遍历未审计。所有字段均相对经验证的角色组件 C，不是 Game.dll 基址直接加这些偏移。</p>
<p>读取链：当前模块基址 → 目标句柄与实体管理器 → 实体树对象 → E+380 组件 C；重新核对对象 ID、回链、虚表及目标前后值。没有目标时是“不可取得该判定”，不能返回“活着”。</p>
<h3>停止条件与结论边界</h3>
<table><thead><tr><th>观察</th><th>拟执行行为</th><th>可以声称什么</th></tr></thead><tbody>
<tr><td>生命指示为0，死亡判定尚未真</td><td>暂停新攻击，等待后续状态；禁止自动恢复</td><td>生命归零候选；单个零值不独立证明死亡</td></tr>
<tr><td>已验证对象的 ClientDead 为真</td><td>结束当前攻击对象，锁存停止原因</td><td>客户端把对象视作死亡；不等于服务端日志认证</td></tr>
<tr><td>目标清空、切换或原对象不存在</td><td>停止；重新选择必须重新建立身份</td><td>原目标不再有效；不能推定击杀成功</td></tr>
<tr><td>句柄、名称相同但ID或绑定改变</td><td>拒绝继续使用旧对象，不随新对象复活</td><td>观察到句柄/存储复用；旧地址不能跨生命周期使用</td></tr>
<tr><td>读失败、过期、身份不一致、字段前后变化</td><td>停止并保留不完整事实</td><td>未知；不能把失败值填成0、满血或存活</td></tr>
</tbody></table>
<p><b>停止应锁存</b>：目标重新出现、读数恢复或又选中同名怪物，都不能自行恢复攻击。这是后续执行器的设计要求；本轮只读停止策略不发送攻击，未验证实际执行器能否及时停手。</p>
<h3>三轮原始时间序列</h3><p>下表仅在值或身份变化时列一行，完整采样保存于JSON。4294967295为原始无符号FFFFFFFF，语义未另行命名。原对象=false后的生命值属于复用句柄解析到的新对象，绝不能解释成旧怪物复活。</p>''' + experiments + '''
<h3>验证范围</h3><p>三轮真实采样回放检查全部通过，另覆盖样本过期、读失败、目标切换、同名ID复用、组件更换、异常比例、先归零后死亡、死亡状态与比例冲突等8项停止策略检查。它们验证本地观察策略，不验证游戏服务器或自动攻击执行。</p>
<p>已有100→79→100受伤/回血记录继续保留。当前 +135C 仍可能为比例重建量；UnitHP/UnitHPMax 也按对象选择分支，目标选择值2的HP情况在3205E0中返回不可用，不能凭接口名称宣布取得怪物精确HP。</p>
<p class="warn">尚未证明：所有怪物/地图与特殊死亡状态、长期尸体与拾取权限、敌我和可攻击性、障碍/射程、玩家自身停止条件、执行器停手效果、服务器受理与伤害结算。本轮没有修改正式修改器的Alive/Hostile接口。</p>
<p><a href="../aion-autocombat-20261024/health-stop-findings.json">完整证据与检查</a> · <a href="../aion-autocombat-20261024/capture_health_stop.py">只读采样与停止策略脚本</a> · <a href="../aion-autocombat-20261024/health-stop-player-kill-series.json">本人击杀480次原始采样</a> · <a href="../aion-autocombat-20261024/health-stop-kill-series.json">NPC介入原始采样</a> · <a href="../aion-autocombat-20261024/health-stop-quest-kill-series.json">任务物品尝试原始采样</a></p>
<details><summary>本轮REA原始Evidence</summary><ul>''' + links + '''</ul></details></section>
<!-- HEALTH-STOP-EVIDENCE-END -->'''
report = ROOT.parent / 'aion-autocombat-20261021/实体与技能调用链进展.html'
source = report.read_text('utf-8-sig')
backup = ROOT / 'report-before-health-stop.html'
if not backup.exists():
    backup.write_text(source, encoding='utf-8')
begin = source.find('<!-- HEALTH-STOP-EVIDENCE-BEGIN -->')
if begin >= 0:
    end = source.index('<!-- HEALTH-STOP-EVIDENCE-END -->', begin) + len('<!-- HEALTH-STOP-EVIDENCE-END -->')
    source = source[:begin] + section + source[end:]
else:
    begin = source.index('<!-- LIVE-REA-HEALTH-BEGIN -->')
    source = source[:begin] + section + source[begin:]
report.write_text(source, encoding='utf-8')
print(json.dumps(dict(newReaQueries=len(evidence), originalChecks=len(checks), replaySamples=sum(s['counts']['samples'] for s in series),
                      failureCases=len(cases), report=str(report)), ensure_ascii=False))
