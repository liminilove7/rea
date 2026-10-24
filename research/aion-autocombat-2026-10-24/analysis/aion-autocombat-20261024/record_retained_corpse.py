"""Preserve the selected-corpse observation without changing prior experiment records."""
import hashlib
import json
import pathlib

root = pathlib.Path(__file__).resolve().parent
capture = root/'health-stop-retained-corpse.json'
data = json.loads(capture.read_text('utf-8'))
anchor = data['anchor']
checks = []
for row in data['samples']:
    obj = row['anchorObject']
    values = obj['values']
    checks.append(dict(stable=row['stable'] and obj['stable'],
        selected=row['selectedBefore'] == row['selectedAfter'] == anchor['handle'],
        sameIdentity=all(obj[k] == anchor[k] for k in ('handle','entity','character','identifier')),
        zeroIndicator=values['byte40'] == 0,
        clientDead=values['state2c8'] == 7 or (values['stateafc'] == 18 and values['flagaf8'] != 0),
        stopCandidate=row['stopAssessment']['stopCandidate']))
assert checks and all(all(c.values()) for c in checks)
assert data['handleClosed'] and not data['errors']
result = dict(source=capture.name, sha256=hashlib.sha256(capture.read_bytes()).hexdigest(),
    anchor=anchor, sampleCount=len(checks), observedSeconds=data['samples'][-1]['elapsed'],
    startedUtc=data['samples'][0]['utc'], endedUtc=data['samples'][-1]['utc'], checks=checks,
    userObservation='用户称当前目标已由本人击杀且尸体没有消失。',
    observation='During this 10-second capture the same client entity remained selected with zero health indicator and client death predicate true.',
    limits=['No live-to-dead transition captured in this supplementary run.',
            'Does not establish permanent corpse retention, quest item presence, loot permission or server exact HP.',
            'Read-only auxiliary capture using previously established REA field semantics; no new REA query or automated attack test.'],
    gameWrites=0, automaticInputs=0, targetCalls=0, handleClosed=True)
(root/'health-stop-retained-corpse-findings.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
report = root.parent/'aion-autocombat-20261021/实体与技能调用链进展.html'
source = report.read_text('utf-8')
section = '''<!-- RETAINED-CORPSE-BEGIN -->
<section id="retained-corpse-20261024"><h2>补充实测：尸体仍被选中，2026-10-24 20:04（北京时间）</h2>
<p><b>尖牙劍齒豹在连续10秒、41次只读采样中均保持同一对象和选中状态，同时生命指示为0、客户端死亡判定为真。</b>用户报告已由本人击杀且尸体没有消失。此次未采到它从存活变为死亡的过程。</p>
<table><tr><th>字段</th><th>实测值</th></tr>
<tr><td>目标句柄 / 对象ID</td><td>65529 / 2153973818</td></tr>
<tr><td>实体 E / 角色组件 C（本次进程）</td><td>0x7BCCA800 / 0x71F46000</td></tr>
<tr><td>生命指示 C+40 / 数值 C+135C</td><td>0 / 0</td></tr>
<tr><td>状态 C+2C8 / C+AFC / C+AF8</td><td>7 / 0xFFFFFFFF / 0</td></tr></table>
<p>这支持在目标仍存在时依据已验证的客户端死亡判定停止，而非等待目标消失。地址仅描述本次对象，不能跨重启复用；不据此证明永久保留、任务物品或拾取权限。本次复用既有REA静态证据，新增Win32辅助只读采样；没有新REA查询、游戏写入、函数调用或自动攻击。</p>
<p><a href="../aion-autocombat-20261024/health-stop-retained-corpse.json">41次原始采样</a> · <a href="../aion-autocombat-20261024/health-stop-retained-corpse-findings.json">身份与死亡判定逐样本核对</a></p></section>
<!-- RETAINED-CORPSE-END -->'''
start = source.find('<!-- RETAINED-CORPSE-BEGIN -->')
if start >= 0:
    end = source.index('<!-- RETAINED-CORPSE-END -->', start)+len('<!-- RETAINED-CORPSE-END -->')
    source = source[:start]+section+source[end:]
else:
    source = source.replace('<!-- HEALTH-STOP-EVIDENCE-BEGIN -->', section+'\n<!-- HEALTH-STOP-EVIDENCE-BEGIN -->', 1)
report.write_text(source, encoding='utf-8')
print(json.dumps(dict(name=anchor['name'], samples=len(checks), allChecksPassed=True, report=str(report)), ensure_ascii=False))
