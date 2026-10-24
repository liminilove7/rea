"""Preserve completed user-run observation journals and summarize their stop evidence."""
import datetime
import hashlib
import html
import json
import pathlib
import shutil

root=pathlib.Path(__file__).resolve().parent
review=root/'live-user-review'
review.mkdir(exist_ok=True)
cases=[]
for source in sorted((root/'runtime/logs').glob('target-health-*.jsonl')):
    before=source.stat()
    raw=source.read_bytes()
    after=source.stat()
    assert (before.st_size,before.st_mtime_ns)==(after.st_size,after.st_mtime_ns),'Journal is still being written'
    records=[json.loads(line) for line in raw.decode('utf-8-sig').splitlines() if line.strip()]
    if not records or records[-1]['kind']!='stop':
        continue
    destination=review/source.name
    if destination.exists():
        assert destination.read_bytes()==raw,'Do not overwrite differing archived evidence'
    else:
        destination.write_bytes(raw)
    samples=[r for r in records if r['kind'] in ('start','sample')]
    anchor=records[0]['anchor']
    changes=[]
    for r in samples:
        s=r['observation']['Value']
        v=s['Life']
        row=dict(utc=r['utc'],indicator=v['RawIndicator'],clientDead=v['ClientDead'],
                 selectedBefore=s['SelectedBefore'],selectedAfter=s['SelectedAfter'],
                 stable=s['Stable'],sameIdentity=s['Binding']==anchor,
                 stopRequired=r['stop']['StopRequired'],reasons=r['stop']['Reasons'])
        if not changes or {k:v for k,v in row.items() if k!='utc'}!={k:v for k,v in changes[-1].items() if k!='utc'}:
            changes.append(row)
    end=records[-1]
    last=samples[-1]
    s=last['observation']['Value']
    checks=dict(completedStopRecord=end['kind']=='stop',lastStable=s['Stable'],
        sameTargetIdentity=s['Binding']==anchor,
        targetStillSelected=s['SelectedBefore']==s['SelectedAfter']==anchor['Handle'],
        zeroIndicator=s['Life']['RawIndicator']==0,clientDead=s['Life']['ClientDead'] is True,
        stopLatched=end['stop']['StopRequired'],noAttackAuthority=not end['stop']['AttackAuthorized'],
        noGameWrites=all(r['gameWrites']==0 for r in records),noAutomaticInputs=all(r['automaticInputs']==0 for r in records))
    cases.append(dict(file=source.name,sha256=hashlib.sha256(raw).hexdigest(),records=len(records),
        observations=len(samples),name=records[0]['observation']['Value']['Name'],anchor=anchor,
        startedUtc=records[0]['utc'],endedUtc=end['utc'],
        elapsedSeconds=(datetime.datetime.fromisoformat(end['utc'])-datetime.datetime.fromisoformat(records[0]['utc'])).total_seconds(),
        transitions=changes,finalChecks=checks,allFinalChecksPassed=all(checks.values())))
assert len(cases)>=2 and all(c['allFinalChecksPassed'] for c in cases)
result=dict(cases=cases,scope='User-run production read-only health observation; completed journals show stop on zero indicator and client death while same target remained selected.',
            limits=['No automated attack actuator was connected. These records do not prove attacks stopped.',
                    'Stop-record timestamps do not establish exact server-death latency or permanent corpse retention.',
                    'UI reports and logs are client evidence, not independent server logs.'],newReaQueries=0)
(review/'review.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
report=root.parent.parent/'aion-autocombat-20261021/实体与技能调用链进展.html'
source=report.read_text('utf-8')
prefix='../aion-autocombat-20261024/health-implementation/live-user-review/'
rows=[]
for c in cases:
    start=datetime.datetime.fromisoformat(c['startedUtc']).astimezone(datetime.timezone(datetime.timedelta(hours=8))).strftime('%H:%M:%S')
    sequence=' → '.join(str(r['indicator']) for r in c['transitions'])
    rows.append('<tr><td>'+start+'</td><td>'+html.escape(c['name'])+'</td><td>'+str(c['anchor']['Identifier'])+'</td><td>'+sequence+'</td><td>'+str(round(c['elapsedSeconds'],2))+'秒</td><td><a href="'+prefix+c['file']+'">原始日志</a></td></tr>')
section='''<!-- USER-HEALTH-OBSERVATION-BEGIN -->
<section id="user-health-observation-20261024"><h2>用户实机验收 · 2026-10-24 20:32 / 20:35</h2>
<p><b>找到两份完整的新版ImGui观察日志，两轮均在目标仍选中、身份一致时，因生命指示归零与客户端死亡判定为真而结束观察。</b>最新一轮覆盖满血到死亡，补充了此前预检目标为空、未能开始观察之外的实机证据。</p>
<table><thead><tr><th>开始时间（北京时间）</th><th>目标</th><th>对象ID</th><th>生命指示序列</th><th>观察时长</th><th>证据</th></tr></thead><tbody>'''+''.join(rows)+'''</tbody></table>
<p>两轮结尾均有独立stop记录，原因为“生命指示归零；客户端死亡判定为真；观察停止”。这验证的是生产只读观察器的停止路径；自动攻击执行器尚未接入，因此不能称为实际攻击停手验证。具体死亡时刻、服务器结算和长期尸体保留仍未由这些日志证明。</p>
<p><a href="'''+prefix+'''review.json">逐轮身份、死亡及停止核对</a>。已按SHA256保存原日志副本；没有修改正在运行的工具或游戏。</p></section>
<!-- USER-HEALTH-OBSERVATION-END -->'''
a=source.find('<!-- USER-HEALTH-OBSERVATION-BEGIN -->')
if a>=0:
    b=source.index('<!-- USER-HEALTH-OBSERVATION-END -->',a)+len('<!-- USER-HEALTH-OBSERVATION-END -->')
    source=source[:a]+section+source[b:]
else:
    source=source.replace('<!-- HEALTH-IMPLEMENTATION-BEGIN -->',section+'\n<!-- HEALTH-IMPLEMENTATION-BEGIN -->',1)
report.write_text(source,encoding='utf-8')
backup=root.parent.parent/'aion-report-backup/aion-tw-20261019/health-user-observation-20261024'
manifest=[]
for p in [*review.iterdir(), pathlib.Path(__file__).resolve(), report]:
    if not p.is_file(): continue
    dest=backup/p.name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,dest)
    digest=hashlib.sha256(p.read_bytes()).hexdigest();assert hashlib.sha256(dest.read_bytes()).hexdigest()==digest
    manifest.append(dict(file=p.name,sha256=digest,bytes=p.stat().st_size))
(backup/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(dict(completedLogs=len(cases),allChecksPassed=True,backupFiles=len(manifest),latestSequence=[r['indicator'] for r in cases[-1]['transitions']]),ensure_ascii=False))
