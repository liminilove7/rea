"""Record implementation verification and preserve the preceding HTML evidence sections."""
import hashlib
import html
import importlib.util
import json
import pathlib
import shutil
import struct
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

root = pathlib.Path(__file__).resolve().parent
local = root.parent.parent
runtime = root/'runtime'
source = local/'aion-imgui-lab-20261020/source/research/aion-tw-2026-10-20/modifier-imgui'
spec = importlib.util.spec_from_file_location('audit', local/'aion-autocombat-20261021/audit_evidence.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
pe = audit.PE(local/'aion-tw-20261019/samples/Game.dll')
expected_hash = 'b3043f0eaf225b3dc7ba320ac7671cc5b28cefbd637135943dc9e67c114ccae7'
assert hashlib.sha256(pe.data).hexdigest() == expected_hash
checks = []
def check(label, rva, actual, expected):
    checks.append(dict(label=label, rva=hex(rva), actual=actual, expected=expected, passed=actual == expected))
for rva, target in [(0x1455f6,0x16d600),(0x16d88e,0x7cfbf0)]:
    raw=pe.at(rva,5)
    check('direct call', rva, [raw[0],hex(rva+5+struct.unpack_from('<i',raw,1)[0])], [0xe8,hex(target)])
for rva, expected in [(0x1455f3,'488bcf'), (0x16d6b5,'0386901e0000'),
                      (0x16d89b,'b801000000'), (0x16d8a0,'89ae901e0000')]:
    check('original argument/timing/return instruction', rva, pe.at(rva,len(expected)//2).hex(),expected)
raw=pe.at(0x16d887,7)
check('LEA address of global object, not load of its qword value',0x16d887,
      [raw[:3].hex(),hex(0x16d887+7+struct.unpack_from('<i',raw,3)[0])],['488d0d','0x145eed0'])
assert all(c['passed'] for c in checks)
rea_dir = root.parent/'rea-health-2026-10-24T11-28-17.313Z'
rea_sources=[]
for name in ['stop-144f10-pseudo','stop-144f10-insns','stop-144f10-callers',
             'stop-16d600-pseudo','stop-16d600-insns','stop-16d600-callers']:
    p=rea_dir/(name+'.evidence.json')
    d=json.loads(p.read_text('utf-8'))['data']
    assert d['subject']['digest']['sha256']==expected_hash
    rea_sources.append(dict(file=str(p.relative_to(local)).replace('\\','/'), evidenceId=d['evidence_id'],
                            sha256=hashlib.sha256(p.read_bytes()).hexdigest()))
chain=dict(newReaQueries=0, reusedReaSources=rea_sources, originalPeChecks=checks,
    observed=['144F10 passes its saved object argument in RCX to 16D600 at 1455F6.',
              '16D600 combines object+1E90 and module attack interval for a timing check.',
              '16D88E calls 7CFBF0 after LEA RCX,module+145EED0; do not substitute the qword stored there.',
              '16D600 can return 1 when conditional transport send is skipped; it does not prove a server hit.'],
    missing=['Verified upper action construction and request lifetime.', 'Executing thread, engine scheduler and reentrancy constraints.',
             'Attack cancellation and queued-request behavior.', 'Hostility, range/LOS, local-player death and scene transition conditions.',
             'Server acceptance and real no-further-attack verification.'],
    targetCalls=0, serverHitProven=False)
(root/'attack-chain-readiness.json').write_text(json.dumps(chain,ensure_ascii=False,indent=2),encoding='utf-8')

for p in root.parent.glob('health-stop*.json'):
    shutil.copy2(p,runtime/'evidence'/p.name)
replay=json.loads((runtime/'verification/capture-replay.json').read_text('utf-8'))
assert replay['allPassed'] and replay['samples']==1481
program_checks=0
for p in (runtime/'verification').glob('controller*.json'):
    d=json.loads(p.read_text('utf-8-sig')); assert d['allPassed']; program_checks+=len(d['checks'])
render_checks=0
for folder in ['render','controls']:
    d=json.loads((runtime/'verification'/folder/'render-verification.json').read_text('utf-8')); assert d['allPassed']; render_checks+=len(d['checks'])
build=json.loads((runtime/'BUILD-IDENTITY.json').read_text('utf-8-sig'))
assert hashlib.sha256((runtime/'SpeedLab.dll').read_bytes()).hexdigest()==build['assemblySHA256']
for f in build['sourceFiles']:
    assert hashlib.sha256(pathlib.Path(f['path']).read_bytes()).hexdigest()==f['sha256']
live=json.loads((runtime/'verification/live-observer.json').read_text('utf-8'))
assert live['active'] is False and live['stop']['StopRequired'] and not live['stop']['AttackAuthorized']
metrics_path=runtime/'verification/live-observer-process.json'
metrics=json.loads(metrics_path.read_text('utf-8-sig'))
metrics.update(requestedSeconds=5, observerStarted=False,
               scope='Current target was empty: start rejected during preflight. CPU is this command only; no 5-second active observation, peak working set unavailable.')
metrics_path.write_text(json.dumps(metrics,ensure_ascii=False,indent=2),encoding='utf-8')
result=dict(assemblySHA256=build['assemblySHA256'], sourceFiles=build['sourceFiles'],
            programChecks=program_checks,renderChecks=render_checks,newHealthChecks=24,
            replaySamples=1481,readOnlyLiveTargetSnapshot='runtime/evidence/live-target.json',
            liveEmptyTargetStartRejected=True,attackActuatorConnected=False,newReaQueries=0,
            gameWrites=0,automaticInputs=0,limits=['Runtime data reads are auxiliary Win32, supported by saved REA evidence.',
            'Live observer refused empty selection; positive observer lifecycle is fixture-tested, not a new in-game kill test.',
            'No real attack executor or cancellation validation; no auto-targeting or movement.',
            'Polling/ordered reads are not atomic or a hard real-time guarantee.'],
            performance=metrics)
(root/'implementation-verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')

report=local/'aion-autocombat-20261021/实体与技能调用链进展.html'
text=report.read_text('utf-8')
prefix='../aion-autocombat-20261024/health-implementation/'
section='''<!-- HEALTH-IMPLEMENTATION-BEGIN -->
<section id="health-implementation-20261024"><h2>2026-10-24 · 已实现：生命观察、身份绑定与停止锁存</h2>
<p><b>第一阶段已接入现有ImGui工具。</b>“实体观察”页现在可以读取当前目标生命指示、客户端死亡判定及原始字段，并显式开始最长60秒的只读观察。</p>
<ol><li>启动新版 <a href="'''+prefix+'''runtime/start.cmd">start.cmd</a>，进入“实体观察”。</li>
<li>游戏中手选目标，点击“读取目标生命”查看一次快照。</li>
<li>点击“观察当前目标60秒”。约每500ms采样；死亡、生命归零、目标切换/清空、读失败、身份变化或到期即结束并锁存原因。</li>
<li>查看下方停止原因与logs中的JSONL。后续出现满血或同名怪物不会自动恢复；必须手动重新开始。</li></ol>
<figure><img style="max-width:100%;height:auto" src="'''+prefix+'''runtime/screenshots/target-health.png" alt="离线合成尸体夹具的生产ImGui界面"><figcaption>生产ImGui/D3D11真实渲染，使用离线合成尸体夹具；不是游戏实测截图。</figcaption></figure>
<p>观察器单独持有目标身份，包括进程出生、模块基址、本地角色、目标句柄、对象ID、实体和组件。一次显式观察开始时核对模块文件SHA256，每轮检查进程/模块与对象绑定。每次采样关闭只读句柄，结束或关闭窗口时关闭日志。周围实体表仍为手动快照；当前目标观察有独立刷新。轮询和两次顺序读取不能提供原子或硬实时保证。</p>
<p><b>停止观察器没有连接攻击执行器。</b>敌我、可攻击性、普通攻击线程/参数/队列及实际停手还待证据；当前版本不自动攻击、找怪或移动。</p>
<h3>验证与实机边界</h3><p>程序及夹具 '''+str(program_checks)+''' 项、ImGui渲染与开关交互 '''+str(render_checks)+''' 项通过；新增生命/停止检查24项。四组实测共1,481个样本通过生产C#停止锁存回放。</p>
<p>新版C#曾在本机当前进程读到满血尖牙劍齒豹（与旧尸体ID不同）。随后尝试有限观察时，目标已清空，工具正确拒绝启动。没有据此声称完成了新一轮实机击杀/执行器停手验证。性能记录仅覆盖拒绝启动的预检命令；完整分析CPU、峰值内存与模型token成本未测。</p>
<h3>普通攻击调用链复核</h3><p>复用已保存REA Evidence，本轮新增REA请求0；新增7项原PE字节核对通过。1455F6向16D600传入当前对象参数；16D600有对象+1E90与攻击间隔的时间门槛。16D887以LEA把模块+145EED0的<b>地址</b>送入RCX，再调用7CFBF0。伪代码中的全局变量表达式不能替代机器指令的参数含义。返回1亦不能证明服务器受理或命中。</p>
<p>下一阶段先追上游动作构造与引擎调度、排队/取消及可攻击性，再接单目标执行器，验证真正的启动→攻击→死亡→停手；自动找怪、追击和连续升级随后开展。</p>
<p><a href="'''+prefix+'''runtime/architecture.html">新版图文使用说明</a> · <a href="'''+prefix+'''implementation-verification.json">构建与验证记录</a> · <a href="'''+prefix+'''attack-chain-readiness.json">调用链证据与缺口</a> · <a href="'''+prefix+'''runtime/verification/capture-replay.json">1,481样本回放</a></p></section>
<!-- HEALTH-IMPLEMENTATION-END -->'''
a=text.find('<!-- HEALTH-IMPLEMENTATION-BEGIN -->')
if a>=0:
    b=text.index('<!-- HEALTH-IMPLEMENTATION-END -->',a)+len('<!-- HEALTH-IMPLEMENTATION-END -->')
    text=text[:a]+section+text[b:]
else:
    shutil.copy2(report,root/'report-before-implementation.html')
    text=text.replace('<!-- RETAINED-CORPSE-BEGIN -->',section+'\n<!-- RETAINED-CORPSE-BEGIN -->',1)
report.write_text(text,encoding='utf-8')

class Links(HTMLParser):
    def __init__(self): super().__init__(); self.values=[]
    def handle_starttag(self,tag,attrs):
        self.values.extend(value for key,value in attrs if (tag,key) in [('a','href'),('img','src')])
link_checks=[]
for document,content in [(report,section),(runtime/'architecture.html',(runtime/'architecture.html').read_text('utf-8'))]:
    parser=Links();parser.feed(content)
    for value in parser.values:
        u=urlsplit(value)
        if u.scheme or u.netloc or not u.path: continue
        resolved=document.parent/unquote(u.path)
        link_checks.append(dict(document=str(document),reference=value,exists=resolved.is_file()))
assert all(c['exists'] for c in link_checks),[c for c in link_checks if not c['exists']]
(root/'report-link-verification.json').write_text(json.dumps(link_checks,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(dict(programChecks=program_checks,renderChecks=render_checks,replaySamples=1481,originalChecks=len(checks),links=len(link_checks)),ensure_ascii=False))
