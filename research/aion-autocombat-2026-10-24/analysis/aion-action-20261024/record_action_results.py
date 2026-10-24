"""Audit REA artifacts, independently check PE instructions, and preserve report history."""
import hashlib
import html
import importlib.util
import json
import pathlib
import shutil
import struct
from html.parser import HTMLParser
from urllib.parse import urlsplit, unquote

root=pathlib.Path(__file__).resolve().parent
local=root.parent
spec=importlib.util.spec_from_file_location('audit',local/'aion-autocombat-20261021/audit_evidence.py')
audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)
pe=audit.PE(local/'aion-tw-20261019/samples/Game.dll')
sha='b3043f0eaf225b3dc7ba320ac7671cc5b28cefbd637135943dc9e67c114ccae7'
assert hashlib.sha256(pe.data).hexdigest()==sha
checks=[]
def check(label,rva,actual,expected):
    checks.append(dict(label=label,rva=hex(rva),actual=actual,expected=expected,passed=actual==expected))
for rva,dest in [(0x53cbca,0x151a90),(0x151e8a,0x116470),(0x116bb4,0x15ce80),
                 (0x15cf0b,0xb1d5c0),(0x15cf2c,0xb1d5c0),(0x1657bb,0x144f10),
                 (0x7cfcc0,0x816520),(0x7cfd2e,0xb1d5d2),(0x13bb92,0x116470)]:
    raw=pe.at(rva,5)
    check('direct E8 call',rva,[raw[0],hex(rva+5+struct.unpack_from('<i',raw,1)[0])],[0xe8,hex(dest)])
for rva,code in [(0x116c41,'89b790160000'),(0x116d13,'c7879416000001000000'),
                 (0x15ce8f,'4c8db190160000'),(0x15cf13,'89be94160000'),
                 (0x15cf5e,'41c70601000000'),(0x15cf76,'41c7060a000000'),
                 (0x15cf7f,'41c70609000000'),(0x15cf86,'c7869416000006000000'),
                 (0x7cfd33,'01bbb8040100'),(0x16d76a,'ff8604110000')]:
    check('original state/continuation/counter instruction',rva,pe.at(rva,len(code)//2).hex(),code)
check('Player vtable +8 callback',0xd53948,hex(struct.unpack('<Q',pe.at(0xd53948,8))[0]),'0x1801652a0')
raw=pe.at(0x53cb11,7);dest=0x53cb11+7+struct.unpack_from('<i',raw,3)[0]
literal=pe.at(dest,32).split(b'\0')[0].decode('ascii')
check('force_attack literal referenced by command branch',0x53cb11,[raw[:3].hex(),literal.lower()],['488d15','force_attack'])
raw=pe.at(0x16d887,7)
check('transport object is addressed with LEA',0x16d887,[raw[:3].hex(),hex(0x16d887+7+struct.unpack_from('<i',raw,3)[0])],['488d0d','0x145eed0'])
assert all(c['passed'] for c in checks),[c for c in checks if not c['passed']]
evidence=[]
for folder in sorted(root.glob('rea-action-*')):
    for p in sorted(folder.glob('*.evidence.json')):
        wrapper=json.loads(p.read_text('utf-8'));d=wrapper['data']
        assert wrapper['ok'] and d['subject']['digest']['sha256']==sha
        evidence.append(dict(file=p.relative_to(root).as_posix(),sha256=hashlib.sha256(p.read_bytes()).hexdigest(),
                             id=d['evidence_id'],operation=d['operation'],parameters=d['parameters']))
assert len(evidence)==63
results=dict(inputSha256=sha,newReaQueries=len(evidence),evidence=evidence,originalPeChecks=checks,
    initialAuditCorrection=json.loads((root/'initial-byte-audit-failure.json').read_text('utf-8')),
    observations=[
      '53C260 force_attack branch passes local Player to 151A90 with action 1; shortcut key 1 mapping is not yet demonstrated.',
      '151A90 action 0 calls 14BD40 to select an action from current target; it is not a generic cancel.',
      '151A90 honors ManualAttack and can map attack 1 to modes 9/10 while moving.',
      '116470 sets action data and mode at +1690, phase at +1694; it has preconditions, early returns, protected calls and other side effects.',
      'Player vtable slot +8 references 1652A0; it dispatches modes 1 and conditionally 9/10 to 144F10. Runtime executing thread is not proven.',
      '15CE80 clears a 184-byte action block in some branches and can restore prior modes or set modes 1/9/10; it cannot be treated as universal cancel.',
      '7CFBF0 may keep remaining outbound bytes in a shared transport buffer; zero pending bytes does not prove no kernel/server-side work remains.',
      '16D600 increments +1104 before conditional send; the field is not a hit counter and all writers have not been audited.'
    ],
    unknowns=['Exact shortcut-key 1 entry and input action representation.',
              'Engine thread, scheduling/reentrancy, execution authority and request lifetime.',
              'A validated cancel operation and guarantee against later state restoration.',
              'Queued attack-specific content, server acceptance, hits and exact completion time.',
              'Other writers/reset/wrap semantics for the request-sequence-related field.',
              'Runtime correlation of newly logged goal modes with normal attack/movement/cancel input.'],
    authority=dict(databaseSaved=False,databaseClosed=False,targetCalls=0,gameWrites=0,automaticInputs=0))
(root/'action-findings.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
runtime=root/'runtime-action'
shutil.copy2(root/'action-state-readonly.json',runtime/'evidence/action-baseline.json')
shutil.copy2(root/'action-findings.json',runtime/'evidence/action-findings.json')
old=local/'aion-autocombat-20261024/health-implementation/runtime'
for target,source in [('verification/capture-replay.json','verification/capture-replay.json'),
                      ('evidence/live-target.json','evidence/live-target.json'),
                      ('screenshots/target-health.png','screenshots/target-health.png')]:
    shutil.copy2(old/source,runtime/target)
program_count=0
for p in (runtime/'verification').glob('controller*.json'):
    d=json.loads(p.read_text('utf-8-sig'));assert d['allPassed'];program_count+=len(d['checks'])
render_count=0
for name in ['render','controls']:
    d=json.loads((runtime/'verification'/name/'render-verification.json').read_text('utf-8'));assert d['allPassed'];render_count+=len(d['checks'])
build=json.loads((runtime/'BUILD-IDENTITY.json').read_text('utf-8-sig'))
assert hashlib.sha256((runtime/'SpeedLab.dll').read_bytes()).hexdigest()==build['assemblySHA256']
for file in build['sourceFiles']:
    assert hashlib.sha256(pathlib.Path(file['path']).read_bytes()).hexdigest()==file['sha256']
observed=json.loads((root/'action-state-readonly.json').read_text('utf-8'))['Value']
assert observed['IdentityMatched'] and observed['LocalAction']['Stable']
verification=dict(programChecks=program_count,renderChecks=render_count,newActionChecks=6,
    sourceFiles=build['sourceFiles'],assemblySHA256=build['assemblySHA256'],
    liveBaseline=observed['LocalAction'],targetSelected=observed['SelectedBefore'],
    finalPackagedCapture=dict(file='action-state-final-readonly.json',assemblySHA256=build['assemblySHA256'],
        snapshot=json.loads((root/'action-state-final-readonly.json').read_text('utf-8'))),
    limitations='Idle current-role read only; mode meanings still need controlled normal input. Existing retained-corpse replay is health-only, not action validation.',
    measuredCosts='REA call elapsed times are in each batch journal. Whole-task CPU, peak memory and model token costs not measured.',
    attackActuatorConnected=False,gameWrites=0,automaticInputs=0)
(root/'implementation-verification.json').write_text(json.dumps(verification,ensure_ascii=False,indent=2),encoding='utf-8')

rows=''.join('<li><a href="../aion-action-20261024/'+e['file']+'">'+html.escape(e['file'])+'</a></li>' for e in evidence)
section='''<!-- ACTION-DISPATCH-BEGIN -->
<section id="action-dispatch-20261024"><h2>2026-10-24 · 普通攻击上游与取消路径：本轮新增REA证据</h2>
<p><b>本轮63次REA→IDA只读查询成功，原始PE核对'''+str(len(checks))+'''项通过。</b>已从最终请求向上追到命名命令、目标动作封装、动作状态写入与Player更新分派；执行线程和通用取消语义仍未得到证明。</p>
<svg viewBox="0 0 1000 255" style="width:100%;max-width:1000px;background:#10253a;border-radius:12px" role="img" aria-label="命令写入状态，再由更新回调分派发送"><g fill="#163953" stroke="#62b5db"><rect x="20" y="20" width="280" height="85" rx="10"/><rect x="360" y="20" width="280" height="85" rx="10"/><rect x="700" y="20" width="280" height="85" rx="10"/><rect x="20" y="155" width="280" height="75" rx="10"/><rect x="360" y="155" width="280" height="75" rx="10"/><rect x="700" y="155" width="280" height="75" rx="10"/></g><g fill="#eef8ff" text-anchor="middle" font-family="Microsoft YaHei,sans-serif" font-size="18"><text x="160" y="55">force_attack分支 53C260</text><text x="160" y="83">不等于已证实快捷键1入口</text><text x="500" y="55">目标动作封装 151A90</text><text x="500" y="83">ManualAttack / 移动影响参数</text><text x="840" y="55">116470 写动作状态</text><text x="840" y="83">C+1690 / C+1694 等</text><text x="160" y="185">Player更新回调 1652A0</text><text x="160" y="214">读取状态，线程尚未证实</text><text x="500" y="185">144F10 → 16D600</text><text x="500" y="214">资格、距离与时间门槛</text><text x="840" y="185">7CFBF0 传输对象</text><text x="840" y="214">可能保留尚未发送字节</text><text x="330" y="70">→</text><text x="670" y="70">→</text><text x="330" y="200">→</text><text x="670" y="200">→</text><text x="500" y="136">上排写状态；下排在更新中消费。两排之间不是直接函数调用。</text></g></svg>
<h3>这轮排除的错误实现假设</h3><ul>
<li><code>151A90(Player,0,...)</code> 会通过14BD40按当前目标选择动作；0不能当作取消。</li>
<li><code>15CE80</code> 部分分支会清空184字节动作块，但随后可恢复先前模式或写入1/9/10；它不是通用停止接口。</li>
<li>16D600在条件发送前递增<code>C+1104</code>。请求序号变化不能证明实际发包，更不能证明命中；其他写入者、重置和回绕未审完。</li>
<li>7CFBF0的待发字节属于共享传输缓冲。0不能证明内核、网络或服务器上没有未完成攻击，不能直接据此作停手验收。</li>
</ul>
<h3>可复核的字段与边界</h3><table><tr><th>位置</th><th>本轮证据含义</th><th>仍未知</th></tr>
<tr><td>Game RVA D53948</td><td>Player虚表+8指向1652A0</td><td>实际执行线程ID、重入与调度约束</td></tr>
<tr><td>玩家组件C+1690 / +1694</td><td>动作值及阶段；更新器读取后分派</td><td>完整枚举、所有写入者及正常按键关联</td></tr>
<tr><td>C+16A0 / +16A4 / +16A8</td><td>部分动作转换/恢复分支使用</td><td>所有生命周期和彻底取消条件</td></tr>
<tr><td>C+16AC / +1E90 / +1ED8</td><td>第五参数、攻击尝试计时及相关标志的原始值</td><td>完整业务语义、保护计时来源及上限</td></tr>
<tr><td>模块B+145EED0+104B8</td><td>以LEA取得全局传输对象后访问的待发字节字段</td><td>攻击特定队列、服务端受理与完成情况</td></tr></table>
<p>以上代码地址为RVA，组件字段相对本次重新定位的C；只适用于固定SHA256版本。伪代码行地址可能落在参数准备指令，调用点以指令复核：1657B8是mov，真正call在1657BB。cattack字符串位于动画事件字符串匹配，未将其当作按键攻击入口。</p>
<h3>新版工具：本地角色动作只读记录</h3><p><a href="../aion-action-20261024/runtime-action/start.cmd">启动新版</a>。先正常关闭旧窗口，再启动新路径；原旧包保留。实体观察页展开“本地角色动作 / 攻击调用链观察”，当前目标60秒JSONL同时保存动作字段。字段两读变化或读取失败保留原始值与独立错误，不把附加字段未知覆盖为生命事实。</p>
<p>程序与夹具'''+str(program_count)+'''项、真实ImGui渲染/交互'''+str(render_count)+'''项通过，其中新增6项动作读取检查。实机只读基线当前目标为空，本地角色绑定一致，动作值0/阶段1/请求序号93/待发字节0；仅说明当次读值，不将93解释成93次命中或请求，也未完成新动作的游戏输入对照。</p>
<ol><li>手选普通目标，开始60秒只读观察，先静止约3秒。</li><li>正常按1攻击几次，再停止按键并按你平时的方式取消攻击；无需刻意击杀。</li><li>保留日志。若提前死亡、目标清空或观察停止，直接记录该结果，不强行重复。</li></ol>
<p><b>尚未接攻击执行器。</b>下一步以正常输入对照动作值和序号，再核实线程、动作取消与后续恢复，完成后才能验证真正的自动攻击停手。</p>
<p><a href="../aion-action-20261024/action-findings.json">63份Evidence、原字节核对与未知</a> · <a href="../aion-action-20261024/implementation-verification.json">新版构建和检查</a> · <a href="../aion-action-20261024/action-state-readonly.json">本地角色只读基线</a></p>
<details><summary>本轮REA原始Evidence</summary><ul>'''+rows+'''</ul></details></section>
<!-- ACTION-DISPATCH-END -->'''
report=local/'aion-autocombat-20261021/实体与技能调用链进展.html'
text=report.read_text('utf-8')
a=text.find('<!-- ACTION-DISPATCH-BEGIN -->')
if a>=0:
    b=text.index('<!-- ACTION-DISPATCH-END -->',a)+len('<!-- ACTION-DISPATCH-END -->');text=text[:a]+section+text[b:]
else:
    shutil.copy2(report,root/'report-before-action.html')
    text=text.replace('<!-- USER-HEALTH-OBSERVATION-BEGIN -->',section+'\n<!-- USER-HEALTH-OBSERVATION-BEGIN -->',1)
report.write_text(text,encoding='utf-8')
style='<style>body{font:16px/1.8 system-ui,"Microsoft YaHei";max-width:1100px;margin:30px auto;padding:20px;color:#173449}table{width:100%;border-collapse:collapse}td,th{border:1px solid #abc;padding:10px}a,code{overflow-wrap:anywhere}pre{overflow:auto}</style>'
(runtime/'action-analysis.html').write_text('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>普通攻击动作链分析</title>'+style+section.replace('../aion-action-20261024/runtime-action/','').replace('../aion-action-20261024/','../')+'</html>',encoding='utf-8')
class Links(HTMLParser):
    def __init__(self):super().__init__();self.links=[]
    def handle_starttag(self,tag,attrs):self.links.extend(v for k,v in attrs if (tag,k) in [('a','href'),('img','src')])
link_checks=[]
for path,content in [(report,section),(runtime/'architecture.html',(runtime/'architecture.html').read_text('utf-8')),
                     (runtime/'action-analysis.html',(runtime/'action-analysis.html').read_text('utf-8'))]:
    parser=Links();parser.feed(content)
    for ref in parser.links:
        u=urlsplit(ref)
        if u.scheme or u.netloc or not u.path:continue
        link_checks.append(dict(document=str(path),reference=ref,exists=(path.parent/unquote(u.path)).is_file()))
assert all(c['exists'] for c in link_checks),[c for c in link_checks if not c['exists']]
(root/'link-verification.json').write_text(json.dumps(link_checks,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(dict(reaQueries=len(evidence),originalChecks=len(checks),programChecks=program_count,renderChecks=render_count,links=len(link_checks)),ensure_ascii=False))
