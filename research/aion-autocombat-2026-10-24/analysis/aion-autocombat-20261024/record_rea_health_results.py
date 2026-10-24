"""Index live REA results and check selected original PE bytes; no game access."""
import hashlib
import html
import importlib.util
import json
import pathlib
import struct

ROOT = pathlib.Path(__file__).resolve().parent
OLD = ROOT.parent / 'aion-tw-20261019'
spec = importlib.util.spec_from_file_location('pe_audit', ROOT.parent / 'aion-autocombat-20261021/audit_evidence.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
pe = audit.PE(OLD / 'samples/Game.dll')
expected_sha = 'b3043f0eaf225b3dc7ba320ac7671cc5b28cefbd637135943dc9e67c114ccae7'
assert hashlib.sha256(pe.data).hexdigest() == expected_sha
checks = []
for rva, expected in [(0x867BDB, '89915c130000'), (0x867BE4, '44898158130000'),
                      (0x867BF0, '899154130000'), (0x867C37, '884340'),
                      (0x867B35, '40887b40'), (0x853657, '44887740'),
                      (0x853630, '8b8f58130000'), (0x85363C, '410fbed6')]:
    raw = pe.at(rva, len(bytes.fromhex(expected)))
    checks.append(dict(kind='field-instruction', rva=hex(rva), expected=expected,
                       observed=raw.hex(), passed=raw.hex() == expected))
for rva, dest in [(0x867B1E, 0x19FC7C2), (0x867B30, 0x867BC0),
                  (0x867C06, 0x19FC7C2), (0x867C22, 0x19FC7C2),
                  (0x8C5394, 0x853160), (0x853207, 0x867B00),
                  (0x853640, 0x19FC7C2), (0x853652, 0x867BC0)]:
    raw = pe.at(rva, 5)
    target = rva + 5 + struct.unpack_from('<i', raw, 1)[0]
    checks.append(dict(kind='direct-call', rva=hex(rva), expected=hex(dest),
                       observed=hex(target), raw=raw.hex(), passed=raw[0] == 0xe8 and target == dest))
evidence = []
for directory in sorted(ROOT.glob('rea-health-*')):
    if not directory.is_dir():
        continue
    for file in sorted(directory.glob('*.evidence.json')):
        wrapper = json.loads(file.read_text('utf-8'))
        data = wrapper['data']
        assert wrapper['ok'] and data['subject']['digest']['sha256'] == expected_sha
        evidence.append(dict(file=str(file.relative_to(ROOT)), sha256=hashlib.sha256(file.read_bytes()).hexdigest(),
                             evidence_id=data['evidence_id'], operation=data['operation'], parameters=data['parameters']))
assert len(evidence) == 24, f'Expected this round\'s 24 results, found {len(evidence)}'
result = dict(gameSha256=expected_sha, provider='REA MCP → IDA attached database', newReaRequests=24,
              evidence=evidence, checks=checks, targetExecuted=False, gameMemoryWritten=False,
              observations=[
                  '867BC0 stores argument 2 at C+135C and argument 3 at C+1358; when C+1348 is zero, it also stores argument 2 at C+1354 and calls vtable+490.',
                  '867BC0 obtains a ratio-like byte via unresolved H(a2,100,a3), forces minimum 1 before byte conversion, overrides with 0 for a2=0, and stores C+40. No explicit clamp to 100 was observed in this function.',
                  '867B00 computes H(C+1358, byte, 100), calls 867BC0, then overwrites C+40 with the supplied byte.',
                  '8C52E0 looks up object identifier in the map at Game+14225F0, maps node+20 to an entity handle, obtains component type 1, and calls 853160.',
                  '853160 branches on event type. Some branches pass the supplied byte to 867B00. The default non-local-entity branch reconstructs a value using H then overwrites C+40 with the supplied byte.',
                  '19FC7C2 leads through 19F32D8 and further protected control flow; the decompiler reports a positive stack pointer warning. Arithmetic and rounding remain unresolved.'
              ],
              inferences=[
                  'C+40 has both derived and received-byte update paths; it is not exclusively a locally computed value.',
                  'On the received-byte path, C+135C is reconstructed from a reference amount and the byte. It must not be labeled independently verified exact server HP.',
                  'The controlled 100→79→100 observation is consistent with a quantized health indication, but does not establish server HP or rounding.'
              ],
              unknowns=['H arithmetic, overflow, division-by-zero and rounding', 'UI consumer and display interpolation',
                        'Exact HP sent for this monster', 'Death, hostility and target eligibility',
                        'Event-type meanings and remaining health writers', 'Active skill invocation contract'],
              softwarePromotion='Health/Alive/Hostile remain unknown; no auto-combat decisions added')
(ROOT / 'rea-health-findings.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
if not all(c['passed'] for c in checks):
    raise RuntimeError('Original-byte verification failed; report not updated')

report = ROOT.parent / 'aion-autocombat-20261021/实体与技能调用链进展.html'
source = report.read_text('utf-8-sig')
backup = ROOT / 'report-before-live-rea-health.html'
if not backup.exists():
    backup.write_text(source, encoding='utf-8')
links = ''.join('<li><a href="../aion-autocombat-20261024/' + html.escape(e['file']) + '">' +
                html.escape(e['file'].split('/')[-1]) + '</a>：<code>' + e['evidence_id'] + '</code></li>' for e in evidence)
section = '''<!-- LIVE-REA-HEALTH-BEGIN -->
<section id="live-rea-health-20261024"><h2>最新进展 · 2026-10-24：REA 已连通，血量写入链得到代码证据</h2>
<p><b>本节包含 24 次实际执行的 REA 查询，全部成功并保存 Evidence；16 项原始 PE 字节与调用目标核对通过。</b>以下旧章节保留当时的状态，“尚未执行/接口阻塞”请以本节更新为准。</p>
<p>本次使用固定 Game.dll 的原数据库。指定进程环境后，IDA 正常加载自带 Python 3.11.7，随后启动仅监听本机的只读接口。未执行游戏函数、未写游戏内存、未自动攻击；数据库没有由代理保存或关闭。</p>
<h3>两条更新路径，不能混成一种“真实血量”</h3>
<div class="flow"><div class="box">消息 3：本角色<br>两个 32 位数值</div>→<div class="box">867BC0<br>+135C / +1358</div>→<div class="box">换算函数 H<br>生成 +40 字节</div></div>
<p></p><div class="flow"><div class="box">消息 5：其他对象<br>对象标识 + 字节等参数</div>→<div class="box">8C52E0 → 853160<br>查实体、按事件类型分支</div>→<div class="box">867B00 或内联重建<br>最终 +40 = 收到的字节</div></div>
<p>已确认：第二条路径先用 <code>H(C+1358, 字节, 100)</code> 重建一个数值，再调用 867BC0，最后又把传入字节写回 <code>C+40</code>。因此这里的比例指示有接收消息更新的来源；重建出的数值不能直接当作服务器精确 HP。</p>
<table><thead><tr><th>对象字段（十六进制）</th><th>本轮可确认的写入行为</th><th>解释边界</th></tr></thead><tbody>
<tr><td>+40，1 字节</td><td>867BC0 计算写入；867B00 与 853160 部分路径覆盖为传入字节</td><td>支持生命比例相关指示；不是所有路径都在本地计算</td></tr>
<tr><td>+1358，4 字节</td><td>867BC0 写入第三参数；比例重建时作为参考量</td><td>最大/参考生命角色更明确，仍缺完整来源审计</td></tr>
<tr><td>+135C，4 字节</td><td>867BC0 写入第二参数</td><td>有收到数值与比例重建两类来源，不能一律称精确 HP</td></tr>
<tr><td>+1354，4 字节</td><td>仅当 +1348 为零时同步写入第二参数，随后调用虚表 +490</td><td>条件性副本；平滑/显示用途尚待读者证明</td></tr></tbody></table>
<h3>100 → 79 → 100，现在能说明什么</h3>
<div class="flow"><div class="box">同一森林光蟲<br>满血：100</div>→<div class="box">正常受伤<br>79；用户看到剩约 3/4</div>→<div class="box">脱战回满<br>100；用户确认回满</div></div>
<p>受控观察与代码写入链互相支持。但 <b>79 不能证明服务器 HP 恰好等于 619×79%</b>：收到的比例可能已经量化，H 的计算与取整尚未还原，也没有同版本服务器日志作独立核对。</p>
<h3>没有越过证据边界</h3><p class="warn">19FC7C2 经保护跳转到 19F32D8，继续进入其他函数；后者反编译出现栈指针异常警告。本报告保留 H 为未知函数，不把它擅自写成乘除公式。867BC0 对第二参数为零有写零分支，但这不等于已验证死亡状态。移除对象消息也不能直接等同死亡。</p>
<p>本轮只推进生命状态来源研究。软件的正式 Health / Alive / Hostile 尚未升级为已验证字段，没有据此开放自动攻击。</p>
<h3>下一步：补齐一个可复现的生命状态闭环</h3><ol><li>追保护换算函数 H 的实际算术与异常边界，并核对原始指令。</li><li>追 +1354/+135C/+40 的界面读取者、虚表 +490 和 +1348 的写入者，区分收到值、重建值与显示副本。</li><li>以同一目标正常死亡、消失、取消选择为不同对照，验证状态失效；不能用一个零值代替死亡判断。</li><li>之后再核对敌我与可攻击性，以及主动技能的参数和执行上下文。</li></ol>
<p><a href="../aion-autocombat-20261024/rea-health-findings.json">完整结论、限制与 16 项字节核对</a> · <a href="../aion-autocombat-20261024/health-damage-comparison.json">受伤/恢复原始观察</a></p>
<details><summary>展开本轮 24 份 REA Evidence</summary><ul>''' + links + '''</ul></details></section>
<!-- LIVE-REA-HEALTH-END -->'''
start = source.find('<!-- LIVE-REA-HEALTH-BEGIN -->')
if start >= 0:
    end = source.index('<!-- LIVE-REA-HEALTH-END -->', start) + len('<!-- LIVE-REA-HEALTH-END -->')
    source = source[:start] + section + source[end:]
else:
    anchor = source.index('<section>')
    source = source[:anchor] + section + source[anchor:]
report.write_text(source, encoding='utf-8')
print(json.dumps(dict(reaResults=len(evidence), byteChecks=len(checks), passed=sum(c['passed'] for c in checks), report=str(report)), ensure_ascii=False))
