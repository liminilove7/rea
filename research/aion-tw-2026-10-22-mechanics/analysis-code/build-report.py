"""Offline HTML report, evidence ledger and canonical REA record export."""
from pathlib import Path
import hashlib,html,json
ROOT=Path(__file__).resolve().parents[1]
SHA='b3043f0eaf225b3dc7ba320ac7671cc5b28cefbd637135943dc9e67c114ccae7'
def read(p):return json.loads((ROOT/p).read_text(encoding='utf-8-sig'))
def save(p,x):(ROOT/p).write_text(json.dumps(x,ensure_ascii=False,indent=2),encoding='utf8',newline='\n')
evidence=[]
for p in sorted((ROOT/'binary-evidence').glob('*.mcp.json')):
    raw=json.loads(p.read_text(encoding='utf8'));s=raw['result'].get('structuredContent',{})
    if s.get('predicate_type')!='rea.analysis':continue
    assert s['subject']['digest']['sha256']==SHA
    dest=p.with_name(p.name.replace('.mcp.json','.evidence.json'))
    dest.write_text(json.dumps(s,ensure_ascii=False,indent=2),encoding='utf8',newline='\n')
for dest in sorted((ROOT/'binary-evidence').glob('*.evidence.json')):
    s=json.loads(dest.read_text(encoding='utf8'))
    assert s['subject']['digest']['sha256']==SHA
    evidence.append({'id':s['evidence_id'],'operation':s['operation'],'parameters':s['parameters'],'file':dest.relative_to(ROOT).as_posix(),'sha256':hashlib.sha256(dest.read_bytes()).hexdigest()})
save('binary-evidence/index.json',{'sample_sha256':SHA,'method':'Current REA MCP to owned headless IDA, no game execution','evidence':evidence})
claims=[
 {'id':'G1','topic':'神石','status':'observed-resource','statement':'250条候选，249条关联到102个技能；left缺失和0分开，不能固定减半','sources':['godstone/summary.json','godstone/item-skill-joins.json'],'unknown':'概率单位、触发事件及服务端RNG'},
 {'id':'G2','topic':'神石','status':'observed-client-schema','statement':'原PE描述符声明概率成员0x194宽2；已审相同偏移候选主要是复制或无身份关联UI','sources':['binary-evidence/descriptor-candidates.json','godstone/binary-review.txt'],'unknown':'概率字段到运算消费者的完整链'},
 {'id':'E1','topic':'普通强化','status':'derived-from-current-instructions','statement':'665B80按品质、等级差、下一阶段计算；显示乘0.1并带百分号','sources':['enchant/current-formula-model.json','enchant/binary-review.txt','binary-evidence/enchant-formula-insns.evidence.json','binary-evidence/enchant-prob-display-insns.evidence.json'],'unknown':'服务端概率、失败处置、线上可达范围'},
 {'id':'E2','topic':'强化分类','status':'observed-resource-and-client','statement':'普通强化、六档option、跳跃、累计强化分开；累计85关联技能207','sources':['enchant/enchant-current-evidence.json','enchant/option-display-model.json'],'unknown':'累计叠加及活动启用条件'},
 {'id':'P1','topic':'PVP','status':'observed-resource','statement':'3873物品含PVP属性，96技能显式伤害ratio，52显式持续时间ratio','sources':['pvp/feature-summary.json','pvp/resource-evidence.json'],'unknown':'完整伤害公式与属性合并顺序'},
 {'id':'P2','topic':'PVP显示','status':'derived-from-current-instructions','statement':'106/107及111..114输入按十分之一显示百分比；不能套作技能ratio单位','sources':['pvp/binary-review.txt','pvp/binary-literal-facts.json','binary-evidence/pvp-format-insns.evidence.json'],'unknown':'资源进入formatter前的生产链及服务端语义'},
 {'id':'A1','topic':'自动打怪/任务','status':'design-only','statement':'资源目录、目标观察、技能约束、规划与结果观察的设计边界','sources':['combat-feature-plan.md'],'unknown':'实体/任务状态与执行接口；未实现自动打怪'}
]
save('finding-ledger.json',{'date':'2026-10-22','sample_sha256':SHA,'materials':'client-only','target_executed':False,'claims':claims})
def link(p,t):return '<a href="'+html.escape(p)+'">'+html.escape(t)+'</a>'
def details(p,t):
    f=ROOT/p
    return '<details><summary>'+html.escape(t)+'</summary><pre>'+html.escape(f.read_text(encoding='utf8'))+'</pre></details>' if f.exists() else ''
def table(head,rows):
    return '<div class="table"><table><tr>'+''.join('<th>'+html.escape(str(x))+'</th>' for x in head)+'</tr>'+''.join('<tr>'+''.join('<td>'+html.escape(str(x))+'</td>' for x in row)+'</tr>' for row in rows)+'</table></div>'
sections=[]
sections.append('''<section id="scope"><h2>本次覆盖与版本</h2><div class="grid"><div class="card"><b>250</b>神石候选物品</div><div class="card"><b>28</b>原items包XML经CRC核验补解</div><div class="card"><b>96</b>显式PVP伤害ratio技能</div></div>
<p>初始完整遍历46个XML、122,063条顶层记录，其中物品74,259条、技能10,797条。补解items与初始范围有重叠，不直接相加。神石候选中44条test命名，不能全部认作线上可取得物品。</p>
<p>GitHub研究分支检查时本地与远端均为 <code>ee6943ff7</code>，没有新提交需要拉取。<a href="sync-verification.json">同步记录</a> · <a href="release-verification.json">发布检查</a></p>
<p class="note">当前只有客户端资料。资源事实、代码推导、设计建议分别标记；显示百分比不等于服务端真实概率。旧Classic样本未混入本次公式。没有启动游戏、读写游戏内存或执行战斗行为。</p></section>''')
sections.append('''<section id="godstone"><h2>神石：物品 → 技能 → 效果</h2><div class="flow"><span>proc_enchant_skill</span>→<span>精确名称关联技能ID</span>→<span>Provoked效果与目标条件</span></div>'''+table(['物品ID','技能ID','效果','主列 / left列原值'],[
['168000035','8536','Paralyze','20 / 10'],['168000037','8538','Silence','100 / 50'],['168000028','8428','ProcATK_Instant / Fire','40 / 缺失'],['168000041','8542','Poison','100 / 100'],['168000119','8852','Root','60 / 10']])+'''
<p>249条物品关联到102个不同技能，覆盖直接伤害、麻痹、沉默、中毒等12类效果。唯一缺失是test_proc_give → HolyOffenseProvokerEffect。</p>
<p>204条存在left列：95条精确半值、90条相等、8条呈整数半值、11条其他关系；46条没有该列。<strong>不能统一解释为左手减半，也不能把缺失改成0。</strong></p>
<p>当前PE描述符给出概率成员0x194、宽2字节。已审同偏移候选主要是复制或无字段身份关联的UI。概率单位、手别选择、触发事件、抵抗/免疫和服务端RNG仍未知，以上数值不擅自换算百分比。</p>
<a href="godstone/summary.json">统计摘要</a> · <a href="godstone/item-skill-joins.json">全部250条关联</a>'''+details('godstone/findings.txt','资源细节与限制')+details('godstone/binary-review.txt','二进制候选复核')+'</section>')
sections.append('''<section id="enchant"><h2>普通强化：当前客户端显示公式已核对</h2><div class="flow"><span>材料 → 模式1</span>→<span>RVA 0x665B80</span>→<span>返回值 × 0.1</span>→<span>%g%% → enchant_prob</span></div>
<p>q为装备品质，L为装备等级，S为强化石等级，n为下一阶段（实例uint8字段+1），A为辅助剂原值。</p>'''+table(['品质','common','rare','legend','unique','epic','mythic'],[['q',1,2,3,4,5,6],['K',60,40,30,20,15,10]])+'''
<pre>Δ = S − L + 10
+1..+10： base = clamp(K × Δ, 0, 800)
+11..+20：base = clamp(trunc0(K × Δ / 2), 0, 500)
result = clamp(base + A, 0, 1000)
客户端显示 = float32(result × 0.1) %</pre>
<p>补剂在基础限幅后相加；trunc0表示向零截断。n≤20且q不在1..6时直接返回0。n&gt;20的内部路径见详细复核，不表示正常UI或服务器允许；此演算只覆盖1..20。</p>
<h3>离线演算：仅模拟客户端显示</h3><div class="form">
<label>品质<select id="q"><option value="1">common</option><option value="2">rare</option><option value="3">legend</option><option value="4" selected>unique</option><option value="5">epic</option><option value="6">mythic</option></select></label>
<label>装备等级<input id="level" type="number" value="55" min="0" max="255"></label><label>石头等级<input id="stone" type="number" value="85" min="0" max="255"></label>
<label>下一阶段<input id="stage" type="number" value="10" min="1" max="20"></label><label>补剂原值<input id="supp" type="number" value="150" min="0" max="65535"></label></div>
<output id="calc" aria-live="polite"></output>
<p class="note">当前资源：55级unique武器100000831配85级石166000085，到+10无补剂显示80%、补150显示95%；到+11为40%/55%。这些是离线客户端算例，不是服务器实测概率。</p>
<h3>其他强化功能分别建模</h3>'''+table(['功能','资源/代码事实','边界'],[
['option六档','5品质×6档，独立查表，加补剂并限幅；当前显示路径×0.1','不是普通装备+1..6；调用方槽位语义未全闭合'],
['跳跃强化','30条，现有0..5，结果字段10，成本10..5','没有概率字段不能称必成；启用未知'],
['累计强化','16条，阈值30/45/60/65/75/80/85/90','两类型引用同组8技能；叠加方式未知'],
['累计85','技能207声明PvPAttackRatio/PVEAttackRatio原值各50','属性声明不等于最终伤害增幅']])+'''
<p>强化石候选424条，辅助剂24条。普通每级属性增量、失败降级/碎裂、保护/保底与服务端判定未闭合。</p>
<a href="enchant/current-formula-model.json">普通强化模型</a> · <a href="enchant/option-display-model.json">option显示模型</a> · <a href="enchant/enchant-current-evidence.json">资源全证据</a>'''+details('enchant/binary-review.txt','当前函数、边界与证据ID')+details('enchant/findings.txt','资源分类与累计技能关联')+'</section>')
sections.append('''<section id="pvp"><h2>PVP：属性来源与显示单位，不冒充最终伤害公式</h2><div class="flow"><span>装备/技能/阵营/惩罚</span>→<span>PVP攻防属性</span>→<span>客户端显示</span><span>最终战斗计算：未知</span></div>
<p>3,873物品含PVP属性声明；普通/a/b槽和充能条件分别保留，不能直接相加。96技能显式pvp_damage_ratio，52技能显式pvp_remain_time_ratio，缺失不当默认100。</p>'''+table(['枚举','名称','已核实'],[['106 / 107','PvPAttackRatio / PvPDefendRatio','总攻防名称及显示'],['111 / 112','物理PVP攻 / 防','独立枚举与同一显示分支'],['113 / 114','魔法PVP攻 / 防','独立枚举与同一显示分支']])+'''
<p>RVA 0x333530以%s%d%%或%s%.1f%%格式显示输入的十分之一：输入24→2.4%，80→8%。<strong>尚未证明资源值进入格式函数前没有转换；技能pvp_damage_ratio也不能套用这个单位。</strong></p>
<p>技能3790 ratio原值75，3804为80，11905为200且另带PVP防御下降声明。pc_attr_max=520/430只证明配置字段，不能认作战斗硬上限。基础伤害、物防/魔防、PVP攻防、技能ratio、暴击/格挡与等级差的合成顺序仍未知。</p>
<a href="pvp/feature-summary.json">PVP摘要</a> · <a href="pvp/resource-evidence.json">资源索引</a>'''+details('pvp/binary-review.txt','显示函数与原字节复核')+details('pvp/findings.txt','PVP字段、技能与阵营关系')+'</section>')
sections.append('''<section id="automation"><h2>自动打怪与任务：功能基础设计</h2><p>可建立机制目录、技能约束与效果标签。自动打怪使用PVE场景，PVP属性不直接计作打怪收益；神石Provoked效果与主动技能分开，不能假定必定触发。</p>'''+table(['模块','当前可用','尚缺'],[['机制目录','物品→技能→效果，强化及PVP/PVE声明','线上范围与实际效果'],['技能规划','目标/距离/冷却/消耗/连段原字段','单位、当前技能与状态'],['目标观察','静态目标条件','实体、HP、位置、仇恨、可达性'],['任务流程','设计边界','任务表、状态与执行接口']])+'''
<div class="flow"><span>观察</span>→<span>选目标</span>→<span>检查约束</span>→<span>选技能</span>→<span>等结果</span>→<span>重新评估</span></div>
<p>这是设计建议，本次没有实现自动战斗/任务执行。动作表现、命中、伤害与任务完成分别验证。</p><a href="combat-feature-plan.md">完整功能与数据契约设计</a></section>''')
sections.append('<section id="evidence"><h2>证据与复现</h2><p>Game.dll SHA256：<code>'+SHA+'</code></p><p>REA本次使用自有临时IDA数据库；原始MCP响应留在本地，规范Evidence入档。辅助PE/PAK/XML解析单独标记。</p><p>'+link('finding-ledger.json','结论台账')+' · '+link('binary-evidence/index.json','REA证据索引')+' · '+link('enchant/source-manifest.json','PAK成员CRC/SHA')+' · '+link('verification.json','交付验证')+' · '+link('README.md','复现说明')+'</p></section>')
style="""*{box-sizing:border-box}body{margin:0;background:#edf2f6;color:#172b3b;font:16px/1.8 system-ui,"Microsoft YaHei",sans-serif}main{max-width:1160px;margin:auto;padding:32px 24px 80px}header{background:#17364b;color:white;padding:32px;border-radius:18px}h1{font-size:32px;line-height:1.4}h2{font-size:24px;margin-top:0}h3{font-size:18px}section{margin-top:24px;padding:26px;background:white;border:1px solid #dce4eb;border-radius:14px}nav{display:flex;flex-wrap:wrap;gap:16px;margin-top:18px}nav a{color:#c8f2ef}a{color:#116d8c}code,pre,output{font:14px/1.7 Consolas,"Microsoft YaHei",monospace}code{overflow-wrap:anywhere;background:#edf2f6;padding:2px 5px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f6f8;padding:16px;border-radius:8px}.note{border-left:4px solid #c88e20;background:#fff6df;padding:14px 18px}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}.card{background:#eaf5f2;padding:17px;border-radius:10px}.card b{display:block;font-size:29px;color:#16685e}.table{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:14px}th,td{padding:11px;border:1px solid #dce4eb;text-align:left;vertical-align:top}th{background:#e7f0f4}details{margin:16px 0;border-top:1px solid #dce4eb;padding-top:10px}summary{cursor:pointer;color:#156b7b;font-weight:600}.flow{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:18px 0}.flow span{background:#e8f0f7;padding:10px 14px;border-radius:7px}.form{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}label{display:block}input,select{width:100%;padding:8px;font:inherit;border:1px solid #9aafbd;border-radius:6px}output{display:block;margin-top:16px;background:#17364b;color:#effff9;padding:18px;border-radius:8px;font-size:18px}.error{background:#86352f}footer{margin-top:24px;color:#536b7c}@media(max-width:650px){main{padding:14px 12px}header,section{padding:20px 16px}h1{font-size:25px}.grid,.form{grid-template-columns:1fr}td,th{padding:8px}}@media print{body{background:white}main{padding:0}section{break-inside:avoid}nav{display:none}}"""
script="""const K={1:60,2:40,3:30,4:20,5:15,6:10};
function calculate(q,l,s,n,a){if(![q,l,s,n,a].every(Number.isInteger)||!K[q]||l<0||l>255||s<0||s>255||n<1||n>20||a<0||a>65535)throw Error('请输入有效整数：等级0～255，阶段1～20，辅助剂0～65535。');let base=K[q]*(s-l+10);if(n>10)base=Math.trunc(base/2);base=Math.max(0,Math.min(n>10?500:800,base));const raw=Math.max(0,Math.min(1000,base+a));return {base,raw,display:Math.fround(Math.fround(raw)*Math.fround(0.1))};}
window.study={calculate};function update(){const out=document.getElementById('calc');try{const values=['q','level','stone','stage','supp'].map(id=>{const text=document.getElementById(id).value;if(text.trim()==='')throw Error('输入不能为空');return Number(text)});const r=calculate(...values);out.className='';out.textContent='基础原值 '+r.base+' → 加补剂并限幅 '+r.raw+' → 客户端显示 '+Number(r.display.toPrecision(6))+'%';}catch(e){out.className='error';out.textContent=e.message;}}for(const id of ['q','level','stone','stage','supp'])document.getElementById(id).addEventListener('input',update);update();"""
doc='<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AION TW 神石、强化与PVP静态研究</title><style>'+style+'</style><main><header><div>REA · 当前台服样本 · 2026-10-22</div><h1>神石、强化与 PVP<br>资源定义 → 客户端消费者 → 功能边界</h1><p>当前普通强化显示公式已核对。神石实际概率与最终伤害仍缺服务端证据。</p><nav>'+''.join('<a href="#'+i+'">'+t+'</a>' for i,t in [('scope','范围'),('godstone','神石'),('enchant','强化'),('pvp','PVP'),('automation','自动打怪基础'),('evidence','证据')])+'</nav></header>'+''.join(sections)+'<footer>客户端静态研究 · 未知项不以猜测填补。</footer></main><script>'+script+'</script></html>'
(ROOT/'AION-TW-机制分析.html').write_text(doc,encoding='utf8',newline='\n')
print(json.dumps({'evidence_records':len(evidence),'claims':len(claims),'html_bytes':len(doc.encode('utf8'))}))
