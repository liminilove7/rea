"""Retain normal-scroll observations and bounded local trials with evidence limits."""
from pathlib import Path
from collections import Counter
import json
root=Path(__file__).parent
def load(name):
    return json.loads((root/name).read_text(encoding='utf-8-sig'))
comparison=load('attack-scroll-comparison.json')
expiry=load('attack-scroll-expiry-observation.json')
post=load('after-melee-scroll-state-context.json')
post_global=load('after-melee-scroll-state-baseline.json')
feedback700=load('melee-trial-user-feedback.json')
feedback700['after_restoration']='已恢复原来的较慢节奏'
feedback700['latest_interpretation']='User confirmed faster ordinary melee swing cadence and slower cadence after restoration; no measured hit/HP-loss rate.'
(root/'melee-trial-user-feedback.json').write_text(json.dumps(feedback700,ensure_ascii=False,indent=2),encoding='utf8')
checks=[]
def check(name,value):
    checks.append({'name':name,'passed':bool(value)})
    if not value:raise RuntimeError(name)
normal={x['field']:x for x in comparison['fields']}
for name in ['received_attack_interval','attack_interval_mirror','V']:
    check('Normal 9% scroll '+name,normal[name]['before']==1200 and normal[name]['after']==1092)
check('Normal scroll kept U and scale',normal['U']['before']==normal['U']['after']==1200 and normal['AnimationScale']['after']==1)
check('One-point 9% arithmetic',1200*(100-9)//100==1092)
check('Natural expiry returns all selected interval values',expiry['observed_received_interval']==expiry['observed_mirror']==expiry['observed_U']==expiry['observed_V']==1200)
trial_names=[('local1092','scroll-state-trial-state.json'),('first900','fast-scroll-state-trial-state.json'),('retry900','fast-scroll-state-retry-trial.json'),('local800','visible-scroll-state-trial-state.json'),('melee700','melee-scroll-state-trial-state.json')]
trials=[]
for tag,name in trial_names:
    t=load(name)
    check(tag+' completed/closed',t['Failure'] is None and t['HandleClosed'] and t['RestoreStatus']=='RestoredOriginalTupleAndReadBack')
    check(tag+' three typed fields applied',t['Apply']['Success'] and [x['Width'] for x in t['Apply']['Fields']]==[2,4,2])
    check(tag+' all returned restoration writes succeeded',t['Restoration']['Success'] and all(x['Success'] for x in t['Restoration']['Fields']))
    modes=Counter(x['ObservedTickDelta'] for x in t['Events']).most_common()
    trials.append({'tag':tag,'record':name,'target_tuple':t['TestTuple'],'samples':t['Samples'],'timing_state_changes':len(t['Events']),'raw_timing_delta_frequencies':[{'delta':a,'count':b} for a,b in modes],'early_exit':t.get('EarlyExitReason'),'final_before_restoration':t['Final'],'restore_status':t['RestoreStatus'],'applied_utc':t['AppliedUtc'],'completed_utc':t['CompletedUtc']})
check('Latest context independently verified',post['Failure'] is None and post['HandleClosed'] and post['IdentityReadbackMatched'])
values={x['Name']:x['Value'] for x in post_global['Observations']}
check('Latest globals independently restored',post_global['Failure'] is None and post_global['HandleClosed'] and values['received_attack_interval']==values['attack_interval_mirror']==1200)
check('Latest U/V independently restored',post['Character']['U']==post['Character']['V']==1200)
check('700 unaided swing feedback is positive and reversed',feedback700['during_trial']=='出刀速度明显变快了' and feedback700['after_restoration']=='已恢复原来的较慢节奏')
feedback800=load('visible-trial-user-feedback.json')
check('800 stronger initial answer qualified by later correction',feedback800['server_damage_frequency_verified'] is False and bool(feedback800['later_user_clarification']))
base=int(post_global['ModuleBefore']['Base'],16)
component=int(post['Character']['C'],16)
fields=[{'name':'同步攻击间隔','relative':'Game.dll+0x142DB40','address':hex(base+0x142DB40),'type':'uint16','normal_scroll':1092,'local_melee_trial':700,'restored':1200},
        {'name':'间隔镜像','relative':'Game.dll+0x142DC10','address':hex(base+0x142DC10),'type':'uint32','normal_scroll':1092,'local_melee_trial':700,'restored':1200},
        {'name':'动画分母V','relative':'C+0x532','address':hex(component+0x532),'type':'uint16','normal_scroll':1092,'local_melee_trial':700,'restored':1200},
        {'name':'动画分子U（本组保持不变）','relative':'C+0x530','address':hex(component+0x530),'type':'uint16','normal_scroll':1200,'local_melee_trial':1200,'restored':1200}]
summary={'scope':'Selected current-client state; user-observed melee swing cadence and client timing-state changes, not proven server damage frequency',
 'primary_static_provider':'REA MCP to offline IDA; runtime read/write helpers are auxiliary Win32, not REA live memory tools',
 'current_character_base':hex(component),'loaded_game_base':hex(base),'stale_previous_character_base':'0xc3b14000','current_fields':fields,
 'normal_scroll':{'user_reported_percent':9,'duration_minutes':5,'cancellable':True,'before':1200,'after':1092,'expired':1200,'U_unchanged':True,'complete_stacking_formula_verified':False},
 'trials':trials,'feedback700':feedback700,'feedback800':feedback800,
 'server_accepted_hit_rate_verified':False,'damage_rate_verified':False,'actual_skill_cooldown_verified':False,
 'client_request_cadence_inference':'Normal baseline contains repeated raw timing increments around1203, local800 around812/813, melee700 around703/704. Together with the REA gate/writer chain this supports changed client request bookkeeping cadence, not complete request counts or accepted server hits.',
 'limitations':['Only unaided visual feedback; no synchronized video or timestamped combat damage log supplied.','Timing state has other writes, short/reversed deltas and idle/target-switch gaps; its updates cannot be counted as attacks.','Normal scroll changes and three matching local fields do not establish identical server buff state.','First900 was overwritten in interval/mirror after about2.4s while V remained900; source unobserved, no anti-cheat conclusion.','Local1092 was confounded by user scroll use during or after the window; timing unknown.','900retry showed no timing-state activity and no valid subjective comparison, not proof of no effect.','Object addresses change across scene/entity recreation even within one PID. Re-resolve before access.'],
 'restored_and_independently_verified':True,'all_trial_handles_closed':True,'verification':{'allPassed':True,'checks':checks}}
(root/'scroll-state-trials-summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf8')
table=''.join(f'<tr><td>{f["name"]}<br><code>{f["relative"]}</code><br>{f["type"]}</td><td><code>{f["address"]}</code></td><td>{f["normal_scroll"]}</td><td>{f["local_melee_trial"]}</td><td>{f["restored"]}</td></tr>' for f in fields)
fragment=f'''<div id="scroll-state-trials"><h3>最新：正常9%卷轴与三字段平砍试验</h3>
<p><strong>当前角色基址已变为{hex(component)}，旧0xc3b14000不再作为当前地址使用。</strong>本轮重新遍历实体表定位，Game.dll加载基址为{hex(base)}。后续修改必须重新核对角色身份，不能照抄历史绝对地址。</p>
<p>用户正常使用提示“攻速提升9%”的卷轴后，只读观察到同步间隔、镜像和V同时1200→1092，U仍1200；1092正好等于1200×(1−9%)。5分钟到期后这三处自然回到1200。这个样本支持本次间隔减少9%，不能外推全部增益叠加公式，也不能把倒数频率直接当服务器实际伤害增长。</p>
<table><thead><tr><th>字段</th><th>当前绝对地址</th><th>正常9%卷轴</th><th>本地700平砍窗口</th><th>独立回读还原值</th></tr></thead><tbody>{table}</tbody></table>
<p>三字段试验只写上述前3项，保持U、系数、移速、增益列表、请求标志和代码字节不变。写入前用户停止攻击，回读确认后明确通知“现在开始平砍”；最多约60秒后还原，无循环锁定、自动重启或常驻服务。</p>
<h3>哪些结果有效，哪些不能算结论</h3><ul>
<li>本地1092窗口：用户无法区分或未赶上，并在窗口期间或之后又使用卷轴，顺序未精确记录，不能作为严格对照。</li>
<li>第一次900：约2.4秒时同步间隔和镜像已变回1200，V仍900。脚本停止并恢复V；改回来源未捕获，不能归因为反作弊或服务器限制。</li>
<li>独立900重试：先只读观察10秒、6个样本稳定，再试验60秒；未观察到计时状态更新，也没有有效游戏内反馈，不能视为生效或无效证明。</li>
<li>800窗口：用户先选了“命中/掉血更快”，随后明确补充动作明显更快、技能释放感知更快，但掉血节奏分辨不出。<strong>采用后续澄清，不声称已证明伤害频率提高。</strong></li>
<li>700普通平砍：用户明确反馈“出刀速度明显变快了”，还原后确认“已恢复原来的较慢节奏”。这构成普通出刀节奏的肉眼往返对照。</li></ul>
<p>计时状态记录也随门槛发生规律变化：原1200基线多次出现约1203的原始增量，800窗口多次812/813，700窗口多次703/704。结合REA已证的门槛/写回链，这支持客户端请求计时节奏受影响。状态还存在其他写入、短间隔和回退，不能把更新次数当完整攻击次数；计时源仍未完整破解。</p>
<p><strong>当前证据边界：</strong>客户端出刀节奏变化已有代码、内存及用户往返观察支持；服务器认可的命中频率、实际伤害频率和技能冷却没有量化验证。用户选择现场肉眼观察，尚无逐帧录像或带时间戳的战斗日志。不能仅凭“动作更快”写“DPS提高”或“与服务器卷轴效果完全相同”。</p>
<p>REA另追到消息36处理入口RVA0x7E8FD0→0x7DE090解析→0x8CABD0实体分发→0x29D7F0→0x29D9C0，后者写角色+0x1178起的记录并进入多个消费者。尚未取得可证明完整、唯一的实际命中计数器；这条线只作为下一步入口，未注入钩子、未捕获或伪造网络包。</p>
<p><a href="runtime-20261019/scroll-state-trials-summary.json">最新结论、地址、逐项核对</a> · <a href="runtime-20261019/attack-scroll-comparison.json">正常9%卷轴前后记录</a> · <a href="runtime-20261019/attack-scroll-expiry-observation.json">自然到期读数</a> · <a href="runtime-20261019/melee-scroll-state-trial-state.json">700平砍原始试验</a> · <a href="runtime-20261019/melee-trial-user-feedback.json">700往返反馈</a> · <a href="runtime-20261019/visible-trial-user-feedback.json">800反馈及用户后续澄清</a> · <a href="runtime-20261019/after-melee-scroll-state-context.json">最新独立还原读取</a> · <a href="runtime-20261019/run-melee-scroll-state-trial.ps1">700有时限试验脚本</a></p></div>'''
(root/'scroll-state-trials-fragment.html').write_text(fragment,encoding='utf8')
print(json.dumps({'checksPassed':len(checks),'currentC':hex(component),'allRestored':True,'serverHitRateVerified':False},ensure_ascii=False))
