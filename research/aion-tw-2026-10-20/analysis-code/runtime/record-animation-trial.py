"""Verify current-player identity, the timed animation trial and user observations."""
from pathlib import Path
import json
root=Path(__file__).parent
case=root.parent
def load(name):
    return json.loads((root/name).read_text(encoding='utf-8-sig'))
trial=load('animation-trial-state.json')
before=load('level5-before-animation-context.json')
after=load('after-animation-trial-context.json')
post=load('after-animation-trial-baseline.json')
feedback=load('animation-trial-user-observations.json')
baseline=load('normal-attack-baseline.json')
live=load('effective-speed-followup/live-critical-byte-verification.json')
checks=[]
def check(name,value):
    checks.append({'name':name,'passed':bool(value)})
    if not value:raise RuntimeError(name)
check('Bounded trial completed and closed',trial['Failure'] is None and trial['HandleClosed'] and trial['RestoreStatus']=='RestoredOriginalAndReadBack')
check('Single-field write and restoration readbacks',trial['Apply']['Success'] and trial['Restoration']['Success'] and int.from_bytes(bytes(trial['Apply']['Readback']['Bytes']),'little')==1500 and int.from_bytes(bytes(trial['Restoration']['Readback']['Bytes']),'little')==1200)
check('Helper scratch-memory boundary checks',load('animation-trial-helper-verification.json')['AllPassed'])
check('Role identity independently rechecked',before['IdentityReadbackMatched'] and after['IdentityReadbackMatched'] and before['Character']['C']==after['Character']['C']==trial['Component'])
check('Original U/V independently verified after restoration',after['Character']['U']==after['Character']['V']==1200 and after['Character']['AnimationScale']==1)
check('Global interval and mirror restored/unchanged',post['Failure'] is None and post['HandleClosed'] and all(x['Value']==1200 for x in post['Observations'] if x['Name'] in ['received_attack_interval','attack_interval_mirror']))
sample_rows=trial['Events']+trial['Heartbeats']+[trial['Final']]
check('Retained trial observations kept U1500 V1200 and matching gate/mirror',all(x['U']==1500 and x['V']==1200 and x['Interval']==x['Mirror']==1200 for x in sample_rows))
check('User reported animation speedup then normal restoration',feedback['during_trial']=='出手动画明显更快' and feedback['after_restoration']=='已恢复原来的节奏')
check('All eight runtime code/table checks matched',live['AllCriticalBytesMatched'] and len(live['Checks'])==8 and live['HandleClosed'] and live['Failure'] is None)
instruction_checks={
 'effective-speed-followup/attack-tick-insns.normalized.json':['0x1801652c4: mov rdi, rcx','0x1801656fe: mov rcx, rdi','0x180165701: call sub_180144F10'],
 '../attack-controller-insns.normalized.json':['0x180144f1f: mov rdi, rcx','0x1801455f3: mov rcx, rdi','0x1801455f6: call sub_18016D600'],
 '../attack-interval-access-insns.normalized.json':['0x18016d61f: mov rsi, rcx','0x18016d6b5: add eax, [rsi+1E90h]','0x18016d8a0: mov [rsi+1E90h], ebp'],
 '../panel-source-insns.normalized.json':['0x18052a29c: test sil, 2','0x18052a2a0: jz loc_18052A2B8','0x18052a2b3: call sub_180530650']}
for filename,lines in instruction_checks.items():
    actual=load(filename)['instructions']
    for line in lines:check('REA instruction '+line,line in actual)
check('Baseline completed with handle closed',baseline['Failure'] is None and baseline['HandleClosed'])
summary={'scope':'Current client Player and audited cattack prefix branch only; gameplay animation feedback is subjective',
 'game_sha256':trial['GameSHA256'],'process_birth_utc':trial['StartedUtc'],
 'character_base':trial['Component'],'field_offset':'0x530','field_address':hex(int(trial['Component'],16)+0x530),'type':'uint16',
 'values':[1200,1500,1200],'other_animation_field_offset':'0x532','other_animation_value':1200,'scale':1,
 'predicted_audited_branch_multipliers':[1,1.25,1],'user_feedback':feedback,
 'client_animation_effect_observed':True,'exact_visual_speed_ratio_measured':False,
 'server_accepted_attack_rate_verified':False,'damage_rate_verified':False,
 'current_player_A_C_P_same_pointer_verified':True,'attack_timing_offset':'0x1E90',
 'baseline':{'samples':baseline['Samples'],'timing_state_changes':len(baseline['Events']),'negative_raw_delta_present':any(x['ObservedTickDelta']>2147483647 for x in baseline['Events']),'not_equivalent_to_attack_count':True,'possible_level_transition_uncontrolled':True},
 'modified_window':{'samples':trial['Samples'],'timing_state_changes':len(trial['Events']),'first_observed_state_change_seconds':trial['Events'][0]['ElapsedSeconds'] if trial['Events'] else None,'exposure_not_comparable_to_baseline':True},
 'restored_and_independently_verified':True,'handles_closed':True,'checks':checks,
 'limitations':['The absolute character address is valid only for the selected process and current entity.','U/V business names remain unproved independently of their ratio in the audited branch.','Do not infer damage rate or server-accepted attack frequency from subjective animation feedback.','Timing state has additional initialization writes and observed backward/short deltas; no attack-count or complete timer-source proof.','Panel rendering is gated by update-mask bit 0x2 in an existing caller, but the flag seen during the prior UI trial was not captured.']}
(root/'animation-trial-summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf8')
fragment=f'''<div id="animation-trial"><h3>已在游戏内观察到效果：当前角色+0x530</h3>
<p><strong>当前角色对象C = {trial['Component']}；可影响攻击动画的字段为C+0x530，当前绝对地址{summary['field_address']}，类型uint16。</strong>用户报告已升5级，重新只读定位实体和组件后，原值仍为1200。该绝对地址需在重登、重启或实体重建后重新定位，不能作为通用固定地址。</p>
<table><thead><tr><th>阶段</th><th>U / V / 系数</th><th>已审分支预测倍率</th><th>游戏内观察</th></tr></thead><tbody><tr><td>修改前</td><td>1200 / 1200 / 1</td><td>1</td><td>原始动画节奏</td></tr><tr><td>临时写入约60秒</td><td>1500 / 1200 / 1</td><td>1.25</td><td>用户反馈：出手动画明显更快</td></tr><tr><td>还原并独立回读</td><td>1200 / 1200 / 1</td><td>1</td><td>用户反馈：已恢复原来的节奏</td></tr></tbody></table>
<p>仅向C+0x530写入2字节并最终还原。同步攻击间隔及镜像保持1200，V保持1200，没有改写请求标志、计时保护或客户端代码。预测倍率1.25来自REA审过的cattack前缀分支U/V×系数，<strong>并非精确测得实际动画快25%，也不是服务器认可的攻击次数提升25%。</strong></p>
<h3>本次补齐：当前Player的A、C、P同址链</h3><pre>Player虚表RVA 0xD53940
  槽+0x8 → RVA0x1652A0（保存this）
    → RVA0x144F10（保存并传递同一this）
      → RVA0x16D600
        读取 this+0x1E90 与同步间隔作门槛比较
        后续请求路径写回 this+0x1E90
当前 this = C = P = {trial['Component']}</pre>
<p>REA交叉引用给出Player虚表+8入口；运行中虚表、实体回链以及8处关键指令/入口字节与原文件匹配。故当前Player控制上下文A已不再悬空，但不能外推所有实体。保护计时源及其物理单位仍未完全解析。</p>
<p>45秒基线共{baseline['Samples']}次采样、25次计时状态变化，其中存在短间隔和原值回退；初始化路径也写该成员。60秒修改窗口共{trial['Samples']}次采样、4次变化，前约41秒未观察到该状态变化。两段活动暴露和等级/目标控制不足，<strong>不能把25与4当成攻击次数，不能据此比较服务器攻击频率。</strong></p>
<p>面板侧另查到RVA0x529F60先组装快照，但只有更新掩码bit0x2成立时才调用RVA0x530650绘制属性。这个条件解释了为何需要查刷新入口；上次实验并未捕获实际掩码，仍不能断言它就是面板未变的原因。</p>
<p><a href="runtime-20261019/animation-trial-summary.json">地址、验证及结论边界</a> · <a href="runtime-20261019/animation-trial-state.json">写入、观察及还原记录</a> · <a href="runtime-20261019/animation-trial-user-observations.json">用户往返观察</a> · <a href="runtime-20261019/after-animation-trial-context.json">还原后独立对象读取</a> · <a href="runtime-20261019/effective-speed-followup/live-critical-byte-verification.json">8处运行中字节核对</a> · <a href="runtime-20261019/run-animation-trial.ps1">单次有时限试验脚本</a> · <a href="runtime-20261019/normal-attack-baseline.json">原始基线</a></p></div>'''
(root/'animation-trial-fragment.html').write_text(fragment,encoding='utf8')
print(json.dumps({'checksPassed':len(checks),'fieldAddress':summary['field_address'],'clientAnimationFeedbackPositive':True,'restorationIndependentlyVerified':True,'serverRateVerified':False}))
