"""Verify the bounded write/restoration record and retain the negative UI result."""
from pathlib import Path
import datetime,hashlib,json
root=Path(__file__).parent
def load(name):
    return json.loads((root/name).read_text(encoding='utf-8-sig'))
state=load('interval-trial-state.json')
panel=load('user-panel-interval-trial-observation.json')
post=load('after-interval-trial-baseline.json')
fixture=load('interval-trial-helper-verification.json')
assert fixture['AllPassed']
assert state['Apply']['Success'] and state['Apply']['BytesWritten']==2
assert state['Restoration']['Success'] and state['Restoration']['BytesWritten']==2
assert int.from_bytes(bytes(state['Apply']['Readback']['Bytes']),'little')==1100
assert int.from_bytes(bytes(state['Restoration']['Readback']['Bytes']),'little')==1200
assert state['RestoreStatus']=='RestoredOriginalAndReadBack' and state['HandleClosed'] and state['Failure'] is None
assert len(state['Samples'])==6 and all(x['Interval']==1100 and x['Mirror']==1200 for x in state['Samples'])
assert post['Failure'] is None and post['HandleClosed'] and post['ModuleAfter']['MetadataMatched']
assert post['Pid']==state['Pid'] and post['StartedUtc']==state['StartedUtc']
assert next(x['Value'] for x in post['Observations'] if x['Name']=='received_attack_interval')==1200
assert hashlib.sha256((root/panel['Screenshot']).read_bytes()).hexdigest()==panel['SHA256']
assert panel['DisplayedAttackSpeed']==1.2 and not panel['ReportedPanelChange']
summary={'method':'Auxiliary explicit single-field Win32 write and independent read-only restoration check; REA provides preceding static evidence',
 'field_write_verified':True,'test_interval':1100,'original_interval':1200,'restored_and_independently_verified':True,
 'samples':state['Samples'],'user_panel_interval_seconds':1.2,'ui_change_observed':False,
 'snapshot_alignment':'User screenshot file timestamp falls in the trial interval; exact capture-to-memory synchronization unverified',
 'attack_effect':'Unknown; no combat experiment requested in this trial','automatic_reapplication':False,
 'changed_fields':['B+0x142DB40 uint16 only, followed by original-value restoration'],
 'unchanged_by_writer':['interval mirror','animation U/V','movement speed','packet flags','protection code/state'],
 'limitations':['Sequential reads do not prove uninterrupted persistence between sample points.','Unchanged panel does not prove an unchanged attack request interval, a wrong address, or server protection.','UI snapshot/refresh path is a candidate explanation, not established cause.','RVA0x16D72E..0x16D74C conditionally sets outgoing argument bit7 on interval/mirror difference; its business meaning remains unknown.'],
 'next':'Trace active panel snapshot ownership and refresh/invalidation; do not change additional fields to hide the discrepancy.',
 'apply_utc':state['AppliedUtc'],'completed_utc':state['CompletedUtc'],'handles_closed':True}
(root/'interval-trial-summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf8')
tz=datetime.timezone(datetime.timedelta(hours=8))
def local(s):return datetime.datetime.fromisoformat(s.replace('Z','+00:00')).astimezone(tz).strftime('%Y-%m-%d %H:%M:%S')
fragment=f'''<div id="interval-trial"><h3>首次临时写入：回读1100，但面板仍为1.2</h3>
<p>用户明确同意测试并确认已停止攻击。重新装备武器后，先只读确认同步间隔/镜像及动画U/V均恢复1200，完成持武器→空手→持武器的客户端字段往返对照。本次首次实际写入发生在北京时间{local(state['AppliedUtc'])}，结束于{local(state['CompletedUtc'])}。</p>
<p>仅向B+0x142DB40写入2字节：1200→1100；没有改写镜像、动画U/V、移速、请求标志或保护代码。窗口内0/5/15/30/45/60秒附近共6次采样均读到1100，镜像均为1200；没有反复锁定或重新应用。不能把有限采样外推为每一瞬间都没有更新。</p>
<p><strong>用户截图仍显示1.2，报告无变化。</strong>截图文件时间落在试验窗口内，但并非与内存读数原子同步。因此此前“面板刷新后预计显示1.1”没有在这次试验中得到验证，不能写成面板修改成功；只能确认内存写入与回读成功。缓存/快照、刷新调用路径或其他运行时消费者仍需逐项追查，不把它们直接定论为服务器保护。</p>
<p>REA已保存的指令显示：RVA0x16D706以后比较间隔与镜像，RVA0x16D74C存在置位bit7的路径，业务含义未知。本轮让用户保持非战斗，没有进行攻击节奏验证，也没有改写镜像或标志以消除差异。下一步优先追面板快照的所有者与刷新入口。</p>
<p><strong>还原结果：</strong>结束时1100→1200写入及回读成功，随后独立只读脚本再次确认1200，相关句柄全部关闭。测试没有修改磁盘上的客户端文件，也没有常驻进程或自动重启。</p>
<p><a href="runtime-20261019/user-panel-interval-trial.png">用户测试截图</a> · <a href="runtime-20261019/interval-trial-state.json">写入、6次采样与还原原始记录</a> · <a href="runtime-20261019/after-interval-trial-baseline.json">还原后独立复核</a> · <a href="runtime-20261019/interval-trial-summary.json">结论与待查项</a> · <a href="runtime-20261019/interval-trial-helper-verification.json">辅助进程自身内存的4项验证</a></p></div>'''
(root/'interval-trial-fragment.html').write_text(fragment,encoding='utf8')
print(json.dumps({'writeVerified':True,'samples':len(state['Samples']),'panelChangedObserved':False,'restoredVerified':True,'handlesClosed':True}))
