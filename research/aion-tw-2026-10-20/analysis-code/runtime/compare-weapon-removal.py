"""Retain the observed weapon-removal comparison without inferring server behavior."""
from pathlib import Path
import hashlib,json,struct
root=Path(__file__).parent
def load(name):
    return json.loads((root/name).read_text(encoding='utf-8-sig'))
panel=load('user-panel-unarmed-level4-observation.json')
assert hashlib.sha256((root/panel['Screenshot']).read_bytes()).hexdigest()==panel['SHA256']
before=load('level4-character-readonly.json')
after=load('unarmed-level4-character-readonly.json')
base_before=load('level4-baseline-readonly.json')
base_after=load('unarmed-level4-baseline-readonly.json')
for capture in [before,after,base_before,base_after]:
    assert capture['Failure'] is None and capture['HandleClosed']
    assert capture['Pid']==before['Pid'] and capture['StartedUtc']==before['StartedUtc']
for capture in [before,after]:
    assert capture['IdentityReadbackMatched']
    assert all(x['Success'] and x['Requested']==x['BytesRead'] for x in capture['Reads'])
    c=capture['Character']
    raw=next(x for x in capture['Reads'] if x['Role'].startswith('C+0x530'))
    assert struct.unpack('<HH',bytes.fromhex(raw['Hex']))==(c['U'],c['V'])
rows=[]
for field in ['received_attack_interval','attack_interval_mirror','local_move_speed_mirror']:
    a=next(x for x in base_before['Observations'] if x['Name']==field)
    b=next(x for x in base_after['Observations'] if x['Name']==field)
    assert a['Success'] and b['Success']
    fmt={'uint16':'<H','uint32':'<I','float32':'<f'}[b['Type']]
    assert struct.unpack(fmt,bytes.fromhex(b['Hex']))[0]==b['Value']
    rows.append({'field':field,'location':'B+'+b['RVA'],'before':a['Value'],'after':b['Value']})
for field,offset in [('PanelSpeed','0x38'),('Speed','0x70C'),('Square','0x710'),('Inverse','0x714'),('U','0x530'),('V','0x532'),('AnimationScale','0x51C')]:
    rows.append({'field':field,'location':'C+'+offset,'before':before['Character'][field],'after':after['Character'][field]})
assert rows[0]['before']==1200 and rows[0]['after']==1500
assert rows[1]['after']==1500
assert before['Character']['U']==before['Character']['V']==1200
assert after['Character']['U']==after['Character']['V']==1500
assert panel['DisplayedAttackSpeed']==rows[0]['after']/1000
assert panel['DisplayedMoveSpeed']==after['Character']['Speed']==6.0
out={'method':'REA-located static fields plus auxiliary Win32 read-only snapshots and user screenshots',
     'before_capture_utc':before['CapturedAtUtc'],'after_capture_utc':after['CapturedAtUtc'],
     'before':'level 4, weapon equipped','after':'level 4, right-hand weapon removed per user',
     'fields':rows,'cattack_prefix_ratio_before':1.0,'cattack_prefix_ratio_after':1.0,
     'same_entity':before['Character']['Entity']==after['Character']['Entity'],
     'same_component':before['Character']['C']==after['Character']['C'],
     'conclusions':['Received attack interval and mirror changed from 1200 to 1500, matching panel 1.2 to 1.5.','Both animation fields changed together, so the audited U/V branch remains 1 with scale 1.','Selected movement fields remained unchanged.'],
     'limitations':['Two snapshots do not show the intervening write or the exact packet received.','U and V business names remain unproved; correlated changes alone do not identify base versus final interval.','The screenshot also changes HP 351 to 386 and physical defense 37 to 41; source unknown, so not a fully controlled single-factor experiment.','No game writes or modification effectiveness test; no accepted server attack-rate claim.','The cattack prefix formula describes one audited branch, not every animation/action.'],
     'game_memory_written':False,'remote_functions_invoked':False,'all_handles_closed':True}
(root/'weapon-removal-comparison.json').write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf8')
table=''.join(f'<tr><td><code>{x["location"]}</code><br>{x["field"]}</td><td>{x["before"]}</td><td>{x["after"]}</td></tr>' for x in rows)
fragment=f'''<div id="weapon-removal"><h3>卸下右手武器：间隔1200 → 1500</h3>
<p>用户确认卸下右手武器，4级角色面板攻击速度从1.2变为1.5、移动速度仍6.0。随后只读采样定位到同一实体及组件，记录如下。间隔变大表示等待时间变长；不把它直接视为服务器认可的攻击频率。</p>
<table><thead><tr><th>字段</th><th>先前持武器采样</th><th>卸下武器后采样</th></tr></thead><tbody>{table}</tbody></table>
<p><strong>关键区别：</strong>动画U/V从1200/1200变成1500/1500，因此此前审过的cattack前缀分支中，U/V×系数仍为1。面板与请求门槛读取的间隔则已发生变化。这说明只盯动画倍率会漏掉间隔变化；还不能据此给U/V命名为“基础/最终攻速”。</p>
<p>截图还出现生命351→386、物防37→41，具体原因未核实。本轮记录为“卸武器后的观察”，不宣称全部变化都由卸武器导致；也没有捕获两次采样之间的实际写入或网络包。至少这组间隔可以直接读取，不能将其等同于已解开的全部计时保护。</p>
<p>下一步重新装备同一把武器，观察间隔与动画字段是否恢复1200、移速是否仍6.0，形成一次持武器→空手→持武器的往返对照。无需强化、消耗材料或修改游戏内存。</p>
<p><a href="runtime-20261019/user-character-panel-unarmed-level4.png">空手截图</a> · <a href="runtime-20261019/weapon-removal-comparison.json">对照结论及局限</a> · <a href="runtime-20261019/unarmed-level4-character-readonly.json">空手组件原始采样</a> · <a href="runtime-20261019/unarmed-level4-baseline-readonly.json">空手模块原始采样</a></p></div>'''
(root/'weapon-removal-fragment.html').write_text(fragment,encoding='utf8')
print(json.dumps({'fieldsCompared':len(rows),'intervalBefore':1200,'intervalAfter':1500,'animationRatioBefore':1,'animationRatioAfter':1,'handlesClosed':True}))
