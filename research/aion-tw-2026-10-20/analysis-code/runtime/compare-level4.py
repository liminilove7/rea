"""Compare user panel observations and separately retained read-only samples."""
from pathlib import Path
import hashlib, json, struct

root = Path(__file__).parent
def load(name):
    return json.loads((root/name).read_text(encoding='utf-8-sig'))

before = load('character-fields-readonly.json')
after = load('level4-character-readonly.json')
base_before = load('baseline-readonly.json')
base_after = load('level4-baseline-readonly.json')
panel = load('user-panel-level4-observation.json')
assert hashlib.sha256((root/panel['Screenshot']).read_bytes()).hexdigest() == panel['SHA256']
for record in [before,after,base_before,base_after]:
    assert record['Failure'] is None and record['HandleClosed']
    assert record['Pid'] == before['Pid'] and record['StartedUtc'] == before['StartedUtc']
for record in [before,after]:
    assert record['IdentityReadbackMatched']
    assert all(x['Success'] and x['BytesRead'] == x['Requested'] for x in record['Reads'])
    raw = next(x for x in record['Reads'] if x['Role'].startswith('C+0x70C'))
    decoded = struct.unpack('<fff',bytes.fromhex(raw['Hex']))
    assert decoded[0] == record['Character']['Speed'] and decoded[1] == record['Character']['Square']
    assert abs(decoded[2]-record['Character']['Inverse']) < 1e-8

keys = ['PanelSpeed','Speed','Square','Inverse','U','V','AnimationScale']
fields = [{'field':key,'before':before['Character'][key],'after':after['Character'][key],
           'unchanged':before['Character'][key] == after['Character'][key]} for key in keys]
module_fields = []
for name in ['received_attack_interval','attack_interval_mirror','local_move_speed_mirror']:
    x=next(v for v in base_before['Observations'] if v['Name']==name)
    y=next(v for v in base_after['Observations'] if v['Name']==name)
    assert x['Success'] and y['Success'] and x['Hex']==y['Hex']
    module_fields.append({'field':name,'before':x['Value'],'after':y['Value'],'unchanged':True})
assert all(x['unchanged'] for x in fields)
ui_rows=[('生命',305,351),('精神',310,380),('右手命中',234,242),
         ('盾牌防御',130,142),('武器防御',263,275),('回避',227,259),('魔法命中',42,57),
         ('攻击速度',1.2,1.2),('移动速度',6.0,6.0)]
out={'method':'Auxiliary comparison of user screenshots and read-only fields previously located through REA',
     'screenshot_level_before':3,'screenshot_level_after':4,
     'panel_changes':[{'attribute':name,'before':a,'after':b,'difference':round(b-a,6)} for name,a,b in ui_rows],
     'memory_fields':module_fields+fields,'same_entity_pointer':before['Character']['Entity']==after['Character']['Entity'],
     'same_component_pointer':before['Character']['C']==after['Character']['C'],
     'before_capture_utc':before['CapturedAtUtc'],'after_capture_utc':after['CapturedAtUtc'],
     'conclusion':'Selected attack/movement fields were unchanged in these two read-only samples; UI reports level 3 then 4.',
     'limitations':['Screenshot and memory sampling are not atomic or synchronized.','Other equipment/buff/target changes were not fully controlled.','Panel attribute differences have not been independently read from memory.','No basis to infer all-level growth formulas or absence of indirect level effects.','Weapon remains visible in screenshot; this is not a weapon-removal experiment.'],
     'game_memory_written':False,'handles_closed':True}
(root/'level4-comparison.json').write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf8')
rows=''.join(f'<tr><td>{name}</td><td>{a}</td><td>{b}</td></tr>' for name,a,b in ui_rows)
fragment=f'''<div id="level4-comparison"><h3>后续样本：角色从3级到4级</h3>
<p>用户报告升级后速度未变，第二张截图仍能看到右手武器。随后重新遍历实体表并只读采样：同一进程、实体与组件仍匹配；同步攻击间隔及镜像均为1200，角色移速6.0、平方36.0、倒数约0.16666667，动画U/V均1200，系数1.0，均与前次相同。</p>
<table><thead><tr><th>截图面板属性</th><th>3级截图</th><th>4级截图</th></tr></thead><tbody>{rows}</tbody></table>
<p>表内生命、精神、命中与防御变化来自截图人工读取，尚未独立核对相应内存字段。这组样本支持“本次升级前后，已观察的速度字段未变化”，不能推出所有等级均不影响速度，也不能据此拟合完整成长公式；期间其他因素并未完全控制。</p>
<p>当前还不是卸下武器的对照实验。下一步保持同一等级，只卸下武器，核对同步间隔与动画字段是否跟随改变；若面板仍相同也应保留结果。</p>
<p><a href="runtime-20261019/user-character-panel-level4.png">4级截图原件</a> · <a href="runtime-20261019/level4-comparison.json">对照数据与局限</a> · <a href="runtime-20261019/level4-character-readonly.json">4级组件采样</a> · <a href="runtime-20261019/level4-baseline-readonly.json">4级模块采样</a></p></div>'''
(root/'level4-fragment.html').write_text(fragment,encoding='utf8')
print(json.dumps({'compared_fields':len(fields)+len(module_fields),'all_selected_speed_fields_unchanged':True,'same_component':out['same_component_pointer'],'handles_closed':True}))
