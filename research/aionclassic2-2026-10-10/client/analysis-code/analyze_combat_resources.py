"""Reproducible offline resource joins; raw fields are never server claims."""
from analyze_aion_native import CASE, OUT, BACK, save
from pathlib import Path
from collections import Counter, defaultdict
import xml.etree.ElementTree as ET
import hashlib, json, re

ROOT = CASE / 'exports' / 'decoded'
sources = []
def read(rel):
    path = ROOT / rel
    raw = path.read_bytes()
    elements = list(ET.fromstring(raw))
    sources.append({'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'records': len(elements)})
    return [{e.tag: e.text or '' for e in record} for record in elements]

items = read('data/items/items/client_items.xml')
china = read('data/China/Items/Items/client_items.xml')
skills = read('data/skills/skills/client_skills.xml')
strings = defaultdict(list)
for path in sorted((ROOT / 'L10N/CHS/Data/Data/Strings').glob('*.xml')):
    for d in read(path.relative_to(ROOT)):
        if d.get('name') and 'body' in d:
            strings[d['name'].casefold()].append({'body': d['body'], 'source': str(path), 'id': d.get('id')})

def texts(key):
    return strings.get(key.casefold(), [])
def localized(d):
    return {k: texts(v) for k, v in d.items() if k in ('desc', 'desc_long', 'desc_proc', 'desc_abnormal', 'desc_abnormal_long')}
def record(d):
    return {'raw': d, 'localized': localized(d), 'test_name_marker': bool(re.search(r'test|测试', d.get('name', ''), re.I)), 'availability': 'not verified'}
by_skill = defaultdict(list)
for d in skills:
    by_skill[d.get('name', '').casefold()].append(d)

procs = []
for d in items:
    if 'proc_enchant_effect_occur_prob' not in d: continue
    linked = by_skill.get(d.get('proc_enchant_skill', '').casefold(), [])
    procs.append({**record(d), 'linked_skill_candidates': [record(s) for s in linked], 'join': 'case-insensitive exact skill name; level selection preserved, not inferred'})
materials = [record(d) for d in items if 'sub_enchant_material_effect' in d]
pvp = [record(d) for d in skills if any(k.startswith('pvp_') for k in d)]
weapons = defaultdict(list)
for d in items:
    if 'attack_delay' in d: weapons[d.get('weapon_type', '(missing)')].append(d)
weapon_summary = []
for kind, ds in sorted(weapons.items()):
    weapon_summary.append({'weapon_type': kind, 'records': len(ds), 'test_name_marker_count': sum(record(d)['test_name_marker'] for d in ds), 'attack_delay_raw_distribution': dict(Counter(d['attack_delay'] for d in ds)), 'attack_range_raw_distribution': dict(Counter(d.get('attack_range', '(missing)') for d in ds)), 'example': record(next((d for d in ds if not record(d)['test_name_marker']), ds[0]))})
movement = []
speed = []
for d in skills:
    effects = {k:v for k,v in d.items() if re.fullmatch(r'effect\d+_type', k)}
    if any(re.search('teleport|blink|dash|move|pull|return|back', v, re.I) for v in effects.values()): movement.append(record(d))
    if any(v.casefold() in ('speed','flyspeed','attackdelay','attackspeed') for v in d.values()): speed.append(record(d))
speed_items = [record(d) for d in items if any(re.match(r'(speed|flyspeed|attackdelay|attackspeed)\s',v,re.I) for k,v in d.items() if k.startswith('bonus_attr'))]
enchant_texts = []
for key, values in strings.items():
    selected = [v for v in values if ('强化' in v['body'] and re.search(r'概率|成功率|百分|\d+(?:\.\d+)?%', v['body'])) or ('神石' in v['body'] and re.search(r'概率|\d+(?:\.\d+)?%', v['body']))]
    if selected: enchant_texts.append({'key': key, 'matches': selected})
common_by_id = {d['id']:d for d in items}
differences=[]
for d in china:
    c=common_by_id.get(d['id'])
    if c != d:
        differences.append({'id':d['id'], 'changes': {k:{'common':c.get(k) if c else None,'china':d.get(k)} for k in set(c or {})|set(d) if (c or {}).get(k)!=d.get(k)}})

results={'sources':sources,'scope':'Offline extracted client resources. Test-name marker is a heuristic, not an availability filter. Absent values are unknown defaults. Numeric fields remain raw unless independently verified.', 'counts': {'items':len(items),'china_items':len(china),'skills':len(skills),'proc_items':len(procs),'supplement_materials':len(materials),'skills_explicit_pvp_damage_ratio':sum('pvp_damage_ratio' in d for d in skills),'skills_explicit_pvp_remain_time_ratio':sum('pvp_remain_time_ratio' in d for d in skills),'movement_effect_candidates':len(movement),'speed_skill_candidates':len(speed),'speed_bonus_items':len(speed_items),'regional_differences':len(differences)}, 'weapon_groups':weapon_summary,'godstones':procs,'enchant_materials':materials,'pvp_skills':pvp,'movement_skills':movement,'speed_skills':speed,'speed_bonus_items':speed_items,'enchant_localization':enchant_texts,'region_differences':differences}
save('combat-resource-evidence.json',results)
print(json.dumps(results['counts'],ensure_ascii=False,indent=2))
for label, rows in [('GODSTONES',procs),('MATERIALS',materials),('PVP',pvp),('MOVEMENT',movement)]:
    print(label)
    selected=[r for r in rows if not r['test_name_marker']]
    for r in selected[:6]:
        d=r['raw'];print(json.dumps({'id':d.get('id'),'name':d.get('name'),'values':{k:v for k,v in d.items() if k.startswith(('proc_enchant','sub_enchant','pvp_')) or re.fullmatch(r'effect\d+_type',k)},'localized':r['localized']},ensure_ascii=False))
print('WEAPONS',json.dumps([{k:v for k,v in w.items() if k!='example'} for w in weapon_summary],ensure_ascii=False))
