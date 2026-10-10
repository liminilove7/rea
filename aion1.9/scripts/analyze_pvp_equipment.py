"""Extract equipment evidence from the fixed historical server XML; no game launch."""
from pathlib import Path
import json
import xml.etree.ElementTree as ET
from collections import defaultdict

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'server/gameserver/data/static_data'
items = {e.attrib['id']: e for e in ET.parse(DATA / 'items/item_templates.xml').getroot()}

def mods(e):
    return [dict(m.attrib, kind=m.tag) for m in e.findall('modifiers/*')]

def values(e, name, bonus=None):
    return sum(float(m.get('value', 0)) for m in e.findall('modifiers/*')
               if m.get('name') == name and (bonus is None or (m.get('bonus') == 'true') == bonus))

weapons = []
for e in items.values():
    if not e.get('id', '').startswith('101300'):
        continue
    if e.get('level') == '50' and values(e, 'MIN_DAMAGES') in (235, 251):
        if (values(e, 'MIN_DAMAGES') == 251 and values(e, 'PHYSICAL_ACCURACY', True) == 140
            or values(e, 'MIN_DAMAGES') == 235 and values(e, 'ATTACK_RANGE') >= 4000
            or values(e, 'MIN_DAMAGES') == 235 and values(e, 'PVP_ATTACK_RATIO') == 100):
            weapons.append(dict(e.attrib, modifiers=mods(e)))
    if e.get('level') == '30' and values(e, 'PVP_ATTACK_RATIO') > 0:
        weapons.append(dict(e.attrib, modifiers=mods(e)))

sets = []
for s in ET.parse(DATA / 'item_sets/item_sets.xml').getroot():
    if s.get('id') not in ('95', '98', '101', '104', '119', '122', '125', '128'):
        continue
    total = defaultdict(float)
    parts = []
    for part in s.findall('itempart'):
        e = items[part.get('itemid')]
        parts.append(dict(e.attrib, modifiers=mods(e)))
        for m in e.findall('modifiers/*'):
            if m.tag == 'add':
                total[m.get('name')] += float(m.get('value', 0))
    for m in s.findall('partbonus/modifiers/*') + s.findall('fullbonus/modifiers/*'):
        if m.tag == 'add':
            total[m.get('name')] += float(m.get('value', 0))
    sets.append(dict(s.attrib, total_additive_template_stats=dict(total), parts=parts,
                     set_modifiers=[dict(m.attrib, kind=m.tag) for m in s.findall('partbonus/modifiers/*') + s.findall('fullbonus/modifiers/*')]))

stones = []
for e in items.values():
    if e.get('item_category') != 'MAGICSTONE':
        continue
    bonuses = [dict(m.attrib, kind=m.tag) for m in e.findall('.//modifiers/*')]
    if any(m.get('name') in ('PHYSICAL_ATTACK', 'PHYSICAL_CRITICAL', 'PHYSICAL_ACCURACY', 'PARRY')
           and m.get('value') in ('5', '15', '25', '17', '27') for m in bonuses):
        stones.append(dict(e.attrib, modifiers=bonuses))
class_stats = []
for path in sorted((DATA / 'stats/player').glob('*-templates.xml')):
    for e in ET.parse(path).getroot():
        if e.get('level') == '50':
            class_stats.append(dict(e.attrib, stats=dict(e.find('stats_template').attrib)))
out = {'commit': '94fc8048e5fc198f000c0ca2176c65034c57cb39',
       'limitations': 'Template evidence only. Armor totals exclude enchantment, class base stats, stones, jewelry, buffs. Weapon names require independent matching.',
       'weapons': weapons, 'elite_tribunus_armor': sets, 'stones': stones, 'level_50_class_base_stats': class_stats,
       'fusion_physical_attack_mean_stats': sorted({m['name'] for w in weapons for m in w['modifiers'] if m['kind'] == 'mean'})}
(ROOT / 'analysis/pvp-equipment-evidence.json').write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding='utf-8')
print(json.dumps({'weapon_ids': [w['id'] for w in weapons], 'stone_evidence': stones,
                  'armor': [{'id': s['id'], 'name': s['name'], 'totals': s['total_additive_template_stats']} for s in sets]}, ensure_ascii=False))
