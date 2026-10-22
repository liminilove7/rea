"""Derive small queryable feature facts; never infer a server damage formula."""
import collections, json
from pathlib import Path
from xml.etree import ElementTree as ET
from analyze_pvp import DEFAULT

HERE = Path(__file__).parent
data = json.loads((HERE/'resource-evidence.json').read_text(encoding='utf8'))
files = {Path(x['path']).name:x for x in data['files']}
skills = files['client_skills.xml']; items = files['client_items.xml']
damage_ratio_count = skills['field_counts'].get('pvp_damage_ratio', 0)
attrs=collections.Counter(); item_count=0; slots=collections.Counter()
for row in items['all_pvp_records']:
    hits=[(k,v) for k,v in row['matches'] if 'bonus_attr' in k and 'pvp' in v.lower()]
    item_count += bool(hits)
    for k,v in hits:
        attrs[v.split()[0].lower()] += 1
        slots['a' if k.startswith('bonus_attr_a') else 'b' if k.startswith('bonus_attr_b') else 'ordinary'] += 1
out={'scope':data['scope'],'coverage':data['totals'], 'source_hashes':{k:v['sha256'] for k,v in files.items()},
     'item_pvp_attribute_records':item_count,'item_pvp_attribute_occurrences_lowercase_grouped':dict(attrs),
     'item_pvp_slot_occurrences':dict(slots),
     'explicit_skill_pvp_fields':{k:v for k,v in skills['matched_values'].items() if k.startswith('pvp_')},
     'explicit_damage_ratio_records':damage_ratio_count, 'absent_damage_ratio_records':skills['records']-damage_ratio_count,
     'absence_semantics':'Absent is not a proven 100% default. Test-named records are retained and are not evidence of live availability.',
     'representative_skill_and_learn_relationships':[]}
selected={'645','3790','3804','11905','20357','1958','1959','1961','1962','1965'}
allskills=ET.parse(DEFAULT/'data/skills/skills/client_skills.xml').getroot()
learns=ET.parse(DEFAULT/'data/skills/skills/client_skill_learns.xml').getroot()
for r in allskills:
    if r.findtext('id') in selected:
        name=r.findtext('name')
        matches=[[(x.tag,x.text) for x in q] for q in learns if q.findtext('skill')==name]
        out['representative_skill_and_learn_relationships'].append({'id':r.findtext('id'),'name':name,
            'fields':[(x.tag,x.text) for x in r], 'learn_links_exact_name':matches,
            'learn_link_semantics':'Exact case-sensitive name join only; no runtime unlock/availability claim.'})
(HERE/'feature-summary.json').write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf8')
print(json.dumps({k:v for k,v in out.items() if k not in ('source_hashes','representative_skill_and_learn_relationships')},ensure_ascii=False,indent=2))
