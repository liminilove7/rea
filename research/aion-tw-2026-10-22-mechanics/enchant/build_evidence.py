"""Interpret decoded current resources, preserving full selected records and identities."""
from pathlib import Path
import collections, hashlib, json, re, xml.etree.ElementTree as E
OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[2]
RES=ROOT/'_reference/github-releases/aion-tw-offline-20261020/analysis__complete-static-study-20261020/aion-tw-20261019/resources'
def fields(x):
    out=dict(x.attrib)
    for c in x:
        value=fields(c) if len(c) or c.attrib else c.text or ''
        if c.tag in out:
            if not isinstance(out[c.tag],list):out[c.tag]=[out[c.tag]]
            out[c.tag].append(value)
        else:out[c.tag]=value
    return out
def rows(p):return [fields(x) for x in E.parse(p).getroot()]
def save(name,d):(OUT/name).write_text(json.dumps(d,ensure_ascii=False,indent=2),encoding='utf8')
items=rows(RES/'data/items/items/client_items.xml')
manifest=json.loads((OUT/'source-manifest.json').read_text(encoding='utf8'))
expected={s['member']:s['decoded_sha256'] for s in manifest['sources']}
for p in (OUT/'decoded').glob('*.xml'):
    assert hashlib.sha256(p.read_bytes()).hexdigest()==expected[p.name],p
assert hashlib.sha256((RES/'data/items/items/client_items.xml').read_bytes()).hexdigest()==expected['client_items.xml']
table_summary={}
for p in sorted((OUT/'decoded').glob('*.xml')):
    rr=rows(p)
    table_summary[p.name]=dict(count=len(rr),fields=dict(collections.Counter(t for r in rr for t in r)),examples=rr[:3])
save('table-summary.json',table_summary)
option=rows(OUT/'decoded/client_enchant_option_prob.xml')
jump=rows(OUT/'decoded/client_jumping_enchant.xml')
acc=rows(OUT/'decoded/client_accumulated_enchant_effect.xml')
supp=[r for r in items if 'sub_enchant_material_effect' in r]
stones=[r for r in items if 166000000<=int(r.get('id',0))<166100000]
stone_fields={k:dict(collections.Counter(str(r.get(k,'<absent>')) for r in stones)) for k in sorted(set().union(*(r.keys() for r in stones)))}
skills=rows(RES/'data/skills/skills/client_skills.xml')
index=collections.defaultdict(list)
for s in skills:index[s.get('name','').lower()].append(s)
joins=[dict(enchant_record=r,join_mode='casefold exact name, preserves raw values',skills=index[r['activation_skill'].lower()]) for r in acc]
selection=[]
for r in items:
    if r.get('accumulated_enchant_effect')=='TRUE' and 'test' not in r.get('name','').lower():
        kind=r.get('enchant_type','<absent>')
        if not any(s.get('enchant_type')==kind for s in selection):selection.append(r)
option_matrix=[dict(quality=r['quality'],raw_probabilities=[v['enchant_option_level_prob'] for v in r['option_enchant']['data']],levels=[v['enchant_option_level'] for v in r['option_enchant']['data']],sub_matter_counts=[v['enchant_sub_matter_count'] for v in r['option_enchant']['data']]) for r in option]
counts=dict(items=len(items),supplements=len(supp),stone_id_range_records=len(stones),accumulated_true=sum(r.get('accumulated_enchant_effect')=='TRUE' for r in items),accumulated_rules=len(acc),joined_skill_records=sum(len(r['skills']) for r in joins),option_quality_rows=len(option),option_cells=sum(len(r['option_enchant']['data']) for r in option),jump_rows=len(jump))
source_manifest=json.loads((OUT/'source-manifest.json').read_text(encoding='utf8'))
data=dict(method='auxiliary current PAK/BXML metadata and exact resource joins, not server or runtime proof',target_executed=False,counts=counts,option_matrix=option_matrix,option_raw=option,jump_raw=jump,supplements=supp,stone_id_range=stones,stone_field_values=stone_fields,accumulated_skill_joins=joins,representative_equipment=selection,sources=source_manifest['sources'],skill_source=dict(path=str((RES/'data/skills/skills/client_skills.xml').relative_to(ROOT)),sha256=hashlib.sha256((RES/'data/skills/skills/client_skills.xml').read_bytes()).hexdigest(),records=len(skills)),unknowns=['Ordinary equipment enhancement success formula in current Game.dll has not been established by this resource parser.','Probability scale for option fields and supplement combination need current native consumer evidence.','No complete failure transition, RNG, pity counter, ordinary per-level attack/defense increment rule in these parsed records.','Presence of records, especially test names, does not establish availability or activation.','enchant_type 1/2 PVE/PVP naming supported by accumulated-rule names; not evidence of full PVP damage formula.','breakable is a generic item field and cannot be called enhancement-break chance.'])
save('enchant-current-evidence.json',data)
print(json.dumps(dict(counts=counts,option_matrix=option_matrix,stones=[{k:v for k,v in r.items() if k in ['id','name','level','quality']} for r in stones[:3]],stone_field_keys=list(stone_fields),joins=[dict(name=j['enchant_record']['activation_skill'],matched=len(j['skills'])) for j in joins]),ensure_ascii=False))
