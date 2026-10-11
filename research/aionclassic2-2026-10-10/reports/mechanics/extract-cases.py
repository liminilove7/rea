"""Auxiliary XML and pinned-source extraction; no binary disassembly or game access."""
from pathlib import Path
import xml.etree.ElementTree as ET
import json, hashlib
ROOT = Path('D:/RVE/.codex/local/aion-mechanics-report')
BASE = Path('F:/RVE-Workspace/cases/aionclassic2-2026-10-10/exports/decoded')
SRC = Path('F:/RVE-Workspace/sources/AionLightning-1.9-94fc8048')
manifest = json.loads(Path('D:/RVE/.codex/local/aion19-source-manifest.json').read_text(encoding='utf-8-sig'))
blobs = {x['path']: x['git_blob_sha1'] for x in manifest['files']}
sources=[]
def identity(p):
    b=p.read_bytes(); return {'path':str(p),'sha256':hashlib.sha256(b).hexdigest()}
def records(p,tag,ids=None):
    sources.append(identity(p)); out=[]
    for _,e in ET.iterparse(p,events=('end',)):
        if e.tag==tag:
            raw={c.tag:c.text for c in e}
            if ids is None or int(raw.get('id',0)) in ids: out.append(raw)
            e.clear()
    return out
weapons={100900591,101300564}
ids=weapons|{166000093,166000094,166000100,166000106,166000107,166000110,166100008}
items=records(BASE/'data/items/items/client_items.xml','client_item',ids)
china=records(BASE/'data/China/Items/Items/client_items.xml','client_item',ids)
assert items==china, 'Selected item fields differ between common and China'
skills=records(BASE/'data/skills/skills/client_skills.xml','skill_base_client')
# Save the complete resource fields for selected examples and block/counter candidates.
selected=[x for x in skills if int(x['id']) in {234,244,2013,248,2035,444,449,529}]
counters=[x for x in skills if x.get('counter_skill')=='Block' or 'shieldimpact' in x.get('name','').lower()]
names={}
strings=BASE/'L10N/CHS/Data/Data/Strings/client_strings_item.xml'
sources.append(identity(strings))
for _,e in ET.iterparse(strings,events=('end',)):
    if e.tag=='string':
        names[e.findtext('name')]=e.findtext('body'); e.clear()
for x in items: x['_label']=names.get(x.get('desc'))
skillNames={}
skillStrings=BASE/'L10N/CHS/Data/Data/Strings/client_strings_skill.xml'
sources.append(identity(skillStrings))
for _,e in ET.iterparse(skillStrings,events=('end',)):
    if e.tag=='string':
        skillNames[e.findtext('name')]=e.findtext('body'); e.clear()
for x in selected+counters:
    x['_label']=skillNames.get(x.get('desc')); x['_description']=skillNames.get(x.get('desc_long'))
resource=json.loads(Path('D:/RVE/.codex/local/aion-report-backup/binary/combat-resource-evidence.json').read_text(encoding='utf-8-sig'))
for x in selected:
    old=next((z for z in resource['pvp_skills'] if z['raw']['id']==x['id']),None)
    if old: x['_localized']=old.get('localized')
treePath=SRC/'gameserver/data/static_data/skill_tree/skill_tree.xml'
tplPath=SRC/'gameserver/data/static_data/skills/skill_templates.xml'
tree=ET.parse(treePath).getroot(); tpl=ET.parse(tplPath).getroot()
learn=[dict(e.attrib) for e in tree.iter('skill') if int(e.attrib.get('skillId',0)) in {234,244,2013,248,2035,444,449,529}]
templates=[{'attributes':dict(e.attrib),'xml':ET.tostring(e,encoding='unicode')} for e in tpl.iter('skill_template') if int(e.attrib.get('skill_id',0)) in {234,244,2013,248,2035,444,449,529}]
sourceFiles=[
 'gameserver/src/org/openaion/gameserver/utils/stats/StatFunctions.java',
 'gameserver/src/org/openaion/gameserver/controllers/attack/AttackUtil.java',
 'gameserver/src/org/openaion/gameserver/skill/effect/DamageEffect.java',
 'gameserver/src/org/openaion/gameserver/skill/model/Skill.java',
 'gameserver/src/org/openaion/gameserver/skill/model/Effect.java',
 'gameserver/src/org/openaion/gameserver/model/gameobjects/stats/PlayerGameStats.java',
 'gameserver/src/org/openaion/gameserver/model/gameobjects/stats/listeners/ItemEquipmentListener.java',
 'gameserver/src/org/openaion/gameserver/model/gameobjects/stats/StatEnum.java',
 'gameserver/data/static_data/skill_tree/skill_tree.xml',
 'gameserver/data/static_data/skills/skill_templates.xml'
]
audits=[]
for rel in sourceFiles:
    p=SRC/rel; b=p.read_bytes(); blob=hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
    assert blob==blobs[rel],rel
    # Preserve Java consumers; XML selected records are already inline with full-source digest.
    if p.suffix=='.java': (ROOT/'evidence'/p.name).write_bytes(b)
    audits.append({'relativePath':rel,'gitBlobSha1':blob,**identity(p)})
out={'method':'Auxiliary resource extraction and pinned-source reading; no new REA binary analysis.',
 'date':'2026-10-11','commit':manifest['commit'],'items':items,'chinaSelectedFieldsIdentical':True,
 'skills':selected,'counterCandidates':counters,'skillLearn':learn,'serverTemplates':templates,
 'sources':sources,'sourceAudits':audits,
 'officialVersionBoundaries':[
 {'url':'https://www.aiononline.com/en-us/news/classic-ignite-update-patch-notes-feb-2025','title':'NA Classic Ignite 官方更新（2025-02）','claim':'引入独立保证强化至+10路径，起始阶段有限；不证明本机普通强化概率。'},
 {'url':'https://forum.aion.gameforge.com/forum/thread/13347-update-3-7-rankings-enchantments/','title':'Gameforge Classic 3.7 官方更新（2025-04-21）','claim':'也加入独立保证强化路径；不同地区/版本不能直接移植。'}]}
(ROOT/'evidence/case-evidence.json').write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps({'items':[(x['id'],x.get('_label'),x.get('quality')) for x in items],
 'skills':[(x['id'],x['name']) for x in selected],'counterCandidates':len(counters),'learn':learn},ensure_ascii=False))
