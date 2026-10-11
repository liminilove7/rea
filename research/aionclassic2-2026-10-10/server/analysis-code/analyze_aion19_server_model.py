"""Pinned-source audit and discrete probability enumeration; never connects to a game."""
from pathlib import Path
import hashlib
import json
import math
import shutil
import struct
import xml.etree.ElementTree as ET
from fractions import Fraction

ROOT = Path(r'F:\RVE-Workspace\sources\AionLightning-1.9-94fc8048')
JAVA = ROOT / 'gameserver/src/org/openaion/gameserver'
CASE = Path(r'F:\RVE-Workspace\cases\aionclassic2-2026-10-10')
LOCAL = Path(r'D:\RVE\.codex\local')
BACK = LOCAL / 'aion-report-backup'
COMMIT = '94fc8048e5fc198f000c0ca2176c65034c57cb39'
assert ROOT.is_dir() and CASE.is_dir()

# Excerpts preserve the producer representation, locations and hashes.
specs = {
 'model/gameobjects/stats/Stat.java': [(50,104)],
 'model/gameobjects/stats/CreatureGameStats.java': [(159,165),(245,298),(306,310),(337,372),(554,563)],
 'model/gameobjects/stats/PlayerGameStats.java': [(80,107),(165,191),(218,260),(283,328)],
 'model/gameobjects/stats/StatEnum.java': [(54,64),(302,315)],
 'model/gameobjects/stats/StatModifierPriority.java': [(25,30)],
 'model/gameobjects/stats/StatModifiers.java': [(35,56)],
 'model/gameobjects/stats/modifiers/StatModifier.java': [(78,87)],
 'model/gameobjects/stats/modifiers/AddModifier.java': [(31,82)],
 'model/gameobjects/stats/modifiers/RateModifier.java': [(31,84)],
 'model/gameobjects/stats/modifiers/SetModifier.java': [(25,37)],
 'skill/effect/BufEffect.java': [(93,97),(111,135),(155,183)],
 'skill/effect/StatupEffect.java': [(27,32)],
 'skill/effect/StatdownEffect.java': [(27,32)],
 'network/aion/clientpackets/CM_ATTACK.java': [(56,82)],
 'controllers/PlayerController.java': [(447,449),(854,865)],
 'controllers/CreatureController.java': [(162,233),(281,393)],
 'controllers/attack/AttackUtil.java': [(56,129),(198,259),(325,355),(363,446),(456,499),(552,612),(625,717),(722,748)],
 'utils/stats/StatFunctions.java': [(276,363),(373,410),(480,505),(549,745)],
 'skill/effect/DamageEffect.java': [(48,118)],
 'skill/effect/EffectTemplate.java': [(260,420)],
 'skill/effect/DelayDamageEffect.java': [(50,79)],
 'skill/model/SkillTemplate.java': [(86,94),(366,369)],
 'skill/model/Effect.java': [(866,869)],
 'network/aion/serverpackets/SM_STATS_INFO.java': [(67,127)],
 'network/aion/serverpackets/SM_EMOTION.java': [(82,95),(285,291)],
 'model/items/GodStone.java': [(52,67),(76,110),(117,120)],
 'model/templates/item/GodstoneInfo.java': [(30,76)],
 'controllers/ObserveController.java': [(113,126)],
 'services/EnchantService.java': [(119,280)],
 'configs/main/EnchantsConfig.java': [(45,50)],
 'configs/main/CustomConfig.java': [(365,366)],
 'skill/effect/RandomMoveLocEffect.java': [(51,123)],
 'skill/properties/FirstTargetRangeProperty.java': [(52,96)],
 'skill/properties/TargetRangeProperty.java': [(73,115)],
 'utils/MathUtil.java': [(336,347)],
 'network/aion/clientpackets/CM_MOVE.java': [(71,106),(113,190)],
 'world/World.java': [(109,148)],
}
files = []
texts = {}
for rel, spans in specs.items():
    path = JAVA / rel
    raw = path.read_bytes()
    lines = raw.decode('utf-8-sig').splitlines()
    texts[rel] = '\n'.join(lines)
    files.append({'relative_path': 'gameserver/src/org/openaion/gameserver/' + rel,
                  'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(),
                  'excerpts': [{'start_line': a, 'end_line': min(b,len(lines)),
                               'lines': [{'line': i+1, 'text': lines[i]} for i in range(a-1,min(b,len(lines)))]}
                               for a,b in spans]})
    dest = BACK / 'server-reference/key-sources' / rel
    dest.parent.mkdir(parents=True,exist_ok=True)
    shutil.copy2(path,dest)
rnd = ROOT / 'commons/src/org/openaion/commons/utils/Rnd.java'
raw = rnd.read_bytes()
texts['Rnd.java'] = raw.decode('utf-8-sig')
files.append({'path':str(rnd),'relative_path':'commons/src/org/openaion/commons/utils/Rnd.java',
              'sha256':hashlib.sha256(raw).hexdigest(),
              'excerpts':[{'start_line':27,'end_line':40,'text':'\n'.join(texts['Rnd.java'].splitlines()[26:40])}]})
rnd_backup=BACK/'server-reference/key-sources/commons/utils/Rnd.java'
rnd_backup.parent.mkdir(parents=True,exist_ok=True)
shutil.copy2(rnd,rnd_backup)
checks = []
def check(rel, snippet):
    assert snippet in texts[rel], (rel,snippet)
    checks.append({'relative_path':rel,'source_expression':snippet,'passed':True})
for rel,snippet in [
 ('model/gameobjects/stats/Stat.java','return base+bonus;'),
 ('model/gameobjects/stats/Stat.java','this.base = amount;'),
 ('model/gameobjects/stats/CreatureGameStats.java','int MIN_ATTACK_SPEED = 600;'),
 ('model/gameobjects/stats/CreatureGameStats.java','newValue = modifier.apply(oStat.getBase(), oStat.getCurrent());'),
 ('model/gameobjects/stats/PlayerGameStats.java','getBaseStat(StatEnum.ATTACK_SPEED)/2f'),
 ('model/gameobjects/stats/PlayerGameStats.java','int MAX_SPEED = 12000;'),
 ('model/gameobjects/stats/PlayerGameStats.java','int MAX_FLY_SPEED = 16000;'),
 ('model/gameobjects/stats/PlayerGameStats.java','int MAX_BOOST_MAGICAL_SKILL = 2600;'),
 ('model/gameobjects/stats/PlayerGameStats.java','((SimpleModifier)aspeedBonus).getValue() > ((SimpleModifier)mod).getValue()'),
 ('model/gameobjects/stats/modifiers/RateModifier.java','Math.round(value * baseStat / 100f)'),
 ('controllers/PlayerController.java','milis - lastAttackMilis < attackSpeed'),
 ('controllers/CreatureController.java','milis - lastAttackMilis < attackSpeed'),
 ('network/aion/clientpackets/CM_ATTACK.java','time = readH();'),
 ('controllers/CreatureController.java','}, time);'),
 ('controllers/attack/AttackUtil.java','baseDamages = Math.round(baseDamages * 0.60f);'),
 ('controllers/attack/AttackUtil.java','baseDamages * (1 + pvpAttackBonus - pvpDefenceBonus)'),
 ('controllers/attack/AttackUtil.java','baseDamages -=(diff * 0.04f);'),
 ('controllers/attack/AttackUtil.java','damage -= Math.round((damage * shieldDamageReduce) / 100);'),
 ('controllers/attack/AttackUtil.java','StatFunctions.calculatePhysicalCriticalRate(attacker, attacked, 1)'),
 ('skill/effect/DamageEffect.java','valueWithDelta * (effect.getPvpDamage() / 100f)'),
 ('utils/stats/StatFunctions.java','if(critical <= 440)'),
 ('utils/stats/StatFunctions.java','else if(critical <= 600)'),
 ('utils/stats/StatFunctions.java','if(resist > 95)'),
 ('model/items/GodStone.java','Rnd.get(probability - probabilityLeft, probability)'),
 ('model/items/GodStone.java','rand *= 0.5;'),
 ('model/items/GodStone.java','if(rand > Rnd.get(0, 1000))'),
 ('services/EnchantService.java','if(Rnd.get(0, 100) < success)'),
 ('services/EnchantService.java','targetItem.setEnchantLevel(currentEnchant);'),
 ('Rnd.java','max - min + 1'),
 ('utils/MathUtil.java','dx * dx + dy * dy + dz * dz < range * range'),
]: check(rel,snippet)

def f32(x): return struct.unpack('<f',struct.pack('<f',x))[0]
def jroundf(x): return math.floor(f32(x)+0.5)
def probability_lt(threshold,upper):
    count = sum(v < threshold for v in range(upper+1))
    p = Fraction(count,upper+1)
    return {'threshold':threshold,'success_count':count,'total_outcomes':upper+1,
            'fraction':str(p),'percent':float(p*100)}
def crit_rate(c):
    if c <= 440: rate=f32(c*f32(0.1))
    elif c <= 600: rate=f32(f32(440*f32(.1))+f32((c-440)*f32(.05)))
    else: rate=f32(f32(f32(440*f32(.1))+f32(160*f32(.05)))+f32((c-600)*f32(.02)))
    return max(1.,rate)

# Exact enumeration of integer outcomes; uniform RNG is an explicit assumption.
critical = [{'net_critical':c,**probability_lt(crit_rate(c),100)} for c in [0,100,400,439,440,441,450,500,599,600,601,650,700,800,1000,3000]]
enchant = [probability_lt(s,100) for s in [50,60,65,70,80,90,95]]
def godstone(p,left,offhand):
    lo=p-left
    if lo>p: return {'unmodeled_reason':'negative probabilityleft makes reversed RNG bounds'}
    thresholds=range(lo,p+1)
    favorable=sum(max(0,min(1001,math.trunc(t*.5) if offhand else t)) for t in thresholds)
    frac=Fraction(favorable,(left+1)*1001)
    return {'fraction':str(frac),'percent':float(frac*100),
            'threshold_min':lo,'threshold_max':p,'offhand':offhand,
            'uniform_outcomes_assumption':True,'scope':'random branch only; skill.canUseSkill and target checks follow'}
discrete_checks={
 'enchant_cap_counts_95_of_101':sum(v<95 for v in range(101))==95,
 'forced_rate100_still_one_failure':sum(v<100 for v in range(101))==100,
 'critical440_counts44':sum(v<crit_rate(440) for v in range(101))==44,
 'critical441_counts45':sum(v<crit_rate(441) for v in range(101))==45,
 'offhand_odd_threshold_truncates':math.trunc(101*.5)==50,
 'godstone_fixed100':godstone(100,0,False)['fraction']=='100/1001',
 'godstone_left50':godstone(100,50,False)['fraction']=='75/1001',
 'java_negative_half_round':jroundf(-700.5)==-700,
}
assert all(discrete_checks.values())
pd,pp,pb=Fraction(30,101),Fraction(40,101),Fraction(50,101)
defensive={'assumptions':'ordinary attack, defender has weapon and shield, no forced-status overrides; independent uniform draws',
 'dodge':str(pd),'parry':str((1-pd)*pp),'block':str((1-pd)*(1-pp)*pb),
 'ordinary_hit':str((1-pd)*(1-pp)*(1-pb))}
speed_examples=[]
for main,off,bonus_values in [(1400,None,[-19]),(1400,1200,[-19,-17]),(2000,None,[-70]),(1401,None,[-70]),(1000,None,[-70])]:
    base=main if off is None else main+jroundf(off*.25)
    selected=bonus_values if off is None else [min(bonus_values)]
    raw=base+sum(jroundf(v*base/100.) for v in selected)
    final=max(raw,600,base-math.floor(base/2))
    speed_examples.append({'main_ms':main,'off_ms':off,'weapon_rate_bonuses':bonus_values,
                           'base_ms':base,'selected_weapon_bonuses':selected,'raw_ms':raw,'final_ms':final})

resources=[]
def xml(path):
    raw=path.read_bytes(); root=ET.fromstring(raw)
    resources.append({'path':str(path),'sha256':hashlib.sha256(raw).hexdigest(),'records':len(root)})
    return root
data=ROOT/'gameserver/data/static_data'
server_items={x.attrib['id']:x for x in xml(data/'items/item_templates.xml')}
server_skills={x.attrib['skill_id']:x for x in xml(data/'skills/skill_templates.xml')}
decoded=CASE/'exports/decoded'
client_items={x.findtext('id'):{a.tag:a.text or '' for a in x} for x in xml(decoded/'data/items/items/client_items.xml')}
client_skills={x.findtext('id'):{a.tag:a.text or '' for a in x} for x in xml(decoded/'data/skills/skills/client_skills.xml')}
godstones=[]
for ident,item in server_items.items():
    node=item.find('godstone')
    if node is None: continue
    c=client_items.get(ident,{})
    p=int(node.get('probability','0')); left=int(node.get('probabilityleft','0'))
    sid=node.get('skillid');sk=server_skills.get(sid)
    godstones.append({'id':ident,'server':dict(node.attrib),'server_probabilityleft_default':left,
                     'client':{k:v for k,v in c.items() if k.startswith('proc_enchant') or k in ['name','id']},
                     'server_skill_name':sk.get('name') if sk is not None else None,
                     'probability_equal':c.get('proc_enchant_effect_occur_prob')==str(p),
                     'probabilityleft_equal':c.get('proc_enchant_effect_occur_left_prob','0')==str(left),
                     'mainhand_random_branch':godstone(p,left,False),
                     'offhand_random_branch':godstone(p,left,True)})
weapon_comparisons=[]
for ident,item in server_items.items():
    speed=item.find("modifiers/set[@name='ATTACK_SPEED']")
    c=client_items.get(ident,{})
    if speed is not None and 'attack_delay' in c:
        weapon_comparisons.append({'id':ident,'server_ms':speed.get('value'),
                                   'client_raw':c['attack_delay'],'equal_as_number':float(speed.get('value'))==float(c['attack_delay'])})
pvp=[]
for ident,sk in server_skills.items():
    if 'pvp_damage' not in sk.attrib: continue
    c=client_skills.get(ident,{})
    pvp.append({'id':ident,'server_name':sk.get('name'),'server_pvp_damage':sk.get('pvp_damage'),
                'client_name':c.get('name'),'client_pvp_damage_ratio':c.get('pvp_damage_ratio'),
                'same_numeric_ratio':c.get('pvp_damage_ratio')==sk.get('pvp_damage')})
movement=[]
for ident in ['1424','1463','1544','1545','2278']:
    sk=server_skills[ident];c=client_skills[ident]
    movement.append({'id':ident,'server_name':sk.get('name'),
                     'server_effects':[dict(x.attrib) for x in sk.findall('.//randommoveloc')],
                     'client':{k:v for k,v in c.items() if k in ['id','name'] or k.startswith('effect') and ('RandomMoveLoc' in v or '_reserved' in k)}})
counts={'source_files':len(files),'source_expression_checks':len(checks),'discrete_checks':len(discrete_checks),
 'server_godstones':len(godstones),'godstones_with_client_probability':sum('proc_enchant_effect_occur_prob' in r['client'] for r in godstones),
 'godstone_same_raw_probability':sum(r['probability_equal'] for r in godstones),
 'godstone_same_raw_left_or_default':sum(r['probabilityleft_equal'] for r in godstones),
 'weapons_compared':len(weapon_comparisons),'weapon_same_numeric_interval':sum(r['equal_as_number'] for r in weapon_comparisons),
 'server_skills_explicit_pvp_damage':len(pvp),'same_id_pvp_ratio':sum(r['same_numeric_ratio'] for r in pvp)}
manifest=json.loads((LOCAL/'aion19-source-manifest.json').read_text(encoding='utf-8-sig'))
assert manifest['commit']==COMMIT
blobs={r['path']:r['git_blob_sha1'] for r in manifest['files']}
blob_checks=[]
for record in files+resources[:2]:
    path=Path(record['path']);rel=path.relative_to(ROOT).as_posix();raw=path.read_bytes()
    actual=hashlib.sha1(b'blob '+str(len(raw)).encode('ascii')+b'\0'+raw).hexdigest()
    assert actual==blobs[rel],rel
    blob_checks.append({'relative_path':rel,'git_blob_sha1':actual,'passed':True})
counts['pinned_git_blob_checks']=len(blob_checks)
result={'emulator_commit':COMMIT,'scope':'offline source audit, current client resource comparison and previously verified native windows; no build or live server verification',
 'counts':counts,'source_files':files,'source_checks':checks,'discrete_checks':discrete_checks,
 'pinned_git_blob_checks':blob_checks,
 'resources':resources,'critical_probability_table':critical,'enchant_probability_table':enchant,
 'conditional_defense_example':defensive,'speed_examples':speed_examples,
 'godstones':godstones,'weapon_comparisons':weapon_comparisons,'pvp_skill_comparisons':pvp,'movement':movement,
 'coverage_limits':['Integer outcome probabilities assume uniform draws; Java PRNG implementation not statistically audited',
 'Arithmetic examples restricted to ordinary finite values and do not model Java integer overflow',
 'Skills sharing an ID across versions can differ; ratio equality is numeric comparison only',
 'Source formulas describe this emulator commit; current-client native addresses remain RVAs',
 'Not all effect families audited: shields, reflect, absorption, healing, summon scaling and abnormal resistance remain separate branches']}
encoded=(json.dumps(result,ensure_ascii=False,indent=2)+'\n').encode('utf-8')
destinations=[CASE/'reports/binary/aion19-server-model.json',BACK/'binary/aion19-server-model.json']
for target in destinations:
    target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(encoded)
    assert target.read_bytes()==encoded
for folder in [CASE/'reports/scripts',BACK/'scripts']:
    folder.mkdir(parents=True,exist_ok=True);shutil.copy2(Path(__file__),folder/Path(__file__).name)
print(json.dumps({'counts':counts,'speed_examples':speed_examples,'defense':defensive,
                 'godstone_examples':godstones[:2],
                 'godstone_mismatches':[r for r in godstones if not r['probability_equal']][:3],
                 'pvp_examples':pvp[:3],
                 'evidence_sha256':hashlib.sha256(encoded).hexdigest()},ensure_ascii=False,indent=2))
