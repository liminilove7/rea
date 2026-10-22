"""Inspect original-file pointer records. Candidates require code corroboration."""
import hashlib,json,struct,sys
from pathlib import Path
source=Path(sys.argv[1]); seeds=Path(sys.argv[2]); output=Path(sys.argv[3])
raw=source.read_bytes(); seed=json.loads(seeds.read_text(encoding='utf8'))
assert hashlib.sha256(raw).hexdigest()==seed['sha256']
pe=struct.unpack_from('<I',raw,60)[0];opt=pe+24;base=struct.unpack_from('<Q',raw,opt+24)[0]
at=opt+struct.unpack_from('<H',raw,pe+20)[0];sections=[]
for n in range(struct.unpack_from('<H',raw,pe+6)[0]):
    vs,rva,size,pos=struct.unpack_from('<IIII',raw,at+40*n+8);sections.append((rva,size,pos))
def va(pos):
    for r,size,p in sections:
        if p<=pos<p+size:return hex(base+r+pos-p)
    return None
terms={'proc_enchant_effect_occur_prob','proc_enchant_effect_occur_left_prob','proc_enchant_skill','proc_enchant_skill_level','enchant_option_level_prob','enchant_cut_prob_count_10','enchant_cut_prob_count_0','enchant_cut_prob_count_15','enchant_cut_prob_count_20','PvPAttackRatio','PvPAttackRatio_Physical','PvPAttackRatio_Magical','PvPDefendRatio','PvPDefendRatio_Physical','PvPDefendRatio_Magical','sub_enchant_material_effect','pvp_damage_ratio','pvpdefendratio_light','pvpdefendratio_dark'}
records=[]
for s in seed['literals']:
    if s['text'] not in terms or s['va'] is None:continue
    needle=struct.pack('<Q',int(s['va'],16));start=0;refs=[]
    while (p:=raw.find(needle,start))>=0:
        start=p+1
        if p+24>len(raw):continue
        _,off,width,converter=struct.unpack_from('<QIIQ',raw,p)
        refs.append({'location_va':va(p),'file_offset':p,'following_u32_1':off,'following_u32_2':width,'following_qword':hex(converter),'bytes_32':raw[p:p+32].hex(),'candidate_layout':'pointer,u32 offset,u32 width,pointer converter; unconfirmed unless corroborated'})
    records.append({'literal':s,'pointer_occurrences':refs})
output.write_text(json.dumps({'method':'auxiliary original PE byte/table inspection, no execution; candidate layout is not a conclusion','sha256':seed['sha256'],'records':records},ensure_ascii=False,indent=2),encoding='utf8')
for r in records:
    print(r['literal']['text'],[(x['location_va'],hex(x['following_u32_1']),x['following_u32_2'],x['following_qword']) for x in r['pointer_occurrences']])
