"""Reconstruct the observed client UI formula; never claim server equivalence."""
from analyze_aion_native import *
b=Binary(CASE/'samples'/'Game.dll')
digest=hashlib.sha256(b.data).hexdigest()
assert digest=='834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786'
def wide(rva):
    raw=b.pe.get_data(rva,256)
    end=next(i for i in range(0,254,2) if raw[i:i+2]==b'\0\0')
    return raw[:end].decode('utf-16le')
quality=[]
for i in range(7):
    ptr,num=struct.unpack('<QI',b.pe.get_data(0x82fa40+16*i,12))
    quality.append({'name':wide(ptr-b.base),'value':num,'table_rva':hex(0x82fa40+16*i)})
descriptors=[]
for rva in [0x6ec468,0x6eca68,0x6ecfe8,0x6ed008]:
    ptr,off,width,converter=struct.unpack('<QIIQ',b.pe.get_data(rva,24))
    descriptors.append({'rva':hex(rva),'field_name':wide(ptr-b.base),'record_offset':hex(off),'width':width,'converter_rva':hex(converter-b.base) if converter else None})
bounds=[(0x316610,0x31682b),(0x3967a0,0x3967fe),(0x396d00,0x396d5b),(0x397bd0,0x397c2b),(0x392dd0,0x392e34),(0x16f200,0x16f237),(0x1719f0,0x171a49),(0x171f70,0x172138)]
functions=[{'start_rva':hex(s),'end_rva':hex(e),'instructions':b.disasm(s,e-s)} for s,e in bounds]
byrva={int(i['rva'],16):i for f in functions for i in f['instructions']}
expected={0x3967e6:'movzx eax, byte ptr [rax + 0x1e1]',0x396d46:'movzx eax, byte ptr [rax + 0x1ed]',0x397c16:'movzx eax, word ptr [rax + 0x1dc]',0x3166e5:'movzx r8d, byte ptr [rbp + 0xa9]',0x3166ed:'inc r8d',0x316722:'imul eax, edx, 0x3c',0x316739:'imul eax, edx, 0x1e',0x316750:'imul eax, edx, 0xf',0x31679f:'mov eax, 0x320',0x3167ea:'mov eax, 0x1f4',0x3167ff:'add ebx, eax',0x316801:'mov eax, 0x3e8',0x172030:'call 0x180316610'}
checks=[]
for rv,instruction in expected.items():
    assert byrva[rv]['instruction']==instruction,(hex(rv),byrva.get(rv))
    checks.append({'rva':hex(rv),'instruction':instruction,'passed':True})
tables=[list(struct.unpack('<6I',b.pe.get_data(rv,24))) for rv in [0x31682c,0x316844]]
assert tables==[[0x31671d,0x316727,0x316734,0x31673e,0x31674b,0x316755],[0x316784,0x3167a6,0x3167b3,0x3167bd,0x3167ca,0x3167d4]]
scale_ref=next(x for x in byrva[0x172050]['references'] if x['kind']=='rip_relative')
scale=struct.unpack('<f',b.pe.get_data(int(scale_ref['rva'],16),4))[0]
assert abs(scale-0.1)<1e-8
factors={1:60,2:40,3:30,4:20,5:15,6:10}
def displayed_raw(q, equipment_level, stone_level, next_stage, supplement_raw):
    if not 1<=next_stage<=20: raise ValueError('This report models observed stages 1..20 only')
    if q not in factors:return 0
    raw=(stone_level-equipment_level+10)*factors[q]
    if next_stage>10:raw=int(raw/2)
    raw=max(0,min(800 if next_stage<=10 else 500,raw))
    return max(0,min(1000,raw+supplement_raw))
examples=[]
for q,level,stone,stage,supp in [(4,50,50,1,0),(4,50,70,10,0),(4,50,80,10,0),(4,50,80,10,150),(4,50,80,11,0),(4,50,80,11,150),(4,50,100,11,150),(5,50,100,10,150)]:
    raw=displayed_raw(q,level,stone,stage,supp)
    examples.append({'quality_code':q,'equipment_level':level,'stone_level':stone,'next_stage':stage,'supplement_raw':supp,'predicted_client_raw':raw,'predicted_client_display_percent':raw/10,'status':'offline model, not a game observation'})
j=json.loads((BACK/'combat-resource-evidence.json').read_text(encoding='utf-8'))
proc_checks=[];missing=[]
for r in j['godstones']:
    d=r['raw'];text=' '.join(v['body'] for v in r['localized'].get('desc_proc',[]));ps=re.findall(r'(\d+(?:\.\d+)?)%',text)
    if not ps:missing.append(d['id']);continue
    matches=float(ps[0])*10==int(d['proc_enchant_effect_occur_prob'])
    proc_checks.append({'id':d['id'],'raw':d['proc_enchant_effect_occur_prob'],'text':text,'percent_text':ps[0],'raw_div_10_agrees':matches})
assert all(r['raw_div_10_agrees'] for r in proc_checks)
save('enchant-formula-evidence.json',{'sha256':digest,'scope':'Observed CLIENT UI calculation and resource metadata. No server RNG, online probability, availability, or exploitation claim. n is literally instance byte +0xA9 plus one; interpretation as next enchant stage is supported by enchant UI context, not live validation.','quality_mapping':quality,'descriptors':descriptors,'coefficient_by_quality':factors,'branch_target_tables':[[hex(v) for v in vs] for vs in tables],'display_scale':{'rva':scale_ref['rva'],'float32':scale},'formula_for_n_1_to_20':'raw = clamp(clamp(trunc0(k[q]*(stoneLevel-equipmentLevel+10)/(1 if n<=10 else 2)), 0, 800 if n<=10 else 500) + supplementRaw, 0, 1000); displayPercent = raw * float32(0.1)','static_instruction_checks':checks,'examples':examples,'godstone_probability_text_checks':proc_checks,'godstone_no_numeric_desc_proc':missing,'native_functions':functions})
print(json.dumps({'static_checks':len(checks),'jump_tables_verified':True,'probability_display_scale':scale,'godstone_matches':len(proc_checks),'godstone_unchecked':len(missing),'examples':examples},ensure_ascii=False,indent=2))
