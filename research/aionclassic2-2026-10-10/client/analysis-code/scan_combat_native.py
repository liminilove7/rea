"""Offline native candidate collection; candidates are not gameplay conclusions."""
from analyze_aion_native import *
b=Binary(CASE/'samples'/'Game.dll')
expected='834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786'
assert hashlib.sha256(b.data).hexdigest()==expected
names=set('enchant_prob successenchant proc_enchant_effect_occur_prob proc_enchant_effect_occur_left_prob proc_enchant_skill sub_enchant_material_effect sub_enchant_material_effect_type attack_range target_range add_wpn_range pvp_damage_ratio pvp_remain_time_ratio S_REQUEST_TELEPORT C_ACCEPT_TELEPORT S_ENCHANT_ITEM C_ENCHANT_ITEM speed_limit max_speed speed flySpeed attackDelay'.split())
targets={}
for enc,expr in [('ascii',rb'[ -~]{4,}'),('utf-16le',rb'(?:[ -~]\x00){4,}')]:
    for m in re.finditer(expr,b.data):
        s=m.group().decode(enc)
        if s in names or re.fullmatch('[SC]_.*(?:ENCHANT|PROC|SPEED|MOVE|DAMAGE|ATTACK).*',s):
            rv=b.pe.get_rva_from_offset(m.start());targets[rv]={'text':s,'encoding':enc,'rva':hex(rv),'code_xrefs':[],'pointer_xrefs':[]}
for rv,t in targets.items():
    for m in re.finditer(re.escape(struct.pack('<Q',b.base+rv)),b.data):
        r=b.pe.get_rva_from_offset(m.start())
        t['pointer_xrefs'].append({'rva':hex(r),'following_bytes':b.pe.get_data(r+8,24).hex()})
rip=re.compile(r'\[rip(?: ([+-]) (0x[0-9a-f]+|[0-9]+))?\]')
field_reads=[]
for start,end in b.ranges:
    for va,size,mn,op in b.md.disasm_lite(b.pe.get_data(start,end-start),b.base+start):
        for m in rip.finditer(op):
            d=int(m[2],0) if m[2] else 0
            rv=va+size+(-d if m[1]=='-' else d)-b.base
            if rv in targets:targets[rv]['code_xrefs'].append({'rva':hex(va-b.base),'range_start':hex(start),'instruction':mn+' '+op})
        if mn=='movzx' and re.search(r'word ptr \[rax \+ 0x(?:1bc|1d6)\]',op):
            field_reads.append({'rva':hex(va-b.base),'range_start':hex(start),'instruction':mn+' '+op})
save('combat-native-candidates.json',{'sha256':expected,'scope':'RIP-relative references within exception ranges plus exact static pointer matches. Missing leaf/indirect/protected references are not excluded.','strings':list(targets.values()),'record_field_reads':field_reads})
print(json.dumps({'strings':[{'text':t['text'],'rva':t['rva'],'code_xrefs':t['code_xrefs']} for t in targets.values() if t['code_xrefs']],'record_field_reads':field_reads},indent=2))
