"""Offline consumer and synchronization evidence; target bytes are never executed."""
from analyze_aion_native import *
import shutil
b=Binary(CASE/'samples'/'Game.dll')
digest=hashlib.sha256(b.data).hexdigest()
assert digest=='834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786'
assert hashlib.sha256((SOURCE/'Game.dll').read_bytes()).hexdigest()==digest
def u32(rv):return struct.unpack('<I',b.pe.get_data(rv,4))[0]
def qword(rv):return struct.unpack('<Q',b.pe.get_data(rv,8))[0]
def wide(rv):
    raw=b.pe.get_data(rv,256)
    return raw[:next(i for i in range(0,254,2) if raw[i:i+2]==b'\0\0')].decode('utf-16le')
effects=[{'id':i,'name':wide(qword(0x6c5880+i*8)-b.base),'pointer_slot_rva':hex(0x6c5880+i*8)} for i in range(173)]
properties=[{'id':i,'name':wide(qword(0x6e2190+i*8)-b.base),'pointer_slot_rva':hex(0x6e2190+i*8)} for i in range(88)]
assert effects[82]['name']=='RandomMoveLoc'
assert properties[33]['name']=='Distance'
assert properties[41]['name']=='FixDamage'
assert properties[54]['name']=='MaxDamage'
assert properties[56]['name']=='MinDamage'
effect_cases=[{'effect_id':i,'effect':effects[i]['name'],'map_byte_rva':hex(0x28ca20+i),'branch_index':b.pe.get_data(0x28ca20+i,1)[0],'target_rva':hex(u32(0x28c904+4*b.pe.get_data(0x28ca20+i,1)[0]))} for i in [0,2,8,9,82]]
assert effect_cases[-1]['target_rva']=='0x28c468'
spell_fix_target=u32(0x28cac0+4*b.pe.get_data(0x28cadc+41,1)[0])
assert spell_fix_target==0x28bd05

# Explicit ranges avoid treating an unwind fragment as the whole logical function.
windows=[
 ('effect_property_parser',0x28d490,0x28d6b7),
 ('tooltip_context',0x28d6c0,0x28e141),
 ('tooltip_effect_dispatch',0x28b960,0x28c904),
 ('distance_formatter',0x28a420,0x28a4c3),
 ('physical_min_formatter',0x289ec0,0x289ffd),
 ('physical_max_formatter',0x28a000,0x28a13d),
 ('spell_fixed_formatter',0x28a340,0x28a416),
 ('skill_range_parser',0x53e186,0x53e1ca),
 ('weapon_range_flag_parser',0x53e24a,0x53e285),
 ('client_range_consumer',0x19b20,0x19bfd),
 ('message_dispatch_header',0x426f70,0x4270a2),
 ('hp_message_branch',0x427e45,0x427ea3),
 ('mp_message_branch',0x427fc1,0x428052),
 ('status_message_handler',0x42dd90,0x42e13c),
 ('hp_component_update',0x488f00,0x488f85),
 ('snapshot_reader',0x368e50,0x3693c7),
 ('status_component_update',0x4fcb00,0x4fceab),
 ('teleport_branch',0x427bd2,0x427c6a),
 ('moveback_branch',0x427a09,0x427aca),
 ('moveback_consumer',0x477210,0x47764b),
 ('move_new_branch',0x428d45,0x428f00),
]
functions=[{'label':label,'start_rva':hex(s),'end_rva':hex(e),'instructions':b.disasm(s,e-s),'scope':'Explicit analysis window; may contain multiple unwind fragments or end before a branch body finishes.'} for label,s,e in windows]
rows={int(r['rva'],16):r for f in functions for r in f['instructions']}
expected={
0x28c468:'cmp r9d, 0x21',0x28bc11:'call 0x18028a420',
0x28a44c:'mov rcx, qword ptr [rax + 8]',0x28a46a:'mov rcx, qword ptr [rax]',
0x28a484:'imul eax, ebx',0x28a497:'add eax, ebp',
0x28da72:'call 0x180368e50',0x28dfbe:'mov dword ptr [rsp + 0x6c], eax',
0x28e01a:'call 0x18028b960',
0x426fc1:'movzx edx, word ptr [rdx + 0x14]',
0x427e54:'mov ebx, dword ptr [rax + 4]',0x427e57:'mov edi, dword ptr [rax]',
0x427e8b:'call 0x180488f00',0x42df15:'call 0x1804fcb00',
0x488f1b:'mov dword ptr [rcx + 0x11a4], edx',0x488f24:'mov dword ptr [rcx + 0x11a0], r8d',
0x488f30:'mov dword ptr [rcx + 0x119c], edx',0x36907c:'mov ecx, dword ptr [rsi + 0x119c]',
0x427c52:'call 0x180051c80',0x427ab2:'call 0x180477210',
0x477341:'mov dword ptr [rbx + 8], eax',0x47734f:'mov dword ptr [rbx + 0x10], eax',
0x53e1bd:'movss dword ptr [rbp + 0x714], xmm1',0x53e27a:'mov dword ptr [rbp + 0x71c], eax',
0x19b87:'movss xmm0, dword ptr [rax + 0x724]',
0x289fc9:'cvttss2si eax, xmm2',0x28a109:'cvttss2si eax, xmm2',0x28a3e8:'cvttss2si eax, xmm2',
}
checks=[]
for rv,wanted in expected.items():
    assert rows[rv]['instruction']==wanted,(hex(rv),rows.get(rv))
    checks.append({'rva':hex(rv),'instruction':wanted,'passed':True})

regs=[];registration=b.dump_function(0x316950)['instructions']
for i,r in enumerate(registration[:-1]):
    for ref in r.get('references',[]):
        if ref['kind']!='rip_relative':continue
        raw=b.pe.get_data(int(ref['rva'],16),120).split(b'\0')[0]
        if not re.fullmatch(rb'S_[A-Z0-9_]+',raw):continue
        m=re.fullmatch(r'mov dword ptr \[(?:rsp|rbp) \+ 0x[0-9a-f]+\], (0x[0-9a-f]+|\d+)',registration[i+1]['instruction'])
        if not m:continue
        ix=int(m[1],0)
        regs.append({'name':raw.decode(),'id':ix,'registration_instructions':registration[i:i+4],'switch_slot_rva':hex(0x42bbb4+4*ix),'case_rva':hex(u32(0x42bbb4+4*ix)) if ix<=0x12d else None})
byname={r['name']:r for r in regs}
for name,ix,target in [('S_STATUS',1,0x427e0f),('S_HIT_POINT',3,0x427e45),('S_MANA_POINT',4,0x427fc1),('S_REQUEST_TELEPORT',20,0x427bd2),('S_MOVEBACK',195,0x427a09)]:
    assert byname[name]['id']==ix and byname[name]['case_rva']==hex(target)
types=json.loads((BACK/'Game.dll.rtti.json').read_text(encoding='utf-8'))
router=next(t for t in types if t['name']=='.?AVServerToClientRouter@@')
assert qword(0x8381e0)==b.base+0x426f70
assert any(v['entries'][5]['target_rva']=='0x426f70' for c in router['locators'] for v in c['vtables'] if len(v['entries'])>5)
constants=[]
for rv,expected_value in [(0x8753c0,100.0),(0x875418,200.0),(0x874d94,1.0),(0x875580,-1.0)]:
    observed=struct.unpack('<f',b.pe.get_data(rv,4))[0];assert observed==expected_value
    constants.append({'rva':hex(rv),'value_float32':observed,'bytes':b.pe.get_data(rv,4).hex()})
resource=json.loads((BACK/'combat-resource-evidence.json').read_text(encoding='utf-8'))
movement=[r for r in resource['movement_skills'] if r['raw']['id'] in ['1424','1463','1544','1545','2278']]
payload={'sha256':digest,'scope':'Static offline analysis. Dispatcher is identified as ServerToClientRouter by RTTI and vtable slot, not by the S_ prefix alone. Message-object offsets are internal decoded-buffer offsets, not claimed encrypted wire offsets. Formulas below are client tooltip/range code, not server hit or damage rules.',
 'effect_names':effects,'property_names':properties,'effect_dispatch':effect_cases,'spell_fixed_property_target':hex(spell_fix_target),
 'router_rtti':router,'named_message_registrations':regs,'constants':constants,'checks':checks,
 'numeric_conversion':{'slot_rva':'0x6bc170','file_qword':hex(qword(0x6bc170)),'meaning':'Indirect text-to-integer candidate, exact runtime target not resolved. Symbol C(s) below denotes its returned integer; null input is explicitly treated as zero. Not falsely named _wtoi.'},
 'tooltip_formulas':{
  'RandomMoveLoc.Distance':'C(reserved1)*L + C(reserved2); L is context+0x1C, effect parameters=context+0x30. No direction parameter read by this formatter.',
  'SkillATK_Instant.MinDamage':'trunc0_f32( ((C(r1)*L+C(r2))/100 + ((X0-100)/200 + 1)) * Wmin + (C(r3)*L+C(r4)) ); X0=u16(snapshot+0), Wmin=context+0x14. Each SSE arithmetic step rounds to float32; parentheses preserve add order.',
  'SkillATK_Instant.MaxDamage':'Same instruction order, Wmax=context+0x18.',
  'SpellATK_Instant.FixDamage':'trunc0_f32( (C(r1)*L+C(r2)) * ((X8-100)/100 + 1) ); X8=u16(snapshot+8).',
  'client_range':'r=skill_record.float_724 + (skill_record.int_72c != 0 ? cache_D71BDC : 0); output2=max(r-(object.int_AEC!=0 ? 1 : 0),1); missing record uses r=5. Names of object mode flag remain unknown.'},
 'state_flow':{'cache_rva':'0xD71B78','block_bytes':200,'source':'S_STATUS decoded buffer +8, copied through stack; time-like fields +0x50/+0x54 scaled by1000 before copy, other extension separately updated','snapshot_reader':'0x368E50 copies the cache, then overrides output+0x40 with max(component+0x119C,0)','hp_update':'S_HIT_POINT gives current/max; component+0x11A4 current and +0x11A0 max are updated, +0x119C current updates only when component+0x1190 equals zero. Flag semantics unknown.'},
 'movement_resources':movement,'native_windows':functions,
 'remaining_unknowns':['RandomMoveLoc execution direction mapping and runtime distance; formatter alone does not implement movement','Final player attack interval and movement speed consumers','Meaning of every snapshot field and input L for all placeholder syntaxes','Numeric conversion slot target','PVP damage ratio consumption, authoritative server formula, caps and roll order','Actual server acceptance of client position changes']}
save('deep-combat-consumers.json',payload)
print(json.dumps({'instruction_checks':len(checks),'effect_names':len(effects),'property_names':len(properties),'message_registrations':len(regs),'router_class':router['name'],'random_move_branch':effect_cases[-1],'spell_fixed_target':hex(spell_fix_target),'resource_examples':len(movement)},ensure_ascii=False,indent=2))
for destination in [CASE/'reports'/'scripts',BACK.parent/'scripts']:
    destination.mkdir(exist_ok=True)
    shutil.copy2(Path(__file__),destination/Path(__file__).name)
