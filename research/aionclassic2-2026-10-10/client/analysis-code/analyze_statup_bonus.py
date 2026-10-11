"""Offline evidence for skill resource layout and item-bonus bit packing.

Does not load DLLs, attach to processes, emulate the game, or modify samples.
The arithmetic check models only the observed integer instruction sequence.
"""
from analyze_aion_native import *
import xml.etree.ElementTree as ET

b = Binary(CASE/'samples'/'Game.dll')
expected = '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786'
assert hashlib.sha256(b.data).hexdigest() == expected, 'Wrong sample'

def wide(rv):
    raw = b.pe.get_data(rv, 512)
    stop = next((i for i in range(0, len(raw)-1, 2) if raw[i:i+2] == b'\0\0'), None)
    if stop is None:
        raise ValueError('Unterminated string at '+hex(rv))
    return raw[:stop].decode('utf-16le')

def ins(rv):
    return b.disasm(rv, 16)[0]['instruction']

def sext(value, bits):
    value &= (1 << bits)-1
    return value-(1 << bits) if value & (1 << (bits-1)) else value

def observed_unpack(raw):
    ecx = sext(raw,16) & 0xffffffff
    edx = ((raw * 2) & 0xffff) ^ ecx
    eax = sext((ecx * 2) & 0xffff,16) & 0xffffffff
    return sext((edx & 0x7fff) ^ eax,32)

arithmetic_mismatches = [v for v in range(65536) if observed_unpack(v) != sext(v & 0x7fff,15)]
effect_names = [wide(struct.unpack('<Q',b.pe.get_data(0x6c5880+i*8,8))[0]-b.base) for i in range(173)]
rtti = json.loads((BACK/'Game.dll.rtti.json').read_text(encoding='utf8'))
inventory_types = [t for t in rtti if any(v['address']['rva']=='0x82fc38' for c in t['locators'] for v in c['vtables'])]

resource_root = CASE/'exports'/'decoded'/'data'
resource_paths = [resource_root/'skills'/'skills'/'client_skills.xml',resource_root/'items'/'items'/'client_items.xml',resource_root/'items'/'items'/'client_setitem.xml']
resource_evidence = []
for path in resource_paths:
    root = ET.parse(path).getroot()
    matches = []
    for record in root:
        for child in record:
            if child.text and re.search(r'attackdelay\s+[-+]?\d+%',child.text,re.I):
                matches.append({'id':record.findtext('id'),'name':record.findtext('name'),'field':child.tag,'text':child.text})
    evidence = {'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'record_count':len(root),'explicit_percent_matches':matches}
    if 'skills' in str(path):
        evidence['example_skill'] = {c.tag:c.text for e in root if e.findtext('id')=='335' for c in e}
    resource_evidence.append(evidence)

expected_unpack = {
    0x3a0c29:'shr ax, 0xf',0x3a0c2d:'mov byte ptr [rbx + rcx*8 + 0xe4], al',
    0x3a0c34:'movsx ecx, word ptr [r9 + 0xe4]',0x3a0c3c:'movzx edx, cx',
    0x3a0c3f:'add dx, dx',0x3a0c42:'xor edx, ecx',0x3a0c44:'lea eax, [rcx + rcx]',
    0x3a0c47:'and edx, 0x7fff',0x3a0c4d:'cwde ',0x3a0c4e:'xor edx, eax',
    0x3a0c50:'mov dword ptr [rbx + r8*8 + 0xe0], edx',
}
checks = {
    'sample_sha256':hashlib.sha256(b.data).hexdigest()==expected,
    'effect_name_8_statup':effect_names[8]=='StatUp',
    'effect_name_9_statdown':effect_names[9]=='StatDown',
    'effect_enum_loop_bound':ins(0x53c09b)=='cmp ebx, 0xad',
    'skill_record_stack_base':ins(0x53c737)=='lea rcx, [rbp - 0x10]' and ins(0x53c73f)=='call 0x1801200c0',
    'delay_type_store':ins(0x53d7c3)=='mov dword ptr [rbp + 0xc0], eax',
    'delay_time_store':ins(0x53d857)=='mov dword ptr [rbp + 0xc4], eax',
    'delay_id_store':ins(0x53d80d)=='mov dword ptr [rbp + 0xd0], eax',
    'effect2_type_store':ins(0x53e107)=='mov dword ptr [rbp + 0x108], eax',
    'reserved_pointer_store':ins(0x5405ac)=='mov qword ptr [rbp + rcx*8 + 0x118], rax',
    'effect_stride':ins(0x54072a)=='add rax, 0x17',
    'accessor_type_layout':ins(0x541a5a)=='mov eax, dword ptr [rcx + rax*4 + 0x114]',
    'accessor_reserved_layout':ins(0x541af7)=='mov rax, qword ptr [r8 + rax*8 + 0x128]',
    'percent_marker_branch':ins(0x394ddc)=='cmp word ptr [rax + rcx*2 - 2], 0x25',
    'percent_mask':ins(0x394df3)=='mov ecx, 0x8000' and ins(0x394df8)=='or ax, cx',
    'compact_type_store':ins(0x394db2)=='mov byte ptr [rbx + r13 + 0xd8], al',
    'compact_value_store':ins(0x394dfb)=='mov word ptr [r13 + rbx*2 + 0xe4], ax',
    'unpack_instruction_sequence':all(ins(rv)==text for rv,text in expected_unpack.items()),
    'exhaustive_signed15_equivalence':not arithmetic_mismatches,
    'inventoryitem_rtti':any(t['name']=='.?AVInventoryItem@@' for t in inventory_types),
    'inventoryitem_constructor':b.disasm(0x3a0098,7)[0]['references'][0]['rva']=='0x82fc38',
    'inventoryitem_normalizer_tailcall':ins(0x3a06e5)=='jmp 0x1803a0be0',
    'item_percent_resource_exists':any(e['explicit_percent_matches'] for e in resource_evidence),
    'display_percent_format':wide(0x7d2110)=='%s%d%%' and b.disasm(0x1d9441,7)[0]['references'][0]['rva']=='0x7d2110',
    'display_absolute_attackdelay_selector':ins(0x1d945e)=='cmp ebx, 0x1d' and ins(0x1d9461)=='je 0x1801d94ad',
    'display_absolute_attackdelay_scale':b.disasm(0x1d94b5,8)[0]['references'][0]['rva']=='0x874b24' and b.pe.get_data(0x874b24,4).hex()=='6f12833a',
}
if not all(checks.values()):
    raise RuntimeError('Evidence checks failed: '+str({k:v for k,v in checks.items() if not v}))

windows = [
    (0x53c060,0x53c0ca),(0x53c732,0x53c7d7),(0x53d793,0x53d862),
    (0x53e028,0x53e186),(0x540523,0x5405b4),(0x540709,0x540741),
    (0x541a00,0x541bad),(0x7d810,0x7da54),(0x3930c0,0x39329c),
    (0x394ccd,0x394e1e),(0x398b0d,0x398bdf),(0x3a0be0,0x3a0f8f),
    (0x3a0250,0x3a06ea),(0x3a0030,0x3a00a2),(0x395d20,0x395df4),
    (0x1d9370,0x1d94ff),
]
save('statup-bonus-evidence.json',{
    'sample_sha256':expected,'mode':'offline static analysis; no target execution',
    'checks':checks,'effect_names':[{'id':i,'name':name} for i,name in enumerate(effect_names)],
    'inventory_rtti':inventory_types,
    'skill_record_layout':{'size':'0x7d8','delay_type':'0xd0','delay_time':'0xd4','delay_id':'0xe0','effect_type':'0x114 + 4*i','reserved_pointer':'0x128 + 0xb8*i + 8*j','indices':'i = effect number - 1; j = reserved number - 1; effect count 4, reserved text loop count 18'},
    'compact_item_layout':{'attribute_ids':'uint8 record[0xd8 + slot]','encoded_values':'uint16 record[0xe4 + 2*slot]','slot_count':12},
    'expanded_item_layout':{'value':'int32 item[0xe0 + 8*attribute_id]','percent_flag':'uint8 item[0xe4 + 8*attribute_id]','attackdelay_derived_offsets':{'value':'0x1c8','percent_flag':'0x1cc'},'scope':'InventoryItem-associated attribute cache, not player object or final attack speed'},
    'display_consumer':{'rva':'0x1d9370','percent':'For attribute 29 and nonzero flag, formats integer value with %s%d%%.','absolute':'For attribute 29 and zero flag, multiplies float32(value) by float32 0.001 then formats with %s%.1f.','scale_rva':'0x874b24','scale_float32':struct.unpack('<f',b.pe.get_data(0x874b24,4))[0]},
    'integer_equivalence':{'tested_inputs':65536,'mismatches':arithmetic_mismatches,'meaning':'bit 15 = percent flag; low 15 bits interpreted as signed two\u2019s complement','examples':[{'raw':hex(v),'percent_flag':v>>15,'signed_value':observed_unpack(v)} for v in (0x8003,0x8008,0x8012,0x01f4,0x7ff6,0xfff6)]},
    'windows':[{'start_rva':hex(a),'end_rva':hex(z),'instructions':b.disasm(a,z-a)} for a,z in windows],
    'unknowns':['Final character speed and attack scheduling are not identified.','StatUp reserved-field numeric meanings and stacking are not established.','Protected IAT slot contents do not identify the comparison/numeric conversion functions in the on-disk image.','Direct and virtual paths establish static class association, not live object identity.'],
})
save('statup-bonus-resources.json',resource_evidence)
print(json.dumps({'checks_passed':sum(checks.values()),'checks_total':len(checks),'arithmetic_inputs':65536,'mismatch_count':len(arithmetic_mismatches),'resource_matches':[{ 'name':Path(e['path']).name,'count':len(e['explicit_percent_matches'])} for e in resource_evidence]},indent=2))
