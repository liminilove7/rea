"""Read-only continuation: classify attack-delay consumers in the pinned sample."""
from analyze_aion_native import *
import xml.etree.ElementTree as ET
from collections import Counter

b = Binary(CASE / 'samples' / 'Game.dll')
expected = '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786'
assert hashlib.sha256(b.data).hexdigest() == expected, 'Sample identity changed'

def wide(rv):
    raw = b.pe.get_data(rv, 512)
    for i in range(0, len(raw)-1, 2):
        if raw[i:i+2] == b'\0\0':
            return raw[:i].decode('utf-16le', errors='replace')
    return None

targets = {x: [] for x in (0x3b2500, 0x3b2370, 0x3a1940, 0x1da810, 0x1dc1a0, 0x3b2100)}
for start, end in b.ranges:
    for va, size, mn, op in b.md.disasm_lite(b.pe.get_data(start, end-start), b.base+start):
        if mn in ('call', 'jmp') and op.startswith('0x'):
            dest = int(op, 16)-b.base
            if dest in targets:
                targets[dest].append({'rva': hex(va-b.base), 'range_start': hex(start), 'kind': mn})

descriptors = []
for section in b.pe.sections:
    raw = section.get_data()
    for off in range(0, len(raw)-24, 8):
        ptr, displacement, width, reserved = struct.unpack_from('<QIIQ', raw, off)
        if displacement not in (0xd0, 0xd4, 0xd8, 0xdc, 0xe0) or width not in (1, 2, 4, 8) or reserved:
            continue
        rv = ptr-b.base
        if 0x760000 <= rv < 0x810000:
            name = wide(rv)
            if name and re.fullmatch('[A-Za-z_][A-Za-z_0-9]*', name):
                descriptors.append({'rva': hex(section.VirtualAddress+off), 'name': name, 'field_offset': hex(displacement), 'width': width})

rtti = json.loads((BACK / 'Game.dll.rtti.json').read_text(encoding='utf8'))
types = [t for t in rtti if any(v['address']['rva'] in ('0x82fc08', '0x82fc78') for c in t['locators'] for v in c['vtables'])]
windows = [(0x3b2500,0x3b27ce),(0x3b2370,0x3b24fc),(0x3a1940,0x3a19b7),(0x3a19c0,0x3a19e2), (0x39fff0,0x3a0024),(0x1da810,0x1daa10),(0x1dc1a0,0x1dc1e5),(0x3b2100,0x3b21c4), (0x521dd0,0x521ea5),(0x521eb0,0x521f85),(0x3b27d0,0x3b2838),(0x3a190,0x3a3a1)]
skill_path = CASE/'exports'/'decoded'/'data'/'skills'/'skills'/'client_skills.xml'
root = ET.parse(skill_path).getroot()
effects = []
for el in root:
    for child in el:
        if child.text and child.text.lower() in ('attackdelay', 'attackspeed'):
            prefix = child.tag.split('_')[0] + '_'
            effects.append({'id':el.findtext('id'),'name':el.findtext('name'), 'matched_field':child.tag, 'matched_value':child.text, 'effect_fields':{c.tag:c.text for c in el if c.tag.startswith(prefix)}})
ui_path = CASE/'exports'/'decoded'/'L10N'/'CHS'/'Data'/'Data'/'Strings'/'client_strings_ui.xml'
labels = [{c.tag:c.text for c in e} for e in ET.parse(ui_path).getroot() if e.findtext('id') in ('900480','900481','900482','900483')]

def instruction(rv):
    return b.disasm(rv,16)[0]['instruction']

checks = {
    'sample_identity': hashlib.sha256(b.data).hexdigest() == expected,
    'skillitem_constructor_vtable': b.disasm(0x3a198e,7)[0]['references'][0]['rva'] == '0x82fc78',
    'skillitem_rtti': any(t['name'] == '.?AVSkillItem@@' for t in types),
    'allocation_0x88': instruction(0x3b23f7) == 'mov ecx, 0x88',
    'create_calls_constructor': instruction(0x3b241c) == 'call 0x1803a1940',
    'duration_store': instruction(0x3b2567) == 'mov dword ptr [rax + 0x50], ebx',
    'end_store': instruction(0x3b257f) == 'mov dword ptr [r14 + 0x54], eax',
    'scaled_source_flag': instruction(0x3b26f1) == 'cmp byte ptr [rsp + 0xf0], 0',
    'scaled_source_value': instruction(0x3b2712) == 'mov eax, dword ptr [rsp + 0xf4]',
    'scaling_divisor': b.disasm(0x3b266d,8)[0]['references'][0]['rva'] == '0x8754a0' and struct.unpack('<f',b.pe.get_data(0x8754a0,4))[0] == 1000.0,
    'scale_then_truncate': [instruction(x) for x in (0x3b271e,0x3b2722,0x3b2726)] == ['divss xmm1, xmm6','mulss xmm1, xmm0','cvttss2si edi, xmm1'],
    'comparison_subtracts_intervals': instruction(0x1dc1ce) == 'sub ebx, ecx',
    'tooltip_labels_exist': {e['name'] for e in labels} == {'STR_TOOLTIP_ATKDELAY_FAST','STR_TOOLTIP_ATKDELAY_NORMAL','STR_TOOLTIP_ATKDELAY_SLOW','STR_TOOLTIP_ATKDELAY_VERYSLOW'},
    'attackdelay_effect_resource_exists': any(e['id']=='335' and e['matched_field']=='effect2_reserved13' for e in effects),
}
if not all(checks.values()):
    raise RuntimeError('Evidence mismatch: '+str(checks))
save('attack-timing-resources.json', {
    'sources':[{'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in (skill_path,ui_path)],
    'skill_count':len(root), 'delay_type_counts':dict(Counter(e.findtext('delay_type','<absent>') for e in root)),
    'tooltip_labels':labels, 'attribute_effect_count':len(effects), 'attribute_effects':effects,
    'special_action_records':[{c.tag:c.text for c in e} for e in root if e.findtext('id') in ('50042','50043')],
    'unknowns':['Resource field numbers are not proven to map to the +0xd0/+0xd4/+0xe0 native record members.', 'StatUp reserved field units, sign, stacking, caps and native consumers remain unverified.', 'Mixed-case resource spellings do not by themselves establish case-insensitive name conversion.'],
})
save('attack-timing-followup.json', {
    'sample_sha256': expected,
    'scope': 'Offline bytes only. Direct branch scan within PE exception ranges; missing leaf functions, indirect calls and protected code are not covered.',
    'direct_xrefs': {hex(k):v for k,v in targets.items()},
    'descriptor_candidates': descriptors,
    'constructor_vtable_types': types,
    'checks': checks,
    'interpretation': 'SkillItem-associated timing path; +0x50 resembles duration and +0x54 resembles end time. Protected return value is used additively but its clock source/units are not proven. Not established as final normal-attack speed.',
    'windows': [{'start_rva':hex(a),'end_rva':hex(z),'instructions':b.disasm(a,z-a)} for a,z in windows],
})
print(json.dumps({'checks':checks,'direct_xref_counts':{hex(k):len(v) for k,v in targets.items()},'descriptor_candidates':descriptors,'constructor_vtable_types':[t['name'] for t in types],'skill_count':len(root),'attribute_effect_count':len(effects)},ensure_ascii=False,indent=2))
