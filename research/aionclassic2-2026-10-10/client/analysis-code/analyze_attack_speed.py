"""Offline first attack-speed lesson; exact sample, no game execution or patching."""
from analyze_aion_native import *

b=Binary(CASE/'samples'/'Game.dll')
expected='834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786'
if hashlib.sha256(b.data).hexdigest()!=expected:
    raise RuntimeError('This lesson is specific to the recorded Game.dll SHA-256')
targets={}
pattern=re.compile(r'attack.?speed|attack.?delay|attack.?interval',re.I)
for enc,expr in (('ascii',rb'[ -~]{5,}'),('utf-16le',rb'(?:[ -~]\x00){5,}')):
    for m in re.finditer(expr,b.data):
        s=m.group().decode(enc)
        if pattern.search(s):
            rv=b.pe.get_rva_from_offset(m.start())
            targets[rv]={'text':s,'encoding':enc,**b.loc(rv),'code_xrefs':[],'pointer_xrefs':[]}
for rv,t in targets.items():
    for m in re.finditer(re.escape(struct.pack('<Q',b.base+rv)),b.data):
        t['pointer_xrefs'].append(b.loc(b.pe.get_rva_from_offset(m.start())))
rip=re.compile(r'\[rip(?: ([+-]) (0x[0-9a-f]+|[0-9]+))?\]')
callers=[]
for start,end in b.ranges:
    for va,size,mn,op in b.md.disasm_lite(b.pe.get_data(start,end-start),b.base+start):
        if mn in ('call','jmp') and op=='0x180396e80':
            callers.append({'rva':hex(va-b.base),'range_start':hex(start),'kind':mn})
        for m in rip.finditer(op):
            disp=int(m[2],0) if m[2] else 0
            if m[1]=='-':disp=-disp
            target=va+size+disp-b.base
            if target in targets:
                targets[target]['code_xrefs'].append({'instruction_rva':hex(va-b.base),'range_start':hex(start),'instruction':mn+' '+op})
checks={
    'attribute_name_pointer':struct.unpack('<Q',b.pe.get_data(0x94e2f0,8))[0]==b.base+0x774918,
    'attribute_id':struct.unpack('<I',b.pe.get_data(0x94e2f8,4))[0]==0x1d,
    'record_descriptor_offset':struct.unpack('<I',b.pe.get_data(0x6ecaf0,4))[0]==0x1be,
    'record_descriptor_width':struct.unpack('<I',b.pe.get_data(0x6ecaf4,4))[0]==2,
    'getter_read':b.disasm(0x396ec6,7)[0]['instruction']=='movzx eax, word ptr [rax + 0x1be]',
    'display_divisor':struct.unpack('<f',b.pe.get_data(0x8754a0,4))[0]==1000.0,
}
if not all(checks.values()):raise RuntimeError('Evidence check failed: '+str(checks))
save('attack-speed-lesson.json',{
    'sample_sha256':expected,'strings':list(targets.values()),'getter_callers':callers,
    'name_to_id_window':b.disasm(0x868bd,0x2c),
    'record_getter':b.dump_function(0x396e80),
    'display_conversion':b.dump_function(0x1d90c0),
    'secondary_consumer_window':b.disasm(0x3b2551,0x27d),
    'checks':checks,
    'observed':'attackDelay maps to ID 0x1d; record getter reads uint16 at record+0x1be; a display caller divides by 1000.0',
    'unknown':'Final character attack-speed calculation, protected storage representation, update timing, and live value are not established. The secondary consumer may serve another timing subsystem.',
    'user_prior_observation':'User reports a hidden calculation instead of a direct fixed-offset read; retained as an unverified hypothesis for this exact build.',
})
print(json.dumps({'checks':checks,'getter_callers':callers},indent=2))
