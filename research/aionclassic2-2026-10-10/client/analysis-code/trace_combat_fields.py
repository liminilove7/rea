"""Collect offline native cross-references; do not execute a target."""
from analyze_aion_native import *
b=Binary(CASE/'samples'/'Game.dll')
assert hashlib.sha256(b.data).hexdigest()=='834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786'
hits=[]
for start,end in b.ranges:
    for va,size,mn,op in b.md.disasm_lite(b.pe.get_data(start,end-start),b.base+start):
        if (mn=='call' and op=='0x180396e20') or (0x16e000<=start<=0x175000 and ' + 0x540]' in op):
            hits.append({'rva':hex(va-b.base),'range_start':hex(start),'instruction':mn+' '+op})
functions={hex(rv):b.dump_function(rv) for rv in [0x1701a0,0x537ecf,0x53a930,0x396e20,0x316e18,0x31a8f3,0x31934b]+[int(h['rva'],16) for h in hits]}
save('combat-native-followup.json',{'sha256':hashlib.sha256(b.data).hexdigest(),'scope':'Exception-directory ranges may be function fragments; xrefs exclude indirect calls and uncovered code. Packet name registration does not establish runtime handling or authority.','hits':hits,'functions':functions})
print(json.dumps(hits,indent=2))
for h in hits:
    rows=functions[h['rva']]['instructions'];ix=next(i for i,r in enumerate(rows) if r['rva']==h['rva'])
    print('\nHIT',h['rva'])
    for r in rows[max(0,ix-7):ix+22]: print(r['rva'],r['instruction'])
