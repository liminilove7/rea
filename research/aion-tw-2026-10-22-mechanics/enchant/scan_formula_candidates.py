"""Auxiliary raw-byte candidates only; .pdata spans do not prove instruction semantics."""
from pathlib import Path
import struct,hashlib,json,bisect
ROOT=Path(__file__).resolve().parents[3]
P=ROOT/'_reference/github-releases/aion-tw-offline-20261020/client__static-programs-20261020/bin56/Game.dll'
b=P.read_bytes(); digest=hashlib.sha256(b).hexdigest()
assert digest=='b3043f0eaf225b3dc7ba320ac7671cc5b28cefbd637135943dc9e67c114ccae7'
u16=lambda o:struct.unpack_from('<H',b,o)[0]
u32=lambda o:struct.unpack_from('<I',b,o)[0]
pe=u32(0x3c); n=u16(pe+6); opt=pe+24; sec=opt+u16(pe+20)
base=struct.unpack_from('<Q',b,opt+24)[0]
sections=[]
for i in range(n):
    s=sec+40*i; sections.append((b[s:s+8].rstrip(b'\0').decode(),u32(s+12),u32(s+8),u32(s+20),u32(s+16)))
def off(rva):
    for _,r,v,o,z in sections:
        if r<=rva<r+z:return o+rva-r
    raise ValueError(hex(rva))
exc=u32(opt+112+3*8); size=u32(opt+112+3*8+4)
spans=[struct.unpack_from('<III',b,off(exc)+i)[:2] for i in range(0,size,12)]
hits=[]
for start,end in spans:
    if end-start>20000:continue
    raw=b[off(start):off(start)+end-start]
    patterns={str(v):[start+i for i in range(len(raw)) if raw.startswith(struct.pack('<I',v),i)] for v in (800,500,1000)}
    # These are raw constants, not decoded operands; only a shortlist.
    if all(patterns[k] for k in ('800','500')):
        hits.append(dict(function_span_rva=[hex(start),hex(end)],va=hex(base+start),length=end-start,constants={k:[hex(v) for v in vs] for k,vs in patterns.items()}))
out=dict(method='auxiliary raw bytes + PE exception directory spans; REA/IDA required to validate candidate semantics',sha256=digest,target_executed=False,candidates=hits)
(Path(__file__).parent/'formula-byte-candidates.json').write_text(json.dumps(out,indent=2),encoding='utf8')
print(json.dumps(out))
