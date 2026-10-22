"""Auxiliary original PE descriptors matched to current REA formula field reads."""
from pathlib import Path
import struct,json,hashlib
ROOT=Path(__file__).resolve().parents[3]
src=ROOT/'_reference/github-releases/aion-tw-offline-20261020/client__static-programs-20261020/bin56/Game.dll'
b=src.read_bytes();digest=hashlib.sha256(b).hexdigest()
assert digest=='b3043f0eaf225b3dc7ba320ac7671cc5b28cefbd637135943dc9e67c114ccae7'
pe=struct.unpack_from('<I',b,60)[0];opt=pe+24;base=struct.unpack_from('<Q',b,opt+24)[0]
at=opt+struct.unpack_from('<H',b,pe+20)[0];secs=[]
for i in range(struct.unpack_from('<H',b,pe+6)[0]):
    vs,rva,size,pos=struct.unpack_from('<IIII',b,at+40*i+8);secs.append((rva,size,pos))
def va(pos):
    for r,s,p in secs:
        if p<=pos<p+s:return base+r+pos-p
def off(addr):
    for r,s,p in secs:
        if base+r<=addr<base+r+s:return p+addr-base-r
    raise ValueError(hex(addr))
def wide(addr):
    p=off(addr);end=p
    while end+2<=len(b) and b[end:end+2]!=b'\0\0':end+=2
    return b[p:end].decode('utf-16le')
records=[]
for name,expected,width in [('quality',421,1),('level',436,1),('sub_enchant_material_effect',410,2)]:
    needle=(name+'\0').encode('utf-16le');start=0
    while (p:=b.find(needle,start))>=0:
        start=p+2;ptr=va(p)
        if ptr is None:continue
        seek=0;pv=struct.pack('<Q',ptr)
        while (q:=b.find(pv,seek))>=0:
            seek=q+1
            if q+24>len(b):continue
            _,offset,size,converter=struct.unpack_from('<QIIQ',b,q)
            if offset==expected and size==width:
                records.append(dict(name=name,field_offset=hex(offset),width=size,descriptor_va=hex(va(q)),string_va=hex(ptr),converter_va=hex(converter),raw24=b[q:q+24].hex()))
enum_candidates=[]
for label in ('junk','common','rare','legend','unique','epic','mythic'):
    needle=(label+'\0').encode('utf-16le');p=0
    while (p:=b.find(needle,p))>=0:
        ptr=va(p);p+=2
        if ptr is None:continue
        seek=0
        while (q:=b.find(struct.pack('<Q',ptr),seek))>=0:
            seek=q+1
            if q+12<=len(b):
                v=struct.unpack_from('<I',b,q+8)[0]
                if v<=6:enum_candidates.append(dict(label=label,value=v,table_va=hex(va(q)),raw16=b[q:q+16].hex()))
scale_offset=off(0x180DB5A80)
out=dict(method='auxiliary PE descriptor bytes corroborated against REA formula reads; converter/enum consumer checked separately by current REA evidence',sha256=digest,descriptors=records,quality_enum_candidates=enum_candidates,display_scale=dict(va='0x180DB5A80',bytes=b[scale_offset:scale_offset+4].hex(),float32=struct.unpack_from('<f',b,scale_offset)[0]))
(Path(__file__).parent/'formula-field-descriptors.json').write_text(json.dumps(out,indent=2),encoding='utf8')
print(json.dumps(out))
