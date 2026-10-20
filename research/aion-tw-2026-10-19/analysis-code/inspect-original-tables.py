"""Auxiliary original PE table facts, not decompiled program behavior."""
from pathlib import Path
import json,struct
root=Path(__file__).parent
meta=json.loads((root/'sample-observations.json').read_text(encoding='utf8'))['modules'][0]
raw=(root/'samples/Game.dll').read_bytes();base=int(meta['imagebase'],16)
def off(va):
    for s in meta['sections']:
        start=base+int(s['rva'],16)
        if start<=va<start+s['file_bytes']:return s['file_offset']+va-start
    raise ValueError('Address is not file backed: '+hex(va))
tables=[]
for entry in [0x180d4fc10,0x180d53ba0,0x180d54690,0x180cedb70,0x180e46b18,0x180e46b78]:
    candidates=[]
    for i in range(1,513):
        cell=entry-i*8
        try:
            locator=struct.unpack_from('<Q',raw,off(cell))[0]
            sig,delta,cd,typ,cls,selfrva=struct.unpack_from('<6I',raw,off(locator))
            if sig!=1 or base+selfrva!=locator:continue
            typeoff=off(base+typ)+16;end=raw.index(0,typeoff)
            slots_to_read=[0x730,0x758] if raw[typeoff:end]==b'.?AVDlgPlayerInfo@@' else [0x260]
            slots={hex(slot):hex(struct.unpack_from('<Q',raw,off(cell+8+slot))[0]) for slot in slots_to_read}
            candidates.append({'vtable':hex(cell+8),'locator':hex(locator),'type':raw[typeoff:end].decode('ascii',errors='backslashreplace'),'object_offset':delta,'referenced_function_slot':hex(entry-cell-8),'function_pointer_va':hex(entry),'additional_slot_values':slots})
        except (ValueError,struct.error):continue
        break
    tables.extend(candidates)
constants=[]
for va in [0x180db63e4,0x180db5c1c,0x180db59f4,0x180db6484,0x180db6198,0x180db5b3c,0x180db5ba4,0x180db5c78]:
    at=off(va);constants.append({'va':hex(va),'bytes':raw[at:at+4].hex(),'float32':struct.unpack_from('<f',raw,at)[0]})
result={'method':'auxiliary PE RTTI locator validation and original file-backed float decoding','vtables':tables,'constants':constants}
(root/'original-table-facts.json').write_text(json.dumps(result,indent=2),encoding='utf8')
print(json.dumps(result,indent=2))
