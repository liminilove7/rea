"""Auxiliary literal-displacement/pointer search and original PE unwind ranges.
These are unverified candidate locations, not instruction decoding or REA findings.
"""
from pathlib import Path
import bisect,json,struct
root=Path(__file__).parent
meta=json.loads((root/'sample-observations.json').read_text(encoding='utf8'))['modules'][0]
raw=(root/'samples/Game.dll').read_bytes();base=int(meta['imagebase'],16)
sections=meta['sections'];pe=struct.unpack_from('<I',raw,0x3c)[0];opt=pe+24
optsize=struct.unpack_from('<H',raw,pe+20)[0]
executable_sections={i for i in range(len(sections)) if struct.unpack_from('<I',raw,opt+optsize+40*i+36)[0]&0x20000000}
def rvaoff(rva):
    for s in sections:
        at=int(s['rva'],16)
        if at<=rva<at+s['file_bytes']:return s['file_offset']+rva-at
    raise ValueError('Unbacked RVA '+hex(rva))
prva,psize=struct.unpack_from('<II',raw,opt+112+3*8);poff=rvaoff(prva)
ranges=[struct.unpack_from('<III',raw,poff+i)[:2] for i in range(0,psize-11,12)]
ranges=sorted((a,b) for a,b in ranges if a<b);starts=[a for a,b in ranges]
def containing(rva):
    i=bisect.bisect_right(starts,rva)-1
    return ranges[i] if i>=0 and ranges[i][0]<=rva<ranges[i][1] else None
hits={};by_function={}
for field in [0x530,0x532,0x70c,0x710,0x714]:
    needle=struct.pack('<I',field);found=[]
    for section_index,s in enumerate(sections):
        if section_index not in executable_sections:continue
        data=raw[s['file_offset']:s['file_offset']+s['file_bytes']];offset=0
        while (pos:=data.find(needle,offset))>=0:
            rva=int(s['rva'],16)+pos;f=containing(rva)
            record={'literal_va':hex(base+rva),'unwind_function':hex(base+f[0]) if f else None}
            found.append(record)
            if f:by_function.setdefault(f[0],set()).add(field)
            offset=pos+4
    hits[hex(field)]=found
paired=[{'procedure':hex(base+f),'fields':[hex(x) for x in sorted(fields)]} for f,fields in by_function.items() if {0x530,0x532}<=fields or {0x70c,0x710,0x714}<=fields]
tables=[]
for va in [0x180d4fc10,0x180d53ba0,0x180d54690]:
    at=rvaoff(va-base)
    tables.append({'reference_va':hex(va),'qwords':[hex(struct.unpack_from('<Q',raw,at+o)[0]) for o in range(-0x80,0x30,8)]})
result={'method':'auxiliary literal-byte search plus original .pdata ranges; all code semantics require REA verification','hits':hits,'paired_candidates':paired,'vtable_pointer_neighborhoods':tables}
(root/'supplementary-speed-candidates.json').write_text(json.dumps(result,indent=2),encoding='utf8')
jobs=[]
for i,record in enumerate(paired):
    for suffix,name in [('insns','read_function_instructions'),('pseudo','procedure_pseudo_code'),('callers','procedure_callers')]:jobs.append({'file':f'field-candidate-{i}-{suffix}','name':name,'arguments':{'procedure':record['procedure']}})
for i,address in enumerate([0x180838060,0x180d4fc10-0x248,0x180d53ba0-0x248,0x180d54690-0x248]):
    jobs.append({'file':f'setter-container-{i}','name':'xrefs','arguments':{'address':hex(address)}})
(root/'jobs-fields.json').write_text(json.dumps(jobs,indent=2),encoding='utf8')
print(json.dumps({'literal_counts':{k:len(v) for k,v in hits.items()},'paired_candidates':paired,'jobs':len(jobs)},indent=2))
