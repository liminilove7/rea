"""Auxiliary PE literal inventory; no execution or disassembly claims."""
import hashlib,json,re,struct,sys
from pathlib import Path
src=Path(sys.argv[1]); dest=Path(sys.argv[2]); raw=src.read_bytes()
pe=struct.unpack_from('<I',raw,0x3c)[0]
if raw[pe:pe+4]!=b'PE\0\0': raise ValueError('not PE')
nsec=struct.unpack_from('<H',raw,pe+6)[0]; opt=pe+24
if struct.unpack_from('<H',raw,opt)[0]!=0x20b: raise ValueError('expected PE32+')
base=struct.unpack_from('<Q',raw,opt+24)[0]
secs=[]; at=opt+struct.unpack_from('<H',raw,pe+20)[0]
for i in range(nsec):
    x=at+40*i; vs,rva,size,pos=struct.unpack_from('<IIII',raw,x+8)
    secs.append((pos,size,rva))
def address(pos):
    for p,size,rva in secs:
        if p<=pos<p+size: return base+rva+pos-p
    return None
rows=[]; pattern=re.compile(r'godstone|god_stone|enchant|pvp|activation.*prob|proc.*prob',re.I)
for encoding,rx in [('ascii',rb'[\x20-\x7e]{4,}'),('utf-16le',rb'(?:[\x20-\x7e]\x00){4,}')]:
    for m in re.finditer(rx,raw):
        text=m.group().decode(encoding)
        if not pattern.search(text):continue
        va=address(m.start())
        rows.append({'text':text,'encoding':encoding,'file_offset':m.start(),'rva':hex(va-base) if va else None,'va':hex(va) if va else None})
dest.parent.mkdir(parents=True,exist_ok=True)
dest.write_text(json.dumps({'method':'auxiliary literal bytes, not REA instruction evidence','source':str(src),'sha256':hashlib.sha256(raw).hexdigest(),'imagebase':hex(base),'count':len(rows),'literals':rows},ensure_ascii=False,indent=2),encoding='utf8')
print(json.dumps({'count':len(rows),'output':str(dest)}))
