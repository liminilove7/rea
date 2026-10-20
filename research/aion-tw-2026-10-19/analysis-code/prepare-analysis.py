"""Prepare stable sample copies and auxiliary PE/string observations, no execution."""
from pathlib import Path
import collections,hashlib,json,math,shutil,struct,zipfile
ROOT=Path('D:/RVE/.codex/local/aion-tw-20261019')
CLIENT=Path('D:/Workspace/AION_TW/DeuLuncher')
(ROOT/'samples').mkdir(parents=True,exist_ok=True)
terms=['attackDelay','attack_speed','attackSpeed','AttackSpeed','moveSpeed','move_speed','MoveSpeed','runSpeed','speed','S_STATUS','S_ACTION','cattack','StatUp','StatDown','movement','Game.dll']
rows=[]
for name in ['Game.dll','Aion.bin','CrySystem.dll','ScriptDLL64.dll']:
    src=CLIENT/'bin56'/name;before=src.stat();raw=src.read_bytes();after=src.stat()
    if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise RuntimeError('Source changing: '+name)
    dst=ROOT/'samples'/name;dst.write_bytes(raw)
    digest=hashlib.sha256(raw).hexdigest()
    if hashlib.sha256(dst.read_bytes()).hexdigest()!=digest:raise RuntimeError('Copied sample hash mismatch')
    pe=struct.unpack_from('<I',raw,0x3c)[0]
    if raw[pe:pe+4]!=b'PE\0\0':raise RuntimeError('Missing PE header: '+name)
    machine,nsec,stamp=struct.unpack_from('<HHI',raw,pe+4);opt=pe+24
    optsize=struct.unpack_from('<H',raw,pe+20)[0];magic=struct.unpack_from('<H',raw,opt)[0]
    base=struct.unpack_from('<Q' if magic==0x20b else '<I',raw,opt+(24 if magic==0x20b else 28))[0]
    sections=[]
    for i in range(nsec):
        at=opt+optsize+40*i;nm=raw[at:at+8].rstrip(b'\0').decode('ascii',errors='backslashreplace')
        vs,va,rs,rp=struct.unpack_from('<IIII',raw,at+8);data=raw[rp:rp+rs];freq=collections.Counter(data)
        entropy=-sum((n/len(data))*math.log2(n/len(data)) for n in freq.values()) if data else None
        sections.append({'name':nm,'rva':hex(va),'virtual_bytes':vs,'file_offset':rp,'file_bytes':rs,'entropy':entropy})
    hits=[]
    for term in terms:
        for encoding in ['ascii','utf-16le']:
            needle=term.encode(encoding);start=0
            while (pos:=raw.find(needle,start))>=0:
                rva=None
                for s in sections:
                    if s['file_offset']<=pos<s['file_offset']+s['file_bytes']:rva=int(s['rva'],16)+pos-s['file_offset'];break
                hits.append({'term':term,'encoding':encoding,'file_offset':pos,'rva':hex(rva) if rva is not None else None,'va':hex(base+rva) if rva is not None else None})
                start=pos+len(needle)
    rows.append({'source':str(src),'sample':str(dst),'bytes':len(raw),'sha256':digest,'architecture':hex(machine),'imagebase':hex(base),'entry_rva':hex(struct.unpack_from('<I',raw,opt+16)[0]),'sections':sections,'literal_hits':hits,'copy_verified':True})
resources=[]
for folder in ['items','skills','pc']:
    for p in sorted((CLIENT/'data'/folder).glob('*.pak')):
        record={'path':str(p),'bytes':p.stat().st_size,'header_hex':p.open('rb').read(16).hex()}
        try:
            with zipfile.ZipFile(p) as z:record.update({'zip_compatible':True,'entries':[{'name':i.filename,'bytes':i.file_size,'compressed_bytes':i.compress_size,'flags':i.flag_bits} for i in z.infolist()]})
        except (zipfile.BadZipFile,OSError) as e:record.update({'zip_compatible':False,'directory_error':str(e)})
        resources.append(record)
result={'method':'auxiliary original-file PE and literal-byte inventory, not REA disassembly','target_executed':False,'modules':rows,'resources':resources}
(ROOT/'sample-observations.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf8')
print(json.dumps({'modules':[{k:r[k] for k in ['source','bytes','sha256','architecture','imagebase','entry_rva']}|{'literal_hits':len(r['literal_hits'])} for r in rows],'resources':[{'path':r['path'],'zip_compatible':r['zip_compatible'],'entries':len(r.get('entries',[]))} for r in resources]},ensure_ascii=False))
