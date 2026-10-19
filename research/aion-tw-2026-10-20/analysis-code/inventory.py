"""Auxiliary filesystem/PE inventory only; no execution or disassembly."""
from pathlib import Path
import datetime,hashlib,json,struct
root=Path('D:/Workspace/AION_TW/DeuLuncher')
out=Path('D:/RVE/.codex/local/aion-tw-20261019')
files=sorted(p for p in root.rglob('*') if p.is_file())
inventory=[];errors=[]
for p in files:
    try:
        s=p.stat();inventory.append({'path':p.relative_to(root).as_posix(),'bytes':s.st_size,'modified_ns':s.st_mtime_ns})
    except OSError as e:errors.append({'path':str(p),'error':str(e)})
selected=[p for p in files if p.parent==root and p.suffix.lower()=='.exe']
selected += [root/folder/n for folder in ['bin56','bin64'] for n in ['Aion.bin','Game.dll','CrySystem.dll','version.dll','ScriptDLL64.dll'] if (root/folder/n).is_file()]
modules=[]
for p in selected:
    before=p.stat();raw=p.read_bytes();after=p.stat()
    row={'path':p.relative_to(root).as_posix(),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'stable_during_read':before.st_size==after.st_size and before.st_mtime_ns==after.st_mtime_ns}
    if raw[:2]==b'MZ' and len(raw)>=64:
        off=struct.unpack_from('<I',raw,0x3c)[0]
        if off+24<=len(raw) and raw[off:off+4]==b'PE\0\0':
            machine,nsec,stamp=struct.unpack_from('<HHI',raw,off+4)
            opt=off+24;magic=struct.unpack_from('<H',raw,opt)[0]
            row.update({'format':'PE','machine':hex(machine),'architecture':{0x8664:'x86-64',0x14c:'x86',0xaa64:'arm64'}.get(machine,'unknown'),'sections':nsec,'coff_timestamp_raw':stamp,'optional_magic':hex(magic)})
            directories=opt+(112 if magic==0x20b else 96)
            if directories+15*8<=len(raw):
                clr,size=struct.unpack_from('<II',raw,directories+14*8)
                row['clr_directory']={'rva':hex(clr),'size':size}
                row['managed_header_present']=bool(clr and size)
    modules.append(row)
case={'created_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'root':str(root),'method':'auxiliary Python filesystem/PE header inventory, not REA semantic analysis','target_executed':False,'file_count':len(inventory),'total_bytes':sum(x['bytes'] for x in inventory),'inventory_errors':errors,'modules':modules,'files':inventory,'old_classic_sample_sha256':'834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786','notes':['Deployment may still change files; regenerate inventory before analysis.','PE timestamps and launcher labels do not establish game version.','No server directory supplied yet.']}
out.mkdir(parents=True,exist_ok=True)
(out/'inventory.json').write_text(json.dumps(case,ensure_ascii=False,indent=2),encoding='utf8')
print(json.dumps({k:case[k] for k in ['root','file_count','total_bytes','inventory_errors','modules']},ensure_ascii=False,indent=2))
