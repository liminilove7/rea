"""Auxiliary resource decoding with the existing CRC-checked format reader."""
from pathlib import Path,PurePosixPath
import collections,hashlib,json,re,sys,xml.etree.ElementTree as ET,zipfile
ROOT=Path('D:/RVE/.codex/local/aion-tw-20261019');LOCAL=ROOT.parent
CLIENT=Path('D:/Workspace/AION_TW/DeuLuncher')
sys.path.insert(0,str(LOCAL))
from aion_pak import SignatureView
ns={'__file__':str(LOCAL/'extract_aion_data.py')}
exec((LOCAL/'extract_aion_data.py').read_text(encoding='utf8').split('archives = sorted')[0],ns)
archives=[];decoded=[];errors=[]
for folder in ['items','skills','pc']:
    for pak in sorted((CLIENT/'data'/folder).glob('*.pak')):
        before=pak.stat();digest=hashlib.sha256(pak.read_bytes()).hexdigest()
        try:
            with SignatureView(pak) as view,zipfile.ZipFile(view) as z,pak.open('rb') as stream:
                entries=z.infolist()
                archives.append({'path':str(pak),'sha256':digest,'entries':[{'name':e.filename,'bytes':e.file_size,'crc32':f'{e.CRC:08x}'} for e in entries]})
                for e in entries:
                    if e.is_dir() or not e.filename.lower().endswith('.xml'):continue
                    if not (folder in ['skills','pc'] or re.search('client_items|item_set|item_option',e.filename,re.I)):continue
                    try:
                        rel=PurePosixPath(e.filename.replace('\\','/'))
                        if rel.is_absolute() or '..' in rel.parts or ':' in str(rel):raise ValueError('Unsafe archive path')
                        raw,mode=ns['payload'](stream,e)
                        if raw[:1]==b'\x80':text,tag,count=ns['bxml'](raw)
                        else:
                            tree=ET.fromstring(raw);text=raw;tag=tree.tag;count=len(tree)
                        dst=ROOT/'resources'/pak.relative_to(CLIENT).with_suffix('')/str(rel)
                        dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(text)
                        decoded.append({'archive':str(pak),'entry':e.filename,'output':str(dst),'raw_sha256':hashlib.sha256(raw).hexdigest(),'decoded_sha256':hashlib.sha256(text).hexdigest(),'transform_mode':mode,'root':tag,'records':count,'crc_verified':True})
                    except Exception as e2:errors.append({'archive':str(pak),'entry':e.filename,'error':str(e2)})
        except Exception as e:errors.append({'archive':str(pak),'error':str(e)})
        after=pak.stat()
        if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise RuntimeError('Resource changed while reading: '+str(pak))
records=[];counts={}
for source in decoded:
    rows=list(ET.fromstring(Path(source['output']).read_bytes()));counts[source['output']]=len(rows)
    selected=[]
    for row in rows:
        d={e.tag:e.text or '' for e in row}
        fields={k:v for k,v in d.items() if re.search(r'attack.?delay|attack.?speed|move.?speed|run.?speed|fly.?speed|(^|\s)speed(\s|$)',k+' '+v,re.I)}
        if fields:selected.append({'id':d.get('id'),'name':d.get('name'),'matched_fields':fields,'raw':d})
    records.append({'source':source['output'],'selected_count':len(selected),'selected':selected})
result={'method':'auxiliary PAK/BXML decoding and raw resource joins; not REA binary semantics or current server rules','target_executed':False,'archives':archives,'decoded':decoded,'errors':errors,'source_counts':counts,'speed_candidates':records}
(ROOT/'speed-resources.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf8')
print(json.dumps({'archives':len(archives),'decoded':len(decoded),'errors':errors,'counts':[{'entry':s['entry'],'archive':Path(s['archive']).name,'records':s['records']} for s in decoded],'speed_candidates':[{'source':Path(s['source']).name,'count':s['selected_count']} for s in records]},ensure_ascii=False))
