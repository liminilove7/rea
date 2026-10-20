"""Read-back verified local case backup; excludes databases and commercial files."""
from pathlib import Path
import hashlib,json,shutil
root=Path(__file__).parent
destination=root.parent/'aion-report-backup/aion-tw-20261019'
files=[]
for p in sorted(root.rglob('*')):
    if not p.is_file():continue
    rel=p.relative_to(root)
    if rel.parts[0] in {'samples','ida-python-backup'}:continue
    if p.suffix not in {'.json','.html','.py','.mjs','.cjs','.png','.xml','.log'}:continue
    if p.name=='backup-verification.json':continue
    raw=p.read_bytes();digest=hashlib.sha256(raw).hexdigest()
    target=destination/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
    if hashlib.sha256(target.read_bytes()).hexdigest()!=digest:raise RuntimeError('Backup mismatch: '+str(rel))
    files.append({'path':rel.as_posix(),'bytes':len(raw),'sha256':digest})
result={'source':str(root),'destination':str(destination),'allReadBackHashesMatched':True,'fileCount':len(files),'totalBytes':sum(x['bytes'] for x in files),'files':files,'excluded':['sample binaries already retained separately','IDA database and sidecars','commercial IDA plugin backups'],'F_drive_available':Path('F:/').exists()}
raw=json.dumps(result,ensure_ascii=False,indent=2)
(root/'backup-verification.json').write_text(raw,encoding='utf8')
(destination/'backup-verification.json').write_text(raw,encoding='utf8')
print(json.dumps({k:result[k] for k in ['allReadBackHashesMatched','fileCount','totalBytes','destination','F_drive_available']},ensure_ascii=False))
