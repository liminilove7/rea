"""Copy source, distributable and evidence to the local report backup and verify bytes."""
import hashlib
import json
import pathlib
import shutil

root=pathlib.Path(__file__).resolve().parent
local=root.parent.parent
source=local/'aion-imgui-lab-20261020/source/research/aion-tw-2026-10-20/modifier-imgui'
destination=local/'aion-report-backup/aion-tw-20261019/health-implementation-20261024'
files={p: pathlib.Path('implementation')/p.relative_to(root) for p in root.rglob('*') if p.is_file()}
for p in source.iterdir():
    if p.is_file() and p.suffix in ('.cs','.csproj','.ps1','.cmd','.txt','.html','.json'):
        files[p]=pathlib.Path('source/modifier-imgui')/p.name
core=source.parent/'modifier/AttackSpeedLab.cs'
files[core]=pathlib.Path('source/modifier/AttackSpeedLab.cs')
report=local/'aion-autocombat-20261021/实体与技能调用链进展.html'
files[report]=pathlib.Path('report')/report.name
for stem in ['stop-144f10','stop-16d600']:
    for p in (root.parent/'rea-health-2026-10-24T11-28-17.313Z').glob(stem+'-*'):
        files[p]=pathlib.Path('rea-evidence')/p.name
manifest=[]
for p, relative in sorted(files.items()):
    target=destination/relative
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copy2(p,target)
    digest=hashlib.sha256(p.read_bytes()).hexdigest()
    assert hashlib.sha256(target.read_bytes()).hexdigest()==digest
    manifest.append(dict(path=relative.as_posix(),bytes=p.stat().st_size,sha256=digest))
(destination/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(dict(files=len(manifest),bytes=sum(x['bytes'] for x in manifest),backup=str(destination)),ensure_ascii=False))
