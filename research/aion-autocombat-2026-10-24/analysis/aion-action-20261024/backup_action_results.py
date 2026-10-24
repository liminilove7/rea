"""Back up this analysis, current modifier source and HTML with a verified digest manifest."""
import hashlib
import json
import pathlib
import shutil

root=pathlib.Path(__file__).resolve().parent
local=root.parent
source=local/'aion-imgui-lab-20261020/source/research/aion-tw-2026-10-20/modifier-imgui'
destination=local/'aion-report-backup/aion-tw-20261019/action-dispatch-20261024'
files={p:pathlib.Path('analysis')/p.relative_to(root) for p in root.rglob('*') if p.is_file()}
for p in source.iterdir():
    if p.is_file() and p.suffix in ('.cs','.csproj','.json','.ps1','.cmd','.txt','.html'):
        files[p]=pathlib.Path('source/modifier-imgui')/p.name
core=source.parent/'modifier/AttackSpeedLab.cs';files[core]=pathlib.Path('source/modifier/AttackSpeedLab.cs')
report=local/'aion-autocombat-20261021/实体与技能调用链进展.html';files[report]=pathlib.Path('report')/report.name
manifest=[]
for p,relative in sorted(files.items()):
    out=destination/relative;out.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,out)
    digest=hashlib.sha256(p.read_bytes()).hexdigest();assert hashlib.sha256(out.read_bytes()).hexdigest()==digest
    manifest.append(dict(path=relative.as_posix(),bytes=p.stat().st_size,sha256=digest))
(destination/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(dict(files=len(manifest),bytes=sum(r['bytes'] for r in manifest),destination=str(destination)),ensure_ascii=False))
