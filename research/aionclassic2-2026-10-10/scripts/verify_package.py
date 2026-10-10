"""Verify committed input/evidence identity without loading any PE executable."""
import hashlib
import json
from pathlib import Path

root=Path(__file__).resolve().parents[1]
manifest=json.loads((root/'manifest.json').read_text(encoding='utf-8'))
errors=[]
for item in manifest['files']:
    path=(root/item['path']).resolve()
    if not path.is_relative_to(root):
        errors.append(item['path']+': outside case directory')
        continue
    if not path.is_file():
        errors.append(item['path']+': missing')
        continue
    if path.stat().st_size!=item['bytes'] or hashlib.sha256(path.read_bytes()).hexdigest()!=item['sha256']:
        errors.append(item['path']+': content mismatch')
print(json.dumps({'files_checked':len(manifest['files']),'errors':errors},indent=2))
raise SystemExit(1 if errors else 0)
