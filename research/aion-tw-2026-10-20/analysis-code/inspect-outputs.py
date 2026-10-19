from pathlib import Path
import json,re,sys
root=Path(__file__).parent
pattern=re.compile(sys.argv[1],re.I)
for name in sys.argv[2:]:
    p=root/(name+'.normalized.json');value=json.loads(p.read_text(encoding='utf8'))
    lines=value.get('instructions',[]) if isinstance(value,dict) else value.splitlines() if isinstance(value,str) else [json.dumps(value)]
    indices=set()
    for n,line in enumerate(lines):
        if pattern.search(line):indices.update(range(max(0,n-4),min(len(lines),n+7)))
    print('\nFILE '+name)
    for n in sorted(indices):print(lines[n].strip())
