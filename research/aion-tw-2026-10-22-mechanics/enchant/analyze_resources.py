"""Decode current archived items PAK XML with CRC, then inspect enchant metadata.
Auxiliary format analysis, not REA native instruction or server evidence.
"""
from pathlib import Path
import collections, hashlib, json, re, sys, xml.etree.ElementTree as ET, zipfile
ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / '_reference/github-releases/aion-tw-offline-20261020'
LIB = BASE / 'analysis__complete-static-study-20261020'
OUT = Path(__file__).resolve().parent
sys.path.insert(0, str(LIB))
from aion_pak import SignatureView
ns = {'__file__': str(LIB / 'extract_aion_data.py')}
exec((LIB / 'extract_aion_data.py').read_text(encoding='utf8').split('archives = sorted')[0], ns)
def sha(b): return hashlib.sha256(b).hexdigest()
def node_value(node):
    if not len(node) and not node.attrib: return node.text or ''
    value = {'@attributes':dict(node.attrib)} if node.attrib else {}
    grouped = collections.defaultdict(list)
    for child in node: grouped[child.tag].append(node_value(child))
    value.update({key:values[0] if len(values)==1 else values for key,values in grouped.items()})
    if node.text and node.text.strip(): value['#text']=node.text
    return value
def save(name, data):
    (OUT/name).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf8')
sources, datasets, errors = [], {}, []
for pak in sorted((BASE/'resources__original-paks-20261020/data/items').glob('*.pak')):
    digest = sha(pak.read_bytes())
    with SignatureView(pak) as view, zipfile.ZipFile(view) as z, pak.open('rb') as stream:
        for e in z.infolist():
            if not e.filename.lower().endswith('.xml'): continue
            if Path(e.filename).name != e.filename: raise ValueError('Unexpected nested member')
            try:
                raw, mode = ns['payload'](stream, e)
                decoded = ns['bxml'](raw)[0] if raw[:1] == b'\x80' else raw
                root = ET.fromstring(decoded)
                rows = [node_value(r) for r in root]
                sources.append(dict(archive=str(pak.relative_to(ROOT)), archive_sha256=digest,
                    member=e.filename, crc32=f'{e.CRC:08x}', crc_verified=True,
                    raw_sha256=sha(raw), decoded_sha256=sha(decoded), mode=mode, records=len(rows)))
                datasets[e.filename] = rows
                if e.filename != 'client_items.xml':
                    dest=OUT/'decoded'/e.filename; dest.parent.mkdir(parents=True, exist_ok=True); dest.write_bytes(decoded)
            except Exception as exc: errors.append(dict(member=e.filename,error=str(exc)))
save('source-manifest.json', dict(method='auxiliary CRC-checked PAK/BXML decoding',target_executed=False,sources=sources,errors=errors))
items = datasets['client_items.xml']
fields = collections.defaultdict(collections.Counter)
for row in items:
    for k,v in row.items():
        if re.search('enchant|strength|break|failure',k,re.I): fields[k][v]+=1
selected = [r for r in items if re.search('enchant|strength',r.get('name',''),re.I) or any(re.search('enchant_prob|enchant_stone|enchant_bonus',k,re.I) for k in r)]
save('item-enchant-field-inventory.json',dict(total_items=len(items),fields={k:dict(v) for k,v in sorted(fields.items())}))
save('enchant-item-records.json',selected)
summary={k:dict(count=len(rows),fields=dict(collections.Counter(t for r in rows for t in r)),examples=rows[:3]) for k,rows in datasets.items() if k!='client_items.xml'}
save('table-summary.json',summary)
print(json.dumps(dict(source_count=len(sources),errors=errors,total_items=len(items),selected_items=len(selected),tables={k:v['count'] for k,v in summary.items()},fields={k:dict(v.most_common(12)) for k,v in fields.items()}),ensure_ascii=False))
