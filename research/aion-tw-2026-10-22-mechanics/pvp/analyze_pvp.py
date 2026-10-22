"""Read-only, format-aware inventory of supplied decoded client XML resources."""
import argparse, collections, hashlib, json, re
from pathlib import Path
from xml.etree import ElementTree as ET

DEFAULT = Path('D:/REA/_reference/github-releases/aion-tw-offline-20261020/analysis__complete-static-study-20261020/aion-tw-20261019/resources')
KEY = re.compile(r'pvp|pve|pvpattack|pvpdefend|pvpdefense', re.I)
RELATED = re.compile(r'attack|defen|damage|resist|critical|accuracy|boost|race|level|effect|element|modifier|ratio|bonus', re.I)
SELECTED = {'100000363','100001282','110100604','110101375','187000069','114601236','3790','3804','11905','645','1430','1434','1755','1958','1959','1961','1962','1965'}

def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--resources', type=Path, default=DEFAULT)
    ap.add_argument('--output', type=Path, default=Path(__file__).parent / 'resource-evidence.json')
    args = ap.parse_args()
    result = {'method': 'Auxiliary ElementTree XML parsing, not REA disassembly; complete supplied XML inventory, exact field/value keyword selection.',
              'target_executed': False, 'scope': str(args.resources), 'files': [], 'unknowns': [
                  'Resources are client declarations; server formulas, effective caps, stacking order, rounding and authoritative values are not established.',
                  'Exact pvp/pve keyword selection may miss undocumented aliases or encoded fields. Absence within this inventory is not absence from the game.']}
    for path in sorted(args.resources.rglob('*.xml')):
        sha = hashlib.sha256()
        with path.open('rb') as f:
            for block in iter(lambda: f.read(1024*1024), b''): sha.update(block)
        info = {'path': str(path.relative_to(args.resources)), 'sha256': sha.hexdigest(), 'bytes': path.stat().st_size,
                'records': 0, 'matching_records': 0, 'field_counts': collections.Counter(), 'matched_field_counts': collections.Counter(), 'matched_values': {}, 'representative_records': [], 'all_pvp_records': []}
        seen_special = set()
        depth = 0
        for event, el in ET.iterparse(path, events=('start', 'end')):
            if event == 'start': depth += 1; continue
            if depth == 2:
                info['records'] += 1
                pairs = [(x.tag, (x.text or '').strip()) for x in el.iter() if len(x)==0]
                info['field_counts'].update(k for k,v in pairs)
                hits = [(k,v) for k,v in pairs if KEY.search(k) or KEY.search(v)]
                if hits:
                    info['matching_records'] += 1
                    for k,v in hits:
                        info['matched_field_counts'][k] += 1
                        info['matched_values'].setdefault(k, collections.Counter())[v] += 1
                    rec = {'ordinal': info['records'], 'tag': el.tag, 'id': el.findtext('id'), 'name': el.findtext('name'), 'matches': hits}
                    info['all_pvp_records'].append(rec)
                    special = {(k,v) for k,v in hits if k.startswith('pvp_')}
                    if (len(info['representative_records']) < 3 or rec['id'] in SELECTED or special-seen_special
                        or ('\\pc\\' in str(path.relative_to(args.resources)) and path.stat().st_size < 100000)):
                        info['representative_records'].append(dict(rec, fields=pairs))
                    seen_special.update(special)
                el.clear()
            depth -= 1
        info['matched_field_counts'] = dict(info['matched_field_counts'])
        info['field_counts'] = dict(info['field_counts'])
        info['matched_values'] = {k:dict(v) for k,v in info['matched_values'].items()}
        result['files'].append(info)
    result['totals'] = {'files': len(result['files']), 'records': sum(x['records'] for x in result['files']), 'matching_records': sum(x['matching_records'] for x in result['files'])}
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'totals':result['totals'], 'files':[{'path':x['path'],'records':x['records'],'matching_records':x['matching_records'],'fields':x['matched_field_counts']} for x in result['files'] if x['matching_records']]}, ensure_ascii=False, indent=2))

if __name__ == '__main__': main()
