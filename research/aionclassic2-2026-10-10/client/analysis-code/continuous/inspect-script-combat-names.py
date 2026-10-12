"""Original ASCII name candidates in the identity-locked ScriptDLL; not confirmed consumers."""
import argparse
import hashlib
import json
from pathlib import Path
import re

parser = argparse.ArgumentParser()
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
study = Path(__file__).resolve().parents[3]
root = study / 'evidence/continuous'
meta = next(row for row in json.loads((root / 'original-four-module-entries.json').read_text())['modules']
    if row['sample'] == 'ScriptDLL64.dll')
data = (study / meta['source']).read_bytes()
assert hashlib.sha256(data).hexdigest() == meta['targetSha256']
base = int(meta['imagebase'], 16)
pattern = re.compile(r'damage|critical|physical|pvp|parry|dodge|block|resist|chain_skill|prob', re.I)
candidates = []
for match in re.finditer(rb'[\x20-\x7e]{4,}\x00', data):
    value = match.group()[:-1].decode('ascii')
    if not pattern.search(value):
        continue
    sections = [row for row in meta['sections'] if row['fileOffset'] <= match.start()
        and match.end() <= row['fileOffset']+row['rawSize']]
    assert len(sections) <= 1
    rva = sections[0]['rva']+match.start()-sections[0]['fileOffset'] if sections else None
    candidates.append({'fileOffset': hex(match.start()), 'rva': hex(rva) if rva is not None else None,
        'preferredVa': hex(base+rva) if rva is not None else None, 'text': value,
        'classification': 'Original null-terminated ASCII candidate; consumer and registration unknown'})
result = {'source': 'Auxiliary original ScriptDLL64 ASCII candidate reader', 'targetSha256': meta['targetSha256'],
    'nativeTargetExecuted': False, 'selectionRegex': pattern.pattern, 'caseSensitive': False,
    'candidateCount': len(candidates), 'candidates': candidates,
    'limitations': ['Names are candidates, not resolved business functions or executed formulas.',
        'Original contiguous ASCII strings do not cover UTF-16, transformed or runtime-built names.',
        'Unmapped raw strings retain their file offsets and unknown addresses.']}
output = root / '20261012-script-interface/original-script-combat-name-candidates.json'
if args.check:
    assert json.loads(output.read_text(encoding='utf-8')) == result
else:
    with output.open('x', encoding='utf-8', newline='\n') as handle:
        json.dump(result, handle, indent=2)
print(json.dumps({'candidateCount': len(candidates), 'selected': [row for row in candidates
    if re.search(r'Calculate|PhysicalDamage|PvP|PvpDamage|DamageRatio|chain_skill', row['text'])]}))
