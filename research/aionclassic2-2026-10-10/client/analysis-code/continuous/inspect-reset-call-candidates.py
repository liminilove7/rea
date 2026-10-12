"""Find original direct-displacement virtual call/jump candidates for the reset slot."""
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

study = Path(__file__).resolve().parents[3]
data = (study / 'samples/Game.dll').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786'
pe = struct.unpack_from('<I', data, 0x3c)[0]
optional = pe+24
base = struct.unpack_from('<Q', data, optional+24)[0]
optional_size = struct.unpack_from('<H', data, pe+20)[0]
sections = []
for index in range(struct.unpack_from('<H', data, pe+6)[0]):
    virtual_size, rva, raw_size, raw = struct.unpack_from('<IIII', data, optional+optional_size+index*40+8)
    sections.append((rva, raw_size, raw))

def offset(rva):
    for start, size, raw in sections:
        if start <= rva < start+size:
            return raw+rva-start
    raise ValueError('Unmapped RVA')

exception_rva, exception_size = struct.unpack_from('<II', data, optional+112+3*8)
functions = [struct.unpack_from('<III', data, offset(exception_rva)+12*index)[:2]
             for index in range(exception_size//12)]
slot = 0x1f8
pattern = re.compile(b'\xff[\x90-\x93\x95-\x97\xa0-\xa3\xa5-\xa7]'+re.escape(struct.pack('<I', slot)))
candidates = []
for rva, size, raw in sections:
    for match in pattern.finditer(data[raw:raw+size]):
        position = raw+match.start()
        start = position-1 if match.start() > 0 and 0x40 <= data[position-1] <= 0x4f else position
        target_rva = rva+start-raw
        candidates.append({'address': hex(base+target_rva), 'fileOffset': hex(start),
            'bytes': data[start:position+6].hex(),
            'peExceptionFunctions': [hex(base+begin) for begin, end in functions if begin <= target_rva < end]})
result = {'targetSha256': digest, 'targetExecuted': False, 'slotOffset': hex(slot),
    'source': 'Auxiliary original-PE byte candidates; not decoded calls or confirmed Character objects',
    'candidateCount': len(candidates), 'candidates': candidates,
    'limitations': ['Only FF /2 and /4 non-SIB mod=10 disp32 encodings searched.',
        'Code/data section flags do not distinguish instructions in this protected sample.',
        'Instruction boundaries, pointer identity, indirect aliases and runtime targets require separate verification.']}
output = study / 'evidence/continuous/20261012-state-audit/original-reset-slot-call-candidates.json'
if '--check' in sys.argv[1:]:
    assert json.loads(output.read_text(encoding='utf-8')) == result
else:
    with output.open('x', encoding='utf-8', newline='\n') as handle:
        json.dump(result, handle, indent=2)
print(json.dumps(result))
