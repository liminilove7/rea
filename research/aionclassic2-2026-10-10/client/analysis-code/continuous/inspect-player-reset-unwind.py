"""Classify two data xrefs as chained x64 unwind entries using original producer bytes."""
import hashlib
import json
from pathlib import Path
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

def offset(rva, length=1):
    for start, size, raw in sections:
        if start <= rva and rva+length <= start+size:
            return raw+rva-start
    raise ValueError('Unmapped RVA')

entries = []
for info_rva, reference_rva in [(0x8a1054, 0x8a1060), (0x8a106c, 0x8a1070)]:
    raw = offset(info_rva, 4)
    header, prolog, count, frame = data[raw:raw+4]
    version, flags = header & 7, header >> 3
    assert version == 1 and flags == 4
    tail = info_rva+4+2*((count+1)&~1)
    assert tail == reference_rva
    begin, end, unwind = struct.unpack_from('<III', data, offset(tail, 12))
    assert begin == 0x638e0 and end == 0x638f6 and unwind == 0x8a1040
    primary_raw = offset(unwind, 4)
    assert data[primary_raw] & 7 == 1
    entries.append({'unwindInfoRva': hex(info_rva), 'referenceRva': hex(reference_rva),
        'version': version, 'flags': flags, 'countOfCodes': count, 'prologSize': prolog,
        'frameRegisterEncoding': frame, 'rawHeader': data[raw:raw+4].hex(),
        'chainEntryBytes': data[offset(tail):offset(tail)+12].hex(),
        'beginRva': hex(begin), 'endRva': hex(end), 'primaryUnwindRva': hex(unwind),
        'classification': 'UNW_FLAG_CHAININFO tail containing RUNTIME_FUNCTION RVAs; not a call site'})
result = {'targetSha256': digest, 'imagebase': hex(base), 'targetExecuted': False,
    'source': 'Auxiliary original-PE metadata reader', 'entries': entries,
    'sourceDocumentation': 'https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170',
    'limitations': ['Metadata describes exception unwinding, not actual execution of Player reset.',
        'These entries do not prove all indirect callers or protected dispatch targets.']}
output = study / 'evidence/continuous/20261012-state-audit/original-player-reset-unwind-xrefs.json'
if '--check' in sys.argv[1:]:
    assert json.loads(output.read_text(encoding='utf-8')) == result
else:
    with output.open('x', encoding='utf-8', newline='\n') as handle:
        json.dump(result, handle, indent=2)
print(json.dumps(result))
