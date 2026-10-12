"""Find original instruction-byte candidates; IDA must validate boundaries and object identity."""
import hashlib
import json
from pathlib import Path
import struct
import sys

study = Path(__file__).resolve().parents[3]
source = study / 'samples/Game.dll'
data = source.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786'
pe = struct.unpack_from('<I', data, 0x3c)[0]
assert data[pe:pe+4] == b'PE\0\0'
sections_count = struct.unpack_from('<H', data, pe+6)[0]
optional_size = struct.unpack_from('<H', data, pe+20)[0]
optional = pe+24
assert struct.unpack_from('<H', data, optional)[0] == 0x20b
base = struct.unpack_from('<Q', data, optional+24)[0]
sections = []
for index in range(sections_count):
    position = optional+optional_size+index*40
    virtual_size, rva, raw_size, raw = struct.unpack_from('<IIII', data, position+8)
    sections.append((rva, raw_size, raw))

def offset(rva):
    for start, size, raw in sections:
        if start <= rva < start+size:
            return raw+rva-start
    raise ValueError('Unmapped RVA')

exception_rva, exception_size = struct.unpack_from('<II', data, optional+112+3*8)
functions = []
for index in range(exception_size//12):
    begin, end, unwind = struct.unpack_from('<III', data, offset(exception_rva)+12*index)
    functions.append((begin, end))

def containing(rva):
    return [hex(base+begin) for begin, end in functions if begin <= rva < end]

low, high = 0x3a0000, 0x3c0000
candidates = []
for rva in range(low, high):
    position = offset(rva)
    # MOV r/m32,r32 or MOV r/m32,imm32, mod=01, non-SIB base, disp8=0x64.
    opcode, modrm, displacement = data[position:position+3]
    if opcode not in (0x89, 0xc7) or modrm >> 6 != 1 or modrm & 7 == 4 or displacement != 0x64:
        continue
    if opcode == 0xc7 and (modrm >> 3) & 7 != 0:
        continue
    start = rva-1 if 0x40 <= data[position-1] <= 0x4f else rva
    candidates.append({'address': hex(base+start), 'rva': hex(start),
        'fileOffset': hex(offset(start)), 'bytes': data[offset(start):position+7].hex(),
        'peExceptionFunctions': containing(start)})
result = {'targetSha256': digest, 'imagebase': hex(base),
    'scannedRvaRange': [hex(low), hex(high)], 'candidateCount': len(candidates),
    'candidates': candidates, 'targetExecuted': False,
    'limitations': ['Byte matches can be inside another instruction; IDA validation is required.',
        'Only two MOV encodings and a selected RVA interval were searched.',
        'Shared offsets do not establish that candidates write the same object.']}
output = study / 'evidence/continuous/20261012-chain-value/original-skill-value-store-candidates.json'
if '--check' in sys.argv[1:]:
    assert json.loads(output.read_text(encoding='utf-8')) == result
else:
    with output.open('x', encoding='utf-8', newline='\n') as handle:
        json.dump(result, handle, indent=2)
print(json.dumps(result))
