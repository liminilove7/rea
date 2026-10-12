"""Bind the SkillItem constructor's original RIP-relative LEA to selected vtable slots."""
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
size = struct.unpack_from('<H', data, pe+20)[0]
sections = []
for index in range(struct.unpack_from('<H', data, pe+6)[0]):
    virtual_size, rva, raw_size, raw = struct.unpack_from('<IIII', data, optional+size+40*index+8)
    sections.append((rva, raw_size, raw))

def offset(rva):
    for start, length, raw in sections:
        if start <= rva < start+length:
            return raw+rva-start
    raise ValueError('Unmapped RVA')

instruction = 0x3a198e
raw = offset(instruction)
assert data[raw:raw+3] == bytes.fromhex('488d05')
table = instruction+7+struct.unpack_from('<i', data, raw+3)[0]
slots = {hex(slot): hex(struct.unpack_from('<Q', data, offset(table)+slot)[0])
    for slot in [0, 8, 0x10, 0x18, 0x20]}
next_locator = struct.unpack_from('<Q', data, offset(table)+0x28)[0]-base
assert struct.unpack_from('<I', data, offset(next_locator))[0] == 1
assert struct.unpack_from('<I', data, offset(next_locator)+20)[0] == next_locator
locator = struct.unpack_from('<Q', data, offset(table)-8)[0]-base
signature, locator_offset, cd_offset, descriptor, hierarchy, self_rva = struct.unpack_from('<IIIIII', data, offset(locator))
assert signature == 1 and self_rva == locator
name_start = offset(descriptor)+16
name_end = data.index(0, name_start)
result = {'targetSha256': digest, 'imagebase': hex(base), 'targetExecuted': False,
    'constructor': '0x1803a1940', 'bindingInstruction': hex(base+instruction),
    'bindingBytes': data[raw:raw+7].hex(), 'vtable': hex(base+table), 'slots': slots,
    'rttiTypeName': data[name_start:name_end].decode('ascii'),
    'limitations': ['Original PE vtable, not captured runtime memory.',
                   'Selected slots do not prove every virtual caller or runtime modification.',
                   'The next QWORD after +0x20 is another RTTI locator, not a SkillItem method.']}
output = study / 'evidence/continuous/20261012-chain-value/original-skill-item-vtable.json'
if '--check' in sys.argv[1:]:
    assert json.loads(output.read_text(encoding='utf-8')) == result
else:
    with output.open('x', encoding='utf-8', newline='\n') as handle:
        json.dump(result, handle, indent=2)
print(json.dumps(result))
