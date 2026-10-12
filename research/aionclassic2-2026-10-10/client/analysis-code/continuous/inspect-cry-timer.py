"""Read selected CrySystem RTTI tables from the unchanged case sample.

This auxiliary byte reader does not execute the DLL or establish a runtime vtable.
"""
import hashlib
import json
import struct
from pathlib import Path

case = Path(__file__).resolve().parents[3]
source = case / 'samples/CrySystem.dll'
data = source.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '8705aeef77411a28e178832f2f242128b0b018b9546f58878c9e69df8f4e9061'
pe = struct.unpack_from('<I', data, 0x3C)[0]
assert data[pe:pe + 4] == b'PE\0\0'
count = struct.unpack_from('<H', data, pe + 6)[0]
optional_size = struct.unpack_from('<H', data, pe + 20)[0]
assert struct.unpack_from('<H', data, pe + 24)[0] == 0x20B
base = struct.unpack_from('<Q', data, pe + 48)[0]
sections = []
for i in range(count):
    virtual_size, rva, raw_size, raw_offset = struct.unpack_from(
        '<IIII', data, pe + 24 + optional_size + i * 40 + 8)
    assert raw_offset + raw_size <= len(data)
    sections.append((rva, raw_size, raw_offset, virtual_size))


def rva_at(offset):
    matches = [s for s in sections if s[2] <= offset < s[2] + s[1]]
    if len(matches) != 1:
        raise ValueError('No unique original raw mapping')
    return matches[0][0] + offset - matches[0][2]


tables = []
for name, slot_count in [('CTimer', 10), ('CSystem', 41)]:
    position = data.find(('.?AV' + name + '@@\0').encode())
    if position < 0:
        continue
    descriptor = rva_at(position) - 16
    for section in sections:
        for offset in range(section[2], section[2] + section[1] - 24, 4):
            fields = struct.unpack_from('<6I', data, offset)
            if not (fields[0] == 1 and fields[3] == descriptor and fields[5] == rva_at(offset)):
                continue
            pointer = struct.pack('<Q', base + rva_at(offset))
            start = 0
            while True:
                reference = data.find(pointer, start)
                if reference < 0:
                    break
                start = reference + 1
                if reference + 8 + slot_count * 8 > len(data):
                    continue
                tables.append({'type': name, 'descriptor_rva': hex(descriptor),
                    'col_rva': hex(rva_at(offset)), 'col_bytes': data[offset:offset + 24].hex(),
                    'table_rva': hex(rva_at(reference) + 8), 'table_file_offset': hex(reference + 8),
                    'slots': [{'slot': hex(index * 8), 'file_offset': hex(reference + 8 + index * 8),
                        'bytes_hex': data[reference + 8 + index * 8:reference + 16 + index * 8].hex(),
                        'original_pointer': hex(struct.unpack_from('<Q', data, reference + 8 + index * 8)[0])}
                        for index in range(slot_count)]})
result = {'source_path': str(source), 'source_sha256': digest, 'imagebase': hex(base),
    'provider': 'auxiliary original-PE byte reader', 'targetExecuted': False, 'tables': tables,
    'limitations': ['RTTI identifies these original types; Game.dll interface binding requires separate evidence.',
        'Selected contiguous slots do not establish complete vtable extents.',
        'Preferred VAs are not runtime addresses.']}
output = case / 'evidence/continuous/20261012-cry-timer/original-timer-system-tables.json'
with output.open('x', encoding='utf-8') as stream:
    json.dump(result, stream, ensure_ascii=False, indent=2)
print(json.dumps({'tables': [{'type': t['type'], 'rva': t['table_rva'],
    'selected': [s for s in t['slots'] if s['slot'] in ['0x10', '0x28', '0x138']]}
    for t in tables]}))
