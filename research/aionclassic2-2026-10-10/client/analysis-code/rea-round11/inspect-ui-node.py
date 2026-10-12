"""Locate the UIChainNode table from a previously observed RIP-relative LEA.

This is an original-PE byte observation, not runtime memory or REA Evidence.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--target', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
data = args.target.read_bytes()
sha = hashlib.sha256(data).hexdigest()
assert sha == '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786'
pe = struct.unpack_from('<I', data, 0x3C)[0]
assert data[pe:pe + 4] == b'PE\0\0'
count = struct.unpack_from('<H', data, pe + 6)[0]
optional_size = struct.unpack_from('<H', data, pe + 20)[0]
assert struct.unpack_from('<H', data, pe + 24)[0] == 0x20B
base = struct.unpack_from('<Q', data, pe + 48)[0]
sections = []
for i in range(count):
    _, rva, raw_size, raw_offset = struct.unpack_from('<IIII', data, pe + 24 + optional_size + i * 40 + 8)
    assert raw_offset + raw_size <= len(data)
    sections.append((rva, raw_size, raw_offset))


def read(rva, length):
    matches = [s for s in sections if s[0] <= rva and rva + length <= s[0] + s[1]]
    if len(matches) != 1:
        raise ValueError('Requested bytes have no unique raw mapping')
    offset = matches[0][2] + rva - matches[0][0]
    raw = data[offset:offset + length]
    return {'rva': hex(rva), 'preferred_va': hex(base + rva),
            'file_offset': hex(offset), 'bytes_hex': raw.hex()}, raw


instruction, raw = read(0x27FEA2, 7)
assert raw[:3] == bytes.fromhex('488d05')
table_rva = 0x27FEA2 + 7 + struct.unpack_from('<i', raw, 3)[0]
entries = []
for index in range(3):
    location, raw = read(table_rva + index * 8, 8)
    entries.append({'index': index, **location, 'original_qword': hex(struct.unpack('<Q', raw)[0])})
result = {'source_path': str(args.target.resolve()), 'source_sha256': sha,
          'provider': 'auxiliary original-PE byte reader', 'target_executed': False,
          'image_base': hex(base), 'lea': instruction, 'derived_table_va': hex(base + table_rva),
          'first_three_qwords': entries,
          'limitations': ['REA instruction naming associates this LEA with UIChainNode.',
                         'Three contiguous pointer values alone do not establish the complete vtable extent.',
                         'Preferred VAs are not observed runtime addresses.']}
with args.output.open('x', encoding='utf-8') as stream:
    json.dump(result, stream, ensure_ascii=False, indent=2)
print(json.dumps({'table_va': result['derived_table_va'], 'entries': entries}))
