"""Recompute the REA-observed Aion.bin first-page transform, retaining hashes rather than a binary."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

parser = argparse.ArgumentParser()
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
study = Path(__file__).resolve().parents[3]
root = study / 'evidence/continuous'
meta = next(row for row in json.loads((root / 'original-four-module-entries.json').read_text())['modules']
    if row['sample'] == 'Aion.bin')
data = (study / meta['source']).read_bytes()
assert hashlib.sha256(data).hexdigest() == meta['targetSha256']

def offset(rva, size):
    matches = [row for row in meta['sections'] if row['rva'] <= rva and rva+size <= row['rva']+row['rawSize']]
    assert len(matches) == 1
    return matches[0]['fileOffset']+rva-matches[0]['rva']

stub = 0x5e2000

def arithmetic(relative, opcode):
    raw = offset(stub+relative, 6)
    assert data[raw:raw+2] == opcode
    return struct.unpack_from('<I', data, raw+2)[0]

def pushed(relative):
    raw = offset(stub+relative, 5)
    assert data[raw] == 0x68
    return struct.unpack_from('<I', data, raw+1)[0]

subtract_a = arithmetic(0x10, b'\x48\x2d')
subtract_b = arithmetic(0x16, b'\x48\x2d')
add_a = arithmetic(0x1c, b'\x48\x05')
target = stub+9-subtract_a-subtract_b+add_a
assert target == 0x149000
xor_key, add_key = pushed(0x34), pushed(0x2f)
assert data[offset(stub+8, 1)] == 0xcc
length_raw = offset(stub+0x2a, 5)
assert data[length_raw] == 0xbb
length = struct.unpack_from('<I', data, length_raw+1)[0]
assert length == 0x1000
raw_start = offset(target, length)
original = data[raw_start:raw_start+length]
transformed = b''.join(struct.pack('<I', ((word ^ xor_key)+add_key)&0xffffffff)
    for word in struct.unpack('<1024I', original))
inverse = b''.join(struct.pack('<I', ((word-add_key)&0xffffffff)^xor_key)
    for word in struct.unpack('<1024I', transformed))
assert inverse == original
result = {'source': 'Auxiliary original Aion.bin arithmetic reproduction anchored to saved REA bootstrap instructions',
    'targetSha256': meta['targetSha256'], 'nativeTargetExecuted': False, 'emulatedTargetInstructions': False,
    'imagebase': meta['imagebase'], 'stubRva': hex(stub), 'callReturnRva': hex(stub+8),
    'initialReturnByte': 'cc', 'targetRva': hex(target), 'targetFileOffset': hex(raw_start),
    'length': length, 'xorKey': hex(xor_key), 'addKey': hex(add_key), 'continuationRva': hex(target+0x14),
    'formula': 'little-endian DWORD: ((cipher XOR xorKey) + addKey) modulo 2^32',
    'originalPageSha256': hashlib.sha256(original).hexdigest(),
    'transformedPageSha256': hashlib.sha256(transformed).hexdigest(),
    'inverseRoundtripPassed': True, 'transformedContinuationPrefix': transformed[0x14:0x34].hex(),
    'binaryOutputWritten': False,
    'limitations': ['One observed 4096-byte region only; not a reconstructed PE or fully resolved original entry point.',
        'No loader, native API, TLS, protection initialization or runtime state was executed or captured.',
        'This arithmetic reproduction is distinct from REA observations and from software CPU instruction emulation.']}
output = root / '20261012-aion-bootstrap/original-bootstrap-page-reproduction.json'
if args.check:
    assert json.loads(output.read_text(encoding='utf-8')) == result
else:
    with output.open('x', encoding='utf-8', newline='\n') as handle:
        json.dump(result, handle, indent=2)
print(json.dumps({key: result[key] for key in ['targetRva', 'length', 'continuationRva', 'inverseRoundtripPassed', 'transformedPageSha256']}))
