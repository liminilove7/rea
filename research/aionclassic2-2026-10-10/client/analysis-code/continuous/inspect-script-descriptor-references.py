"""Find original RIP-relative references inside PE exception-table code ranges.

This is an auxiliary candidate finder, not an IDA xref substitute or runtime trace.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, __version__

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

def offset(rva, size=1):
    matches = [row for row in meta['sections'] if row['rva'] <= rva and rva+size <= row['rva']+row['rawSize']]
    assert len(matches) == 1, (hex(rva), size)
    return matches[0]['fileOffset']+rva-matches[0]['rva']

pe = struct.unpack_from('<I', data, 0x3c)[0]
optional = pe+24
assert struct.unpack_from('<H', data, optional)[0] == 0x20b
exception_rva, exception_size = struct.unpack_from('<II', data, optional+112+3*8)
assert exception_size % 12 == 0
exception_raw = offset(exception_rva, exception_size)
targets = {0xf054b0: 'Shared CMonster object discovered via MDamage binding', 0x103f710: 'GetInterface external pointer',
    0x103f828: 'compiled script registry', 0xf708a8: 'MDamage descriptor binding'}
descriptor_start, descriptor_end = 0xf054b0, 0xf05550
decoder = Cs(CS_ARCH_X86, CS_MODE_64)
refs, incomplete = [], []
instructions, decoded_bytes, scanned = 0, 0, 0
ranges = []
pattern = re.compile(r'\[rip(?: (\+|-) (0x[0-9a-f]+|[0-9]+))?\]')
for cursor in range(exception_raw, exception_raw+exception_size, 12):
    begin, end, unwind = struct.unpack_from('<III', data, cursor)
    if begin == 0 and end == 0:
        continue
    assert 0 < begin < end
    ranges.append((begin, end, unwind))
    start = offset(begin, end-begin)
    consumed = 0
    for address, size, mnemonic, operands in decoder.disasm_lite(data[start:start+end-begin], base+begin):
        instructions += 1
        consumed += size
        if 'rip' not in operands:
            continue
        for match in pattern.finditer(operands):
            displacement = int(match[2], 0) if match[2] else 0
            if match[1] == '-':
                displacement = -displacement
            target = address+size+displacement-base
            if target not in targets and not descriptor_start <= target < descriptor_end:
                continue
            raw = start+address-base-begin
            refs.append({'rangeBeginRva': hex(begin), 'rangeEndRva': hex(end), 'unwindRva': hex(unwind),
                'instructionRva': hex(address-base), 'instructionVa': hex(address), 'instructionSize': size,
                'fileOffset': hex(raw), 'originalBytes': data[raw:raw+size].hex(), 'mnemonic': mnemonic,
                'operands': operands, 'targetRva': hex(target),
                'targetLabel': targets.get(target, 'Shared CMonster object vicinity')})
    scanned += end-begin
    decoded_bytes += consumed
    if consumed != end-begin:
        incomplete.append({'beginRva': hex(begin), 'endRva': hex(end), 'decodedBytes': consumed,
            'remainingBytes': end-begin-consumed})

data_refs = []
for section in meta['sections']:
    first = (section['rva']+7)&~7
    for rva in range(first, section['rva']+section['rawSize']-7, 8):
        raw = section['fileOffset']+rva-section['rva']
        value = struct.unpack_from('<Q', data, raw)[0]
        if value-base in targets:
            data_refs.append({'rva': hex(rva), 'fileOffset': hex(raw), 'targetRva': hex(value-base),
                'originalBytes': data[raw:raw+8].hex(), 'section': section['name']})
result = {'source': 'Auxiliary Capstone scan of original PE exception-table ranges and aligned QWORDs',
    'targetSha256': meta['targetSha256'], 'imagebase': hex(base), 'nativeTargetExecuted': False,
    'decoderVersion': __version__, 'exceptionDirectory': {'rva': hex(exception_rva), 'size': exception_size},
    'targets': {hex(key): value for key, value in targets.items()},
    'descriptorVicinity': {'startRva': hex(descriptor_start), 'exclusiveEndRva': hex(descriptor_end)},
    'coverage': {'rangeCount': len(ranges), 'rangeBytesIncludingOverlaps': scanned,
        'decodedBytesIncludingOverlaps': decoded_bytes, 'instructionCountIncludingOverlaps': instructions,
        'incompleteRanges': incomplete}, 'ripReferences': refs, 'alignedPointerCandidates': data_refs,
    'limitations': ['Only original file-backed exception-table ranges are decoded; leaf functions without entries are not exhausted.',
        'Linear decoding of each range does not prove reachability or correct boundaries after embedded data.',
        'RIP memory operands and aligned full pointers do not exhaust register-derived, unaligned, RVA, encrypted or runtime references.',
        'Descriptor vicinity is a search window, not a proven object size.',
        'Candidates require saved REA function analysis before interpreting producer or consumer semantics.']}
output = root / '20261012-script-descriptors/original-descriptor-reference-candidates.json'
if args.check:
    assert json.loads(output.read_text(encoding='utf-8')) == result
else:
    with output.open('x', encoding='utf-8', newline='\n') as handle:
        json.dump(result, handle, indent=2)
print(json.dumps({'ranges': len(ranges), 'incompleteRanges': len(incomplete), 'ripReferences': len(refs),
    'alignedPointerCandidates': len(data_refs)}))
