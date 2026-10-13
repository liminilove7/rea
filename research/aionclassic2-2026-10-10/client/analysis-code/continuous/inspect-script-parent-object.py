"""Bind the shared original constructor LEA to CMonster RTTI and vtable."""
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
    if row['sample'] == 'ScriptDLL64.dll')
data = (study / meta['source']).read_bytes()
assert hashlib.sha256(data).hexdigest() == meta['targetSha256']
base = int(meta['imagebase'], 16)

def offset(rva, size=1):
    matches = [row for row in meta['sections'] if row['rva'] <= rva and rva+size <= row['rva']+row['rawSize']]
    assert len(matches) == 1
    return matches[0]['fileOffset']+rva-matches[0]['rva']

lea_rva = 0x1c507f
raw = offset(lea_rva, 7)
instruction = data[raw:raw+7]
assert instruction[:3] == b'\x48\x8d\x05'
vtable_rva = lea_rva+7+struct.unpack_from('<i', instruction, 3)[0]
locator_rva = struct.unpack_from('<Q', data, offset(vtable_rva-8, 8))[0]-base
signature, subobject, constructor, type_rva, hierarchy_rva, self_rva = struct.unpack_from('<6I', data, offset(locator_rva, 24))
assert signature == 1 and self_rva == locator_rva and subobject == 0
type_raw = offset(type_rva+16)
type_end = data.index(b'\0', type_raw)
offset(type_rva+16, type_end-type_raw+1)
type_name = data[type_raw:type_end].decode('ascii')
assert type_name == '.?AVCMonster@@'
functions = []
cursor = vtable_rva
while True:
    value = struct.unpack_from('<Q', data, offset(cursor, 8))[0]
    code = [row for row in meta['sections'] if row['rva'] <= value-base < row['rva']+row['rawSize']
        and int(row['characteristics'], 16) & 0x20000000]
    if len(code) != 1:
        break
    functions.append({'slotOffset': hex(cursor-vtable_rva), 'pointerFileOffset': hex(offset(cursor, 8)),
        'preferredVa': hex(value)})
    cursor += 8
initializer_cell = 0x97b388
assert struct.unpack_from('<Q', data, offset(initializer_cell, 8))[0] == base+0x1c5060
result = {'source': 'Auxiliary original ScriptDLL64 constructor LEA, RTTI and pointer reader',
    'targetSha256': meta['targetSha256'], 'imagebase': hex(base), 'nativeTargetExecuted': False,
    'objectRva': '0xf054b0', 'constructorRva': '0x1c5060', 'constructorLeaRva': hex(lea_rva),
    'constructorLeaBytes': instruction.hex(), 'vtableRva': hex(vtable_rva), 'locatorRva': hex(locator_rva),
    'typeName': type_name, 'typeRva': hex(type_rva), 'hierarchyRva': hex(hierarchy_rva),
    'initializerPointerCellRva': hex(initializer_cell), 'initializerPointerBytes': data[offset(initializer_cell, 8):offset(initializer_cell, 8)+8].hex(),
    'functions': functions, 'stoppingCell': {'rva': hex(cursor), 'value': hex(value)},
    'limitations': ['A file pointer to an initializer does not prove the protected loader invokes it.',
        'The CMonster type belongs to ScriptDLL64 and is not a Game.dll runtime monster identity.',
        'The +0xA8 parent-like link needs consumers to prove semantic inheritance or fallback execution.']}
output = root / '20261012-script-descriptors/original-shared-script-parent-object.json'
if args.check:
    assert json.loads(output.read_text(encoding='utf-8')) == result
else:
    with output.open('x', encoding='utf-8', newline='\n') as handle:
        json.dump(result, handle, indent=2)
print(json.dumps({'typeName': type_name, 'vtableRva': hex(vtable_rva), 'functions': functions}))
