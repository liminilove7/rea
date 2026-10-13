"""Resolve the original Game object passed to ScriptDLL GetInterface."""
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
    if row['sample'] == 'Game.dll')
data = (study / meta['source']).read_bytes()
assert hashlib.sha256(data).hexdigest() == meta['targetSha256']
base = int(meta['imagebase'], 16)

def offset(rva, size=1):
    matches = [row for row in meta['sections'] if row['rva'] <= rva and rva+size <= row['rva']+row['rawSize']]
    assert len(matches) == 1
    return matches[0]['fileOffset']+rva-matches[0]['rva']

object_rva = 0x938a90
vtable_rva = struct.unpack_from('<Q', data, offset(object_rva, 8))[0]-base
locator_rva = struct.unpack_from('<Q', data, offset(vtable_rva-8, 8))[0]-base
signature, subobject, constructor, type_rva, hierarchy_rva, self_rva = struct.unpack_from('<6I', data, offset(locator_rva, 24))
assert signature == 1 and self_rva == locator_rva and subobject == 0
type_raw = offset(type_rva+16)
type_end = data.index(b'\0', type_raw)
offset(type_rva+16, type_end-type_raw+1)
type_name = data[type_raw:type_end].decode('ascii')
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
result = {'source': 'Auxiliary original Game.dll object and MSVC RTTI reader, anchored to saved REA factory RCX LEA',
    'targetSha256': meta['targetSha256'], 'imagebase': hex(base), 'nativeTargetExecuted': False,
    'objectRva': hex(object_rva), 'objectPointerFileOffset': hex(offset(object_rva, 8)),
    'vtableRva': hex(vtable_rva), 'locatorRva': hex(locator_rva), 'typeName': type_name,
    'typeRva': hex(type_rva), 'hierarchyRva': hex(hierarchy_rva), 'functions': functions,
    'stoppingCell': {'rva': hex(cursor), 'value': hex(value)},
    'limitations': ['Preferred addresses and original object bytes do not prove the actual loaded module or patched runtime vtable.',
        'Adjacent pointers in a broadly executable section need REA body checks, not only executable membership.',
        'This is the caller adapter in the provided client; no current server implementation is present.']}
output = root / '20261013-game-script-binding/original-game-script-caller-rtti.json'
if args.check:
    assert json.loads(output.read_text(encoding='utf-8')) == result
else:
    with output.open('x', encoding='utf-8', newline='\n') as handle:
        json.dump(result, handle, indent=2)
print(json.dumps({'typeName': type_name, 'vtableRva': hex(vtable_rva), 'functions': functions}))
