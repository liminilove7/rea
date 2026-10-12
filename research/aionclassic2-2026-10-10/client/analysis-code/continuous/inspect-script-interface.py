"""Resolve original ScriptDLL64 GetInterface object, RTTI and bounded vtable entries."""
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

object_rva = 0xdae450
vtable = struct.unpack_from('<Q', data, offset(object_rva, 8))[0]
locator = struct.unpack_from('<Q', data, offset(vtable-base-8, 8))[0]
signature, subobject, constructor, type_rva, hierarchy_rva, self_rva = struct.unpack_from('<6I', data, offset(locator-base, 24))
assert signature == 1 and self_rva == locator-base
assert subobject == 0
type_raw = offset(type_rva+16)
type_end = data.index(b'\0', type_raw)
offset(type_rva+16, type_end-type_raw+1)
type_name = data[type_raw:type_end].decode('ascii')
assert type_name.startswith('.?AV') or type_name.startswith('.?AU')
functions = []
cursor = vtable-base
while True:
    value = struct.unpack_from('<Q', data, offset(cursor, 8))[0]
    code_sections = [row for row in meta['sections'] if row['rva'] <= value-base < row['rva']+row['rawSize']
        and int(row['characteristics'], 16) & 0x20000000]
    if len(code_sections) != 1:
        break
    functions.append({'slotOffset': hex(cursor-(vtable-base)), 'pointerFileOffset': hex(offset(cursor, 8)),
        'preferredVa': hex(value), 'originalFunctionBytes': data[offset(value-base, 16):offset(value-base, 16)+16].hex()})
    cursor += 8
result = {'source': 'Auxiliary original ScriptDLL64 object and MSVC RTTI reader',
    'targetSha256': meta['targetSha256'], 'imagebase': meta['imagebase'], 'nativeTargetExecuted': False,
    'returnedObjectRva': hex(object_rva), 'returnedObjectFileOffset': hex(offset(object_rva, 8)),
    'originalVtableVa': hex(vtable), 'locatorVa': hex(locator), 'locatorFileOffset': hex(offset(locator-base, 24)),
    'locator': {'signature': signature, 'subobjectOffset': subobject, 'constructorDisplacement': constructor,
        'typeRva': hex(type_rva), 'hierarchyRva': hex(hierarchy_rva), 'selfRva': hex(self_rva)},
    'typeName': type_name, 'functions': functions,
    'stoppingCell': {'rva': hex(cursor), 'value': hex(value)},
    'limitations': ['Original RTTI and vtable describe a static object; runtime callers and initialization are not captured.',
        'Function-pointer extent stops at the first non-code pointer; it is not a complete class ABI proof.',
        'Executable mapping is a pointer candidate check; function semantics require corresponding REA analysis.']}
output = root / '20261012-script-interface/original-script-interface-rtti.json'
if args.check:
    assert json.loads(output.read_text(encoding='utf-8')) == result
else:
    with output.open('x', encoding='utf-8', newline='\n') as handle:
        json.dump(result, handle, indent=2)
print(json.dumps({'typeName': type_name, 'functions': functions, 'stoppingCell': result['stoppingCell']}))
