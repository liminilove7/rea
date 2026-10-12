"""Bind a REA-observed compiled script constructor to its original LEA, RTTI and vtable."""
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

constructor_lea = 0x172f86
instruction = data[offset(constructor_lea, 7):offset(constructor_lea, 7)+7]
assert instruction[:3] == b'\x48\x8d\x05'
vtable_rva = constructor_lea+7+struct.unpack_from('<i', instruction, 3)[0]
locator_va = struct.unpack_from('<Q', data, offset(vtable_rva-8, 8))[0]
locator_rva = locator_va-base
signature, subobject, constructor, type_rva, hierarchy, self_rva = struct.unpack_from('<6I', data, offset(locator_rva, 24))
assert signature == 1 and self_rva == locator_rva and subobject == 0
type_raw = offset(type_rva+16)
type_end = data.index(b'\0', type_raw)
offset(type_rva+16, type_end-type_raw+1)
type_name = data[type_raw:type_end].decode('ascii')
assert type_name == '.?AVCLDF4a_Mob_MDamage@@'
script_name = 'LDF4a_Mob_MDamage'
name_rva = 0xa529a8
encoded = script_name.encode('utf-16le')+b'\0\0'
assert data[offset(name_rva, len(encoded)):offset(name_rva, len(encoded))+len(encoded)] == encoded
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
result = {'source': 'Auxiliary original ScriptDLL64 bytes anchored to saved REA constructor instructions',
    'targetSha256': meta['targetSha256'], 'nativeTargetExecuted': False, 'imagebase': meta['imagebase'],
    'scriptName': script_name, 'nameRva': hex(name_rva), 'nameRepresentation': 'UTF-16LE with NUL terminator',
    'nameOriginalBytes': encoded.hex(), 'constructorLeaRva': hex(constructor_lea), 'constructorLeaBytes': instruction.hex(),
    'vtableRva': hex(vtable_rva), 'locatorRva': hex(locator_rva), 'typeName': type_name,
    'typeRva': hex(type_rva), 'subobjectOffset': subobject, 'functions': functions,
    'stoppingCell': {'rva': hex(cursor), 'value': hex(value)},
    'limitations': ['Static constructor and class name bind this compiled script, not a current in-game instance.',
        'A script named MDamage is not automatically the general magic damage or current-server calculation formula.',
        'Vtable pointer candidates stop at the first non-code pointer and require REA body analysis for semantics.']}
output = root / '20261012-script-interface/original-magic-damage-script-binding.json'
if args.check:
    assert json.loads(output.read_text(encoding='utf-8')) == result
else:
    with output.open('x', encoding='utf-8', newline='\n') as handle:
        json.dump(result, handle, indent=2)
print(json.dumps({'scriptName': script_name, 'typeName': type_name, 'vtableRva': hex(vtable_rva),
    'functions': functions, 'stoppingCell': result['stoppingCell']}))
