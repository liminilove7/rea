"""Bind archived CryEntitySystem CEntity virtual interfaces using original RTTI bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

parser = argparse.ArgumentParser()
parser.add_argument('--check', action='store_true')
parser.add_argument('--sample', choices=['CryEntitySystem.dll', 'CryPhysics.dll'], default='CryEntitySystem.dll')
args = parser.parse_args()
study = Path(__file__).resolve().parents[3]
archive_root = study / 'client/programs/aion-bin64'
manifest = json.loads((archive_root / 'ARCHIVE_MANIFEST.json').read_text(encoding='utf-8'))
entry = next(row for row in manifest['files'] if row['path'] == 'bin64/'+args.sample)
data = (archive_root / entry['path']).read_bytes()
digest = hashlib.sha256(data).hexdigest()
digests = {'CryEntitySystem.dll': 'd99a60818f27bbe7f50ebef6e4ba6026b25b6d062b60db3ad3ae0eace22f4b90',
    'CryPhysics.dll': '7afd2f7080d8180888d47a790acb1e5ae31533ee260c6563e18661057cf7c38f'}
assert digest == entry['sha256'] == digests[args.sample]
assert len(data) == entry['bytes']
inventory = json.loads((study / 'client/inventory/pe-modules.json').read_text(encoding='utf-8'))
inventory_entry = next(row for row in inventory if row['path'].rsplit('\\', 1)[-1] == args.sample)
assert inventory_entry['sha256'] == digest and inventory_entry['bytes'] == len(data)
pe = struct.unpack_from('<I', data, 0x3c)[0]
optional = pe+24
base = struct.unpack_from('<Q', data, optional+24)[0]
optional_size = struct.unpack_from('<H', data, pe+20)[0]
sections = []
for index in range(struct.unpack_from('<H', data, pe+6)[0]):
    position = optional+optional_size+40*index
    virtual_size, rva, size, raw = struct.unpack_from('<IIII', data, position+8)
    flags = struct.unpack_from('<I', data, position+36)[0]
    sections.append({'rva': rva, 'rawSize': size, 'fileOffset': raw, 'virtualSize': virtual_size,
        'flags': hex(flags), 'executable': bool(flags & 0x20000000)})

def offset(rva, size=1):
    matches = [row for row in sections if row['rva'] <= rva and rva+size <= row['rva']+row['rawSize']]
    if len(matches) != 1:
        raise ValueError('Unmapped original RVA')
    return matches[0]['fileOffset']+rva-matches[0]['rva']

def executable(value):
    return any(row['executable'] and base+row['rva'] <= value < base+row['rva']+row['rawSize'] for row in sections)

def locator(value):
    rva = value-base
    if rva < 0:
        return None
    try:
        signature, subobject, constructor, type_rva, hierarchy, self_rva = struct.unpack_from('<6I', data, offset(rva, 24))
        if signature != 1 or self_rva != rva:
            return None
        start = offset(type_rva+16)
        end = data.index(b'\0', start)
        name = data[start:end].decode('ascii')
        offset(type_rva+16, end-start+1)
        if not name.startswith(('.?AV', '.?AU')):
            return None
        return {'typeName': name, 'locatorRva': hex(rva), 'typeRva': hex(type_rva),
            'subobjectOffset': subobject, 'hierarchyRva': hex(hierarchy)}
    except (ValueError, struct.error, UnicodeDecodeError):
        return None

tables, types = [], set()
for section in sections:
    for raw in range(section['fileOffset'], section['fileOffset']+section['rawSize']-8, 8):
        found = locator(struct.unpack_from('<Q', data, raw)[0])
        if found is None:
            continue
        types.add(found['typeName'])
        selected_names = ['CEntity'] if args.sample == 'CryEntitySystem.dll' else ['PhysicalEntity', 'LivingEntity', 'RigidEntity']
        if not any(name in found['typeName'] for name in selected_names):
            continue
        table_rva = section['rva']+raw+8-section['fileOffset']
        functions, cursor = [], raw+8
        while cursor+8 <= section['fileOffset']+section['rawSize']:
            value = struct.unpack_from('<Q', data, cursor)[0]
            if not executable(value) or locator(value) is not None:
                break
            functions.append({'slotOffset': hex(cursor-raw-8), 'preferredVa': hex(value),
                'pointerFileOffset': hex(cursor)})
            cursor += 8
        tables.append({**found, 'vtableRva': hex(table_rva), 'functions': functions})
required_type = '.?AVCEntity@@' if args.sample == 'CryEntitySystem.dll' else '.?AVCLivingEntity@@'
assert any(row['typeName'] == required_type and row['subobjectOffset'] == 0 for row in tables)
result = {'source': 'Auxiliary original archived '+args.sample.removesuffix('.dll')+' PE RTTI and virtual pointer reader',
    'sourcePath': 'client/programs/aion-bin64/bin64/'+args.sample, 'targetSha256': digest,
    'sourceArchiveManifestEntry': entry, 'imagebase': hex(base), 'nativeGameExecuted': False,
    'sections': sections, 'observedRttiTypes': sorted(types), 'selectedTables': tables,
    'limitations': ['Contiguous executable pointers are candidates, not a complete C++ ABI proof.',
        'Original CEntity table does not prove the live linked entity has this implementation.',
        'Game and CryEntitySystem share a preferred base but belong to separate modules.',
        'Selected targets need saved REA body analysis before attributing position, direction or physics effects.']}
directory = '20261013-entity-motion-interface' if args.sample == 'CryEntitySystem.dll' else '20261013-physics-motion-interface'
output = study / 'evidence/continuous' / directory / 'original-entity-motion-vtables.json'
if args.check:
    assert json.loads(output.read_text(encoding='utf-8')) == result
else:
    with output.open('x', encoding='utf-8', newline='\n') as handle:
        json.dump(result, handle, indent=2)
print(json.dumps({'digest': digest, 'CEntityTables': [{'type': row['typeName'], 'subobjectOffset': row['subobjectOffset'],
    'vtableRva': row['vtableRva'], 'motionSlots': [slot for slot in row['functions']
        if slot['slotOffset'] in (['0x8', '0x10', '0x178', '0x298', '0x478'] if args.sample == 'CryEntitySystem.dll' else ['0x18', '0x20'])]} for row in tables]}))
