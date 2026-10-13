"""Bind archived CryAnimation character slots to original PE RTTI bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

parser = argparse.ArgumentParser()
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
study = Path(__file__).resolve().parents[3]
archive = study / 'client/programs/aion-bin64'
name = 'CryAnimation.dll'
entry = next(row for row in json.loads((archive / 'ARCHIVE_MANIFEST.json').read_text(encoding='utf-8'))['files']
             if row['path'] == 'bin64/' + name)
data = (archive / entry['path']).read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == entry['sha256'] == '32f492dc373e22aa43647546b888e0420044b84a7039a40dc99f6e91b5a637ac'
assert len(data) == entry['bytes']
inventory = json.loads((study / 'client/inventory/pe-modules.json').read_text(encoding='utf-8'))
assert next(row for row in inventory if row['path'].rsplit('\\', 1)[-1] == name)['sha256'] == digest
pe = struct.unpack_from('<I', data, 0x3c)[0]
optional = pe + 24
base = struct.unpack_from('<Q', data, optional + 24)[0]
optional_size = struct.unpack_from('<H', data, pe + 20)[0]
sections = []
for index in range(struct.unpack_from('<H', data, pe + 6)[0]):
    at = optional + optional_size + 40 * index
    virtual_size, rva, raw_size, raw = struct.unpack_from('<IIII', data, at + 8)
    flags = struct.unpack_from('<I', data, at + 36)[0]
    sections.append({'rva': rva, 'rawSize': raw_size, 'fileOffset': raw,
                     'virtualSize': virtual_size, 'executable': bool(flags & 0x20000000)})

def file_offset(rva, size=1):
    matches = [s for s in sections if s['rva'] <= rva and rva + size <= s['rva'] + s['rawSize']]
    if len(matches) != 1:
        raise ValueError('Unmapped original RVA')
    return matches[0]['fileOffset'] + rva - matches[0]['rva']

def executable(va):
    return any(s['executable'] and base + s['rva'] <= va < base + s['rva'] + s['rawSize'] for s in sections)

def locator(va):
    rva = va - base
    if rva < 0:
        return None
    try:
        signature, subobject, _, type_rva, _, self_rva = struct.unpack_from('<6I', data, file_offset(rva, 24))
        if signature != 1 or self_rva != rva:
            return None
        start = file_offset(type_rva + 16)
        end = data.index(b'\0', start)
        type_name = data[start:end].decode('ascii')
        file_offset(type_rva + 16, end - start + 1)
        if not type_name.startswith(('.?AV', '.?AU')):
            return None
        return {'typeName': type_name, 'subobjectOffset': subobject, 'locatorRva': hex(rva)}
    except (ValueError, struct.error, UnicodeDecodeError):
        return None

tables = []
for section in sections:
    end = section['fileOffset'] + section['rawSize']
    for raw in range(section['fileOffset'], end - 8, 8):
        meta = locator(struct.unpack_from('<Q', data, raw)[0])
        if meta is None or 'CryCharInstance' not in meta['typeName']:
            continue
        functions = []
        cursor = raw + 8
        while cursor + 8 <= end:
            va = struct.unpack_from('<Q', data, cursor)[0]
            if not executable(va) or locator(va) is not None:
                break
            functions.append({'slotOffset': hex(cursor - raw - 8), 'preferredVa': hex(va),
                              'pointerFileOffset': hex(cursor)})
            cursor += 8
        tables.append({**meta, 'vtableRva': hex(section['rva'] + raw + 8 - section['fileOffset']),
                       'functions': functions})

assert tables and any(t['subobjectOffset'] == 0 for t in tables)
result = {'source': 'Original archived CryAnimation PE RTTI and virtual pointer reader',
          'sourcePath': 'client/programs/aion-bin64/bin64/' + name, 'targetSha256': digest,
          'imagebase': hex(base), 'nativeGameExecuted': False,
          'selectedTables': tables,
          'limitations': ['CryCharInstance RTTI binds implementation slots; the Game caller receiver type still needs its own path binding.',
                          'Contiguous executable pointers are vtable candidates, not a complete C++ ABI proof.',
                          'Game and CryAnimation share a preferred base but are distinct loaded modules.']}
output = study / 'evidence/continuous/20261013-animation-interface/original-character-vtables.json'
if args.check:
    assert json.loads(output.read_text(encoding='utf-8')) == result
else:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x', encoding='utf-8', newline='\n') as handle:
        json.dump(result, handle, indent=2)
print(json.dumps({'digest': digest, 'tables': [
    {'typeName': t['typeName'], 'subobjectOffset': t['subobjectOffset'], 'vtableRva': t['vtableRva'],
     'slot360': next((f for f in t['functions'] if f['slotOffset'] == '0x360'), None)} for t in tables]}))
