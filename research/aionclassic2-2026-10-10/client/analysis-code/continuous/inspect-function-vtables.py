"""Bind selected function pointers to validated original MSVC RTTI vtables, not runtime calls."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

parser = argparse.ArgumentParser()
parser.add_argument('--extra-target', action='append', default=[])
parser.add_argument('--output', type=Path)
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
assert not args.extra_target or args.output is not None, 'Extra targets require a separate explicit output'
assert args.output is None or args.output.is_absolute(), 'Output must be absolute'
args.extra_target = [hex(int(target, 16)) for target in args.extra_target]

study = Path(__file__).resolve().parents[3]
data = (study / 'samples/Game.dll').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786'
pe = struct.unpack_from('<I', data, 0x3c)[0]
optional = pe+24
base = struct.unpack_from('<Q', data, optional+24)[0]
size = struct.unpack_from('<H', data, pe+20)[0]
sections = []
for index in range(struct.unpack_from('<H', data, pe+6)[0]):
    position = optional+size+40*index
    virtual_size, rva, raw_size, raw = struct.unpack_from('<IIII', data, position+8)
    flags = struct.unpack_from('<I', data, position+36)[0]
    sections.append({'rva': rva, 'size': raw_size, 'raw': raw, 'flags': hex(flags), 'executable': bool(flags & 0x20000000)})

def offset(rva, length=1):
    for section in sections:
        if section['rva'] <= rva and rva+length <= section['rva']+section['size']:
            return section['raw']+rva-section['rva']
    raise ValueError('Unmapped RVA')

def executable(value):
    return any(section['executable'] and base+section['rva'] <= value < base+section['rva']+section['size']
               for section in sections)

def locator(value):
    rva = value-base
    if rva < 0:
        return None
    try:
        signature, displacement, cd, descriptor, hierarchy, self_rva = struct.unpack_from('<IIIIII', data, offset(rva, 24))
        if signature != 1 or self_rva != rva:
            return None
        name_start = offset(descriptor, 17)+16
        name_end = data.index(0, name_start)
        name = data[name_start:name_end].decode('ascii')
        if not name.startswith(('.?AV', '.?AU')):
            return None
        offset(hierarchy, 16)
        return {'typeName': name, 'subobjectOffset': displacement, 'locatorRva': hex(rva)}
    except (ValueError, UnicodeDecodeError, struct.error):
        return None

tables = []
for section in sections:
    for raw in range(section['raw'], section['raw']+section['size']-8, 8):
        found = locator(struct.unpack_from('<Q', data, raw)[0])
        if found is None:
            continue
        entries = []
        position = raw+8
        while position+8 <= section['raw']+section['size']:
            value = struct.unpack_from('<Q', data, position)[0]
            if not executable(value) or locator(value) is not None:
                break
            entries.append(value)
            position += 8
        if entries:
            tables.append({**found, 'tableRva': hex(section['rva']+raw+8-section['raw']),
                'fileOffset': hex(raw+8), 'entries': entries})

owners = json.loads((study / 'evidence/continuous/20261012-session-a/state-possible-writer-owners.json').read_text())['owners']
targets = set(owners)
targets.update(['0x180105910', '0x180115e90', '0x1801ddf60', '0x18029c9d0', '0x1802ef730',
                '0x180344d50', '0x1805e0230', '0x1800638e0', '0x1804bb4c0', '0x1804b0f00'])
targets.update(hex(int(target, 16)) for target in args.extra_target)
bindings = []
for target in sorted(targets):
    matches = []
    for table in tables:
        for slot, value in enumerate(table['entries']):
            if value == int(target, 16):
                matches.append({key: table[key] for key in ['typeName', 'subobjectOffset', 'locatorRva', 'tableRva', 'fileOffset']} |
                    {'slotOffset': hex(slot*8), 'pointerFileOffset': hex(int(table['fileOffset'], 16)+slot*8)})
    bindings.append({'function': target, 'bindings': matches})
result = {'source': 'Auxiliary original-PE RTTI and function-pointer reader', 'targetSha256': digest,
    'imagebase': hex(base), 'targetExecuted': False, 'sections': sections, 'validatedVtables': len(tables),
    'selectedFunctions': len(targets), 'functions': bindings,
    'limitations': ['Vtable bindings describe the original PE, not a sampled runtime object or actual caller.',
        'A function may write an argument or member pointer rather than its own this object.',
        'The protected PE marks data-containing sections executable; flags alone cannot identify code.',
        'Contiguous entries are bounded by mapped/executable pointer ranges and the next validated RTTI locator.',
        'Only selected function pointers establish bindings; other adjacent entries are not independently decoded.',
        'Tables with unsupported RTTI or unmapped entries are not treated as complete coverage.',
        'No binding does not establish that a function lacks indirect callers.']}
output = args.output or study / 'evidence/continuous/20261012-state-audit/original-state-function-vtable-bindings.json'
if args.check:
    assert json.loads(output.read_text(encoding='utf-8')) == result
else:
    with output.open('x', encoding='utf-8', newline='\n') as handle:
        json.dump(result, handle, indent=2)
print(json.dumps({'validatedVtables': len(tables), 'selectedFunctions': len(targets),
    'selectedBindings': [row for row in bindings if row['function'] in (args.extra_target or ['0x1800638e0', '0x18029c9d0', '0x1805e0230', '0x18017e340', '0x180581b40'])]}))
