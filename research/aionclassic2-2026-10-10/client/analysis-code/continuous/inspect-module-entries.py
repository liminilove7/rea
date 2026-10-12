"""Identity-locked original PE entry/export/import/TLS metadata; no native execution."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
assert args.output.is_absolute()
study = Path(__file__).resolve().parents[3]
identities = {
    'Game.dll': '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786',
    'CrySystem.dll': '8705aeef77411a28e178832f2f242128b0b018b9546f58878c9e69df8f4e9061',
    'ScriptDLL64.dll': 'ea42f2e51de3d46b14e958f11c4f33dc9e78a92cf62765c6a42f0cb79584ca27',
    'Aion.bin': '17c8de936526f119e16c1923ba5922d3a524698f04c01562fc878424653cda1e',
}
modules = []
for sample, digest in identities.items():
    data = (study / 'samples' / sample).read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    assert data[pe:pe+4] == b'PE\0\0'
    machine, section_count = struct.unpack_from('<HH', data, pe+4)
    assert machine == 0x8664
    optional, optional_size = pe+24, struct.unpack_from('<H', data, pe+20)[0]
    assert struct.unpack_from('<H', data, optional)[0] == 0x20b
    entry = struct.unpack_from('<I', data, optional+16)[0]
    base = struct.unpack_from('<Q', data, optional+24)[0]
    sections = []
    for index in range(section_count):
        position = optional+optional_size+40*index
        virtual_size, rva, raw_size, raw = struct.unpack_from('<IIII', data, position+8)
        assert raw+raw_size <= len(data)
        sections.append({'name': data[position:position+8].rstrip(b'\0').decode('ascii'),
            'rva': rva, 'virtualSize': virtual_size, 'rawSize': raw_size, 'fileOffset': raw,
            'characteristics': hex(struct.unpack_from('<I', data, position+36)[0])})

    def offset(rva, size=1):
        matches = [row for row in sections if row['rva'] <= rva and rva+size <= row['rva']+row['rawSize']]
        assert len(matches) == 1, 'RVA must have one original file-backed mapping'
        return matches[0]['fileOffset']+rva-matches[0]['rva']

    def cstring(rva):
        start = offset(rva)
        end = data.index(b'\0', start)
        offset(rva, end-start+1)
        return data[start:end].decode('ascii')

    directory_count = struct.unpack_from('<I', data, optional+108)[0]

    def directory(index):
        return struct.unpack_from('<II', data, optional+112+8*index) if index < directory_count else (0, 0)

    exports = []
    export_rva, export_size = directory(0)
    if export_rva:
        export_offset = offset(export_rva, 40)
        ordinal_base, function_count, name_count, functions, names, ordinals = struct.unpack_from('<6I', data, export_offset+16)
        name_by_index = {}
        for index in range(name_count):
            name_rva = struct.unpack_from('<I', data, offset(names+4*index, 4))[0]
            ordinal_index = struct.unpack_from('<H', data, offset(ordinals+2*index, 2))[0]
            assert ordinal_index < function_count
            name_by_index[ordinal_index] = cstring(name_rva)
        for index in range(function_count):
            function_rva = struct.unpack_from('<I', data, offset(functions+4*index, 4))[0]
            if function_rva == 0:
                continue
            forwarded = export_rva <= function_rva < export_rva+export_size
            exports.append({'ordinal': ordinal_base+index, 'name': name_by_index.get(index),
                'rva': hex(function_rva), 'preferredVa': hex(base+function_rva),
                'forwarder': cstring(function_rva) if forwarded else None,
                'originalBytes': None if forwarded else data[offset(function_rva, 16):offset(function_rva, 16)+16].hex()})
    imports = []
    import_rva, import_size = directory(1)
    if import_rva:
        for index in range(import_size//20):
            descriptor = struct.unpack_from('<5I', data, offset(import_rva+20*index, 20))
            if not any(descriptor):
                break
            original, timestamp, forwarder, name_rva, first = descriptor
            table = original or first
            symbols = []
            position = 0
            while True:
                value = struct.unpack_from('<Q', data, offset(table+8*position, 8))[0]
                if value == 0:
                    break
                symbols.append({'name': None if value>>63 else cstring(value+2),
                    'ordinal': value & 0xffff if value>>63 else None, 'iatRva': hex(first+8*position)})
                position += 1
            imports.append({'module': cstring(name_rva), 'symbols': symbols})
    tls = None
    tls_rva, tls_size = directory(9)
    if tls_rva:
        assert tls_size >= 40
        raw_start, raw_end, index_va, callbacks_va, zero_fill, flags = struct.unpack_from('<4Q2I', data, offset(tls_rva, 40))
        callbacks = []
        if callbacks_va:
            cursor = callbacks_va-base
            while True:
                callback = struct.unpack_from('<Q', data, offset(cursor, 8))[0]
                if not callback:
                    break
                callbacks.append(hex(callback))
                cursor += 8
        tls = {'directoryRva': hex(tls_rva), 'rawStartVa': hex(raw_start), 'rawEndVa': hex(raw_end),
            'indexVa': hex(index_va), 'callbacksVa': hex(callbacks_va), 'callbacks': callbacks,
            'zeroFill': zero_fill, 'characteristics': hex(flags)}
    modules.append({'sample': sample, 'source': 'samples/'+sample, 'targetSha256': digest, 'size': len(data),
        'machine': hex(machine), 'imagebase': hex(base), 'entryRva': hex(entry), 'entryVa': hex(base+entry),
        'entryOriginalBytes': data[offset(entry, 16):offset(entry, 16)+16].hex(),
        'sections': sections, 'exports': exports, 'imports': imports, 'tls': tls})
result = {'source': 'Auxiliary original PE metadata reader', 'nativeTargetExecuted': False, 'modules': modules,
    'limitations': ['Original import/export/TLS metadata does not establish protection-time or loader-time resolved pointers.',
        'Section characteristics and entry bytes do not prove every function is decoded or semantically audited.',
        'Each module has an independent address space and identity; equal virtual addresses are not cross-module equivalence.']}
if args.check:
    assert json.loads(args.output.read_text(encoding='utf-8')) == result
else:
    with args.output.open('x', encoding='utf-8', newline='\n') as handle:
        json.dump(result, handle, indent=2)
print(json.dumps([{'sample': row['sample'], 'entryVa': row['entryVa'], 'exportCount': len(row['exports']),
    'importCount': sum(len(module['symbols']) for module in row['imports']), 'tlsCallbacks': row['tls']['callbacks'] if row['tls'] else []}
    for row in modules]))
