"""Observe selected clock imports and exported entry points in case PE files."""
import hashlib
import json
import struct
from pathlib import Path

case = Path(__file__).resolve().parents[3]
identities = {
    'Game.dll': '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786',
    'CrySystem.dll': '8705aeef77411a28e178832f2f242128b0b018b9546f58878c9e69df8f4e9061',
}
results = []
for sample, expected in identities.items():
    source = case / 'samples' / sample
    data = source.read_bytes()
    assert hashlib.sha256(data).hexdigest() == expected
    pe = struct.unpack_from('<I', data, 0x3C)[0]
    assert data[pe:pe + 4] == b'PE\0\0'
    count = struct.unpack_from('<H', data, pe + 6)[0]
    optional_size = struct.unpack_from('<H', data, pe + 20)[0]
    assert struct.unpack_from('<H', data, pe + 24)[0] == 0x20B
    base = struct.unpack_from('<Q', data, pe + 48)[0]
    sections = []
    for i in range(count):
        _, rva, raw_size, raw_offset = struct.unpack_from('<IIII', data, pe + 24 + optional_size + i * 40 + 8)
        assert raw_offset + raw_size <= len(data)
        sections.append((rva, raw_size, raw_offset))

    def offset(rva, length=1):
        matches = [s for s in sections if s[0] <= rva and rva + length <= s[0] + s[1]]
        if len(matches) != 1:
            raise ValueError('No unique raw RVA mapping')
        return matches[0][2] + rva - matches[0][0]

    def string(rva):
        start = offset(rva)
        end = data.index(b'\0', start)
        return data[start:end].decode('ascii')

    imports = []
    selected = []
    import_rva, import_size = struct.unpack_from('<II', data, pe + 24 + 120)
    if import_rva:
        for index in range(import_size // 20):
            original, timestamp, forward, name, first = struct.unpack_from('<5I', data, offset(import_rva + index * 20, 20))
            if not any((original, timestamp, forward, name, first)):
                break
            dll = string(name)
            entry_count = 0
            table = original or first
            while True:
                value = struct.unpack_from('<Q', data, offset(table + entry_count * 8, 8))[0]
                if value == 0:
                    break
                imported = {'ordinal': value & 0xFFFF} if value >> 63 else {'name': string(value + 2)}
                if imported.get('name') in ['QueryPerformanceCounter', 'QueryPerformanceFrequency', 'GetTickCount', 'GetTickCount64', 'GetProcAddress', 'LoadLibraryA', 'LoadLibraryW']:
                    selected.append({'dll': dll, **imported, 'iat_rva': hex(first + entry_count * 8),
                        'preferred_va': hex(base + first + entry_count * 8),
                        'file_offset': hex(offset(first + entry_count * 8, 8))})
                entry_count += 1
            imports.append({'dll': dll, 'entry_count': entry_count})
    exports = []
    export_rva, export_size = struct.unpack_from('<II', data, pe + 24 + 112)
    if export_rva:
        directory = offset(export_rva, 40)
        ordinal_base, function_count, name_count, functions, names, ordinals = struct.unpack_from('<6I', data, directory + 16)
        for index in range(name_count):
            name_rva = struct.unpack_from('<I', data, offset(names + index * 4, 4))[0]
            ordinal = struct.unpack_from('<H', data, offset(ordinals + index * 2, 2))[0]
            assert ordinal < function_count
            function_rva = struct.unpack_from('<I', data, offset(functions + ordinal * 4, 4))[0]
            exports.append({'name': string(name_rva), 'ordinal': ordinal + ordinal_base,
                'rva': hex(function_rva), 'preferred_va': hex(base + function_rva),
                'forwarded': export_rva <= function_rva < export_rva + export_size})
    results.append({'source_path': str(source), 'source_sha256': expected, 'imagebase': hex(base),
        'import_descriptors': imports, 'selected_imports': selected, 'named_exports': exports})
output = case / 'evidence/continuous/20261012-cry-timer/original-clock-imports-and-exports.json'
with output.open('x', encoding='utf-8') as stream:
    json.dump({'provider': 'auxiliary original-PE reader', 'targetExecuted': False, 'samples': results,
        'limitations': ['Only original PE descriptors are interpreted; protected import resolution and runtime targets remain separate.',
            'Preferred VAs are not runtime addresses.']}, stream, ensure_ascii=False, indent=2)
print(json.dumps([{'sample': Path(r['source_path']).name, 'selected_imports': r['selected_imports'], 'exports': r['named_exports']} for r in results]))
