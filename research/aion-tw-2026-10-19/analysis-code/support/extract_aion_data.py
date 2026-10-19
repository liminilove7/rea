"""Export local AION data files with size/CRC checks and optional binary-XML decoding.

Format reference: https://github.com/giordanidev/aion-pak-manager/tree/main/backend/parse
Binary XML layout also documented by https://github.com/gibbed/Gibbed.Aion
All changes are confined to the separate case workspace. Originals remain untouched.
"""
import collections
import hashlib
import json
from pathlib import Path, PurePosixPath
import struct
import xml.etree.ElementTree as ET
import zipfile
import zlib

from aion_pak import SignatureView

LOCAL = Path(__file__).parent
SOURCE = Path(r"F:\SOFTWARE\永恒之塔\aionclassic2")
CASE = Path(r"F:\RVE-Workspace\cases\aionclassic2-2026-10-10")
TABLES = [bytes.fromhex(t) for t in json.loads((LOCAL / 'aion-format-tables.json').read_text())['tables']]
TEXT_TYPES = {'.xml', '.csv', '.cfg', '.ini', '.lua', '.txt', '.html', '.nfo'}


def bxml(data):
    position = 1
    cache = {0: ''}

    def number():
        nonlocal position
        value = 0
        for shift in range(0, 35, 7):
            if position >= len(data):
                raise ValueError('Truncated packed number')
            byte = data[position]
            position += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value
        raise ValueError('Packed integer exceeds 32 bits')

    table_size = number()
    table = data[position:position + table_size]
    if len(table) != table_size or table_size % 2:
        raise ValueError('Invalid UTF-16 string-table bounds')
    position += table_size

    def string():
        index = number()
        if index not in cache:
            start = index * 2
            if start >= len(table):
                raise ValueError('String-table index out of range')
            end = start
            while end + 2 <= len(table) and table[end:end+2] != b'\0\0':
                end += 2
            if end + 2 > len(table):
                raise ValueError('Unterminated UTF-16 string')
            cache[index] = table[start:end].decode('utf-16-le')
        return cache[index]

    def node(depth=0):
        nonlocal position
        if depth > 200:
            raise ValueError('XML nesting exceeds the analysis limit')
        element = ET.Element(string())
        if position >= len(data):
            raise ValueError('Truncated node')
        flags = data[position]
        position += 1
        if flags & ~7:
            raise ValueError('Unknown XML node flags')
        if flags & 1:
            element.text = string()
        if flags & 2:
            for _ in range(number()):
                key = string()
                element.set(key, string())
        if flags & 4:
            for _ in range(number()):
                element.append(node(depth+1))
        return element

    root = node()
    if position != len(data):
        raise ValueError(f'Unconsumed binary XML bytes: {len(data)-position}')
    ET.indent(root)
    output = ET.tostring(root, encoding='utf-8', xml_declaration=True)
    ET.fromstring(output)  # confirm that the exported document is parseable XML
    return output, root.tag, len(root)


def payload(stream, entry, mode_hint=None):
    if entry.file_size > 256 * 1024 * 1024:
        raise ValueError('Entry exceeds the 256 MiB per-file analysis limit')
    stream.seek(entry.header_offset)
    header = struct.unpack('<4s5H3I2H', stream.read(30))
    stream.seek(header[9] + header[10], 1)
    compressed = stream.read(entry.compress_size)
    if len(compressed) != entry.compress_size:
        raise ValueError('Truncated entry payload')
    modes = [mode_hint] if mode_hint is not None else [2, 1, 0]
    for mode in modes:
        block = bytearray(compressed)
        if mode:
            table = TABLES[mode-1]
            offset = (len(block) & 31) * 32 if mode == 1 else len(block) & 1023
            for i in range(min(32, len(block))):
                block[i] ^= table[offset+i]
        try:
            if entry.compress_type == 8:
                decoder = zlib.decompressobj(-15)
                raw = decoder.decompress(block, entry.file_size + 1)
                if not decoder.eof or decoder.unconsumed_tail or decoder.unused_data:
                    continue
            elif entry.compress_type == 0:
                raw = bytes(block)
            else:
                raise ValueError(f'Unsupported compression method {entry.compress_type}')
        except zlib.error:
            continue
        if len(raw) == entry.file_size and zlib.crc32(raw) == entry.CRC:
            return raw, mode
    raise ValueError('No supported transform passed both length and CRC32 validation')


archives = sorted((SOURCE / 'data').rglob('*.pak'))
archives += [SOURCE / 'L10N/CHS/CHS.pak', SOURCE / 'L10N/CHS/Data/Data.pak', SOURCE / 'bin32/bin32.pak']
records, inventory, errors = [], [], []
for index, pak in enumerate(archives):
    relative = pak.relative_to(SOURCE)
    before = pak.stat()
    mode = None
    try:
        with SignatureView(pak) as view, zipfile.ZipFile(view) as archive, pak.open('rb') as stream:
            entries = archive.infolist()
            inventory.append({'archive': str(relative), 'entries': [
                {'name': e.filename, 'bytes': e.file_size, 'compressed': e.compress_size,
                 'crc32': f'{e.CRC:08x}'} for e in entries]})
            for entry in entries:
                if entry.is_dir() or Path(entry.filename).suffix.lower() not in TEXT_TYPES:
                    continue
                name = PurePosixPath(entry.filename.replace('\\', '/'))
                if name.is_absolute() or '..' in name.parts or ':' in str(name):
                    raise ValueError(f'Unsafe archive path: {entry.filename}')
                record = {'archive': str(relative), 'name': entry.filename, 'bytes': entry.file_size}
                try:
                    raw, mode = payload(stream, entry, mode)
                    destination = CASE / 'exports/raw' / relative.with_suffix('') / str(name)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(raw)
                    record.update(crc_verified=True, transform=mode, exported=str(destination),
                                  sha256=hashlib.sha256(raw).hexdigest(), head_hex=raw[:16].hex())
                    if raw[:1] == b'\x80' and destination.suffix.lower() == '.xml':
                        try:
                            text, tag, count = bxml(raw)
                            decoded_path = CASE / 'exports/decoded' / relative.with_suffix('') / str(name)
                            decoded_path.parent.mkdir(parents=True, exist_ok=True)
                            decoded_path.write_bytes(text)
                            record.update(decoded=str(decoded_path), xml_root=tag, root_children=count)
                        except Exception as error:
                            record['xml_decode_error'] = f'{type(error).__name__}: {error}'
                    elif raw.lstrip().startswith((b'<', b'\xef\xbb\xbf<')):
                        try:
                            tree = ET.fromstring(raw)
                            record.update(xml_root=tree.tag, root_children=len(tree), plaintext_xml=True)
                        except ET.ParseError:
                            pass
                except Exception as error:
                    record['error'] = f'{type(error).__name__}: {error}'
                records.append(record)
        after = pak.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            errors.append({'archive': str(relative), 'error': 'Source changed during read'})
    except Exception as error:
        errors.append({'archive': str(relative), 'error': f'{type(error).__name__}: {error}'})
    if index % 15 == 0:
        print(f'Processed {index+1}/{len(archives)} data archives, exported {len(records)} candidates', flush=True)

summary = {'archives_requested': len(archives), 'archives_indexed': len(inventory),
           'indexed_entries': sum(len(x['entries']) for x in inventory),
           'data_files': len(records), 'crc_verified': sum(x.get('crc_verified',False) for x in records),
           'binary_xml_decoded': sum('decoded' in x for x in records),
           'xml_decode_errors': sum('xml_decode_error' in x for x in records),
           'entry_errors': sum('error' in x for x in records), 'archive_errors': errors}
for name, value in [('data-archive-index.json',inventory), ('data-extraction.json',records), ('data-summary.json',summary)]:
    text = json.dumps(value, ensure_ascii=False, indent=2)
    (CASE / 'reports' / name).write_text(text, encoding='utf-8')
    (LOCAL / 'aion-report-backup' / name).write_text(text, encoding='utf-8')
print(json.dumps(summary, ensure_ascii=False, indent=2))
