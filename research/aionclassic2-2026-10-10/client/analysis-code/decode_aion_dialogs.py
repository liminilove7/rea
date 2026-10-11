"""Decode already-exported dialog records; keeps original extracted bytes intact.

Format reference: giordanidev/aion-pak-manager/backend/parse/html-crypt.ts
"""
import hashlib
import json
import re
import sys
from pathlib import Path
from html.parser import HTMLParser

LOCAL = Path(__file__).parent
CASE = Path(r'F:\RVE-Workspace\cases\aionclassic2-2026-10-10')
records = json.loads((CASE / 'reports/data-extraction.json').read_text(encoding='utf-8'))
results = []
if '--retry-errors' in sys.argv:
    previous = json.loads((CASE / 'reports/dialog-decoding.json').read_text(encoding='utf-8'))
    failed = {(x['archive'], x['name']) for x in previous['records'] if 'error' in x}
    results = [x for x in previous['records'] if 'error' not in x]
    records = [x for x in records if (x['archive'], x['name']) in failed]
for entry in records:
    if not entry.get('head_hex', '').startswith('81'):
        continue
    record = {'archive': entry['archive'], 'name': entry['name']}
    try:
        source = Path(entry['exported'])
        data = source.read_bytes()
        if hashlib.sha256(data).hexdigest() != entry['sha256']:
            raise ValueError('Extracted input changed since CRC validation')
        stem = source.stem
        accumulator, counter = 0, 0
        for position, letter in enumerate(stem):
            value = (ord(letter) & 15) + position
            accumulator = (accumulator + value) & 0xffffffff
            counter ^= value
        output = bytearray()
        for byte in data[1:]:
            accumulator = ((accumulator + 29) ^ counter) & 0xffffffff
            counter = (counter + 3) & 0xffffffff
            output.append(byte ^ (accumulator & 255))
        if not output or output[0] != 0x81:
            raise ValueError('Decoded dialog marker did not match')
        content = bytes(output[1:])
        original_content = content
        if content.startswith(b'\xff\xfe<') and content[3:4] != b'\0':
            record['source_format_warning'] = 'UTF-16 BOM precedes single-byte markup; preserved original decoded bytes and decoded payload separately.'
            content = content[2:]
        if content.startswith((b'\xff\xfe', b'\xfe\xff')):
            text = content.decode('utf-16')
            record['encoding'] = 'UTF-16 BOM'
        elif content.lstrip().startswith(b'<') and b'\0' not in content[:32]:
            try:
                text = content.decode('utf-8-sig')
                record['encoding'] = 'UTF-8'
            except UnicodeDecodeError:
                encoding = 'gb18030' if entry['archive'].startswith('L10N\\CHS') else 'cp949'
                text = content.decode(encoding)
                record['encoding'] = encoding
                record['encoding_inferred'] = 'Legacy single-byte markup; encoding inferred from localization path, strict decode passed.'
            lossless = CASE / 'exports/decoded' / source.relative_to(CASE / 'exports/raw')
            lossless.parent.mkdir(parents=True, exist_ok=True)
            lossless.with_suffix(lossless.suffix + '.decoded.bin').write_bytes(original_content)
            record['decoded_bytes'] = str(lossless.with_suffix(lossless.suffix + '.decoded.bin'))
        else:
            text = content.decode('utf-16-le')
            record['encoding'] = 'UTF-16LE without BOM'
        if not text.lstrip().startswith('<'):
            raise ValueError('Decoded dialog does not start with markup')
        parser = HTMLParser()
        parser.feed(text)
        parser.close()
        text = re.sub(r'(<\?xml[^>]*encoding\s*=\s*[\x22\x27])[^\x22\x27]+', r'\1UTF-8', text, count=1, flags=re.I)
        target = CASE / 'exports/decoded' / source.relative_to(CASE / 'exports/raw')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding='utf-8')
        record.update(decoded=str(target), validation='source hash + format marker + strict character decode + markup parse')
    except Exception as error:
        record['error'] = f'{type(error).__name__}: {error}'
    results.append(record)
    if len(results) % 3000 == 0:
        print(f'Dialogs processed: {len(results)}', flush=True)

value = {'requested': len(results), 'decoded': sum('decoded' in x for x in results),
         'errors': sum('error' in x for x in results), 'records': results}
text = json.dumps(value, ensure_ascii=False, indent=2)
(CASE / 'reports/dialog-decoding.json').write_text(text, encoding='utf-8')
(LOCAL / 'aion-report-backup/dialog-decoding.json').write_text(text, encoding='utf-8')
print(json.dumps({k:v for k,v in value.items() if k != 'records'}))
