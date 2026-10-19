"""Read AION archives with complemented ZIP header markers; source is never changed."""
import bisect
import io
import struct
from pathlib import Path
import zipfile


class SignatureView(io.BufferedIOBase):
    def __init__(self, path):
        super().__init__()
        self.source = Path(path).open('rb')
        self.source.seek(0, 2)
        size = self.source.tell()
        self.source.seek(max(0, size - 65557))
        tail_start = self.source.tell()
        tail = self.source.read()
        candidates = [tail.rfind(b'\xaf\xb4\xfa\xf9'), tail.rfind(b'PK\x05\x06')]
        end = max(candidates)
        if end < 0:
            self.source.close()
            raise ValueError('No recognized ZIP end-of-central-directory marker')
        fields = struct.unpack_from('<4s4H2IH', tail, end)
        _, disk, central_disk, disk_count, total_count, central_size, central_offset, comment_size = fields
        if disk or central_disk or disk_count != total_count or total_count == 65535:
            self.source.close()
            raise ValueError('Multi-disk or ZIP64 archive is not supported by this reader')
        end_position = tail_start + end
        if central_offset + central_size != end_position or end_position + 22 + comment_size != size:
            self.source.close()
            raise ValueError('Central-directory bounds do not match the archive')
        self.patches = {end_position: b'PK\x05\x06'}
        position = central_offset
        for _ in range(total_count):
            self.source.seek(position)
            header = self.source.read(46)
            fields = struct.unpack('<4s6H3I5H2I', header)
            if fields[0] not in (b'\xaf\xb4\xfe\xfd', b'PK\x01\x02'):
                self.source.close()
                raise ValueError(f'Invalid central marker at {position}')
            local_offset = fields[16]
            self.source.seek(local_offset)
            local_marker = self.source.read(4)
            if local_marker not in (b'\xaf\xb4\xfc\xfb', b'PK\x03\x04'):
                self.source.close()
                raise ValueError(f'Invalid local marker at {local_offset}')
            self.patches[position] = b'PK\x01\x02'
            self.patches[local_offset] = b'PK\x03\x04'
            position += 46 + fields[10] + fields[11] + fields[12]
        if position != end_position:
            self.source.close()
            raise ValueError('Central-directory entry count/length mismatch')
        self.offsets = sorted(self.patches)
        self.source.seek(0)

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.source.tell()

    def seek(self, offset, whence=0):
        return self.source.seek(offset, whence)

    def read(self, size=-1):
        start = self.source.tell()
        data = bytearray(self.source.read(size))
        end = start + len(data)
        for index in range(bisect.bisect_left(self.offsets, start - 3), len(self.offsets)):
            offset = self.offsets[index]
            if offset >= end:
                break
            left, right = max(start, offset), min(end, offset + 4)
            data[left-start:right-start] = self.patches[offset][left-offset:right-offset]
        return bytes(data)

    def close(self):
        if not self.closed:
            self.source.close()
        super().close()


if __name__ == '__main__':
    import json
    import sys
    for argument in sys.argv[1:]:
        with SignatureView(argument) as view, zipfile.ZipFile(view) as archive:
            entries = archive.infolist()
            print(json.dumps({'archive': argument, 'count': len(entries),
                              'entries': [{'name': i.filename, 'bytes': i.file_size,
                                           'compressed': i.compress_size, 'method': i.compress_type}
                                          for i in entries[:15]]}, ensure_ascii=False))
            for entry in entries:
                if not entry.is_dir() and entry.file_size < 100000:
                    try:
                        data = archive.read(entry)
                        print(json.dumps({'crc_verified': entry.filename, 'head': data[:64].hex(),
                                          'text_preview': data[:300].decode('utf-8', 'replace')}, ensure_ascii=False))
                    except Exception as error:
                        print(type(error).__name__, str(error))
                    break
