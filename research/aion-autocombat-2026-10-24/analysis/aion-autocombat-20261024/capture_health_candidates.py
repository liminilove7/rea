"""Read bounded candidate fields only; does not assert HP semantics or write memory."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import pathlib
import struct

ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('entity_reader', ROOT.parent / 'aion-autocombat-20261021/inspect_entities.py')
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


def capture(snapshot, output):
    source = json.loads(snapshot.read_text('utf-8-sig'))
    s = source['Value']
    if source['State'] != 1 or not s['IdentityMatched'] or not s['TraversalComplete']:
        raise ValueError('Fresh entity capture is not stable')
    pid, base = s['Pid'], int(s['ModuleBase'], 16)
    r = reader.Reader(pid)
    result = dict(recordedUtc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  pid=pid, source=str(snapshot), sourceSha256=hashlib.sha256(snapshot.read_bytes()).hexdigest(),
                  method='auxiliary Win32 read-only; cached REA-derived candidate offsets',
                  gameWrites=False, newReaRequests=0, fieldsConfirmedAsHealth=False, objects=[], errors=[])
    try:
        identity = r.identity()
        if identity['birth_filetime'] != s['Birth'] or identity['path'].casefold() != reader.EXPECTED_PATH.casefold():
            raise ValueError('Process identity changed')
        modules = reader.modules(pid)
        for name, digest in reader.HASHES.items():
            m = next(x for x in modules if x['name'].lower() == name)
            if hashlib.sha256(pathlib.Path(m['path']).read_bytes()).hexdigest() != digest:
                raise ValueError('Module digest mismatch: ' + name)
            if name == 'game.dll' and m['base'] != base:
                raise ValueError('Module base changed')
        def target():
            return struct.unpack('<H', r.read(base + 0x142264A, 2))[0]
        result['targetBefore'] = target()
        if result['targetBefore'] != s['TargetHandleAfter']:
            raise ValueError('Selection changed since entity capture')
        for row in s['Candidates']:
            if not (row['Local'] or row['TargetHandleMatch']):
                continue
            e, c = int(row['EntityAddress'], 16), int(row['CharacterAddress'], 16)
            expected_vt = base + (0xD53940 if row['Local'] else 0xD4F9B0)
            def binding():
                return (r.u64(e + 0x380) == c and r.u64(c) == expected_vt
                        and r.u64(c + 8) == e
                        and struct.unpack('<I', r.read(c + 0x2C, 4))[0] == row['IdentifierCandidate'])
            if not row['BindingMatched'] or not binding():
                raise ValueError('Object identity mismatch')
            values = []
            for _ in range(2):
                raw40 = r.read(c + 0x40, 1)
                raw1358 = r.read(c + 0x1358, 4)
                values.append(dict(byte40=raw40[0], uint32_1358=struct.unpack('<I', raw1358)[0],
                                   raw40=raw40.hex(), raw1358=raw1358.hex()))
            result['objects'].append(dict(handle=row['Handle'], name=row['NameCandidate'],
                                          local=row['Local'], entity=hex(e), character=hex(c),
                                          identifier=row['IdentifierCandidate'], reads=values,
                                          bindingAfter=binding()))
        raw = r.read(base + 0x142DB0C, 8)
        result['localMessage3GlobalCandidates'] = dict(raw=raw.hex(),
            offset142DB0C=struct.unpack_from('<I', raw, 0)[0], offset142DB10=struct.unpack_from('<I', raw, 4)[0])
        result['targetAfter'] = target()
        result['identityAfterMatches'] = r.identity() == identity
        result['stable'] = (result['targetBefore'] == result['targetAfter'] and result['identityAfterMatches']
                            and all(x['bindingAfter'] for x in result['objects']))
    except (OSError, ValueError, StopIteration) as exc:
        result['errors'].append(str(exc))
        result['stable'] = False
    finally:
        r.close()
        result['handleClosed'] = True
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['stable'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('snapshot', type=pathlib.Path)
    parser.add_argument('output', type=pathlib.Path)
    args = parser.parse_args()
    raise SystemExit(capture(args.snapshot, args.output))
