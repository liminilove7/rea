"""Bounded, auxiliary read-only capture of REA-derived health/state candidates.

No input injection, game writes, target calls or semantic Alive/Hostile promotion.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import pathlib
import struct
import time

ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('entity_reader', ROOT.parent / 'aion-autocombat-20261021/inspect_entities.py')
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)
FIELDS = {'byte40': (0x40, 1), 'state2c8': (0x2c8, 4), 'flagaf8': (0xaf8, 4),
          'stateafc': (0xafc, 4), 'gate1348': (0x1348, 4), 'copy1354': (0x1354, 4),
          'reference1358': (0x1358, 4), 'amount135c': (0x135c, 4), 'field13a8': (0x13a8, 4)}


def gate(row, anchor, fresh=True):
    """Stop-only research policy. A clean sample never authorizes attack."""
    reasons = []
    if not fresh:
        reasons.append('sample-expired')
    if not row.get('stable'):
        reasons.append('read-or-identity-uncertain')
    if row.get('selectedBefore') == 0:
        reasons.append('selection-empty')
    if row.get('selectedBefore') != row.get('selectedAfter'):
        reasons.append('selection-changed-during-sample')
    if anchor and row.get('selectedBefore') != anchor['handle']:
        reasons.append('selection-no-longer-anchor')
    obj = row.get('anchorObject')
    if not obj:
        reasons.append('anchor-not-resolved')
    elif anchor and any(obj.get(k) != anchor.get(k) for k in ('handle', 'entity', 'character', 'identifier')):
        reasons.append('anchor-binding-changed')
    elif obj.get('stable'):
        values = obj['values']
        if values['byte40'] == 0:
            reasons.append('zero-health-indicator-not-death-proof')
        elif values['byte40'] > 100:
            reasons.append('health-indicator-outside-observed-domain')
        if values['state2c8'] == 7 or (values['stateafc'] == 18 and values['flagaf8'] != 0):
            reasons.append('client-action-state-exclusion-candidate')
    else:
        reasons.append('object-fields-unstable')
    return dict(stopCandidate=bool(reasons), reasons=reasons, attackAuthorized=False,
                alive=None, hostile=None,
                note='Research stop policy; state predicate is from selected action branches, not all actions.')


def capture(pid, seconds, output):
    result = dict(startedUtc=datetime.datetime.now(datetime.timezone.utc).isoformat(), pid=pid,
                  method='Auxiliary Win32 PROCESS_VM_READ; offsets justified by saved REA Evidence',
                  writes=0, targetCalls=0, automaticInputs=0, requestedSeconds=seconds,
                  intervalSeconds=0.25, fields={k: {'offset': hex(v[0]), 'bytes': v[1]} for k, v in FIELDS.items()},
                  samples=[], errors=[], limits=['Non-atomic reads; matching endpoints cannot exclude ABA changes.',
                  '250ms is an experiment sampling interval, not a game timing guarantee.',
                  'Missing entity is not death. Positive health/state is not proof of attackability.'])
    r = None
    try:
        r = reader.Reader(pid)
        identity = r.identity()
        if identity['path'].casefold() != reader.EXPECTED_PATH.casefold():
            raise ValueError('Unexpected process path')
        mods = reader.modules(pid)
        selected = {m['name'].lower(): m for m in mods if m['name'].lower() in reader.HASHES}
        for name, expected in reader.HASHES.items():
            m = selected[name]
            if hashlib.sha256(pathlib.Path(m['path']).read_bytes()).hexdigest() != expected:
                raise ValueError('Module hash mismatch: ' + name)
        b = selected['game.dll']['base']
        result.update(identity=identity, modules=selected)

        def u16(addr):
            return struct.unpack('<H', r.read(addr, 2))[0]

        def resolve(handle):
            if not handle:
                return None
            manager = r.u64(b + 0xf25c68)
            head = r.u64(manager + 0x58)
            if r.read(head + 25, 1)[0] != 1:
                raise ValueError('Bad tree sentinel')
            node = r.u64(head + 8)
            seen = set()
            while node != head:
                if node in seen or len(seen) >= 128:
                    raise ValueError('Lookup cycle/depth budget; unresolved, not missing')
                seen.add(node)
                raw = r.read(node, 48)
                if raw[25] != 0:
                    raise ValueError('Unexpected nil node')
                key = struct.unpack_from('<H', raw, 32)[0]
                if key == handle:
                    e = struct.unpack_from('<Q', raw, 40)[0]
                    c = r.u64(e + 0x380)
                    vt = r.u64(c)
                    if vt not in (b + 0xD53940, b + 0xD4F9B0) or r.u64(c + 8) != e:
                        raise ValueError('Unrecognized component or backlink')
                    ident = struct.unpack('<I', r.read(c + 0x2c, 4))[0]
                    name_raw = r.read(c + 0x42, 128)
                    end = next((i for i in range(0, 128, 2) if name_raw[i:i+2] == b'\0\0'), None)
                    if end is None:
                        raise ValueError('Unterminated name')
                    name = name_raw[:end].decode('utf-16le')
                    before = {k: r.read(c + off, size) for k, (off, size) in FIELDS.items()}
                    after = {k: r.read(c + off, size) for k, (off, size) in FIELDS.items()}
                    binding = (r.read(node + 32, 16) == raw[32:48] and r.u64(e + 0x380) == c
                               and r.u64(c) == vt and r.u64(c + 8) == e
                               and struct.unpack('<I', r.read(c + 0x2c, 4))[0] == ident)
                    return dict(handle=handle, entity=hex(e), character=hex(c), identifier=ident, name=name,
                                values={k: int.from_bytes(v, 'little') for k, v in before.items()},
                                rawBefore={k: v.hex() for k, v in before.items()},
                                rawAfter={k: v.hex() for k, v in after.items()},
                                stable=binding and before == after, bindingStable=binding)
                node = struct.unpack_from('<Q', raw, 0 if handle < key else 16)[0]
            return None

        anchor = None
        start = time.monotonic()
        while True:
            row = dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), elapsed=time.monotonic()-start)
            try:
                row['selectedBefore'] = u16(b + 0x142264a)
                if anchor is None and row['selectedBefore']:
                    obj = resolve(row['selectedBefore'])
                    if obj and obj['stable']:
                        anchor = {k: obj[k] for k in ('handle', 'entity', 'character', 'identifier', 'name')}
                        result['anchor'] = anchor
                row['anchorObject'] = resolve(anchor['handle']) if anchor else None
                row['selectedAfter'] = u16(b + 0x142264a)
                row['identityMatched'] = r.identity() == identity
                row['stable'] = row['identityMatched'] and row['selectedBefore'] == row['selectedAfter']
                if row['anchorObject']:
                    row['stable'] &= row['anchorObject']['stable']
            except (OSError, ValueError, UnicodeError) as exc:
                row.update(stable=False, error=str(exc))
            row['stopAssessment'] = gate(row, anchor)
            result['samples'].append(row)
            if time.monotonic()-start >= seconds or row.get('identityMatched') is False:
                break
            time.sleep(min(0.25, max(0, seconds-(time.monotonic()-start))))
    except (OSError, ValueError, KeyError, StopIteration) as exc:
        result['errors'].append(str(exc))
    finally:
        if r:
            r.close()
            result['handleClosed'] = True
        result['finishedUtc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    last = result['samples'][-1] if result['samples'] else None
    print(json.dumps(dict(output=str(output), samples=len(result['samples']), anchor=result.get('anchor'),
                         last=last, errors=result['errors'], handleClosed=result.get('handleClosed')), ensure_ascii=False))
    return 0 if not result['errors'] and all(s.get('stable') for s in result['samples']) else 1


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--pid', type=int, required=True)
    ap.add_argument('--seconds', type=float, default=0)
    ap.add_argument('--out', type=pathlib.Path, required=True)
    args = ap.parse_args()
    if not 0 <= args.seconds <= 180:
        ap.error('seconds must be 0..180 (bounded experiment)')
    if args.out.exists():
        ap.error('output already exists; preserve prior evidence')
    raise SystemExit(capture(args.pid, args.seconds, args.out))
