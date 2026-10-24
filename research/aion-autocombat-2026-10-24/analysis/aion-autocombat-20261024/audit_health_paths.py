"""Audit cached REA evidence and original PE bytes; no new decompilation."""
import hashlib
import importlib.util
import json
import pathlib
import struct

ROOT = pathlib.Path(__file__).resolve().parent
OLD = ROOT.parent / 'aion-tw-20261019'
spec = importlib.util.spec_from_file_location('audit', ROOT.parent / 'aion-autocombat-20261021/audit_evidence.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
pe = audit.PE(OLD / 'samples/Game.dll')
expected_hash = 'b3043f0eaf225b3dc7ba320ac7671cc5b28cefbd637135943dc9e67c114ccae7'
assert hashlib.sha256(pe.data).hexdigest() == expected_hash
checks = []
for rva, dest in [(0x7DF918, 0x8E0980), (0x7DF92E, 0x867BC0),
                  (0x7DF97E, 0x8C52E0), (0x7DF4AC, 0x7E8880),
                  (0x8BE787, 0x867BC0), (0x8C0289, 0x867BC0),
                  (0x8C1A13, 0x867BC0), (0x8C1A5A, 0x867B00)]:
    raw = pe.at(rva, 5)
    target = rva + 5 + struct.unpack_from('<i', raw, 1)[0]
    checks.append(dict(kind='direct-call', rva=hex(rva), expected=hex(dest),
                       observed=hex(target), raw=raw.hex(), passed=raw[0] == 0xE8 and target == dest))
for rva, expected in [(0x8BE793, '884740'), (0x8C0295, '884740'),
                      (0x8C025E, '898758130000'), (0x8C0271, '8b8f58130000')]:
    raw = pe.at(rva, len(bytes.fromhex(expected)))
    checks.append(dict(kind='object-field-instruction', rva=hex(rva), raw=raw.hex(),
                       expected=expected, passed=raw.hex() == expected))
for rva, opcode, dest in [(0x7DF903, '893d', 0x142DB10), (0x7DF909, '891d', 0x142DB0C)]:
    raw = pe.at(rva, 6)
    target = rva + 6 + struct.unpack_from('<i', raw, 2)[0]
    checks.append(dict(kind='global-store', rva=hex(rva), observed=hex(target), expected=hex(dest),
                       raw=raw.hex(), passed=raw[:2].hex() == opcode and target == dest))
evidence = []
for stem in ['seed-1-pseudo', 'message-dispatch-insns', 'message-dispatch-pseudo',
             'entity-component-pseudo', 'player-component-getter-pseudo',
             'spawn-status-a-insns', 'spawn-status-b-insns', 'spawn-status-c-insns']:
    path = OLD / (stem + '.evidence.json')
    data = json.loads(path.read_text('utf-8-sig'))['data']
    evidence.append(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                         evidence_id=data['evidence_id'], operation=data['operation'], subject=data['subject']))
result = dict(newReaRequests=0, gameSha256=expected_hash, checks=checks, evidence=evidence,
              observations=['Message 3 registered as aSHitPoint; two uint32 payload values stored at Game+142DB10 and Game+142DB0C, then passed to 867BC0.',
                            'Message 5 registered as aSHitPointOther; dispatch calls 8C52E0 with mixed-width payload values. Their detailed semantics remain unknown.',
                            'Spawn paths pass component+1358 and a byte through unresolved 19FC7C2 with argument 100, then call 867BC0; two paths store the byte at component+40.',
                            'Entity component query 89F3D0 requests type 1. Previously validated CharacterObject query accepts type 1 and returns itself.'],
              candidates={'component+40': 'possible health percentage; needs controlled damage and recovery evidence',
                          'component+1358': 'possible maximum or reference health; not yet validated'},
              unknowns=['867BC0 and 867B00 bodies', '19FC7C2 arithmetic', '8C52E0 identifier lookup and writes',
                        'exact current health', 'death and hostility', 'UI percentage rounding'])
(ROOT / 'health-path-audit.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
jobs = []
for name, address in [('health-pair-writer', 0x867BC0), ('health-byte-writer', 0x867B00),
                      ('other-health-consumer', 0x8C52E0), ('health-scale-helper', 0x19FC7C2),
                      ('remove-object-consumer', 0x7E8880)]:
    for suffix, tool in [('pseudo', 'procedure_pseudo_code'), ('insns', 'read_function_instructions'), ('callers', 'procedure_callers')]:
        jobs.append(dict(file=name+'-'+suffix, name=tool, arguments={'procedure': hex(0x180000000 + address)}))
(ROOT / 'pending-rea-health-jobs.json').write_text(json.dumps(jobs, indent=2), encoding='utf-8')
print(json.dumps(dict(checks=len(checks), passed=sum(x['passed'] for x in checks), failures=[x for x in checks if not x['passed']],
                      nextJobs=len(jobs), executedJobs=0), indent=2))
raise SystemExit(0 if all(x['passed'] for x in checks) else 1)
