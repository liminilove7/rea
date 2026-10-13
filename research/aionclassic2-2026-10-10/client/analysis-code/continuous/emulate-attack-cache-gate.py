"""Compare original Game.dll attack-gate decisions after a synthetic cache edit."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

import capstone
import unicorn
from unicorn import x86_const as reg

parser = argparse.ArgumentParser()
parser.add_argument('--output', required=True, type=Path)
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
assert args.output.is_absolute()
study = Path(__file__).resolve().parents[3]
source = study / 'samples/Game.dll'
data = source.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786'
pe = struct.unpack_from('<I', data, 0x3c)[0]
optional = pe + 24
base = struct.unpack_from('<Q', data, optional + 24)[0]
image_size, header_size = struct.unpack_from('<II', data, optional + 56)
optional_size = struct.unpack_from('<H', data, pe + 20)[0]
sections = [struct.unpack_from('<IIII', data, optional + optional_size + 40*i + 8)
            for i in range(struct.unpack_from('<H', data, pe + 6)[0])]
decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
OBJECT, STACK = 0x60000000, 0x70000000

def trial(label, now, previous, delay):
    cpu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    cpu.mem_map(base, (image_size + 0xfff) & ~0xfff)
    cpu.mem_write(base, data[:header_size])
    for _, rva, size, raw in sections:
        if size:
            cpu.mem_write(base + rva, data[raw:raw + size])
    cpu.mem_map(OBJECT, 0x4000)
    cpu.mem_map(STACK, 0x10000)
    cpu.reg_write(reg.UC_X86_REG_RSI, OBJECT)
    cpu.reg_write(reg.UC_X86_REG_EBP, now)
    cpu.reg_write(reg.UC_X86_REG_RSP, STACK + 0x8008)
    cpu.mem_write(OBJECT + 0x1c88, struct.pack('<I', previous))
    cpu.mem_write(base + 0xd71be0, struct.pack('<H', delay))
    trace, stopped = [], []
    stops = {base + 0x6a173: 'passed-local-comparison', base + 0x6a358: 'rejected-local-comparison'}

    def step(machine, address, size, _):
        if address in stops:
            stopped.append(stops[address])
            machine.emu_stop()
            return
        raw = bytes(machine.mem_read(address, size))
        instruction = next(decoder.disasm(raw, address))
        assert instruction.mnemonic not in ('call', 'ret', 'syscall'), 'Fragment escaped its declared scope'
        trace.append({'rva': hex(address - base), 'bytes': raw.hex(),
                      'instruction': instruction.mnemonic + ' ' + instruction.op_str})

    cpu.hook_add(unicorn.UC_HOOK_CODE, step)
    cpu.emu_start(base + 0x6a15e, 0, count=30)
    assert len(stopped) == 1
    return {'label': label, 'syntheticNow': now, 'previousAcceptedTime': previous,
            'cacheWord': delay, 'thresholdLow32': (previous + delay) & 0xffffffff,
            'result': stopped[0], 'trace': trace}

trials = [trial('baseline', 1150, 1000, 200),
          trial('same-clock-reduced-cache-word', 1150, 1000, 100),
          trial('after-a-hypothetical-successful-request', 1200, 1150, 100),
          trial('after-enough-time', 1251, 1150, 100)]
assert [row['result'] for row in trials] == [
    'rejected-local-comparison', 'passed-local-comparison',
    'rejected-local-comparison', 'passed-local-comparison']
assert hashlib.sha256(source.read_bytes()).hexdigest() == digest
result = {'source': 'Bounded original Game.dll local comparison after synthetic uint16 cache edits',
          'sourcePath': 'samples/Game.dll', 'targetSha256': digest, 'afterSha256': digest,
          'nativeGameExecuted': False, 'syntheticCpuInstructionsExecuted': True,
          'versions': {'unicorn': unicorn.__version__, 'capstone': capstone.__version__},
          'trials': trials,
          'limitations': ['Fragment starts after protected clock and 05D140 adjustment with constructed registers.',
                          'The hypothetical previous accepted time is a constructed next trial, not a completed native request.',
                          'Target checks, animation events, request transmission and server acceptance are outside this experiment.']}
if args.check:
    assert json.loads(args.output.read_text(encoding='utf-8')) == result
else:
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8', newline='\n') as handle:
        json.dump(result, handle, indent=2)
print(json.dumps({'sourceUnchanged': True, 'decisions': [
    {'case': row['label'], 'delay': row['cacheWord'], 'threshold': row['thresholdLow32'],
     'result': row['result']} for row in trials]}))
