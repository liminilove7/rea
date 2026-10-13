"""Execute original speed, animation and attack-gate fragments in synthetic CPU memory.

No game process, DLL loader, network or native API is used.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

import capstone
import unicorn
from unicorn import x86_const as registers

parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--speed', type=float, action='append')
args = parser.parse_args()
assert args.output.is_absolute()
study = Path(__file__).resolve().parents[3]
source = study / 'samples/Game.dll'
data = source.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786'
pe = struct.unpack_from('<I', data, 0x3c)[0]
optional = pe+24
base = struct.unpack_from('<Q', data, optional+24)[0]
image_size, header_size = struct.unpack_from('<II', data, optional+56)
optional_size = struct.unpack_from('<H', data, pe+20)[0]
sections = [struct.unpack_from('<IIII', data, optional+optional_size+40*i+8)
    for i in range(struct.unpack_from('<H', data, pe+6)[0])]
decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
OBJECT, STACK = 0x60000000, 0x70000000

def machine():
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    uc.mem_map(base, (image_size+0xfff)&~0xfff)
    uc.mem_write(base, data[:header_size])
    for _, rva, size, raw in sections:
        if size:
            uc.mem_write(base+rva, data[raw:raw+size])
    uc.mem_map(OBJECT, 0x4000)
    uc.mem_map(STACK, 0x10000)
    uc.reg_write(registers.UC_X86_REG_RSP, STACK+0x8008)
    return uc

def float_bits(value):
    return struct.unpack('<I', struct.pack('<f', value))[0]

def put_float(uc, offset, value):
    uc.mem_write(OBJECT+offset, struct.pack('<f', value))

def get_float(uc, offset):
    return struct.unpack('<f', uc.mem_read(OBJECT+offset, 4))[0]

def run(uc, entry, stops):
    trace, stopped = [], []
    def step(cpu, address, size, _):
        if address-base in stops:
            stopped.append(hex(address-base))
            cpu.emu_stop()
            return
        raw = bytes(cpu.mem_read(address, size))
        instruction = next(decoder.disasm(raw, address))
        trace.append({'rva': hex(address-base), 'bytes': raw.hex(),
            'instruction': instruction.mnemonic+' '+instruction.op_str})
        assert instruction.mnemonic not in ('call', 'ret', 'syscall'), 'Fragment escaped its declared scope'
    uc.hook_add(unicorn.UC_HOOK_CODE, step)
    uc.emu_start(base+entry, 0, count=200)
    assert len(stopped) == 1, 'Bounded fragment did not reach an admitted stop'
    return {'entryRva': hex(entry), 'stopRva': stopped[0], 'instructionCount': len(trace), 'trace': trace}

speed_trials = []
for value in args.speed or [0, 6, 9, 12]:
    uc = machine()
    uc.reg_write(registers.UC_X86_REG_RCX, OBJECT)
    uc.reg_write(registers.UC_X86_REG_XMM1, float_bits(value))
    put_float(uc, 0x6c8, 6)
    experiment = run(uc, 0x460440, {0x4604bf})
    fields = {hex(offset): get_float(uc, offset) for offset in [0x38, 0x6c8, 0x6cc, 0x6d0]}
    speed_trials.append({'inputSpeed': value, 'fieldsAfterOriginalSetterPrefix': fields, **experiment})

animation_trials = []
for initial, current, scale in [(2000, 2000, 1), (2000, 1000, 1), (2000, 1000, 2), (0, 1000, 1), (2000, 0, 1)]:
    uc = machine()
    uc.reg_write(registers.UC_X86_REG_RBX, OBJECT)
    # The preceding cattack name-selection branch supplies this fallback value.
    uc.reg_write(registers.UC_X86_REG_XMM6, float_bits(1))
    uc.mem_write(OBJECT+0x508, struct.pack('<HH', initial, current))
    put_float(uc, 0x4f4, scale)
    experiment = run(uc, 0x4bc5b9, {0x4bc73b})
    result = struct.unpack('<f', struct.pack('<I', uc.reg_read(registers.UC_X86_REG_XMM6)&0xffffffff))[0]
    animation_trials.append({'firstInterval': initial, 'secondInterval': current, 'globalAnimationScale': scale,
        'resultMultiplier': result, **experiment})

gate_trials = []
for now, previous, delay in [(1199, 1000, 200), (1200, 1000, 200), (1201, 1000, 200),
    (0xfffffffa, 0xfffffff0, 32), (10, 0xfffffff0, 32)]:
    uc = machine()
    uc.reg_write(registers.UC_X86_REG_RSI, OBJECT)
    uc.reg_write(registers.UC_X86_REG_EBP, now)
    uc.mem_write(OBJECT+0x1c88, struct.pack('<I', previous))
    uc.mem_write(base+0xd71be0, struct.pack('<H', delay))
    experiment = run(uc, 0x6a15e, {0x6a173, 0x6a358})
    gate_trials.append({'syntheticClockValue': now, 'previousBase': previous, 'delayWord': delay,
        'thresholdLow32': (previous+delay)&0xffffffff, 'localBranchPassed': experiment['stopRva'] == '0x6a173',
        **experiment})

assert [row['resultMultiplier'] for row in animation_trials] == [1, 2, 4, 1, 1]
assert [row['localBranchPassed'] for row in gate_trials] == [False, False, True, True, False]
assert hashlib.sha256(source.read_bytes()).hexdigest() == digest
result = {'source': 'Auxiliary bounded Unicorn execution of original Game.dll instruction fragments',
    'targetSha256': digest, 'afterSha256': digest, 'nativeGameExecuted': False,
    'syntheticCpuInstructionsExecuted': True, 'versions': {'unicorn': unicorn.__version__, 'capstone': capstone.__version__},
    'speedTrials': speed_trials, 'animationTrials': animation_trials, 'attackGateTrials': gate_trials,
    'singleFieldChangeExample': {'source': 'Constructed data comparison, not native or emulated setter execution',
        'before': {'speed': 6, 'square': 36, 'inverse': 1/6},
        'afterWritingOnlySpeed': {'speed': 9, 'square': 36, 'inverse': 1/6}},
    'limitations': ['Each experiment starts with synthetic registers and objects, not a captured game state.',
        'Setter stops before entity callbacks, animation updates and local-player cache update.',
        'Animation begins inside an already-selected cattack branch; name/model selection and whole-function execution are excluded.',
        'Attack gate excludes clock resolution, quota adjustment, target/action checks, request creation and server response.',
        'Passing a local fragment does not establish an accepted attack, world movement or online modification effect.']}
args.output.parent.mkdir(parents=True, exist_ok=True)
with args.output.open('x', encoding='utf-8', newline='\n') as handle:
    json.dump(result, handle, indent=2)
print(json.dumps({'sourceUnchanged': True,
    'speedTrials': [{'input': row['inputSpeed'], 'fields': row['fieldsAfterOriginalSetterPrefix']} for row in speed_trials],
    'animationMultipliers': [row['resultMultiplier'] for row in animation_trials],
    'gateDecisions': [row['localBranchPassed'] for row in gate_trials]}))
