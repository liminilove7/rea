"""Execute Game vector limiting and CryPhysics mode-3 input writes in separate synthetic CPUs."""
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
args = parser.parse_args()
assert args.output.is_absolute()
study = Path(__file__).resolve().parents[3]
inputs = {'Game.dll': ('samples/Game.dll', '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786'),
    'CryPhysics.dll': ('client/programs/aion-bin64/bin64/CryPhysics.dll', '7afd2f7080d8180888d47a790acb1e5ae31533ee260c6563e18661057cf7c38f')}
OBJECT, STACK = 0x60000000, 0x70000000
decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

def machine(module):
    relative, expected = inputs[module]
    data = (study / relative).read_bytes()
    assert hashlib.sha256(data).hexdigest() == expected
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    optional = pe+24
    base = struct.unpack_from('<Q', data, optional+24)[0]
    image_size, header_size = struct.unpack_from('<II', data, optional+56)
    optional_size = struct.unpack_from('<H', data, pe+20)[0]
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    uc.mem_map(base, (image_size+0xfff)&~0xfff)
    uc.mem_write(base, data[:header_size])
    for index in range(struct.unpack_from('<H', data, pe+6)[0]):
        _, rva, size, raw = struct.unpack_from('<IIII', data, optional+optional_size+40*index+8)
        if size:
            uc.mem_write(base+rva, data[raw:raw+size])
    uc.mem_map(OBJECT, 0x4000)
    uc.mem_map(STACK, 0x10000)
    uc.reg_write(registers.UC_X86_REG_RSP, STACK+0x8000)
    return uc, base

def run(uc, base, module, entry, stop):
    trace, finished = [], []
    def step(cpu, address, size, _):
        if address == base+stop:
            finished.append(True)
            cpu.emu_stop()
            return
        raw = bytes(cpu.mem_read(address, size))
        instruction = next(decoder.disasm(raw, address))
        assert instruction.mnemonic not in ('call', 'ret', 'syscall')
        trace.append({'module': module, 'rva': hex(address-base), 'bytes': raw.hex(),
            'instruction': instruction.mnemonic+' '+instruction.op_str})
    uc.hook_add(unicorn.UC_HOOK_CODE, step)
    uc.emu_start(base+entry, 0, count=100)
    assert finished == [True]
    return trace

trials = []
for speed in [6, 9, 12]:
    game, base = machine('Game.dll')
    stack = STACK+0x8000
    game.reg_write(registers.UC_X86_REG_RBX, OBJECT)
    game.reg_write(registers.UC_X86_REG_RDI, OBJECT+0x2000)
    game.reg_write(registers.UC_X86_REG_XMM1, struct.unpack('<I', struct.pack('<f', 10))[0])
    game.reg_write(registers.UC_X86_REG_XMM6, 0)
    game.mem_write(OBJECT+0x6c8, struct.pack('<f', speed))
    game.mem_write(stack+0x68, struct.pack('<ff', 6, 8))
    game_trace = run(game, base, 'Game.dll', 0x4bbb3d, 0x4bbbaa)
    request = bytes(game.mem_read(stack+0x20, 0x14))
    record_type, x, y, z, mode = struct.unpack('<IfffI', request)
    assert record_type == 1 and mode == 3
    physics, base = machine('CryPhysics.dll')
    physics.reg_write(registers.UC_X86_REG_R14, OBJECT)
    physics.reg_write(registers.UC_X86_REG_R15, OBJECT+0x2000)
    physics.reg_write(registers.UC_X86_REG_EAX, mode)
    physics.reg_write(registers.UC_X86_REG_ECX, 0)
    physics.mem_write(OBJECT+0x2000, request)
    physics_trace = run(physics, base, 'CryPhysics.dll', 0x6d696, 0x6d7dd)
    actual = struct.unpack('<fff', physics.mem_read(OBJECT+0x178, 12))
    flag = struct.unpack('<I', physics.mem_read(OBJECT+0x28c, 4))[0]
    assert actual == (x, y, z) and flag == 1
    expected_scale = min(speed, 10)/10
    assert abs(x-6*expected_scale) < 1e-5 and abs(y-8*expected_scale) < 1e-5 and z == 0
    trials.append({'componentSpeed': speed, 'syntheticCandidateLength': 10, 'inputPlaneVector': [6, 8],
        'requestBytes': request.hex(), 'requestType': record_type, 'requestMode': mode, 'requestVector': [x, y, z],
        'livingEntityVector178_17c_180': list(actual), 'livingEntityFlag28c': flag,
        'gameTrace': game_trace, 'physicsTrace': physics_trace})
for relative, expected in inputs.values():
    assert hashlib.sha256((study / relative).read_bytes()).hexdigest() == expected
result = {'source': 'Auxiliary bounded execution of original Game and CryPhysics fragments with a manually transferred input record',
    'sourceDigests': {name: expected for name, (_, expected) in inputs.items()}, 'nativeGameExecuted': False,
    'syntheticCpuInstructionsExecuted': True, 'versions': {'unicorn': unicorn.__version__, 'capstone': capstone.__version__},
    'trials': trials, 'limitations': ['Candidate length 10 and input vector (6,8) are chosen fixtures; the preceding math dispatch is not executed.',
        'The Game fragment starts after status retrieval and stops before its virtual action call.',
        'The record is manually transferred to a known CLivingEntity mode-3 fragment; runtime vtable and object selection are not captured.',
        'The Physics fragment skips base action handling and stops before synchronization, callbacks and physical integration.',
        'These results establish selected original vector limiting and field-write behavior, not world displacement or server acceptance.']}
args.output.parent.mkdir(parents=True, exist_ok=True)
with args.output.open('x', encoding='utf-8', newline='\n') as handle:
    json.dump(result, handle, indent=2)
print(json.dumps({'trials': [{'speed': row['componentSpeed'], 'vector': row['requestVector'],
    'physicsFields': row['livingEntityVector178_17c_180']} for row in trials], 'nativeGameExecuted': False}))
