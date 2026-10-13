"""Run the archived CryAnimation character speed setter with synthetic objects."""
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
source = study / 'client/programs/aion-bin64/bin64/CryAnimation.dll'
data = source.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '32f492dc373e22aa43647546b888e0420044b84a7039a40dc99f6e91b5a637ac'
pe = struct.unpack_from('<I', data, 0x3c)[0]
optional = pe + 24
base = struct.unpack_from('<Q', data, optional + 24)[0]
image_size, header_size = struct.unpack_from('<II', data, optional + 56)
optional_size = struct.unpack_from('<H', data, pe + 20)[0]
sections = [struct.unpack_from('<IIII', data, optional + optional_size + 40*i + 8)
            for i in range(struct.unpack_from('<H', data, pe + 6)[0])]
decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
OBJECT, MANAGER, LAYER, STACK = 0x60000000, 0x60001000, 0x60002000, 0x70000000

def bits(value):
    return struct.unpack('<I', struct.pack('<f', value))[0]

def read_float(cpu, address):
    return struct.unpack('<f', cpu.mem_read(address, 4))[0]

def trial(layer, multiplier):
    cpu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    cpu.mem_map(base, (image_size + 0xfff) & ~0xfff)
    cpu.mem_write(base, data[:header_size])
    for _, rva, size, raw in sections:
        if size:
            cpu.mem_write(base + rva, data[raw:raw + size])
    cpu.mem_map(OBJECT, 0x4000)
    cpu.mem_map(STACK, 0x10000)
    cpu.mem_write(OBJECT + 0x318, struct.pack('<Q', MANAGER))
    cpu.mem_write(OBJECT + 0x328, struct.pack('<f', 1.0))
    cpu.mem_write(MANAGER + 8, struct.pack('<QQ', LAYER, LAYER + 4))
    cpu.mem_write(LAYER, struct.pack('<f', 1.0))
    cpu.reg_write(reg.UC_X86_REG_RCX, OBJECT)
    cpu.reg_write(reg.UC_X86_REG_EDX, layer)
    cpu.reg_write(reg.UC_X86_REG_XMM2, bits(multiplier))
    cpu.reg_write(reg.UC_X86_REG_RSP, STACK + 0x8008)
    trace, stopped = [], []
    stops = {base + 0xb0b7a: 'accepted-return', base + 0xb0b7b: 'rejected-log'}

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
    cpu.emu_start(base + 0x54e10, 0, count=100)
    assert len(stopped) == 1
    return {'layer': layer, 'inputMultiplier': multiplier, 'stop': stopped[0],
            'instanceSpeedSlot': read_float(cpu, OBJECT + 0x328),
            'layerSpeedSlot': read_float(cpu, LAYER), 'trace': trace}

trials = [trial(0, 2.0), trial(0, 0.0), trial(0, -1.0), trial(0, 1000000.0), trial(17, 2.0)]
assert [(t['stop'], t['instanceSpeedSlot'], t['layerSpeedSlot']) for t in trials] == [
    ('accepted-return', 2.0, 2.0), ('accepted-return', 0.0, 0.0),
    ('rejected-log', -1.0, 1.0), ('rejected-log', 1000000.0, 1.0),
    ('rejected-log', 2.0, 1.0)]
assert hashlib.sha256(source.read_bytes()).hexdigest() == digest
result = {'source': 'Bounded Unicorn execution of original CryAnimation.dll virtual slot +0x360 target',
          'sourcePath': 'client/programs/aion-bin64/bin64/CryAnimation.dll',
          'targetSha256': digest, 'afterSha256': digest, 'nativeGameExecuted': False,
          'syntheticCpuInstructionsExecuted': True,
          'versions': {'unicorn': unicorn.__version__, 'capstone': capstone.__version__},
          'trials': trials,
          'limitations': ['The Game-to-Entity-to-CryAnimation virtual calls were statically bound, not executed together.',
                          'Synthetic instance and layer vector; real animation playback and event timing were not observed.',
                          'Stops before invalid-input logging or return; no server or original executable was run.']}
if args.check:
    assert json.loads(args.output.read_text(encoding='utf-8')) == result
else:
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8', newline='\n') as handle:
        json.dump(result, handle, indent=2)
print(json.dumps({'sourceUnchanged': True, 'trials': [
    {'layer': t['layer'], 'input': t['inputMultiplier'], 'stop': t['stop'],
     'instance': t['instanceSpeedSlot'], 'layerSpeed': t['layerSpeedSlot']} for t in trials]}))
