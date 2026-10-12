"""Bounded offline CPU experiment; native APIs and thread environment are never supplied."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import time

import capstone
from capstone.x86_const import X86_OP_MEM
import unicorn
from unicorn import x86_const

parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--max-steps', type=int, default=20000)
args = parser.parse_args()
assert args.output.is_absolute() and args.max_steps > 0
args.output.mkdir(parents=True, exist_ok=False)
study = Path(__file__).resolve().parents[3]
source = study / 'samples/Game.dll'
data = source.read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786'
pe = struct.unpack_from('<I', data, 0x3c)[0]
optional = pe+24
assert struct.unpack_from('<H', data, pe+4)[0] == 0x8664
assert struct.unpack_from('<H', data, optional)[0] == 0x20b
base = struct.unpack_from('<Q', data, optional+24)[0]
image_size, header_size = struct.unpack_from('<II', data, optional+56)
optional_size = struct.unpack_from('<H', data, pe+20)[0]
sections = []
for index in range(struct.unpack_from('<H', data, pe+6)[0]):
    virtual_size, rva, raw_size, raw = struct.unpack_from('<IIII', data, optional+optional_size+40*index+8)
    sections.append((rva, raw_size, raw))
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
STACK, STACK_SIZE, RETURN, OBJECT = 0x70000000, 0x100000, 0x50000000, 0x60000000
register_names = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rsp', 'rip', 'eflags']

def reg(name):
    return getattr(x86_const, 'UC_X86_REG_'+name.upper())

def machine(pattern):
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    uc.mem_map(base, (image_size+0xfff)&~0xfff)
    uc.mem_write(base, data[:header_size])
    for rva, size, raw in sections:
        if size:
            uc.mem_write(base+rva, data[raw:raw+size])
    uc.mem_map(STACK, STACK_SIZE)
    uc.mem_map(RETURN, 0x1000)
    uc.mem_map(OBJECT, 0x1000)
    for index, name in enumerate(register_names[:-3]):
        uc.reg_write(reg(name), (pattern+index*0x111111111111111)&0xffffffffffffffff)
    uc.reg_write(reg('rsp'), STACK+STACK_SIZE//2+8)
    uc.reg_write(reg('eflags'), 2)
    uc.mem_write(STACK+STACK_SIZE//2+8, struct.pack('<Q', RETURN))
    return uc

def snapshot(uc):
    return {name: hex(uc.reg_read(reg(name))) for name in register_names}

def run(label, entry, pattern, fixture=False):
    uc = machine(pattern)
    if fixture:
        uc.reg_write(reg('rcx'), OBJECT)
        uc.mem_write(OBJECT+0x58, struct.pack('<I', 21))
    initial = snapshot(uc)
    state = {'steps': 0, 'stop': None, 'imageWrites': 0}
    started = time.monotonic()
    trace_path = args.output / (label+'.trace.jsonl')
    with trace_path.open('x', encoding='utf-8', newline='\n') as trace:
        def append(value):
            trace.write(json.dumps(value, separators=(',', ':'))+'\n')

        def on_code(engine, address, size, user):
            if address == RETURN:
                state['stop'] = {'reason': 'returned_to_fixture_caller'}
                engine.emu_stop()
                return
            state['steps'] += 1
            instruction = next(md.disasm(bytes(engine.mem_read(address, size)), address, count=1), None)
            if instruction is None:
                state['stop'] = {'reason': 'decoder_did_not_identify_instruction', 'address': hex(address)}
                engine.emu_stop()
                return
            append({'kind': 'instruction', 'address': hex(address), 'bytes': instruction.bytes.hex(),
                'mnemonic': instruction.mnemonic, 'operands': instruction.op_str,
                'rsp': hex(engine.reg_read(reg('rsp')))})
            if instruction.mnemonic == 'ret':
                stack_pointer = engine.reg_read(reg('rsp'))
                append({'kind': 'return_operand', 'address': hex(address), 'rsp': hex(stack_pointer),
                    'bytes': bytes(engine.mem_read(stack_pointer, 8)).hex()})
            if instruction.mnemonic in {'rdtsc', 'rdtscp', 'cpuid', 'xgetbv', 'syscall', 'sysenter', 'int', 'int3', 'ud2'}:
                state['stop'] = {'reason': 'requires_unsupplied_cpu_or_os_environment', 'instruction': instruction.mnemonic, 'address': hex(address)}
                engine.emu_stop()
                return
            for operand in instruction.operands:
                if operand.type == X86_OP_MEM and instruction.reg_name(operand.mem.segment) in {'gs', 'fs'}:
                    state['stop'] = {'reason': 'requires_unsupplied_thread_environment', 'address': hex(address), 'operands': instruction.op_str}
                    engine.emu_stop()
                    return

        def on_invalid(engine, access, address, size, value, user):
            state['stop'] = {'reason': 'unmapped_or_disallowed_memory', 'access': access,
                'address': hex(address), 'size': size, 'rip': hex(engine.reg_read(reg('rip')))}
            append({'kind': 'memory_failure', **state['stop']})
            return False

        def on_write(engine, access, address, size, value, user):
            if base <= address < base+image_size:
                state['imageWrites'] += 1
                append({'kind': 'shadow_image_write', 'address': hex(address), 'size': size, 'value': hex(value & ((1<<(size*8))-1))})

        def on_read(engine, access, address, size, value, user):
            if base <= address < base+image_size:
                append({'kind': 'shadow_image_read', 'rip': hex(engine.reg_read(reg('rip'))),
                    'address': hex(address), 'size': size, 'bytes': bytes(engine.mem_read(address, size)).hex()})

        uc.hook_add(unicorn.UC_HOOK_CODE, on_code)
        uc.hook_add(unicorn.UC_HOOK_MEM_INVALID, on_invalid)
        uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, on_write)
        uc.hook_add(unicorn.UC_HOOK_MEM_READ, on_read)
        error = None
        try:
            uc.emu_start(entry, RETURN+1, timeout=30000000, count=args.max_steps)
        except unicorn.UcError as cause:
            error = str(cause)
        if state['stop'] is None:
            state['stop'] = {'reason': 'instruction_bound' if state['steps'] >= args.max_steps else 'emulator_timeout_or_exception', 'error': error}
        final = snapshot(uc)
    result = {'label': label, 'entry': hex(entry), 'initialRegisters': initial, 'finalRegisters': final,
        **state, 'emulatorError': error, 'elapsedSeconds': time.monotonic()-started, 'trace': trace_path.name}
    if fixture:
        assert state['stop']['reason'] == 'returned_to_fixture_caller'
        assert uc.reg_read(reg('rax')) == 21
        result['fixturePassed'] = True
    return result

results = [run('skill-item-type-fixture', base+0x3a0000, 0, fixture=True)]
for index, pattern in enumerate([0, 0x123456789abcdef0, 0x5555555555555555]):
    results.append(run('clock-entry-state-'+str(index), base+0x1244ae3, pattern))
assert hashlib.sha256(source.read_bytes()).hexdigest() == digest
report = {'provider': 'Auxiliary Capstone decoder and Unicorn software CPU', 'targetSha256': digest,
    'sourcePath': str(source), 'imagebase': hex(base), 'nativeTargetExecuted': False,
    'emulatedTargetInstructions': True, 'versions': {'capstone': capstone.__version__, 'unicorn': unicorn.__version__},
    'maxStepsPerTrial': args.max_steps, 'timeoutMicrosecondsPerTrial': 30000000, 'results': results,
    'limitations': ['Chosen register patterns and fixture caller are not observed game process state.',
        'Original PE mapped at preferred base with shadow RWX pages; loader import resolution and TLS initialization were not performed.',
        'No Windows API implementations, live pointers, thread environment, timing instructions or network transport were supplied.',
        'Faults and bounds are experiment boundaries, not proof the real game takes the same path.',
        'This is an auxiliary offline experiment, separate from REA/IDA observations; it is not complete unpacking.']}
with (args.output / 'report.json').open('x', encoding='utf-8', newline='\n') as handle:
    json.dump(report, handle, indent=2)
print(json.dumps({'versions': report['versions'], 'results': [{key: row[key] for key in ['label', 'steps', 'stop', 'imageWrites']} for row in results]}))
