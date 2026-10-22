"""Auxiliary Capstone/PE candidate finder, NOT REA-verified semantics.
Uses PE exception ranges as decode starts; member offsets alone are ambiguous.
"""
import argparse
import bisect
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import struct
import capstone
from capstone.x86 import X86_OP_MEM, X86_OP_IMM

p = argparse.ArgumentParser()
p.add_argument('binary', type=Path)
p.add_argument('--output', type=Path, default=Path(__file__).with_name('auxiliary-field-consumers.json'))
a = p.parse_args(); raw = a.binary.read_bytes()
sha = hashlib.sha256(raw).hexdigest()
if sha != 'b3043f0eaf225b3dc7ba320ac7671cc5b28cefbd637135943dc9e67c114ccae7':
    raise ValueError('Wrong TW Game.dll')
pe = struct.unpack_from('<I', raw, 0x3c)[0]; opt = pe + 24
nsec = struct.unpack_from('<H', raw, pe+6)[0]
base = struct.unpack_from('<Q', raw, opt+24)[0]
sec_at = opt + struct.unpack_from('<H', raw, pe+20)[0]
sections=[]
for i in range(nsec):
    pos=sec_at+i*40; name=raw[pos:pos+8].rstrip(b'\0').decode('ascii')
    vs,rva,size,offset=struct.unpack_from('<IIII',raw,pos+8)
    sections.append({'name':name,'rva':rva,'size':size,'offset':offset,
                     'characteristics':struct.unpack_from('<I',raw,pos+36)[0]})
def fileoff(rva):
    for s in sections:
        if s['rva'] <= rva < s['rva']+s['size']:
            return rva-s['rva']+s['offset']
    raise ValueError(f'Unbacked RVA {rva:x}')
exc_rva,exc_size=struct.unpack_from('<II',raw,opt+112+3*8)
exc_off=fileoff(exc_rva)
ranges=[struct.unpack_from('<III',raw,exc_off+i) for i in range(0,exc_size,12)]
ranges=sorted((s,e,u) for s,e,u in ranges if s<e)
starts=[x[0] for x in ranges]
fields={0x194:'proc_prob_candidate',0x196:'adjacent_left_candidate',0xe4:'skill_id_candidate',0x1bb:'skill_level_candidate'}
candidate_ranges=set()
for s in sections:
    if not s['characteristics'] & 0x20000000:continue
    blob=raw[s['offset']:s['offset']+s['size']]
    for displacement in fields:
        needle=struct.pack('<I',displacement); pos=0
        while True:
            pos=blob.find(needle,pos)
            if pos<0:break
            rva=s['rva']+pos; idx=bisect.bisect_right(starts,rva)-1
            if idx>=0 and ranges[idx][0]<=rva<ranges[idx][1]:candidate_ranges.add(ranges[idx])
            pos+=1
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
raw_candidates={}
for s in sections:
    if not s['characteristics'] & 0x20000000:continue
    blob=raw[s['offset']:s['offset']+s['size']]
    for displacement in fields:
        needle=struct.pack('<I',displacement); pos=0
        while True:
            pos=blob.find(needle,pos)
            if pos<0:break
            for back in range(1,9):
                start=pos-back
                if start<0:continue
                ins=next(md.disasm(blob[start:start+16],base+s['rva']+start,count=1),None)
                if not ins or not(start+ins.size>=pos+4):continue
                for op in ins.operands:
                    if op.type==X86_OP_MEM and op.mem.disp==displacement and ins.reg_name(op.mem.base) not in ('rsp','rbp','rip'):
                        if displacement==0x194 and op.size==2 or displacement==0x1bb and op.size==1:
                            key=(hex(ins.address),ins.mnemonic,ins.op_str)
                            at=s['offset']+start
                            raw_candidates[key]={'va':hex(ins.address),'file_offset':at,'bytes':ins.bytes.hex(),
                                                 'mnemonic':ins.mnemonic,'operands':ins.op_str,
                                                 'context_bytes_start':hex(ins.address-16),
                                                 'context_bytes':raw[at-16:at+48].hex()}
            pos+=1
rows=[]; failures=[]
for start,end,unwind in sorted(candidate_ranges):
    code=raw[fileoff(start):fileoff(start)+(end-start)]
    insns=list(md.disasm(code,base+start)); last=insns[-1].address+insns[-1].size-base if insns else start
    if last != end:failures.append({'start':hex(base+start),'end':hex(base+end),'decode_end':hex(base+last)})
    matches=[]
    for idx,ins in enumerate(insns):
        for op in ins.operands:
            if op.type==X86_OP_MEM and op.mem.disp in fields:
                # Stack-relative same-offset reads cannot establish item-object fields.
                reg=ins.reg_name(op.mem.base)
                if reg in ('rsp','rbp','rip'):continue
                matches.append({'va':hex(ins.address),'file_offset':fileoff(ins.address-base),
                                'mnemonic':ins.mnemonic,'operands':ins.op_str,'bytes':ins.bytes.hex(),
                                'displacement':hex(op.mem.disp),'memory_operand_size':op.size,
                                'base_register':reg,
                                'context':[f'{x.address:#x}: {x.mnemonic} {x.op_str}' for x in insns[max(0,idx-4):idx+5]]})
    if matches:
        rows.append({'exception_range_start':hex(base+start),'exception_range_end':hex(base+end),
                     'unwind_rva':hex(unwind),'decode_complete':last==end,'matches':matches,
                     'direct_calls':[hex(i.operands[0].imm) for i in insns
                                     if i.mnemonic=='call' and i.operands[0].type==X86_OP_IMM]})
result={'method':'auxiliary Capstone disassembly from PE runtime-function ranges; NOT REA evidence',
        'source':str(a.binary),'sha256':sha,'capstone_version':capstone.__version__,
        'runtime_function_ranges':len(ranges),'raw_candidate_ranges':len(candidate_ranges),
        'candidate_function_ranges':len(rows),'decode_gaps':failures,'candidates':rows,
        'unaligned_raw_instruction_candidates':list(raw_candidates.values()),
        'limitations':['Same numeric displacement does not establish the object type or field meaning.',
                       'PE exception entries may be function fragments; leaf functions without entries are not covered.',
                       'Data embedded in code and unreachable code are not distinguished.',
                       'Only disp32 raw seeds were selected; smaller encodings and computed field addressing are not covered.',
                       '0x196 is only an adjacent-field hypothesis until descriptor verification.']}
a.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'candidate_ranges':len(rows),'raw_candidate_ranges':len(candidate_ranges),'output':str(a.output)}))
for row in rows:
    priority=[m for m in row['matches'] if m['displacement']=='0x194' and m['memory_operand_size']==2]
    if priority: print(row['exception_range_start'],[(m['va'],m['mnemonic'],m['operands']) for m in priority])
print('UNALIGNED CANDIDATES',json.dumps(list(raw_candidates.values()),indent=2))
