"""Statically reproduce the observed 4096-byte XOR/add transform. No execution."""
from analyze_aion_native import *

dest=CASE/'exports'/'protection-stage1';dest.mkdir(exist_ok=True)
summaries=[]
for name in ('Aion.bin','Game.dll','CrySystem.dll'):
    b=Binary(CASE/'samples'/name)
    chain=json.loads((OUT/(name+'.entry-chain.json')).read_text(encoding='utf8'))
    stub=int(chain['chain'][-1]['rva'],16)
    rows=b.disasm(stub,0x7c)
    expected={0:'push rsi',1:'push rax',2:'push rbx',0x2a:'mov ebx, 0x1000',0x68:'xor dword ptr [rsi], eax',0x6a:'add dword ptr [rsi], ebx'}
    ins={int(x['rva'],16)-stub:x for x in rows}
    for off,value in expected.items():
        if ins[off]['instruction']!=value:raise ValueError((name,off,'stub mismatch'))
    def immediate(off):return int(ins[off]['instruction'].split(', ')[-1].split(' ')[-1],0)
    target=(stub+9-immediate(0x10)-immediate(0x16)+immediate(0x1c))&0xffffffff
    xor_key=immediate(0x34)&0xffffffff;add_key=immediate(0x2f)&0xffffffff
    raw=b.pe.get_data(target,0x1000)
    words=struct.unpack('<1024I',raw)
    decoded=struct.pack('<1024I',*[((w^xor_key)+add_key)&0xffffffff for w in words])
    inverse=struct.pack('<1024I',*[((w-add_key)&0xffffffff)^xor_key for w in struct.unpack('<1024I',decoded)])
    assert inverse==raw
    path=dest/(name+'.stage1-rva-'+hex(target)+'.bin');path.write_bytes(decoded)
    # Disassemble only from the observed continuation, not the 20-byte prefix.
    listing=[{'rva':hex(i.address-b.base),'bytes':i.bytes.hex(' '),'instruction':i.mnemonic+' '+i.op_str} for i in b.md.disasm(decoded[0x14:],b.base+target+0x14)]
    report={'module':name,'source_sha256':hashlib.sha256(b.data).hexdigest(),'stub':b.loc(stub),'decoded_region':b.loc(target),'decoded_bytes':len(decoded),'continuation_rva':hex(target+0x14),'xor_key':hex(xor_key),'add_key':hex(add_key),'formula':'plain_u32 = ((cipher_u32 XOR xor_key) + add_key) mod 2^32; little endian','inverse_roundtrip_passed':True,'output':str(path),'output_sha256':hashlib.sha256(decoded).hexdigest(),'status':'first protection layer only; not a reconstructed PE or original entry point','disassembly':listing}
    save(name+'.stage1.json',report)
    summaries.append({k:v for k,v in report.items() if k!='disassembly'})
save('stage1-summary.json',summaries)
print(json.dumps(summaries,indent=2))
