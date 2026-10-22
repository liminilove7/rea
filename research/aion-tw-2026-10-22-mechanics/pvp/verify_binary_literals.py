"""Read original PE bytes at REA-established instruction/data addresses; no execution."""
import hashlib,json,struct
from pathlib import Path

HERE=Path(__file__).parent
BIN=HERE.parent/'binary-evidence'
EXPECTED='b3043f0eaf225b3dc7ba320ac7671cc5b28cefbd637135943dc9e67c114ccae7'
TARGET=Path('D:/REA/_reference/github-releases/aion-tw-offline-20261020/client__static-programs-20261020/bin56/Game.dll')
blob=TARGET.read_bytes();digest=hashlib.sha256(blob).hexdigest()
assert digest==EXPECTED, 'Target identity changed'
pe=struct.unpack_from('<I',blob,0x3c)[0]; assert blob[pe:pe+4]==b'PE\0\0'
count=struct.unpack_from('<H',blob,pe+6)[0]; opt=pe+24
assert struct.unpack_from('<H',blob,opt)[0]==0x20b
base=struct.unpack_from('<Q',blob,opt+24)[0]
sect=opt+struct.unpack_from('<H',blob,pe+20)[0]
sections=[]
for i in range(count):
    row=sect+40*i;vs,va,sz,off=struct.unpack_from('<IIII',blob,row+8)
    sections.append((va,sz,off))
def offset(va,size):
    rva=va-base
    matches=[off+rva-start for start,sz,off in sections if start<=rva and rva+size<=start+sz]
    assert len(matches)==1, (hex(va),size)
    return matches[0]
def bytes_fact(va,size):
    off=offset(va,size);raw=blob[off:off+size];assert len(raw)==size
    return {'va':hex(va),'rva':hex(va-base),'file_offset':off,'length':size,'hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest()}
def utf16_fact(va):
    off=offset(va,2);end=off
    while blob[end:end+2]!=b'\0\0':
        end+=2;assert end-off<512,'Unbounded string'
    return dict(bytes_fact(va,end-off+2),text=blob[off:end].decode('utf-16le'))
def rip_lea(va,expected):
    fact=bytes_fact(va,7);raw=bytes.fromhex(fact['hex']);assert raw[:3] in (b'\x48\x8d\x15',b'\x4c\x8d\x05')
    addr=va+7+struct.unpack_from('<i',raw,3)[0];literal=utf16_fact(addr);assert literal['text']==expected
    return {'instruction':fact,'referenced_utf16':literal}
mapping=[(106,0x1802e52c9,'PvPAttackRatio'),(107,0x1802e52f5,'PvPDefendRatio'),
         (111,0x1802e5321,'PvPAttackRatio_Physical'),(112,0x1802e534d,'PvPDefendRatio_Physical'),
         (113,0x1802e5379,'PvPAttackRatio_Magical'),(114,0x1802e53a5,'PvPDefendRatio_Magical')]
out={'method':'Auxiliary original PE byte readback of REA-established addresses; exact RIP LEA decoding, not generalized disassembly.',
     'source':str(TARGET),'source_sha256':digest,'target_executed':False,'attribute_names':[dict(enum=k,**rip_lea(addr,s)) for k,addr,s in mapping],
     'formats':[rip_lea(0x1803335f3,'%s%d%%'),rip_lea(0x18033361a,'%s%.1f%%')],
     'scale':bytes_fact(0x180db5a80,4),'rea_instruction_evidence':[]}
out['scale']['float32']=struct.unpack('<f',bytes.fromhex(out['scale']['hex']))[0]
assert out['scale']['hex']=='cdcccc3d'
for n,lo,hi in [('pvp-format-insns',0x1803335bb,0x180333640),('pvp-parser-insns',0x1802e52c9,0x1802e53c8)]:
    src=json.loads((BIN/(n+'.evidence.json')).read_text('utf8'))
    assert src['subject']['digest']['sha256']==digest
    out['rea_instruction_evidence'].append({'file':n+'.evidence.json','evidence_id':src['evidence_id'],
        'selected_instructions':[s for s in src['normalized_result']['instructions'] if lo<=int(s.split(':')[0],16)<hi]})
out['conclusion']='These attribute enums use value/10 percent text formatting; this establishes display units only, not a server damage formula or skill pvp_damage_ratio units.'
(HERE/'binary-literal-facts.json').write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf8')
print(json.dumps({'attribute_names':[(x['enum'],x['referenced_utf16']['text']) for x in out['attribute_names']],
                 'formats':[x['referenced_utf16']['text'] for x in out['formats']],'scale':out['scale']},ensure_ascii=False,indent=2))
