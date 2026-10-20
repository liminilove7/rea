"""Check new-version observations against retained REA output and original files."""
from pathlib import Path
import hashlib,json,math,struct,xml.etree.ElementTree as ET
root=Path(__file__).parent
sha='b3043f0eaf225b3dc7ba320ac7671cc5b28cefbd637135943dc9e67c114ccae7'
checks=[]
def check(name,condition,source=None):
    if not condition:raise AssertionError(name)
    checks.append({'name':name,'passed':True,'source':source})
def load(name):return json.loads((root/name).read_text(encoding='utf-8-sig'))
def instruction(stem,text):
    result=load(stem+'.normalized.json')
    check(text,any(text.lower() in x.lower() for x in result['instructions']),stem+'.evidence.json')
check('Copied Game.dll matches selected SHA256',hashlib.sha256((root/'samples/Game.dll').read_bytes()).hexdigest()==sha)
meta=load('sample-observations.json')
for m in meta['modules']:
    check('Original and copy unchanged: '+Path(m['source']).name,hashlib.sha256(Path(m['source']).read_bytes()).hexdigest()==m['sha256'] and hashlib.sha256(Path(m['sample']).read_bytes()).hexdigest()==m['sha256'])
for stem,text in [
 ('seed-0-insns','0x1802e44a1: mov eax, 1Dh'),
 ('seed-0-insns','0x1802e45d5: mov eax, 24h'),
 ('seed-0-insns','0x1802e4735: mov eax, 25h'),
 ('action-consumer-insns','0x1807e94d8: movss xmm9, dword ptr [r8+7]'),
 ('action-consumer-insns','0x1807e9e0c: movaps xmm2, xmm9'),
 ('action-consumer-insns','0x1807e9e12: call sub_1808CA320'),
 ('speed-dispatch-insns','0x1808ca333: movaps xmm6, xmm2'),
 ('speed-dispatch-insns','0x1808ca381: call sub_18089F3D0'),
 ('speed-dispatch-insns','0x1808ca38e: movaps xmm1, xmm6'),
 ('speed-dispatch-insns','0x1808ca394: call qword ptr [rdx+260h]'),
 ('animation-wrapper-insns','0x18089ae0f: movss dword ptr [rsi+38h], xmm6'),
 ('animation-wrapper-insns','0x18089ae14: movss dword ptr [rsi+70Ch], xmm6'),
 ('animation-wrapper-insns','0x18089ae0b: mulss xmm0, xmm6'),
 ('animation-wrapper-insns','0x18089ae1c: movss dword ptr [rsi+710h], xmm0'),
 ('animation-wrapper-insns','0x18089ae41: divss xmm0, xmm6'),
 ('animation-wrapper-insns','0x18089ae4b: movss dword ptr [rsi+714h], xmm0'),
 ('animation-wrapper-insns','0x18089af5e: movss cs:dword_18142DC14, xmm6'),
 ('action-consumer-insns','0x1807e9784: mov [rax+530h], r14w'),
 ('action-consumer-insns','0x1807e978c: mov [rax+532h], bx'),
 ('seed-4-insns','0x18089b4c5: movzx eax, word ptr [rdi+530h]'),
 ('seed-4-insns','0x18089b4d5: movzx ecx, word ptr [rdi+532h]'),
 ('seed-4-insns','0x18089b4f9: divss xmm6, xmm0'),
 ('seed-4-insns','0x18089b689: mulss xmm6, dword ptr [rdi+51Ch]'),
 ('seed-6-insns','0x180530aa0: movzx eax, word ptr [rbp+70h]'),
 ('seed-6-insns','0x180530ab9: divss xmm6, cs:dword_180DB63E4'),
 ('seed-6-insns','0x180530b01: movss xmm1, dword ptr [rbp+3E4h]'),
 ('attack-interval-access-insns','0x18016d6ae: movzx eax, cs:word_18142DB40'),
 ('attack-interval-access-insns','0x18016d6b5: add eax, [rsi+1E90h]'),
 ('attack-interval-access-insns','0x18016d6bb: cmp ebp, eax'),
 ('attack-interval-access-insns','0x18016d6bd: jbe loc_18016D8A8'),
 ('attack-interval-access-insns','0x18016d8a0: mov [rsi+1E90h], ebp'),
 ('status-handler-insns','0x1807e7568: mov cs:dword_18142DC10, eax'),
 ('move-consumer-0-insns','0x180862048: movss xmm3, dword ptr [rdi+70Ch]'),
 ('move-consumer-7-insns','0x1808a2f21: maxss xmm2, dword ptr [r14+714h]')
]:instruction(stem,text)
tables=load('original-table-facts.json')
for name in ['.?AVCharacterObject@@','.?AVPlayer@@']:
    t=next(x for x in tables['vtables'] if x['type']==name)
    check(name+' original vtable +260 points to observed setter',t['additional_slot_values']['0x260']=='0x18089adb0')
check('Original scale constant is 1000.0',next(x for x in tables['constants'] if x['va']=='0x180db63e4')['float32']==1000.0)
bundle=load('procedure-inventory-evidence.json');record=bundle['records'][0]
check('Exported complete procedure inventory bound to current hash',record['subject']['digest']['sha256']==sha)
check('Inventory contains 44646 identified entries',len(record['normalized_result'])==44646)
evidence=[]
for p in sorted(root.glob('*.evidence.json')):
    e=load(p.name)['data'];check('Evidence input hash: '+p.stem,e['subject']['digest']['sha256']==sha,p.name);evidence.append(e)
resources=load('speed-resources.json')
check('All selected resource entries passed CRC',not resources['errors'] and all(x['crc_verified'] for x in resources['decoded']))
for entry,count in [('client_items.xml',74259),('client_skills.xml',10797)]:check(entry+' parsed row count',next(x for x in resources['decoded'] if x['entry']==entry)['records']==count)
f32=lambda n:struct.unpack('<f',struct.pack('<f',n))[0]
gate=lambda t,last,i:(t&0xffffffff)>((last+(i&0xffff))&0xffffffff)
numeric=[]
def number(name,result,expected):
    check(name,result==expected);numeric.append({'name':name,'actual':result,'expected':expected})
number('At threshold the observed unsigned JBE branch stays closed',gate(2800,1000,1800),False)
number('One tick after threshold the gate opens',gate(2801,1000,1800),True)
number('UI 1800 interval units formats as 1.8 seconds',1800/1000,1.8)
number('UI 1500 interval units formats as 1.5 seconds',1500/1000,1.5)
number('Exact addition wraps at 32 bits before unsigned comparison',gate(0xfffffff5,0xfffffff0,40),True)
number('Speed 6 square is 36',f32(f32(6)*f32(6)),36.0)
number('Speed 9 square is 81',f32(f32(9)*f32(9)),81.0)
number('Speed 6 reciprocal is float32 1/6',f32(1/f32(6)),f32(1/6))
number('Cattack ratio uses float32 2000/1500',f32(f32(2000)/f32(1500)),f32(4/3))
functions={e['normalized_result']['procedure']['address'] for e in evidence if isinstance(e.get('normalized_result'),dict) and isinstance(e['normalized_result'].get('procedure'),dict) and 'instructions' in e['normalized_result']}
requests=[]
for p in sorted(root.glob('*.mcp.json')):
    r=load(p.name)
    if isinstance(r,dict) and 'name' in r and 'result' in r:requests.append({'file':p.name,'operation':r['name'],'isError':bool(r['result'].get('isError')),'error':r['result'].get('structuredContent',{}).get('error')})
summary={'all_passed':True,'sample_sha256':sha,'check_count':len(checks),'checks':checks,'numeric_cases':numeric,'saved_request_records':len(requests),'saved_failed_request_records':sum(r['isError'] for r in requests),'evidence_files':len(evidence),'unique_evidence_ids':len({e['evidence_id'] for e in evidence}),'identified_procedures':len(record['normalized_result']),'instruction_entrypoints_observed':len(functions),'instruction_entrypoints':sorted(functions),'target_executed':False,'runtime_modification_tested':False,'requests':requests}
(root/'verification.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf8')
print(json.dumps({k:summary[k] for k in ['all_passed','check_count','saved_request_records','saved_failed_request_records','evidence_files','instruction_entrypoints_observed','identified_procedures']},ensure_ascii=False))
