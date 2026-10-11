"""Trace received attack records and rejection messages without executing the client."""
from analyze_aion_native import *
import xml.etree.ElementTree as ET
import shutil

b=Binary(CASE/'samples'/'Game.dll')
assert hashlib.sha256(b.data).hexdigest()=='834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786'
types=json.loads((BACK/'Game.dll.rtti.json').read_text(encoding='utf-8'))
player=next(t for t in types if t['name']=='.?AVPlayer@@')
vt=next(v for c in player['locators'] for v in c['vtables'] if len(v['entries'])>144)
assert vt['entries'][81]['target_rva']=='0x480890'
assert vt['entries'][144]['target_rva']=='0x2da70'
windows=[('attack_result_dispatch',0x4277fa,0x427853),('player_attack_result',0x2da70,0x2db44),('attack_message',0x430d20,0x431356),('attack_queue_builder',0x480890,0x480ea6),('template_min_reader',0x396d60,0x396dbb),('template_max_reader',0x396dc0,0x396e1b)]
native=[{'label':n,'start_rva':hex(s),'end_rva':hex(e),'instructions':b.disasm(s,e-s)} for n,s,e in windows]
rows={int(r['rva'],16):r for f in native for r in f['instructions']}
expected={0x42780d:'movsx edi, byte ptr [rax]',0x427839:'call qword ptr [r9 + 0x480]',0x430dcf:'movzx edi, word ptr [rdx + 5]',0x43106f:'call qword ptr [r10 + 0x288]',0x48091c:'movss dword ptr [rsi + 8], xmm6',0x480b9e:'lea rcx, [r14 + 0x1110]',0x480baf:'mov qword ptr [rdx], rsi',0x396da6:'movzx eax, word ptr [rax + 0x1b8]',0x396e06:'movzx eax, word ptr [rax + 0x1ba]'}
checks=[]
for rv,wanted in expected.items():
    assert rows[rv]['instruction']==wanted
    checks.append({'rva':hex(rv),'instruction':wanted,'passed':True})
constant=struct.unpack('<f',b.pe.get_data(0x8754a0,4))[0]
assert constant==1000.0
ids_by_target={0x2dae1:1300115,0x2dae8:1300116,0x2dab8:1300032,0x2dabf:1300828,0x2da96:1300033}
source=CASE/'exports'/'decoded'/'L10N'/'CHS'/'Data'/'Data'/'Strings'/'client_strings_msg.xml'
localized={int(d['id']):d for e in ET.parse(source).getroot() if (d:={c.tag:c.text for c in e}).get('id') in {str(i) for i in ids_by_target.values()}}
cases=[]
for i in range(7):
    dest=struct.unpack('<I',b.pe.get_data(0x2db44+4*i,4))[0]
    ident=ids_by_target.get(dest)
    cases.append({'received_signed_code':i+1,'branch_rva':hex(dest),'text_id':ident,'localized_record':localized.get(ident),'limitation':'No threshold or server validation algorithm is established by this mapping.'})
save('received-attack-consumers.json',{'sha256':hashlib.sha256(b.data).hexdigest(),'player_rtti':player,'checks':checks,'native_windows':native,'result_codes':cases,'localization_source':{'path':str(source),'sha256':hashlib.sha256(source.read_bytes()).hexdigest()},'received_timing':{'source':'S_ATTACK internal decoded payload+5 uint16','conversion':'float32(value)/1000.0','constant_rva':'0x8754a0','destination':'new queued attack record+8 via Player vtable+0x288 (0x480890)','unknown':'Time unit and whether this is final attack interval, animation duration, or another timing quantity remain unverified.'},'queue_connection':{'producer':'0x480890 appends attack records to component+0x1110/+0x1118','consumer':'0x477210 searches this queue among others for matching movement updates','unknown':'This does not prove a RandomMoveLoc direction or client-authoritative teleport.'}})
for folder in [CASE/'reports'/'scripts',BACK.parent/'scripts']:
    folder.mkdir(exist_ok=True)
    shutil.copy2(Path(__file__),folder/Path(__file__).name)
print(json.dumps({'checks':len(checks),'result_codes':cases},ensure_ascii=False,indent=2))
