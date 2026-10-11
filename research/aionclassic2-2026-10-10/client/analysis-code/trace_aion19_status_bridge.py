"""Compare a pinned emulator packet prefix with observed client status consumers."""
from analyze_aion_native import *
import shutil
root=Path(r'F:\RVE-Workspace\sources\AionLightning-1.9-94fc8048')
packet=root/'gameserver/src/org/openaion/gameserver/network/aion/serverpackets/SM_STATS_INFO.java'
fields=[];offset=0
sizes={'C':1,'H':2,'D':4,'F':4,'Q':8}
for i,line in enumerate(packet.read_text(encoding='utf-8-sig').splitlines()):
    if i<64:continue
    if i>=127:break
    m=re.match(r'\s*write([CHDFQ])\(buf,\s*(.+?)\);',line)
    if m:
        fields.append({'line':i+1,'type':m[1],'expression':m[2],'payload_offset':hex(offset),'status_block_offset':hex(offset-8) if offset>=8 else None})
        offset+=sizes[m[1]]
by_stat={re.search(r'StatEnum\.(\w+)',r['expression'])[1]:r for r in fields if re.search(r'StatEnum\.(\w+)',r['expression'])}
for stat,expected in [('POWER','0x0'),('KNOWLEDGE','0x8'),('MAXHP','0x3c'),('MAXMP','0x44'),('FLY_TIME','0x50'),('ATTACK_RANGE','0x64'),('ATTACK_SPEED','0x68')]:
    assert by_stat[stat]['status_block_offset']==expected
b=Binary(CASE/'samples'/'Game.dll')
native=[{'label':n,'start':hex(s),'end':hex(e),'instructions':b.disasm(s,e-s)} for n,s,e in [('time_gate_and_request',0x6a0b0,0x6a372),('timestamp_adjustment',0x5d140,0x5d373),('action_time_gate_window',0x14f7e,0x14fb1),('C_ATTACK_registration_window',0x31ac4a,0x31ac68)]]
rows={int(r['rva'],16):r for f in native for r in f['instructions']}
checks=[]
for rv,expected in {0x6a15e:'movzx eax, word ptr [rip + 0xd07a7b]',0x6a165:'add eax, dword ptr [rsi + 0x1c88]',0x6a16b:'cmp ebp, eax',0x6a16d:'jbe 0x18006a358',0x6a350:'mov dword ptr [rsi + 0x1c88], ebp',0x5d2f7:'movzx eax, word ptr [rip + 0xd148e2]',0x14f92:'movzx ecx, word ptr [rip + 0xd5cc47]',0x31ac51:'mov dword ptr [rsp + 0x30], 0x20'}.items():
    assert rows[rv]['instruction']==expected
    checks.append({'rva':hex(rv),'instruction':expected,'passed':True})
assert any(r.get('references') and any(x['kind']=='rip_relative' and x['rva']=='0xd71be0' for x in r['references']) for r in rows.values())
save('aion19-status-bridge.json',{'emulator_commit':'94fc8048e5fc198f000c0ca2176c65034c57cb39','source_packet':{'path':str(packet),'sha256':hashlib.sha256(packet.read_bytes()).hexdigest(),'prefix_fields':fields},'client_sha256':hashlib.sha256(b.data).hexdigest(),'checks':checks,'native_windows':native,'observation':'Current client 0x6A0B0 reads status-cache word+0x68 (RVA D71BE0), adds component+1C88, compares a clock-like returned value, and rejects this path when now <= sum; a later path writes the returned value back to component+1C88. 0x5D140 and 0x14F92 also consume this word in timing logic.','inference':'Emulator names this same packet-block position ATTACK_SPEED; matching HP, MP, flight-time and attack-range prefix offsets strengthen a cross-version attack-interval hypothesis. Current-client semantic name and unit are not established solely by this correspondence.','unknowns':['Compatibility of this source with current Classic client/server','Exact clock-like protected function 0x1244AE3','Whether every action uses this gate or server uses the same interval','Emulator C/SM opcodes versus current client internal IDs and constructed wire bytes'],'message_name_limit':'C_ATTACK registration gives internal name ID0x20; constructed request window has different literal bytes. No equivalence between those namespaces is asserted.'})
for folder in [CASE/'reports'/'scripts',BACK.parent/'scripts']:
    shutil.copy2(Path(__file__),folder/Path(__file__).name)
print(json.dumps({'instruction_checks':len(checks),'packet_prefix_fields':len(fields),'selected_fields':{k:by_stat[k] for k in ['POWER','KNOWLEDGE','MAXHP','MAXMP','FLY_TIME','ATTACK_RANGE','ATTACK_SPEED']}},ensure_ascii=False,indent=2))
