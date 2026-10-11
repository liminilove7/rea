from analyze_aion_native import *

summaries=[]
for name in ('Aion.bin','Game.dll','CrySystem.dll','ScriptDLL64.dll'):
    b=Binary(CASE/'samples'/name)
    entry=b.pe.OPTIONAL_HEADER.AddressOfEntryPoint
    chain=[];cur=entry
    for _ in range(12):
        rows=b.disasm(cur,32)
        if not rows:break
        row=rows[0];chain.append(row)
        if not row['instruction'].startswith('jmp ') or not row.get('references'):break
        ref=row['references'][0]
        if ref['kind']!='direct_branch':break
        cur=int(ref['rva'],16)
    save(name+'.entry-chain.json',{'chain':chain,'terminal_window':b.disasm(cur,384)})
    if name!='Game.dll':continue
    targets={}
    for m in re.finditer(rb'[ -~]{5,}',b.data):
        s=m.group().decode()
        if re.fullmatch(r'(?:GetPlayerPos|GetPlayerMapPosition|TargetUnit|GetPlayerEquip|GetUnitInfo|GetUnitName|GetUnitHealth|GetUnitMana|UnitHealth|UnitMana|UnitLevel|GetHP|GetMP|GetHealth|GetMaxHealth|GetLevel|GetTarget|GetPosition|GetPos|SetPos|SetPosition)',s,re.I):
            rv=b.pe.get_rva_from_offset(m.start());targets[rv]={'kind':'string','text':s,**b.loc(rv),'xrefs':[]}
    targets[0xd647c0]={'kind':'global_address_returned_by_CreateGameInstance',**b.loc(0xd647c0),'xrefs':[]}
    rtti=json.loads((OUT/(name+'.rtti.json')).read_text(encoding='utf8'))
    for ty in rtti:
        if ty['name'] not in ('.?AVPlayer@@','.?AVCXGame@@','.?AVGameSystem@@','.?AVDlgBasicStatus@@','.?AVDlgTarget@@'):continue
        for c in ty['locators']:
            for v in c['vtables']:
                rv=int(v['address']['rva'],16);targets[rv]={'kind':'vtable','class':ty['name'],**v['address'],'xrefs':[]}
    rip=re.compile(r'\[rip(?: ([+-]) (0x[0-9a-f]+|[0-9]+))?\]')
    count=0;selected=set()
    for start,end in b.ranges:
        for va,size,mn,op in b.md.disasm_lite(b.pe.get_data(start,end-start),b.base+start):
            count+=1
            for match in rip.finditer(op):
                displacement=int(match[2],0) if match[2] else 0
                if match[1]=='-':displacement=-displacement
                target=va+size+displacement-b.base
                if target not in targets:continue
                selected.add(start)
                targets[target]['xrefs'].append({'instruction_rva':hex(va-b.base),'function_rva':hex(start),'instruction':mn+' '+op})
    save(name+'.target-xrefs.json',{'scope':'linear decoding within PE exception-directory ranges; leaf functions without unwind records excluded','instruction_count':count,'targets':list(targets.values())})
    save(name+'.xref-functions.json',[b.dump_function(s) for s in sorted(selected)])
    summaries.append({'name':name,'instruction_count':count,'target_count':len(targets),'selected_functions':len(selected),'targets':[{'rva':x['rva'],'label':x.get('text',x.get('class',x['kind'])),'xrefs':len(x['xrefs'])} for x in targets.values()]})
save('xref-summary.json',summaries)
print(json.dumps(summaries,ensure_ascii=False,indent=2))
