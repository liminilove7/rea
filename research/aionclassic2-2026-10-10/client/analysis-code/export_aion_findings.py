from analyze_aion_native import *

b=Binary(CASE/'samples'/'Game.dll')
def binding(r):
    raw=b.pe.get_data(r,16)
    if len(raw)!=16:return None
    sp,fp=struct.unpack('<QQ',raw);sp-=b.base;fp-=b.base
    if not 0<sp<b.pe.OPTIONAL_HEADER.SizeOfImage or not 0<fp<0x6b0000:return None
    value=b.pe.get_data(sp,96).split(b'\0')[0]
    if not re.fullmatch(rb'[A-Za-z_][A-Za-z_0-9]{2,80}',value):return None
    return {'name':value.decode(),'table':b.loc(r),'string':b.loc(sp),'function':b.loc(fp)}
items=[];blocks=[]
for anchor in (0x6cebc0,0x6cedc0):
    start=anchor
    while binding(start-16):start-=16
    cur=start;count=0
    while binding(cur):items.append(binding(cur));cur+=16;count+=1
    blocks.append({'start_rva':hex(start),'end_exclusive_rva':hex(cur),'count':count})
save('Game.dll.script-bindings.json',{'blocks':blocks,'count':len(items),'boundary':'two maximal contiguous validated name-pointer/function-pointer tables around GetPlayerPos and GetPlayerMapPosition; other tables not excluded','entries':items})
functions={}
for r in (0xa2530,0xa2830,0x368e50,0x369d00,0x4f9810,0x4f87e0,0x33aaf0,0x33bec0):
    functions[hex(r)]=b.dump_function(r)
for name in ('GetPlayerPos','GetPlayerMapPosition','UnitObjectID','UnitName','UnitClassID','UnitLevel','UnitGender','UnitIsDead','UnitHP','UnitHPMax','UnitMP','UnitMPMax'):
    ent=next(x for x in items if x['name']==name)
    r=int(ent['function']['rva'],16)
    f=b.dump_function(r);f['binding_name']=name
    if name=='GetPlayerPos':
        f['instructions']=b.disasm(r,0x211);f['end_rva']='0x96511';f['bounds_source']='manual control-flow inspection joins multiple PE unwind fragments through terminal returns'
    functions[hex(r)]=f
functions['0x2b720']={'start':b.loc(0x2b720),'end_rva':'0x2b742','bounds_source':'manual control-flow inspection of leaf/tail-call function','instructions':b.disasm(0x2b720,0x22)}
functions['0x33a8a0']={'start':b.loc(0x33a8a0),'end_rva':'0x33a8a8','bounds_source':'export entry through immediate ret','instructions':b.disasm(0x33a8a0,8)}
save('Game.dll.focus-functions.json',functions)
focus={}
types=json.loads((OUT/'Game.dll.rtti.json').read_text(encoding='utf8'))
by_rva={int(t['type_descriptor']['rva'],16):t['name'] for t in types}
for t in types:
    if t['name'] not in ('.?AVPlayer@@','.?AVCXGame@@','.?AVGameSystem@@'):continue
    for c in t['locators']:
        r=int(c['class_hierarchy_rva'],16)
        signature,attributes,count,array=struct.unpack('<4I',b.pe.get_data(r,16))
        bases=[]
        if count<=128:
            for d in struct.unpack('<'+'I'*count,b.pe.get_data(array,4*count)):
                typ,contained,mdisp,pdisp,vdisp,flags=struct.unpack('<IIiiiI',b.pe.get_data(d,24))
                bases.append({'type':by_rva.get(typ,hex(typ)),'member_displacement':mdisp,'vbtable_displacement':pdisp,'vbase_displacement':vdisp,'attributes':hex(flags)})
        c['base_classes']=bases
    focus[t['name']]=t
save('Game.dll.focus-classes.json',focus)

props=[]
for name,index,offset,width,source in (
    ('UnitHP',0,0x40,4,'max(0, signed32(player_component + 0x119c)); overwrites copied cache value'),
    ('UnitHPMax',1,0x3c,4,'copied from Game.dll RVA 0xd71b78 + 0x3c'),
    ('UnitMP',2,0x48,4,'copied from Game.dll RVA 0xd71b78 + 0x48'),
    ('UnitMPMax',3,0x44,4,'copied from Game.dll RVA 0xd71b78 + 0x44'),
    ('UnitClassID',4,0xa4,4,'copied from Game.dll RVA 0xd71b78 + 0xa4'),
    ('UnitLevel',5,0x18,2,'copied from Game.dll RVA 0xd71b78 + 0x18'),
    ('UnitGender',6,0x160,4,'copied from dword(player_component + 0x22c)'),
):
    ent=next(x for x in items if x['name']==name)
    function=int(ent['function']['rva'],16)
    case=struct.unpack('<I',b.pe.get_data(0xa2ba0+index*4,4))[0]
    props.append({'property':name,'binding_rva':hex(function),'selector':index,'dispatcher_rva':'0xa2830','player_switch_case_rva':hex(case),'snapshot_member_offset':hex(offset),'read_width_bytes':width,'source':source,'scope':'player branch; source description assumes a valid local player component; no-component selected-record fallback differs; snapshot is not Player object','verification':'static code/data-flow; not live-tested'})
save('Game.dll.property-map.json',props)

script=Binary(CASE/'samples'/'ScriptDLL64.dll')
stypes=json.loads((OUT/'ScriptDLL64.dll.rtti.json').read_text(encoding='utf8'))
ty=next(t for t in stypes if t['name']=='.?AVIScriptDLLImpl@@')
funcs={'GetInterface':{'instructions':script.disasm(0x6e21b0,15)}}
for v in ty['locators'][0]['vtables']:
    for e in v['entries']:
        r=int(e['target_rva'],16);f=script.dump_function(r)
        if f['bounds_source'].startswith('256'):
            rows=[]
            for x in f['instructions']:
                rows.append(x)
                if x['instruction'].startswith(('ret','jmp ')):break
            f['instructions']=rows;f['bounds_source']='leaf path through first ret or tail jmp'
        funcs[str(e['slot'])]=f
save('ScriptDLL64.dll.interface.json',{'class':ty,'functions':funcs})
print(json.dumps({'bindings':len(items),'table_start':hex(start),'table_end':hex(cur),'properties':props,'class_bases':{k:v['locators'][0]['base_classes'] for k,v in focus.items()}},indent=2))
