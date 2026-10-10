"""Read-only PE/disassembly/RTTI evidence; never load or execute a target."""
from pathlib import Path
import sys, json, re, hashlib, struct, bisect, os
sys.path.insert(0, str(Path(__file__).parent / 'python-libs'))
import pefile
import capstone
from capstone.x86 import X86_OP_MEM, X86_OP_IMM, X86_REG_RIP

CASE=Path(os.environ.get('AION_CASE_DIR', str(Path(__file__).resolve().parents[1])))
OUT=CASE/'reports'/'binary'
BACK=CASE/'local-backup'/'binary'
SOURCE=Path(os.environ.get('AION_BIN64_DIR', str(CASE/'samples')))
OUT.mkdir(parents=True,exist_ok=True); BACK.mkdir(parents=True,exist_ok=True)

def save(name,obj):
    s=json.dumps(obj,ensure_ascii=False,indent=2)
    (OUT/name).write_text(s,encoding='utf-8'); (BACK/name).write_text(s,encoding='utf-8')

class Binary:
    def __init__(self,path):
        self.path=path; self.data=path.read_bytes(); self.pe=pefile.PE(data=self.data)
        self.base=self.pe.OPTIONAL_HEADER.ImageBase
        self.md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64); self.md.detail=True
        self.ranges=sorted(set((e.struct.BeginAddress,e.struct.EndAddress) for e in getattr(self.pe,'DIRECTORY_ENTRY_EXCEPTION',[]) if e.struct.BeginAddress<e.struct.EndAddress))
        self.starts=[s for s,e in self.ranges]
    def loc(self,rva):
        sec=self.pe.get_section_by_rva(rva)
        backed=sec is not None and 0 <= rva-sec.VirtualAddress < sec.SizeOfRawData
        return {'rva':hex(rva),'preferred_va':hex(self.base+rva), 'file_offset':hex(self.pe.get_offset_from_rva(rva)) if backed else None,'section':sec.Name.rstrip(b'\0').decode('ascii','replace') if sec else None}
    def function(self,rva):
        i=bisect.bisect_right(self.starts,rva)-1
        return self.ranges[i] if i>=0 and rva<self.ranges[i][1] else None
    def disasm(self,rva,size=256):
        rows=[]
        for ins in self.md.disasm(self.pe.get_data(rva,size),self.base+rva):
            row={**self.loc(ins.address-self.base),'bytes':ins.bytes.hex(' '),'instruction':ins.mnemonic+' '+ins.op_str}
            refs=[]
            for op in ins.operands:
                if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
                    target=ins.address+ins.size+op.mem.disp-self.base
                    refs.append({'kind':'rip_relative',**self.loc(target)})
                elif op.type==X86_OP_IMM and ins.mnemonic.startswith(('call','j')):
                    refs.append({'kind':'direct_branch',**self.loc(op.imm-self.base)})
            if refs:row['references']=refs
            rows.append(row)
        return rows
    def dump_function(self,rva):
        bounds=self.function(rva)
        start,end=bounds if bounds else (rva,rva+256)
        return {'start':self.loc(start),'end_rva':hex(end),'bounds_source':'PE exception directory' if bounds else '256-byte window; function end unknown','instructions':self.disasm(start,end-start)}
    def rtti(self):
        types={}
        for m in re.finditer(rb'\.\?A[UV][\x21-\x7e]+?@@\x00',self.data):
            if m.start()<16:continue
            r=self.pe.get_rva_from_offset(m.start()-16)
            types[r]={'name':m.group()[:-1].decode('ascii'), 'type_descriptor':self.loc(r),'locators':[]}
        cols={}
        for sec in self.pe.sections:
            raw=sec.get_data()
            for off in range(0,len(raw)-24,4):
                sig,offset,cd,typ,hier,selfr=struct.unpack_from('<IIIIII',raw,off)
                r=sec.VirtualAddress+off
                if sig!=1 or selfr!=r or typ not in types:continue
                c={'locator':self.loc(r),'subobject_offset':hex(offset),'constructor_displacement':hex(cd),'class_hierarchy_rva':hex(hier),'vtables':[]}
                types[typ]['locators'].append(c);cols[r]=c
        for sec in self.pe.sections:
            raw=sec.get_data()
            for off in range(0,len(raw)-8,8):
                ptr=struct.unpack_from('<Q',raw,off)[0]-self.base
                if ptr not in cols:continue
                vr=sec.VirtualAddress+off+8; entries=[]
                for ix in range(256):
                    pos=off+8+8*ix
                    if pos+8>len(raw):break
                    tr=struct.unpack_from('<Q',raw,pos)[0]-self.base
                    if tr in cols:break
                    target=self.pe.get_section_by_rva(tr)
                    if not target or not target.Characteristics & 0x20000000:break
                    entries.append({'slot':ix,'slot_byte_offset':hex(ix*8),'target_rva':hex(tr)})
                cols[ptr]['vtables'].append({'address':self.loc(vr),'entries':entries,'entry_count':len(entries),'bounded_at_256':len(entries)==256})
        return list(types.values())

if __name__ == '__main__':
    summaries=[]
    for name in ('Aion.bin','Game.dll','CrySystem.dll','ScriptDLL64.dll'):
        b=Binary(CASE/'samples'/name)
        digest=hashlib.sha256(b.data).hexdigest()
        live=hashlib.sha256((SOURCE/name).read_bytes()).hexdigest()
        if live!=digest:raise RuntimeError('Sample mismatch: '+name)
        entry=b.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        exports=[{'name':e.name.decode('ascii','replace') if e.name else None,**b.loc(e.address)} for e in getattr(getattr(b.pe,'DIRECTORY_ENTRY_EXPORT',None),'symbols',[])]
        imports=[{'module':d.dll.decode(),'symbols':[i.name.decode() if i.name else '#'+str(i.ordinal) for i in d.imports]} for d in getattr(b.pe,'DIRECTORY_ENTRY_IMPORT',[])]
        report={'filename':name,'sha256':digest,'matches_source':True,'preferred_base':hex(b.base),'entry':b.loc(entry),'imports':imports,'exports':exports,'exception_function_count':len(b.ranges),'entry_disassembly':b.disasm(entry,192),'export_disassembly':[{**e,'function':b.dump_function(int(e['rva'],16))} for e in exports]}
        if True:
            rtti=b.rtti();save(name+'.rtti.json',rtti)
            report['rtti_type_count']=len(rtti)
            report['rtti_types_with_vtables']=sum(any(c['vtables'] for c in t['locators']) for t in rtti)
        save(name+'.native.json',report)
        summaries.append({k:v for k,v in report.items() if k not in ('entry_disassembly','export_disassembly','imports','exports')})
    save('summary.json',summaries)
    print(json.dumps(summaries,ensure_ascii=False,indent=2))
