"""Offline IDA batch export for this exact sample. Does not start a debugger."""
import json
from pathlib import Path
import re
import traceback
import ida_auto
import ida_funcs
import ida_hexrays
import ida_loader
import ida_nalt
import ida_pro
import idautils
import idc

ROOT = Path(r"F:\RVE-Workspace\cases\aionclassic2-2026-10-10\reports\binary")
ROOT.mkdir(exist_ok=True)
name = Path(ida_nalt.get_input_file_path()).name
base = ida_nalt.get_imagebase()

def save(suffix, data):
    (ROOT / (name + suffix)).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

def addr(ea):
    return {"va": hex(ea), "rva": hex(ea-base), "file_offset": hex(ida_loader.get_fileregion_offset(ea))}

try:
    save('.status.json', {'stage': 'auto_analysis'})
    ida_auto.auto_wait()
    funcs = list(idautils.Functions())
    save('.functions.json', [{**addr(ea), 'end_rva': hex(ida_funcs.get_func(ea).end_ea-base), 'name': idc.get_func_name(ea)} for ea in funcs])
    selected = set()
    entries = []
    for _, ordinal, ea, label in idautils.Entries():
        entries.append({**addr(ea), 'ordinal': ordinal, 'name': label})
        if ida_funcs.get_func(ea): selected.add(ida_funcs.get_func(ea).start_ea)
    pattern = re.compile(r'(?:health|hitpoint|\bhp\b|\bmp\b|mana|GetPos|SetPos|GetEntity|GetPlayer|GetLevel|GetName|GetStat|GetProperty|GetAttribute|GetTarget|SetHealth|GetHealth|max_hp|attack_speed|move_speed|client_items|client_skills|ScriptBind|ScriptObject)', re.I)
    strings = []
    for s in idautils.Strings():
        value = str(s)
        if not pattern.search(value): continue
        refs = []
        for x in idautils.XrefsTo(s.ea):
            f = ida_funcs.get_func(x.frm)
            refs.append({**addr(x.frm), 'type': x.type, 'function_rva': hex(f.start_ea-base) if f else None, 'function': idc.get_func_name(x.frm) if f else None})
            if f: selected.add(f.start_ea)
        strings.append({**addr(s.ea), 'text':value, 'xrefs':refs})
    save('.strings-xrefs.json', strings)
    save('.entries.json', entries)
    save('.status.json', {'stage':'decompile', 'function_count':len(funcs), 'matched_strings':len(strings), 'selected_functions':len(selected)})
    hx = ida_hexrays.init_hexrays_plugin()
    results=[]
    dest = ROOT / (name + '.functions')
    dest.mkdir(exist_ok=True)
    for ea in sorted(selected):
        f = ida_funcs.get_func(ea)
        asm = [{'rva':hex(i-base), 'text':idc.generate_disasm_line(i, 0)} for i in idautils.FuncItems(ea)]
        result={**addr(ea),'name':idc.get_func_name(ea),'end_rva':hex(f.end_ea-base),'instruction_count':len(asm)}
        (dest / (hex(ea-base)+'.asm.json')).write_text(json.dumps(asm,ensure_ascii=False,indent=2),encoding='utf-8')
        if hx:
            try:
                cf=ida_hexrays.decompile(ea)
                if cf:
                    (dest / (hex(ea-base)+'.c')).write_text(str(cf),encoding='utf-8')
                    result['decompiled']=True
                else: result['decompiled']=False
            except Exception as e: result['decompile_error']=str(e)
        results.append(result)
    save('.selected.json', results)
    saved=ida_loader.save_database(idc.get_idb_path(), 0)
    save('.status.json', {'stage':'complete','hexrays':hx,'database_saved':saved,'function_count':len(funcs),'matched_strings':len(strings),'selected_functions':len(selected)})
except Exception:
    save('.error.json', {'traceback':traceback.format_exc()})
finally:
    ida_pro.qexit(0)
