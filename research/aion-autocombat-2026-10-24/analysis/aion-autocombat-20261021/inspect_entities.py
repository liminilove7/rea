"""Auxiliary read-only Win32 capture of a REA-derived entity tree; no code execution in target."""
import argparse
import collections
import ctypes as c
from ctypes import wintypes as w
import datetime
import hashlib
import json
import pathlib
import struct
import time

K = c.WinDLL('kernel32', use_last_error=True)
K.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
K.OpenProcess.restype = w.HANDLE
K.CloseHandle.argtypes = [w.HANDLE]
K.CloseHandle.restype = w.BOOL
K.ReadProcessMemory.argtypes = [w.HANDLE, c.c_void_p, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t)]
K.ReadProcessMemory.restype = w.BOOL
K.QueryFullProcessImageNameW.argtypes = [w.HANDLE, w.DWORD, w.LPWSTR, c.POINTER(w.DWORD)]
K.GetProcessTimes.argtypes = [w.HANDLE] + [c.POINTER(w.FILETIME)] * 4
K.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]
K.CreateToolhelp32Snapshot.restype = w.HANDLE

class Module(c.Structure):
    _fields_ = [('dwSize', w.DWORD), ('th32ModuleID', w.DWORD), ('th32ProcessID', w.DWORD),
                ('GlblcntUsage', w.DWORD), ('ProccntUsage', w.DWORD), ('modBaseAddr', c.c_void_p),
                ('modBaseSize', w.DWORD), ('hModule', w.HANDLE), ('szModule', w.WCHAR * 256),
                ('szExePath', w.WCHAR * 260)]

for f in [K.Module32FirstW, K.Module32NextW]:
    f.argtypes = [w.HANDLE, c.POINTER(Module)]
    f.restype = w.BOOL

EXPECTED_PATH = r'D:\Workspace\AION_TW\DeuLuncher\bin56\aion.bin'
HASHES = {'game.dll': 'b3043f0eaf225b3dc7ba320ac7671cc5b28cefbd637135943dc9e67c114ccae7',
          'cryentitysystem.dll': 'fbca87e5a639551bf7653d464e2863c49800e73c124ae4666ea9fb11d40bef7a'}

def fail(api):
    raise c.WinError(c.get_last_error(), api)

def modules(pid):
    h = K.CreateToolhelp32Snapshot(0x18, pid)
    if h == c.c_void_p(-1).value:
        fail('CreateToolhelp32Snapshot')
    out = []
    try:
        m = Module(); m.dwSize = c.sizeof(m)
        if not K.Module32FirstW(h, c.byref(m)):
            fail('Module32FirstW')
        while True:
            out.append(dict(name=m.szModule, path=m.szExePath, base=m.modBaseAddr, size=m.modBaseSize))
            if not K.Module32NextW(h, c.byref(m)):
                if c.get_last_error() != 18:
                    fail('Module32NextW')
                break
    finally:
        K.CloseHandle(h)
    return out

class Reader:
    def __init__(self, pid):
        self.h = K.OpenProcess(0x1010, False, pid)
        if not self.h:
            fail('OpenProcess(query + VM_READ only)')
        self.calls = 0; self.bytes = 0
    def identity(self):
        path = c.create_unicode_buffer(32768); length = w.DWORD(len(path))
        if not K.QueryFullProcessImageNameW(self.h, 0, path, c.byref(length)):
            fail('QueryFullProcessImageNameW')
        ts = [w.FILETIME() for _ in range(4)]
        if not K.GetProcessTimes(self.h, *[c.byref(x) for x in ts]):
            fail('GetProcessTimes')
        return dict(path=path.value, birth_filetime=(ts[0].dwHighDateTime << 32) | ts[0].dwLowDateTime)
    def read(self, address, size):
        if not (0x10000 <= address <= 0x7fffffffffff and 1 <= size <= 1024):
            raise ValueError('Invalid address/size')
        buf = c.create_string_buffer(size); done = c.c_size_t()
        self.calls += 1
        ok = K.ReadProcessMemory(self.h, address, buf, size, c.byref(done))
        self.bytes += done.value
        if not ok or done.value != size:
            raise OSError(f'ReadProcessMemory {address:#x} requested {size}, got {done.value}, win32={c.get_last_error()}')
        return buf.raw
    def u64(self, a): return struct.unpack('<Q', self.read(a, 8))[0]
    def close(self):
        if self.h:
            if not K.CloseHandle(self.h): fail('CloseHandle')
            self.h = None

def locate(mods, addr):
    for m in mods:
        if m['base'] <= addr < m['base'] + m['size']:
            return dict(module=m['name'], rva=hex(addr-m['base']))
    return None

def rtti(r, mods, vt):
    """Decode observed MSVC x64 RTTI only when COL validates its image base."""
    owner = next((m for m in mods if m['base'] <= vt < m['base'] + m['size']), None)
    if owner is None: return dict(available=False, reason='vtable outside captured modules')
    try:
        col = r.u64(vt - 8)
        if not owner['base'] <= col <= owner['base'] + owner['size'] - 24:
            raise ValueError('COL outside owning module')
        sig, offset, cd, typ, hierarchy, selfrva = struct.unpack('<6I', r.read(col, 24))
        if sig != 1 or col - selfrva != owner['base']:
            raise ValueError('COL signature/base mismatch')
        if not 0 <= typ <= owner['size'] - 272:
            raise ValueError('type descriptor out of range')
        raw = r.read(owner['base'] + typ + 16, 256)
        name = raw.split(b'\0', 1)[0].decode('ascii')
        if not name.startswith('.?A'): raise ValueError('unrecognized MSVC type name')
        return dict(available=True, decorated_name=name, subobject_offset=offset,
                    source='MSVC RTTI; class name alone does not establish hostile monster')
    except (ValueError, OSError, UnicodeError) as e:
        return dict(available=False, reason=str(e))

def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--pid', type=int, required=True)
    ap.add_argument('--out', type=pathlib.Path, required=True); args = ap.parse_args()
    result = dict(captured_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), pid=args.pid,
                  access='PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ', auxiliary=True,
                  writes=0, target_calls=0, entities=[], issues=[], complete=False)
    reader = None
    try:
        reader = Reader(args.pid); ident = reader.identity(); result['identity'] = ident
        if ident['path'].lower() != EXPECTED_PATH.lower(): raise ValueError('Unexpected executable path')
        mods = modules(args.pid); result['modules'] = mods
        selected = {m['name'].lower(): m for m in mods if m['name'].lower() in HASHES}
        if set(selected) != set(HASHES): raise ValueError('Required modules absent')
        for name, m in selected.items():
            with open(m['path'], 'rb') as stream:
                m['sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
            if m['sha256'] != HASHES[name]: raise ValueError('Module hash mismatch: '+name)
        b = selected['game.dll']['base']; engine = selected['cryentitysystem.dll']['base']
        manager = reader.u64(b + 0xf25c68); head = reader.u64(manager + 0x58)
        header = reader.read(head, 48)
        if header[25] != 1: raise ValueError('Tree sentinel mismatch')
        root = struct.unpack_from('<Q', header, 8)[0]
        handles_raw = reader.read(b+0x1422648,4)
        local, attack_target = struct.unpack('<HH', handles_raw)
        result['tree'] = dict(game_base=hex(b), engine_base=hex(engine), manager=hex(manager),
                            head=hex(head), root=hex(root), local_handle=local,
                            attack_target_handle_candidate=attack_target, handles_raw_hex=handles_raw.hex(),
                            count_before=reader.u64(manager+0x60), maximum_nodes=4096,
                            bound_reason='Read-only capture budget; reaching it marks partial inventory')
        stack=[root]; seen=set(); started=time.monotonic()
        while stack:
            if len(seen) >= 4096 or time.monotonic()-started > 20:
                result['issues'].append('Capture budget reached; inventory partial'); break
            node = stack.pop()
            if node == head: continue
            if node in seen:
                result['issues'].append(f'Repeated tree node {node:#x}; concurrent mutation or cycle'); continue
            seen.add(node)
            row=dict(node=hex(node))
            try:
                raw=reader.read(node,48)
                if raw[25] != 0:
                    result['issues'].append(f'Unexpected non-sentinel nil node {node:#x}'); continue
                left, right=struct.unpack_from('<Q',raw,0)[0],struct.unpack_from('<Q',raw,16)[0]
                stack.extend([right,left])
                key=struct.unpack_from('<H',raw,32)[0]; ent=struct.unpack_from('<Q',raw,40)[0]
                row.update(handle=key, local_handle_match=key==local, entity=hex(ent))
                row['attack_target_handle_match']=key==attack_target
                vt=reader.u64(ent); row['entity_vtable']=hex(vt); row['entity_vtable_location']=locate(mods,vt)
                row['entity_rtti']=rtti(reader,mods,vt)
                row['entity_slots']={}
                for slot in [8,16]:
                    fn=reader.u64(vt+slot)
                    row['entity_slots'][hex(slot)]=dict(address=hex(fn),location=locate(mods,fn),
                                                       first32_hex=reader.read(fn,32).hex())
                getter=reader.u64(vt+0xc0); row['container_getter_location']=locate(mods,getter)
                if getter != engine+0x19190: raise ValueError('Entity container getter not validated layout')
                comp=reader.u64(ent+0x380); row['container']=hex(comp)
                if comp:
                    cvt=reader.u64(comp); row['container_vtable']=hex(cvt)
                    row['container_vtable_location']=locate(mods,cvt); row['container_rtti']=rtti(reader,mods,cvt)
                    query=reader.u64(cvt+0x50)
                    row['component_query_slot_50']=dict(address=hex(query),location=locate(mods,query),
                                                       first32_hex=reader.read(query,32).hex())
                    row['backlink_matches']=reader.u64(comp+8)==ent
                    row['container_prefix_64_hex']=reader.read(comp,64).hex()
                    row['container_type_dword_20']=struct.unpack_from('<I',bytes.fromhex(row['container_prefix_64_hex']),32)[0]
                    if row.get('container_rtti',{}).get('decorated_name') in ['.?AVPlayer@@','.?AVCharacterObject@@']:
                        row['container_prefix_512_hex']=reader.read(comp,512).hex()
                        prefix=bytes.fromhex(row['container_prefix_512_hex'])
                        row['name_utf16_at_42_candidate']=prefix[0x42:0xc2].decode('utf-16le',errors='replace').split('\0',1)[0]
                        row['entity_prefix_256_hex']=reader.read(ent,256).hex()
                        row['identifier_dword_2c_candidate']=struct.unpack('<I',reader.read(comp+0x2c,4))[0]
                        pos_getter=row['entity_slots']['0x8']
                        if pos_getter['first32_hex']=='84d27513f7818001000008040000488d812c0600007507488d81ec050000c3cc':
                            pos=reader.read(ent+0x5ec,12)
                            row['position_candidate']=dict(offset='entity+0x5ec',raw_hex=pos.hex(),
                                                         xyz=struct.unpack('<3f',pos),
                                                         source='Exact getter bytes plus saved REA coordinate-difference consumer; display corroboration pending')
                confirm=reader.read(node,48)
                row['binding_unchanged_during_read']=confirm[32:48]==raw[32:48] and reader.u64(ent+0x380)==comp
            except (ValueError,OSError) as e:
                row['error']=str(e)
            result['entities'].append(row)
        result['tree']['count_after']=reader.u64(manager+0x60)
        result['tree']['root_unchanged']=reader.u64(head+8)==root
        result['tree']['handles_after_hex']=reader.read(b+0x1422648,4).hex()
        result['identity_after']=reader.identity()
        result['identity_unchanged']=result['identity_after']==ident
        result['tree_traversal_complete']=not stack and not result['issues'] and not any('error' in x for x in result['entities'])
        result['complete']=False
        result['completeness_reason']='Hostile classification and health/skill state facets remain unknown even if tree traversal completes.'
        result['limitations']=['No atomic game snapshot; individual binding confirmations cannot exclude all concurrent mutations.',
          'Entity count includes non-monsters; hostile state, name, HP, coordinates and selected-target identity not yet validated.',
          'manager+0x60 is a conventional container-size candidate; recorded as raw, not an established game object count.']
    except (ValueError,OSError) as e:
        result['issues'].append(str(e))
    finally:
        if reader:
            result['read_calls']=reader.calls; result['bytes_read']=reader.bytes
            try: reader.close(); result['handle_closed']=True
            except OSError as e: result['handle_closed']=False;result['issues'].append(str(e))
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    counts=collections.Counter(x.get('container_rtti',{}).get('decorated_name','unknown') for x in result['entities'])
    print(json.dumps(dict(output=str(args.out),entities=len(result['entities']),types=dict(counts),
                         issues=result['issues'],handle_closed=result.get('handle_closed')),ensure_ascii=False))
    return 0 if result.get('identity_unchanged') and result.get('handle_closed') else 1

if __name__=='__main__': raise SystemExit(main())
