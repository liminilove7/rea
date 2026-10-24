"""Temporary read-only bridge for the user's already-open offline database.
No process launch, database save/close, debug attachment, or target execution.
"""
import importlib.util
import json
import pathlib
import sys
import time
import ida_kernwin
import ida_loader
import ida_nalt

ROOT = pathlib.Path('D:/RVE/.codex/local/aion-action-20261024')
EXPECTED_DB = pathlib.Path('D:/RVE/.codex/local/aion-tw-20261019/Game-rea.i64')
EXPECTED_SHA = 'b3043f0eaf225b3dc7ba320ac7671cc5b28cefbd637135943dc9e67c114ccae7'
actual_db = pathlib.Path(ida_loader.get_path(ida_loader.PATH_TYPE_IDB))
if actual_db.resolve() != EXPECTED_DB.resolve():
    raise RuntimeError('Wrong database; no bridge started')
sha = ida_nalt.retrieve_input_file_sha256()
if not sha or sha.hex() != EXPECTED_SHA:
    raise RuntimeError('Database input hash mismatch; no bridge started')
if ida_nalt.get_imagebase() != 0x180000000:
    raise RuntimeError('Unexpected database image base')
if 'rea_action_dispatch_readonly_bridge' in sys.modules:
    raise RuntimeError('Bridge module already loaded; inspect instead of restarting')
plugin_path = ROOT.parent / 'ida-mcp-libs/ida_pro_mcp/mcp-plugin.py'
spec = importlib.util.spec_from_file_location('rea_action_dispatch_readonly_bridge', plugin_path)
bridge = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = bridge
spec.loader.exec_module(bridge)
allowed = {'get_metadata', 'get_function_by_address', 'get_function_by_name',
           'list_functions', 'list_imports', 'list_strings', 'list_strings_filter',
           'get_entry_points', 'decompile_function', 'disassemble_function',
           'get_xrefs_to', 'get_callers', 'get_callees'}
missing = allowed - bridge.rpc_registry.methods.keys()
if missing:
    raise RuntimeError('Missing expected read-only methods: ' + repr(missing))
bridge.rpc_registry.methods = {name: bridge.rpc_registry.methods[name] for name in allowed}
bridge.Server.HOST = '127.0.0.1'
bridge.Server.PORT = 13338
bridge.readonly_server = bridge.Server()
bridge.readonly_server.start()
deadline = time.monotonic() + 1800
stop_path = ROOT / 'stop-action-dispatch-bridge-20261024'
def check_stop():
    if stop_path.exists() or time.monotonic() >= deadline:
        bridge.readonly_server.stop()
        print('[REA] Read-only bridge stopped; user database remains open.')
        return -1
    return 1000
bridge.readonly_timer = ida_kernwin.register_timer(1000, check_stop)
(ROOT / 'action-bridge-start-request.json').write_text(json.dumps({
    'database': str(actual_db), 'inputSha256': sha.hex(), 'imagebase': hex(ida_nalt.get_imagebase()),
    'allowedMethods': sorted(allowed), 'endpoint': 'http://127.0.0.1:13338',
    'databaseSaved': False, 'databaseClosed': False, 'targetExecuted': False,
    'note': 'Start requested; verify listener and REA metadata separately.'
}, indent=2), encoding='utf-8')
print('[REA] Read-only bridge requested for the verified offline Game database.')


