"""Explicitly launched offline IDA work session, no target execution."""
from pathlib import Path
import importlib.util
import json
import traceback
import ida_kernwin
import ida_nalt
import ida_pro

ROOT = Path(r'D:\RVE\.codex\local\rea-aion-round9')
try:
    plugin_path = ROOT.parent / 'ida-mcp-libs/ida_pro_mcp/mcp-plugin.py'
    spec = importlib.util.spec_from_file_location('rea_round9_ida_rpc', plugin_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.Server.PORT = 13338
    server = module.Server()
    server.start()
    (ROOT / 'ida-started.json').write_text(json.dumps({
        'input': ida_nalt.get_input_file_path(),
        'imagebase': hex(ida_nalt.get_imagebase()),
        'rpc_port': 13338,
        'target_executed': False
    }), encoding='utf-8')
    def poll_stop():
        if (ROOT / 'stop-ida').exists():
            server.stop()
            ida_pro.qexit(0)
            return -1
        return 1000
    timer = ida_kernwin.register_timer(1000, poll_stop)
except Exception:
    (ROOT / 'ida-start-error.txt').write_text(traceback.format_exc(), encoding='utf-8')
    ida_pro.qexit(1)
