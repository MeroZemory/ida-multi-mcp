"""Tests for GUI vs headless detection in the IDA plugin wrapper."""

from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


def _load_plugin_module(monkeypatch, *, is_idaq: bool, input_path: str = "sample.bin"):
    for name in list(sys.modules):
        if name == "ida_multi_mcp.plugin.ida_multi_mcp":
            sys.modules.pop(name, None)

    idaapi = types.ModuleType("idaapi")
    idaapi.plugin_t = type("plugin_t", (), {})
    idaapi.IDB_Hooks = type("IDB_Hooks", (), {"hook": lambda self: None, "unhook": lambda self: None})
    idaapi.UI_Hooks = type("UI_Hooks", (), {"hook": lambda self: None, "unhook": lambda self: None})
    idaapi.PLUGIN_FIX = 1
    idaapi.PLUGIN_KEEP = 2
    idaapi.get_input_file_path = lambda: input_path
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)

    ida_kernwin = types.ModuleType("ida_kernwin")
    ida_kernwin.is_idaq = lambda: is_idaq
    monkeypatch.setitem(sys.modules, "ida_kernwin", ida_kernwin)

    registration = types.ModuleType("ida_multi_mcp.plugin.registration")
    registration.register_instance = MagicMock(return_value="abcd")
    registration.unregister_instance = MagicMock()
    registration.update_heartbeat = MagicMock()
    registration.get_binary_metadata = MagicMock(
        return_value={
            "idb_path": "sample.i64",
            "binary_path": "sample.bin",
            "binary_name": "sample.bin",
            "arch": "metapc-64",
        }
    )
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.plugin.registration", registration)

    module = importlib.import_module("ida_multi_mcp.plugin.ida_multi_mcp")
    importlib.reload(module)
    return module


def test_plugin_init_autostarts_only_in_gui(monkeypatch):
    module = _load_plugin_module(monkeypatch, is_idaq=True)
    plugin = module.IdaMultiMcpPlugin()
    plugin.start_server = MagicMock()

    rc = plugin.init()

    assert rc == module.idaapi.PLUGIN_KEEP
    plugin.start_server.assert_called_once()


def test_plugin_init_skips_autostart_in_headless(monkeypatch):
    module = _load_plugin_module(monkeypatch, is_idaq=False)
    plugin = module.IdaMultiMcpPlugin()
    plugin.start_server = MagicMock()

    rc = plugin.init()

    assert rc == module.idaapi.PLUGIN_KEEP
    plugin.start_server.assert_not_called()


def test_database_inited_starts_only_in_gui(monkeypatch):
    module = _load_plugin_module(monkeypatch, is_idaq=True)
    plugin = module.IdaMultiMcpPlugin()
    plugin.start_server = MagicMock()

    hooks = module.UiHooks(plugin)
    rc = hooks.database_inited(False, "")

    assert rc == 0
    plugin.start_server.assert_called_once()


def test_database_inited_skips_in_headless(monkeypatch):
    module = _load_plugin_module(monkeypatch, is_idaq=False)
    plugin = module.IdaMultiMcpPlugin()
    plugin.start_server = MagicMock()

    hooks = module.UiHooks(plugin)
    rc = hooks.database_inited(False, "")

    assert rc == 0
    plugin.start_server.assert_not_called()


def test_start_server_passes_input_fingerprint_to_registry(monkeypatch):
    module = _load_plugin_module(monkeypatch, is_idaq=True)
    fingerprint = {"algorithm": "sha256", "digest": "ab" * 32}
    module.get_binary_metadata.return_value["input_fingerprint"] = fingerprint
    server = MagicMock()
    server._http_server.server_address = ("127.0.0.1", 12345)
    monkeypatch.setattr(module, "_load_ida_mcp", lambda: (server, object, lambda: None))
    rpc = types.ModuleType("ida_multi_mcp.ida_mcp.rpc")
    rpc.set_download_base_url = MagicMock()
    monkeypatch.setitem(sys.modules, rpc.__name__, rpc)
    monkeypatch.setattr(module.threading, "Thread", MagicMock())
    plugin = module.IdaMultiMcpPlugin()

    plugin.start_server()

    assert module.register_instance.call_args.kwargs["input_fingerprint"] == fingerprint
