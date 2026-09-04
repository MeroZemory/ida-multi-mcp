"""The idalib worker must point download URLs at its own port.

Truncated tool output returns a `/output/<id>.json` URL, and only the process
holding the output cache can serve it. The GUI plugin already sets its own port;
the worker used to leave rpc's default in place, so URLs from headless sessions
pointed at port 13337 with nothing listening.
"""

import sys
import types
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def stubbed_worker_env(monkeypatch):
    """Stub idalib/IDA imports so worker.main() runs without IDA."""
    idapro = MagicMock()
    monkeypatch.setitem(sys.modules, "idapro", idapro)
    monkeypatch.setitem(sys.modules, "ida_auto", MagicMock())

    ida_mcp = types.ModuleType("ida_multi_mcp.ida_mcp")
    ida_mcp.MCP_SERVER = MagicMock()
    ida_mcp.MCP_UNSAFE = set()
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp", ida_mcp)

    rpc = types.ModuleType("ida_multi_mcp.ida_mcp.rpc")
    rpc.set_download_base_url = MagicMock()
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.rpc", rpc)

    return ida_mcp, rpc


def _run_worker(monkeypatch, tmp_path, port):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x00" * 16)
    monkeypatch.setattr(sys, "argv", [
        "idalib_worker", "--host", "127.0.0.1", "--port", str(port), str(binary),
    ])
    from ida_multi_mcp import idalib_worker
    monkeypatch.setattr(idalib_worker.atexit, "register", MagicMock())
    idalib_worker.main()


def _run_ipv6_worker(monkeypatch, tmp_path, port):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x00" * 16)
    monkeypatch.setattr(sys, "argv", [
        "idalib_worker", "--host", "::1", "--port", str(port), str(binary),
    ])
    from ida_multi_mcp import idalib_worker
    monkeypatch.setattr(idalib_worker.atexit, "register", MagicMock())
    idalib_worker.main()


def test_download_base_url_uses_the_workers_own_port(
    stubbed_worker_env, monkeypatch, tmp_path,
):
    _, rpc = stubbed_worker_env
    _run_worker(monkeypatch, tmp_path, 54321)

    rpc.set_download_base_url.assert_called_once_with("http://127.0.0.1:54321")


def test_download_base_url_is_set_before_serving(
    stubbed_worker_env, monkeypatch, tmp_path,
):
    """A URL set after serve() would never apply — serve blocks until shutdown."""
    ida_mcp, rpc = stubbed_worker_env
    call_order = []
    rpc.set_download_base_url.side_effect = lambda url: call_order.append("set_url")
    ida_mcp.MCP_SERVER.serve.side_effect = lambda **kw: call_order.append("serve")

    _run_worker(monkeypatch, tmp_path, 54321)

    assert call_order == ["set_url", "serve"]


def test_ipv6_download_base_url_is_bracketed(
    stubbed_worker_env, monkeypatch, tmp_path,
):
    _, rpc = stubbed_worker_env
    _run_ipv6_worker(monkeypatch, tmp_path, 54321)

    rpc.set_download_base_url.assert_called_once_with("http://[::1]:54321")


def test_close_database_packs_then_closes_without_resaving(monkeypatch):
    from ida_multi_mcp.idalib_worker import _close_database_packed

    idapro = MagicMock()
    ida_loader = MagicMock()
    ida_loader.PATH_TYPE_IDB = 1
    ida_loader.DBFL_KILL = 2
    ida_loader.DBFL_COMP = 4
    ida_loader.get_path.return_value = "/tmp/sample.i64"
    ida_loader.save_database.return_value = True
    monkeypatch.setitem(sys.modules, "ida_loader", ida_loader)

    assert _close_database_packed(idapro) is True
    ida_loader.save_database.assert_called_once_with("/tmp/sample.i64", 6)
    idapro.close_database.assert_called_once_with(save=False)


def test_close_database_preserves_edits_when_packed_save_fails(monkeypatch):
    from ida_multi_mcp.idalib_worker import _close_database_packed

    idapro = MagicMock()
    ida_loader = MagicMock()
    ida_loader.PATH_TYPE_IDB = 1
    ida_loader.DBFL_KILL = 2
    ida_loader.DBFL_COMP = 4
    ida_loader.get_path.return_value = "/tmp/sample.i64"
    ida_loader.save_database.return_value = False
    monkeypatch.setitem(sys.modules, "ida_loader", ida_loader)

    assert _close_database_packed(idapro) is False
    idapro.close_database.assert_called_once_with(save=True)


def test_shutdown_rpc_requires_token_and_stops_server(monkeypatch):
    from ida_multi_mcp.idalib_worker import _register_shutdown_rpc

    server = MagicMock()
    callbacks = {}
    server.registry.method.side_effect = (
        lambda callback, name: callbacks.__setitem__(name, callback)
    )
    thread = MagicMock()
    monkeypatch.setattr("ida_multi_mcp.idalib_worker.threading.Thread", lambda **kwargs: thread)

    _register_shutdown_rpc(server, "expected")
    shutdown = callbacks["ida-multi-mcp/shutdown"]

    with pytest.raises(PermissionError):
        shutdown("wrong")
    thread.start.assert_not_called()

    assert shutdown("expected") == {"accepted": True}
    thread.start.assert_called_once()
