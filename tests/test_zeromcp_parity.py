"""Tests for the two zeromcp copies (vendor=stdio router, ida_mcp=HTTP plugin).

The copies are intentionally separate (the router must not import IDA deps),
but shared MCP behavior must stay mirrored. These tests pin the behaviors that
were previously out of sync.
"""

import io
import sys
import types
from unittest.mock import MagicMock

import pytest

from ida_multi_mcp.vendor.zeromcp import McpServer as VendorMcpServer


# ---------------------------------------------------------------------------
# stdio() oversized-line handling (router transport)
# ---------------------------------------------------------------------------

class TestStdioOversizedLine:
    def test_oversized_line_returns_error_not_silent_drop(self):
        srv = VendorMcpServer("test")
        srv._STDIO_MAX_LINE = 16  # tiny limit for the test
        oversized = b'{"jsonrpc":"2.0","method":"ping","id":1,"pad":"' + b"A" * 200 + b'"}\n'
        stdin = io.BytesIO(oversized)
        stdout = io.BytesIO()

        srv.stdio(stdin=stdin, stdout=stdout)

        out = stdout.getvalue()
        # Client must receive a JSON-RPC error rather than nothing (which hangs it).
        assert b"-32600" in out

    def test_normal_line_dispatched(self):
        srv = VendorMcpServer("test")
        srv.registry.methods["ping"] = lambda: "pong"
        stdin = io.BytesIO(b'{"jsonrpc":"2.0","method":"ping","id":1}\n')
        stdout = io.BytesIO()

        srv.stdio(stdin=stdin, stdout=stdout)

        assert b"pong" in stdout.getvalue()


# ---------------------------------------------------------------------------
# notifications/initialized parity
# ---------------------------------------------------------------------------

def _import_ida_mcp_zeromcp():
    """Import the ida_mcp zeromcp copy with IDA modules stubbed."""
    for name in ("idaapi", "ida_kernwin", "idc"):
        sys.modules.setdefault(name, MagicMock())
    # ida_multi_mcp.ida_mcp.__init__ eagerly imports IDA-dependent submodules;
    # stub the package so only the zeromcp subpackage loads.
    pkg = sys.modules.get("ida_multi_mcp.ida_mcp")
    if pkg is None:
        from pathlib import Path
        root = Path(__file__).resolve().parents[1] / "src" / "ida_multi_mcp" / "ida_mcp"
        pkg = types.ModuleType("ida_multi_mcp.ida_mcp")
        pkg.__path__ = [str(root)]
        sys.modules["ida_multi_mcp.ida_mcp"] = pkg
    from ida_multi_mcp.ida_mcp.zeromcp.mcp import McpServer
    return McpServer


class _NoopHttpServer:
    def __init__(self, *_args, **_kwargs):
        self.allow_reuse_address = False
        self.allow_reuse_port = False

    def server_bind(self):
        pass

    def server_activate(self):
        pass

    def server_close(self):
        pass

    def serve_forever(self):
        pass


@pytest.mark.parametrize("implementation", ["vendor", "ida_mcp"])
def test_ipv6_advertised_urls_are_bracketed(implementation, monkeypatch, capsys):
    if implementation == "vendor":
        McpServer = VendorMcpServer
    else:
        McpServer = _import_ida_mcp_zeromcp()
    module = sys.modules[McpServer.__module__]
    monkeypatch.setattr(module, "_http_server_class", lambda *_args: _NoopHttpServer)

    McpServer("test").serve("::1", 43210, background=False)

    captured = capsys.readouterr()
    advertised = captured.out + captured.err
    assert "http://[::1]:43210/mcp" in advertised
    assert "http://[::1]:43210/sse" in advertised


class TestNotificationsInitializedParity:
    def test_vendor_registers_handler(self):
        srv = VendorMcpServer("test")
        assert "notifications/initialized" in srv.registry.methods

    def test_ida_mcp_registers_handler(self):
        McpServer = _import_ida_mcp_zeromcp()
        srv = McpServer("test")
        assert "notifications/initialized" in srv.registry.methods

    def test_both_register_cancelled(self):
        McpServer = _import_ida_mcp_zeromcp()
        assert "notifications/cancelled" in VendorMcpServer("t").registry.methods
        assert "notifications/cancelled" in McpServer("t").registry.methods
