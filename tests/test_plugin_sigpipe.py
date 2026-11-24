"""SIGPIPE must not be able to kill IDA.

Embedded IDAPython leaves SIGPIPE at its default action. A client that gives up
on a request (timeout, cancel, router restart) makes the late response write hit
a closed socket, and IDA died instantly: reproduced live on IDA 9.5 / Linux.
"""

import signal
import sys
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def plugin_mod(monkeypatch):
    for name in ("idaapi", "ida_kernwin", "ida_idaapi", "ida_nalt", "ida_ida", "idc"):
        monkeypatch.setitem(sys.modules, name, MagicMock())
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.plugin.registration", MagicMock())
    monkeypatch.delitem(sys.modules, "ida_multi_mcp.plugin.ida_multi_mcp", raising=False)
    import importlib

    return importlib.import_module("ida_multi_mcp.plugin.ida_multi_mcp")


@pytest.mark.skipif(not hasattr(signal, "SIGPIPE"), reason="no SIGPIPE on this platform")
def test_default_sigpipe_is_ignored(plugin_mod, monkeypatch):
    calls = []
    monkeypatch.setattr(signal, "getsignal", lambda s: signal.SIG_DFL)
    monkeypatch.setattr(signal, "signal", lambda s, h: calls.append((s, h)))
    assert plugin_mod._ignore_sigpipe() is True
    assert calls == [(signal.SIGPIPE, signal.SIG_IGN)]


@pytest.mark.skipif(not hasattr(signal, "SIGPIPE"), reason="no SIGPIPE on this platform")
@pytest.mark.parametrize("existing", [lambda *a: None, None])
def test_foreign_sigpipe_handler_is_kept(plugin_mod, monkeypatch, existing):
    """A Python handler (callable) or a C-level one (getsignal() -> None) wins."""
    calls = []
    monkeypatch.setattr(signal, "getsignal", lambda s: existing)
    monkeypatch.setattr(signal, "signal", lambda s, h: calls.append((s, h)))
    assert plugin_mod._ignore_sigpipe() is False
    assert calls == []


def test_off_main_thread_is_harmless(plugin_mod, monkeypatch):
    def _raise(*_a):
        raise ValueError("signal only works in main thread")

    monkeypatch.setattr(signal, "getsignal", lambda s: signal.SIG_DFL)
    monkeypatch.setattr(signal, "signal", _raise)
    assert plugin_mod._ignore_sigpipe() is False
