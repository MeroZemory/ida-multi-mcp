"""Tests for ida_mcp/sync.py reentrancy and GUI-safe handling (IDA stubbed).

sync.py imports IDA modules at module scope, so every IDA module is replaced
with a stub before importing it. idaapi.execute_sync is stubbed to call the
callback inline, which is exactly the situation the real one creates: the
callback runs on the IDA main thread while the requesting thread waits. The
idc stub remains as a regression spy for forbidden batch-mode calls.

Regression coverage for two bugs:
  1. A reentrant @idasync call drained the LifoQueue, so the outer call's
     finally blocked forever on Queue.get() and froze the IDA main thread.
  2. @idasync enabled IDA's process-global batch mode, which suppresses and
     auto-accepts unrelated dialogs in the interactive GUI.
"""

import sys
import threading
import time
import types
from unittest.mock import MagicMock

import pytest

_PKG = "ida_multi_mcp.ida_mcp"

# Sentinel for "this sys.modules key did not exist before we stubbed it".
_ABSENT = object()


# Importing ida_mcp.sync executes the package __init__, which eagerly imports
# every api_* module. Stub the whole IDA surface plus those submodules so only
# sync.py itself really runs.
_IDA_MODULES = [
    "idaapi", "idautils", "idc", "ida_auto", "ida_bytes", "ida_dbg", "ida_dirtree",
    "ida_entry", "ida_frame", "ida_funcs", "ida_gdl", "ida_hexrays", "ida_ida",
    "ida_idaapi", "ida_idp", "ida_kernwin", "ida_lines", "ida_loader", "ida_moves",
    "ida_nalt", "ida_name", "ida_netnode", "ida_offset", "ida_pro", "ida_range",
    "ida_search", "ida_segment", "ida_strlist", "ida_struct", "ida_typeinf", "ida_ua",
    "ida_xref",
]

_SIBLING_MODULES = [
    "http", "framework", "utils", "compat",
    "api_core", "api_analysis", "api_memory", "api_types", "api_modify",
    "api_stack", "api_debug", "api_python", "api_resources", "api_survey",
    "api_composite", "api_similarity",
]


def _install_stubs(saved):
    """Stub every module sync.py touches, then import it fresh.

    Every sys.modules key written here is recorded in `saved` so the fixture
    can put the real (or absent) modules back; otherwise these stubs leak into
    whatever test runs next.
    """

    def _stub(name, value):
        if name not in saved:
            saved[name] = sys.modules.get(name, _ABSENT)
        sys.modules[name] = value

    for name in _IDA_MODULES:
        _stub(name, MagicMock())
    for name in _SIBLING_MODULES:
        _stub(f"{_PKG}.{name}", MagicMock())

    sys.modules["idaapi"].get_kernel_version.return_value = "9.3"
    sys.modules["idaapi"].MFF_WRITE = 0x2

    # execute_sync runs the callback inline, mirroring the real main-thread
    # dispatch. Exceptions escaping the callback are swallowed by IDA.
    def _execute_sync(callback, _flags):
        try:
            callback()
        except Exception:
            pass
        return 1

    sys.modules["idaapi"].execute_sync.side_effect = _execute_sync

    # Track batch state and calls so tests detect any attempt to suppress GUI
    # dialogs through IDA's process-global batch flag.
    batch_state = {"value": 0}

    def _batch(new_value):
        previous = batch_state["value"]
        batch_state["value"] = new_value
        return previous

    sys.modules["idc"].batch.side_effect = _batch

    # sync.py imports McpToolError from .rpc and cancel helpers from zeromcp;
    # stub both so no HTTP/MCP machinery is pulled in.
    rpc_stub = types.ModuleType(f"{_PKG}.rpc")
    rpc_stub.McpToolError = type("McpToolError", (Exception,), {})
    # Names the package __init__ pulls out of .rpc
    rpc_stub.MCP_SERVER = MagicMock()
    rpc_stub.MCP_UNSAFE = set()
    rpc_stub.MCP_EXTENSIONS = {}
    rpc_stub.tool = lambda f: f
    rpc_stub.unsafe = lambda f: f
    rpc_stub.ext = lambda _group: (lambda f: f)
    rpc_stub.resource = lambda _uri: (lambda f: f)
    rpc_stub.get_cached_output = lambda _id: None
    rpc_stub.set_download_base_url = lambda _url: None
    rpc_stub.get_download_base_url = lambda: ""
    _stub(f"{_PKG}.rpc", rpc_stub)

    jsonrpc_stub = types.ModuleType(f"{_PKG}.zeromcp.jsonrpc")
    jsonrpc_stub.get_current_cancel_event = lambda: None
    jsonrpc_stub.RequestCancelledError = type("RequestCancelledError", (Exception,), {})
    _stub(f"{_PKG}.zeromcp", MagicMock())
    _stub(f"{_PKG}.zeromcp.jsonrpc", jsonrpc_stub)

    saved.setdefault(f"{_PKG}.sync", sys.modules.get(f"{_PKG}.sync", _ABSENT))
    sys.modules.pop(f"{_PKG}.sync", None)
    import importlib

    return importlib.import_module(f"{_PKG}.sync"), batch_state


def _call_without_hanging(fn, timeout=5.0):
    """Run fn on a worker thread and fail (rather than hang) if it blocks.

    The regression this guards is an unbounded Queue.get(), so a plain call
    would wedge the whole test session instead of reporting a failure.
    """
    box = {}

    def run():
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised on the main thread
            box["error"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        pytest.fail(f"call blocked for more than {timeout}s (deadlock regression)")
    if "error" in box:
        raise box["error"]
    return box["value"]


@pytest.fixture
def sync_mod():
    saved: dict[str, object] = {}
    module, batch_state = _install_stubs(saved)
    module._test_batch_state = batch_state
    # Timeout machinery installs a profile hook; disable it so the tests
    # exercise the queue and GUI-state logic directly.
    module._DEFAULT_TOOL_TIMEOUT_SEC = 0.0
    try:
        yield module
    finally:
        while not module.call_stack.empty():
            module.call_stack.get_nowait()
        for name, previous in saved.items():
            if previous is _ABSENT:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous


def test_reentrant_idasync_does_not_hang_outer_call(sync_mod):
    """A nested @idasync must not leave the outer call blocked on the queue.

    Reentrancy is rejected by design (the guard raises IDASyncError). The bug
    was what happened next: the rejected inner call had already drained the
    LifoQueue, so the outer call's finally then blocked forever on a blocking
    Queue.get() and froze the IDA main thread for every later request.
    """

    @sync_mod.idasync
    def inner():
        return "inner-done"

    @sync_mod.idasync
    def outer():
        try:
            inner()
        except sync_mod.IDASyncError:
            pass  # guard rejected the reentrant call; the outer tool carries on
        return "outer-done"

    result = _call_without_hanging(outer)
    assert result == "outer-done"
    assert sync_mod.call_stack.empty()


def test_reentrant_call_reports_error_instead_of_blocking(sync_mod):
    """The non-empty-call-stack guard must surface, not deadlock the caller."""
    sync_mod.call_stack.put("someone_else")

    @sync_mod.idasync
    def tool():
        return "unreachable"

    with pytest.raises(sync_mod.IDASyncError, match="Call stack is not empty"):
        tool()


def test_idasync_does_not_enable_global_batch_mode(sync_mod):
    """MCP calls must not suppress or auto-accept unrelated IDA dialogs."""
    observed = {}

    @sync_mod.idasync
    def tool():
        # Inside the tool body, normal interactive prompting must remain on.
        observed["during"] = sync_mod._test_batch_state["value"]
        return "ok"

    assert tool() == "ok"
    assert observed["during"] == 0
    assert sync_mod._test_batch_state["value"] == 0
    sys.modules["idc"].batch.assert_not_called()


def test_native_cancel_fires_at_the_deadline(sync_mod):
    """A pure-C SDK call can only be preempted via ida_kernwin.set_cancelled().

    Ported from upstream ida-pro-mcp 55533c4. The setprofile hook cannot
    interrupt a C call, so the deadline schedules set_cancelled() on a Timer;
    SDK calls that poll user_cancelled() then bail on their own.
    """
    kernwin = sys.modules["ida_kernwin"]
    kernwin.reset_mock()
    sync_mod._DEFAULT_TOOL_TIMEOUT_SEC = 0.15

    fired = threading.Event()
    kernwin.set_cancelled.side_effect = lambda: fired.set()

    @sync_mod.idasync
    def slow_c_call():
        # Stands in for a C SDK call: no Python bytecode executes during it,
        # so profilefunc never runs and only the Timer can intervene.
        fired.wait(3)
        return "done"

    assert _call_without_hanging(slow_c_call, timeout=10) == "done"
    assert fired.is_set(), "set_cancelled() was never fired at the deadline"
    # Sticky flag must be cleared or every later user_cancelled() returns True.
    assert kernwin.clr_cancelled.call_count >= 2, (
        f"clr_cancelled called {kernwin.clr_cancelled.call_count}x; "
        "expected one at entry and one in the finally"
    )


def test_native_cancel_timer_is_cancelled_on_fast_calls(sync_mod):
    """A tool finishing well inside the deadline must not fire set_cancelled."""
    kernwin = sys.modules["ida_kernwin"]
    kernwin.reset_mock()
    kernwin.set_cancelled.side_effect = None
    sync_mod._DEFAULT_TOOL_TIMEOUT_SEC = 5.0

    @sync_mod.idasync
    def quick():
        return "fast"

    assert _call_without_hanging(quick) == "fast"
    time.sleep(0.3)
    assert kernwin.set_cancelled.call_count == 0, "timer was not cancelled"


def test_failing_tool_does_not_change_global_batch_mode(sync_mod):
    @sync_mod.idasync
    def failing_tool():
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        failing_tool()

    assert sync_mod._test_batch_state["value"] == 0
    sys.modules["idc"].batch.assert_not_called()
    assert sync_mod.call_stack.empty()
