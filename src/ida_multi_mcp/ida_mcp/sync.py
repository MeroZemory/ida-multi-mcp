import contextlib
import logging
import queue
import functools
import os
import sys
import threading
import time
from enum import IntEnum
import idaapi
import ida_kernwin
import idc
from . import ui_guard
from .rpc import McpToolError
from .zeromcp.jsonrpc import get_current_cancel_event, RequestCancelledError

# ============================================================================
# IDA Synchronization & Error Handling
# ============================================================================

ida_major, ida_minor = map(int, idaapi.get_kernel_version().split("."))


class IDAError(McpToolError):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]


class IDASyncError(McpToolError):
    """Main-thread dispatch failed: timed out, or a reentrant @idasync call.

    An McpToolError so the message reaches the client. Plain exceptions are
    redacted to their type name, so "Tool timed out after 30.00s" arrived as
    an opaque "Internal Error: IDASyncError".
    """


class CancelledError(RequestCancelledError):
    """Raised when a request is cancelled via notifications/cancelled."""
    pass


logger = logging.getLogger(__name__)
_TOOL_TIMEOUT_ENV = "IDA_MCP_TOOL_TIMEOUT_SEC"
_DEFAULT_TOOL_TIMEOUT_SEC = 15.0

# After the deadline fires ida_kernwin.set_cancelled(), how long a tool may keep
# running so it can notice the flag and format a partial response before
# IDASyncError is raised.
#
# This does extend the worst case to timeout + grace. It only buys anything for
# work that actually polls user_cancelled() (the C SDK calls); a pure-Python
# loop just runs longer. Set to 0 to enforce the timeout strictly.
_NATIVE_CANCEL_GRACE_ENV = "IDA_MCP_CANCEL_GRACE_SEC"
_DEFAULT_NATIVE_CANCEL_GRACE_SEC = 5.0


def _get_native_cancel_grace_seconds() -> float:
    value = os.getenv(_NATIVE_CANCEL_GRACE_ENV, "").strip()
    if value == "":
        return _DEFAULT_NATIVE_CANCEL_GRACE_SEC
    try:
        return max(0.0, float(value))
    except ValueError:
        return _DEFAULT_NATIVE_CANCEL_GRACE_SEC


# Dialog suppression. A modal dialog raised from inside a tool (warning(),
# ask_yn(), an SDK prompt) blocks the IDA main thread, and with it every later
# MCP call, until a human clicks it away. IDA's batch flag answers such prompts
# with their defaults instead of showing them; it is what headless IDA runs
# with. The flag is process-global, so it is set and restored on the main
# thread around the tool's own run only. Nothing else runs on the main thread
# while the tool holds it, so no user dialog can be auto-answered. The earlier
# leak (dialogs muted until restart) came from toggling it off the main thread
# around overlapping requests; that cannot happen here.
#
# Set IDA_MCP_SUPPRESS_DIALOGS=0 to keep interactive prompting during tools.
_SUPPRESS_DIALOGS_ENV = "IDA_MCP_SUPPRESS_DIALOGS"


def _suppress_dialogs_enabled() -> bool:
    value = os.getenv(_SUPPRESS_DIALOGS_ENV, "").strip().lower()
    return value not in ("0", "false", "no", "off")


def _get_tool_timeout_seconds() -> float:
    value = os.getenv(_TOOL_TIMEOUT_ENV, "").strip()
    if value == "":
        return _DEFAULT_TOOL_TIMEOUT_SEC
    try:
        return float(value)
    except ValueError:
        return _DEFAULT_TOOL_TIMEOUT_SEC



call_stack = queue.LifoQueue()


_PENDING, _STARTED, _ABANDONED = "pending", "started", "abandoned"


def _run_with_dialog_scope(ff):
    """Run ff on the main thread with IDA dialogs answered by default."""
    ui_guard.begin_tool(ff.__name__)
    suppress = _suppress_dialogs_enabled()
    previous_batch = None
    if suppress:
        previous_batch = idc.batch(1)
    try:
        return ff()
    finally:
        if suppress:
            # Restore exactly what was there: headless idalib already runs
            # with batch set and must keep it.
            idc.batch(1 if previous_batch else 0)
        ui_guard.end_tool()


def _await_async_result(res_container, phase, phase_lock, request_id, name, cancel_event):
    """Wait for an MFF_NOWAIT request, failing fast behind a modal dialog.

    A request that has not started yet can be abandoned: it is marked so that
    runned() skips it, so it never executes after the client saw an error.
    """
    wait_limit = ui_guard.modal_wait_seconds()

    def _abandon() -> bool:
        with phase_lock:
            if phase[0] != _PENDING:
                return False
            phase[0] = _ABANDONED
        # Best effort: the phase flag alone already makes runned() a no-op.
        with contextlib.suppress(Exception):
            ida_kernwin.cancel_exec_request(request_id)
        return True

    while True:
        try:
            return res_container.get(timeout=0.1)
        except queue.Empty:
            pass

        if cancel_event is not None and cancel_event.is_set() and _abandon():
            raise CancelledError("Request was cancelled before it started")

        blocked = ui_guard.blocking_modal()
        if blocked is None:
            continue
        dialog, age, owner = blocked
        if age < wait_limit:
            continue
        with phase_lock:
            current = phase[0]
        if current == _PENDING and owner is None and _abandon():
            raise IDASyncError(
                f"IDA is blocked by a modal dialog {ui_guard.describe(dialog)}, "
                f"open for {age:.0f}s. IDA does not run requests while it is "
                f"shown, so '{name}' was NOT executed. Ask the user to close "
                f"it, or call ui_dialogs(action='dismiss') if that is "
                f"intended, then retry."
            )
        if current == _STARTED and owner == name:
            raise IDASyncError(
                f"'{name}' is waiting on a dialog it opened: "
                f"{ui_guard.describe(dialog)}. It was not auto-dismissed "
                f"(not a plain message box, or IDA_MCP_DIALOG_POLICY=report). "
                f"Call ui_dialogs(action='dismiss') to let it finish; its "
                f"result will be discarded."
            )


def _sync_wrapper(ff, cancel_event=None):
    """Call a function ff with a specific IDA safety_mode."""

    res_container = queue.Queue()
    phase = [_PENDING]
    phase_lock = threading.Lock()

    def runned():
        with phase_lock:
            if phase[0] == _ABANDONED:
                return  # the caller already gave up; never run late
            phase[0] = _STARTED
        if not call_stack.empty():
            # Non-blocking: a reentrant @idasync call from within another
            # tool's ff() on this same main thread may have drained the queue
            # between empty() and get().
            try:
                last_func_name = call_stack.get_nowait()
            except queue.Empty:
                last_func_name = "<empty>"
            # Report through res_container instead of raising: execute_sync
            # swallows the exception, and the res_container.get() below would
            # then block the requesting thread forever on an empty queue.
            res_container.put(IDASyncError(
                f"Call stack is not empty while calling the function "
                f"{ff.__name__} from {last_func_name}"
            ))
            return

        call_stack.put((ff.__name__))
        try:
            res_container.put(_run_with_dialog_scope(ff))
        except Exception as x:
            res_container.put(x)
        finally:
            # Non-blocking: a reentrant @idasync invoked synchronously inside
            # ff() may have already popped our entry. A blocking get() here
            # would freeze the IDA main thread and hang every later call.
            try:
                call_stack.get_nowait()
            except queue.Empty:
                pass

    if ui_guard.is_installed() and threading.current_thread() is not threading.main_thread():
        # GUI: queue the request instead of blocking inside execute_sync, so
        # the wait can notice a modal dialog and give up cleanly.
        request_id = idaapi.execute_sync(runned, idaapi.MFF_WRITE | idaapi.MFF_NOWAIT)
        res = _await_async_result(
            res_container, phase, phase_lock, request_id, ff.__name__, cancel_event
        )
    else:
        idaapi.execute_sync(runned, idaapi.MFF_WRITE)
        res = res_container.get()
    if isinstance(res, Exception):
        raise res
    return res

def _normalize_timeout(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def sync_wrapper(ff, timeout_override: float | None = None):
    """Wrapper to enable timeout and cancellation during IDA synchronization.

    Batch mode (dialog suppression) is scoped to the tool's own main-thread
    run in _run_with_dialog_scope, never toggled here on the calling thread.
    """
    # Capture cancel event from thread-local before execute_sync
    cancel_event = get_current_cancel_event()

    timeout = timeout_override
    if timeout is None:
        timeout = _get_tool_timeout_seconds()
    if timeout > 0 or cancel_event is not None:
        def timed_ff():
            # Calculate deadline when execution starts on IDA main thread,
            # not when the request was queued (avoids stale deadlines)
            deadline = time.monotonic() + timeout if timeout > 0 else None

            # Native cancellation: clear any stale flag and schedule a
            # set_cancelled() at the deadline. The sys.setprofile hook below
            # only fires between Python bytecodes, so it cannot preempt a
            # pure-C SDK call — a slow scan holds the IDA main thread well
            # past the timeout and every later tool call queues behind it.
            #
            # Many SDK calls already poll user_cancelled() and bail within one
            # poll cycle: ida_search.find_* (unless SEARCH_NOBRK),
            # ida_bytes.find_bytes/bin_search (unless BIN_SEARCH_NOBREAK),
            # ida_hexrays.decompile*, ida_strlist.build_strlist,
            # ida_auto.auto_wait. set_cancelled() is THREAD_SAFE, so firing it
            # from a Timer thread is safe.
            ida_kernwin.clr_cancelled()
            grace = _get_native_cancel_grace_seconds()
            cancel_fired_at: list[float | None] = [None]
            native_timer: threading.Timer | None = None
            if deadline is not None:
                def _fire_native_cancel():
                    cancel_fired_at[0] = time.monotonic()
                    ida_kernwin.set_cancelled()

                native_timer = threading.Timer(timeout, _fire_native_cancel)
                native_timer.daemon = True
                native_timer.start()

            def profilefunc(frame, event, arg):
                # Check request-level cancellation first (higher priority)
                if cancel_event is not None and cancel_event.is_set():
                    raise CancelledError("Request was cancelled")
                # If native cancel just fired, give the tool a short grace
                # period to format a partial response rather than racing the
                # IDASyncError. Beyond that we still raise to bound the
                # response time.
                fired_at = cancel_fired_at[0]
                if fired_at is not None and time.monotonic() < fired_at + grace:
                    return
                if deadline is not None and time.monotonic() >= deadline:
                    # The dialog sampler runs nested inside a stuck tool (in
                    # the dialog's event loop); raising there would kill the
                    # sampler, not the tool.
                    if ui_guard.is_guard_frame(frame):
                        return
                    raise IDASyncError(f"Tool timed out after {timeout:.2f}s")

            old_profile = sys.getprofile()
            sys.setprofile(profilefunc)
            try:
                return ff()
            finally:
                sys.setprofile(old_profile)
                if native_timer is not None:
                    native_timer.cancel()
                # Sticky flag: clear unconditionally so the next tool starts
                # with a clean state. Without this, every subsequent
                # user_cancelled() returns True forever.
                ida_kernwin.clr_cancelled()

        timed_ff.__name__ = ff.__name__
        return _sync_wrapper(timed_ff, cancel_event)
    return _sync_wrapper(ff, cancel_event)


def idasync(f):
    """Run the function on the IDA main thread in write mode.
    
    This is the unified decorator for all IDA synchronization.
    Previously there were separate @idaread and @idawrite decorators,
    but since read-only operations in IDA might actually require write
    access (e.g., decompilation), we now use a single decorator.
    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        timeout_override = _normalize_timeout(
            getattr(f, "__ida_mcp_timeout_sec__", None)
        )
        return sync_wrapper(ff, timeout_override)

    return wrapper


# Backwards compatibility aliases
idaread = idasync
idawrite = idasync


def tool_timeout(seconds: float):
    """Decorator to override per-tool timeout (seconds).

    IMPORTANT: Must be applied BEFORE @idasync (i.e., listed AFTER it)
    so the attribute exists when it captures the function in closure.

    Correct order:
        @tool
        @idasync
        @tool_timeout(90.0)  # innermost
        def my_func(...):
    """
    def decorator(func):
        setattr(func, "__ida_mcp_timeout_sec__", seconds)
        return func
    return decorator


def is_window_active():
    """Returns whether IDA is currently active."""
    # Source: https://github.com/OALabs/hexcopy-ida/blob/8b0b2a3021d7dc9010c01821b65a80c47d491b61/hexcopy.py#L30
    using_pyside6 = (ida_major > 9) or (ida_major == 9 and ida_minor >= 2)
    
    if using_pyside6:
        from PySide6 import QtWidgets
    else:
        from PyQt5 import QtWidgets
    
    app = QtWidgets.QApplication.instance()
    if app is None:
        return False
    return app.activeWindow() is not None
