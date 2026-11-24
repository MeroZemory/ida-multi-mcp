"""Modal-dialog guard for the interactive IDA GUI.

A modal dialog stalls the MCP server in two different ways, and the two need
different treatment:

1. A dialog raised *by a tool* (``warning()``, ``ask_yn()``, a Qt message box
   from plugin code, ...) blocks inside that tool's ``execute_sync`` callback.
   ``sync.py`` scopes IDA's batch mode to the tool's main-thread run, which
   answers every kernwin dialog with its default and never shows it. Anything
   that still slips through as a ``QMessageBox`` is dismissed here (Escape),
   because nobody but the tool could have opened it: IDA runs nothing else on
   the main thread while the tool holds it.

2. A dialog raised *by the user or by IDA itself* (Jump, Options, a loader
   prompt, ...) makes IDA defer every ``execute_sync`` request until it
   closes. That one is never touched automatically. Requests waiting behind it
   fail fast with a message naming the dialog instead of hanging, and they are
   abandoned so they do not run late, after the client already saw an error.
   ``ui_dialogs`` can dismiss it on an explicit request.

Implementation: a ``QTimer`` on the main thread samples
``QApplication.activeModalWidget()``. Qt keeps dispatching timers inside the
nested event loop of a modal dialog, so the sampler keeps running exactly when
the main thread is otherwise unavailable. Worker threads only ever read the
sampled state or queue a command for the next tick; they never touch Qt.

Headless (idalib) never installs the guard, and every query then reports "no
dialog", which leaves the synchronous request path unchanged.

This module must stay importable without IDA or Qt (the pytest suite imports
it), so all IDA/Qt imports are local to the functions that need them.
"""

from __future__ import annotations

import collections
import contextlib
import os
import queue
import threading
import time
import types
from collections.abc import Mapping
from typing import Any, TypedDict


class UiResult(TypedDict, total=False):
    """Shape shared by snapshot(), run_command() and the ui_dialogs tool.

    Nested values stay bare dict/list: the MCP schema generator turns Any into
    "object", which would declare every nested string/int invalid.
    """

    ok: bool
    gui: bool
    note: str
    error: str
    modal: dict | None  # pyright: ignore[reportMissingTypeArgument]
    modal_age_sec: float | None
    modal_owner: str | None
    active_tool: str | None
    recently_dismissed: list  # pyright: ignore[reportMissingTypeArgument]
    dialog: dict  # pyright: ignore[reportMissingTypeArgument]
    action: str
    cleared_cancelled: bool | str
    previous_batch: int | str
    state: Mapping[str, object]

_POLICY_ENV = "IDA_MCP_DIALOG_POLICY"
_WAIT_ENV = "IDA_MCP_MODAL_WAIT_SEC"
_DEFAULT_WAIT_SEC = 3.0
_TICK_MS = 200

# IDA's progress dialog (show_wait_box). It is modal, but it is progress, not a
# question: dismissing it cancels the running operation, so it is never
# auto-dismissed and never treated as "blocked".
_WAIT_DIALOG_CLASS = "WaitDialog"

_lock = threading.Lock()
_state: dict[str, Any] = {
    "installed": False,
    "modal": None,  # description of the current modal widget, or None
    "since": 0.0,  # time.monotonic() when the current modal first appeared
    "owner": None,  # tool name if the modal appeared while that tool ran
    "active_tool": None,  # tool currently running on the main thread
}
_dismissed: collections.deque[dict[str, Any]] = collections.deque(maxlen=20)
_commands: queue.Queue[tuple[str, UiResult, threading.Event]] = queue.Queue()
_timer: Any = None  # keeps the QTimer alive for the life of the process


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def dialog_policy() -> str:
    """``dismiss`` (default): auto-dismiss message boxes a tool raised.
    ``report``: never dismiss automatically, only fail fast and describe."""
    value = os.getenv(_POLICY_ENV, "").strip().lower()
    return value if value in ("dismiss", "report") else "dismiss"


def modal_wait_seconds() -> float:
    """How long a request may sit behind a blocking dialog before it fails."""
    value = os.getenv(_WAIT_ENV, "").strip()
    if value == "":
        return _DEFAULT_WAIT_SEC
    try:
        return max(0.0, float(value))
    except ValueError:
        return _DEFAULT_WAIT_SEC


# ---------------------------------------------------------------------------
# Queries (any thread)
# ---------------------------------------------------------------------------


def is_installed() -> bool:
    with _lock:
        return bool(_state["installed"])


def snapshot() -> UiResult:
    """Thread-safe copy of the sampled UI state."""
    with _lock:
        modal = _state["modal"]
        return {
            "gui": bool(_state["installed"]),
            "modal": dict(modal) if modal else None,
            "modal_age_sec": round(time.monotonic() - _state["since"], 2) if modal else None,
            "modal_owner": _state["owner"],
            "active_tool": _state["active_tool"],
            "recently_dismissed": list(_dismissed),
        }


def blocking_modal() -> tuple[dict[str, Any], float, str | None] | None:
    """Return (description, age_sec, owner_tool) for a modal that blocks the
    main thread, or None. Wait boxes are progress, not blocking."""
    with _lock:
        modal = _state["modal"]
        if not _state["installed"] or not modal or modal.get("kind") == "wait_box":
            return None
        return dict(modal), time.monotonic() - _state["since"], _state["owner"]


def describe(modal: dict[str, Any]) -> str:
    title = modal.get("title") or modal.get("class") or "dialog"
    text = " | ".join(modal.get("text") or [])
    return f"'{title}'" + (f" ({text[:200]})" if text else "")


# ---------------------------------------------------------------------------
# Tool ownership (main thread, called from sync.py around each tool)
# ---------------------------------------------------------------------------


def begin_tool(name: str) -> None:
    with _lock:
        _state["active_tool"] = name


def end_tool() -> None:
    with _lock:
        _state["active_tool"] = None


# ---------------------------------------------------------------------------
# Commands (any thread -> executed on the next main-thread tick)
# ---------------------------------------------------------------------------


def run_command(action: str, timeout: float = 3.0) -> UiResult:
    """Queue ``action`` for the main thread and wait for its result.

    Works while a modal dialog is up, because the sampler tick still fires in
    the dialog's nested event loop. If the main thread is busy in a long C call
    with no event processing, the tick cannot run and this times out.
    """
    if not is_installed():
        return {"ok": False, "error": "UI guard not active (headless or no Qt)"}
    box: UiResult = {}
    done = threading.Event()
    _commands.put((action, box, done))
    if not done.wait(timeout):
        return {
            "ok": False,
            "error": (
                f"main thread did not respond within {timeout:.1f}s; it is busy "
                "outside any dialog (long analysis or SDK call)"
            ),
        }
    return box


# ---------------------------------------------------------------------------
# Main-thread side
# ---------------------------------------------------------------------------


def _qt():
    """Return the QtWidgets module of whichever binding this IDA ships."""
    try:
        from PySide6 import QtWidgets  # IDA 9.2+
    except ImportError:
        from PyQt5 import QtWidgets  # type: ignore[no-redef]  # IDA <= 9.1
    return QtWidgets


def _describe_widget(QtWidgets, w) -> dict[str, Any]:
    meta = w.metaObject().className()
    if meta == _WAIT_DIALOG_CLASS:
        kind = "wait_box"
    elif isinstance(w, QtWidgets.QMessageBox):
        kind = "message_box"
    else:
        kind = "dialog"
    desc: dict[str, Any] = {
        "kind": kind,
        "class": meta,
        "object_name": w.objectName(),
        "title": w.windowTitle(),
    }
    # Best effort: a widget torn down mid-sample must not break the tick.
    with contextlib.suppress(Exception):
        desc["text"] = [
            lbl.text()[:300] for lbl in w.findChildren(QtWidgets.QLabel) if lbl.text()
        ][:6]
        desc["buttons"] = [
            b.text() for b in w.findChildren(QtWidgets.QAbstractButton) if b.text()
        ][:8]
    return desc


def _close(QtWidgets, w, how: str) -> str:
    """Close a modal widget. ``how`` is ``dismiss`` (Escape) or ``accept``."""
    if isinstance(w, QtWidgets.QMessageBox):
        if how == "accept":
            btn = w.defaultButton()
            if btn is not None:
                btn.click()
                return f"clicked default button '{btn.text()}'"
        else:
            btn = w.escapeButton()
            if btn is not None:
                btn.click()
                return f"clicked escape button '{btn.text()}'"
    if isinstance(w, QtWidgets.QDialog):
        if how == "accept":
            w.accept()
            return "accepted"
        w.reject()
        return "rejected"
    w.close()
    return "closed"


def _record_dismissal(desc: dict[str, Any], action: str, reason: str) -> None:
    entry = {
        "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "title": desc.get("title"),
        "text": desc.get("text"),
        "action": action,
        "reason": reason,
    }
    _dismissed.append(entry)
    with contextlib.suppress(Exception):  # logging must never fail the dismissal
        import ida_kernwin

        ida_kernwin.msg(
            f"[ida-multi-mcp] {reason}: {describe(desc)} -> {action}\n"
        )


def _handle_command(QtWidgets, action: str, w) -> UiResult:
    if action in ("dismiss", "accept"):
        if w is None:
            return {"ok": False, "error": "no modal dialog is open"}
        desc = _describe_widget(QtWidgets, w)
        result = _close(QtWidgets, w, action)
        _record_dismissal(desc, result, f"{action} requested via ui_dialogs")
        return {"ok": True, "dialog": desc, "action": result}
    if action == "unstick":
        out: UiResult = {"ok": True}
        try:
            import ida_kernwin

            ida_kernwin.clr_cancelled()
            out["cleared_cancelled"] = True
        except Exception as exc:
            out["cleared_cancelled"] = f"failed: {exc}"
        with _lock:
            tool_running = _state["active_tool"]
        if tool_running is None:
            # Batch mode is only ever ours while a tool runs; outside a tool a
            # set flag is a leak that mutes every IDA dialog. Put it back.
            try:
                import idc

                out["previous_batch"] = int(idc.batch(0))
            except Exception as exc:
                out["previous_batch"] = f"failed: {exc}"
        else:
            out["previous_batch"] = f"left alone: tool '{tool_running}' is running"
        return out
    return {"ok": False, "error": f"unknown action {action!r}"}


def _tick() -> None:
    QtWidgets = _qt()
    has_app = QtWidgets.QApplication.instance() is not None
    w = QtWidgets.QApplication.activeModalWidget() if has_app else None
    desc = _describe_widget(QtWidgets, w) if w is not None else None

    with _lock:
        prev = _state["modal"]
        same = (
            prev is not None
            and desc is not None
            and prev.get("class") == desc.get("class")
            and prev.get("title") == desc.get("title")
        )
        if not same:
            _state["modal"] = desc
            _state["since"] = time.monotonic()
            # Only the tool running right now can have opened a fresh modal:
            # IDA defers every other main-thread request while one is shown.
            _state["owner"] = _state["active_tool"] if desc else None
        owner = _state["owner"]

    if (
        w is not None
        and desc is not None
        and owner is not None
        and desc["kind"] == "message_box"
        and dialog_policy() == "dismiss"
    ):
        action = _close(QtWidgets, w, "dismiss")
        _record_dismissal(desc, action, f"auto-dismissed dialog raised by tool '{owner}'")
        with _lock:
            _state["modal"] = None
            _state["owner"] = None

    while True:
        try:
            action, box, done = _commands.get_nowait()
        except queue.Empty:
            break
        try:
            current = QtWidgets.QApplication.activeModalWidget() if has_app else None
            box.update(_handle_command(QtWidgets, action, current))
        except Exception as exc:  # report, never kill the timer
            box.update({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
        finally:
            done.set()


def _safe_tick() -> None:
    try:
        _tick()
    except Exception as exc:
        # A Qt slot must not raise; one bad sample must not stop the guard.
        with contextlib.suppress(Exception):
            import ida_kernwin

            ida_kernwin.msg(f"[ida-multi-mcp] ui_guard tick failed: {exc}\n")


def install() -> bool:
    """Start the sampler. Call once, on the IDA main thread, in the GUI only."""
    global _timer
    if is_installed():
        return True
    try:
        QtWidgets = _qt()
        from importlib import import_module

        QtCore = import_module(QtWidgets.__name__.rsplit(".", 1)[0] + ".QtCore")
        if QtWidgets.QApplication.instance() is None:
            return False
        timer = QtCore.QTimer()
        timer.setInterval(_TICK_MS)
        timer.timeout.connect(_safe_tick)
        timer.start()
    except Exception as exc:
        print(f"[ida-multi-mcp] Dialog guard unavailable: {exc}")
        return False
    _timer = timer
    with _lock:
        _state["installed"] = True
    return True


def is_guard_frame(frame: types.FrameType) -> bool:
    """True for frames of this module, so sync.py's timeout profiler never
    raises inside the sampler tick (it runs nested inside a stuck tool)."""
    return frame.f_globals.get("__name__") == __name__
