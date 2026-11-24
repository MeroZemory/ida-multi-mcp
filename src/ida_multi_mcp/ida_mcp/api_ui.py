"""UI recovery tool: inspect and clear modal dialogs that block IDA.

Deliberately NOT ``@idasync``. It has to answer while the IDA main thread is
stuck inside a dialog, which is exactly when every ``@idasync`` tool cannot
run. It reads the state sampled by ``ui_guard`` and hands Qt work to the
guard's main-thread timer, which keeps firing inside a modal's event loop.
"""

from typing import Annotated

from . import ui_guard
from .rpc import tool


@tool
def ui_dialogs(
    # Plain str, not Literal: zeromcp's argument validator cannot isinstance()
    # a Literal. The body validates the value.
    action: Annotated[
        str,
        "list|dismiss|accept|unstick. list (default): report the open modal dialog, if any. "
        "dismiss: close it as if Escape/Cancel was pressed. "
        "accept: press its default button. "
        "unstick: clear a stuck cancellation flag and a leaked batch mode.",
    ] = "list",
) -> ui_guard.UiResult:
    """Inspect or clear a modal dialog that blocks IDA (GUI only).

    IDA runs no tool while a modal dialog is open, so other tools fail with
    'IDA is blocked by a modal dialog'. Call this with action='list' to see
    which dialog it is. Only dismiss or accept a dialog that your own call
    opened, or when the user asked you to; a dialog the user opened may hold
    their unsaved input. Message boxes raised by a tool are already
    auto-dismissed, and listed under recently_dismissed."""
    if action not in ("list", "dismiss", "accept", "unstick"):
        return {"ok": False, "error": f"unknown action {action!r}"}

    state = ui_guard.snapshot()
    if not state.get("gui"):
        return {
            "ok": True,
            "gui": False,
            "note": "headless instance: no dialogs can block it",
        }
    if action == "list":
        out: ui_guard.UiResult = {"ok": True}
        out.update(state)
        return out

    result = ui_guard.run_command(action)
    result["state"] = ui_guard.snapshot()
    return result
