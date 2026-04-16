"""idalib management tools — exposed through the router MCP server.

These four tools let MCP clients open/close/list/inspect headless idalib
sessions.  Each session is a subprocess managed by :class:`IdalibManager`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..idalib_manager import IdalibManager

_manager: IdalibManager | None = None


def set_manager(manager: IdalibManager) -> None:
    """Inject the :class:`IdalibManager` instance (called by server.py on startup)."""
    global _manager
    _manager = manager


def _get_manager() -> IdalibManager:
    if _manager is None:
        raise RuntimeError("IdalibManager not initialized")
    return _manager


# ------------------------------------------------------------------
# Tool functions (called from custom_tools_call in server.py)
# ------------------------------------------------------------------


def idalib_open(arguments: dict) -> dict:
    """Open a binary in a new headless idalib session.

    Required args:
        input_path (str): Path to the binary or IDB file.
    Optional args:
        timeout (int): Seconds to wait for analysis (default 120).
        unsafe (bool): Enable unsafe tools (default false).
    """
    mgr = _get_manager()
    input_path = arguments.get("input_path", "")
    if not input_path:
        return {"error": "Missing required argument 'input_path'"}
    timeout = int(arguments.get("timeout", 120))
    unsafe = bool(arguments.get("unsafe", False))
    return mgr.spawn_session(input_path, timeout=timeout, unsafe=unsafe)


def idalib_close(arguments: dict) -> dict:
    """Close a headless idalib session and terminate its worker process.

    Required args:
        instance_id (str): Instance ID of the idalib session.
    """
    mgr = _get_manager()
    instance_id = arguments.get("instance_id", "")
    if not instance_id:
        return {"error": "Missing required argument 'instance_id'"}
    return mgr.close_session(instance_id)


def idalib_list(arguments: dict) -> dict:
    """List all managed idalib sessions."""
    mgr = _get_manager()
    sessions = mgr.list_sessions()
    return {"count": len(sessions), "sessions": sessions}


def idalib_status(arguments: dict) -> dict:
    """Health / readiness check for a specific idalib session.

    Required args:
        instance_id (str): Instance ID to check.
    """
    mgr = _get_manager()
    instance_id = arguments.get("instance_id", "")
    if not instance_id:
        return {"error": "Missing required argument 'instance_id'"}
    return mgr.get_status(instance_id)


# ------------------------------------------------------------------
# Tool schemas (registered in server._refresh_tools)
# ------------------------------------------------------------------

IDALIB_TOOL_SCHEMAS: list[dict] = [
    {
        "name": "idalib_open",
        "description": (
            "Open a binary in a new headless idalib session. "
            "Spawns a background process that loads the binary via idalib, "
            "waits for auto-analysis to complete, then registers as a regular "
            "IDA instance. Use list_instances() to see it alongside GUI instances. "
            "Requires idapro Python package on the configured Python."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "input_path": {
                    "type": "string",
                    "description": "Path to the binary or IDB file to open",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Seconds to wait for analysis to complete (default 120)",
                },
                "unsafe": {
                    "type": "boolean",
                    "description": "Enable unsafe/destructive tools (default false)",
                },
            },
            "required": ["input_path"],
        },
    },
    {
        "name": "idalib_close",
        "description": (
            "Close a headless idalib session and terminate its worker process. "
            "The instance is removed from the registry."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "string",
                    "description": "Instance ID of the idalib session to close",
                },
            },
            "required": ["instance_id"],
        },
    },
    {
        "name": "idalib_list",
        "description": "List all managed headless idalib sessions with pid, port, and binary info.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "idalib_status",
        "description": (
            "Health and readiness check for a specific idalib session. "
            "Reports whether the worker process is alive and reachable via HTTP."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "instance_id": {
                    "type": "string",
                    "description": "Instance ID of the idalib session to check",
                },
            },
            "required": ["instance_id"],
        },
    },
]
