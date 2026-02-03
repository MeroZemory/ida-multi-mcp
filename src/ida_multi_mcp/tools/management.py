"""Management tools for ida-multi-mcp.

These tools are implemented directly in the MCP server (not proxied to IDA).
They manage instance lifecycle: listing, activating, and refreshing.
"""

from typing import Annotated, TYPE_CHECKING

if TYPE_CHECKING:
    from ..registry import InstanceRegistry

# Module-level registry reference, set by server.py on startup
_registry: "InstanceRegistry | None" = None
_refresh_callback = None


def set_registry(registry: "InstanceRegistry") -> None:
    """Set the registry instance for management tools."""
    global _registry
    _registry = registry


def set_refresh_callback(callback) -> None:
    """Set the callback for refreshing tool schemas."""
    global _refresh_callback
    _refresh_callback = callback


def _get_registry() -> "InstanceRegistry":
    if _registry is None:
        raise RuntimeError("Registry not initialized")
    return _registry


def list_instances() -> dict:
    """List all registered IDA Pro instances with their metadata.

    Returns instance ID, binary name, path, architecture, host, port,
    and registration time for each active IDA Pro instance.
    """
    registry = _get_registry()
    instances = registry.list_instances()
    active = registry.get_active()
    result = []
    for id, info in instances.items():
        result.append({
            "id": id,
            "active": id == active,
            "binary_name": info.get("binary_name", "unknown"),
            "binary_path": info.get("binary_path", "unknown"),
            "arch": info.get("arch", "unknown"),
            "host": info.get("host", "127.0.0.1"),
            "port": info.get("port", 0),
            "pid": info.get("pid", 0),
            "registered_at": info.get("registered_at", ""),
        })
    return {
        "active": active,
        "count": len(result),
        "instances": result,
    }


def get_active_instance() -> dict:
    """Get the currently active IDA Pro instance.

    The active instance is used as the default target when no instance_id
    is specified in tool calls.
    """
    registry = _get_registry()
    active_id = registry.get_active()
    if active_id is None:
        return {"error": "No active instance. Open IDA Pro with the multi-MCP plugin."}
    info = registry.get_instance(active_id)
    if info is None:
        return {"error": f"Active instance '{active_id}' not found in registry."}
    return {
        "id": active_id,
        "binary_name": info.get("binary_name", "unknown"),
        "binary_path": info.get("binary_path", "unknown"),
        "arch": info.get("arch", "unknown"),
        "host": info.get("host", "127.0.0.1"),
        "port": info.get("port", 0),
    }


def set_active_instance(
    instance_id: Annotated[str, "Instance ID to set as active (e.g., 'k7m2')"]
) -> dict:
    """Set the active IDA Pro instance for subsequent tool calls.

    When no instance_id is specified in a tool call, the active instance
    is used as the default target.
    """
    registry = _get_registry()
    info = registry.get_instance(instance_id)
    if info is None:
        available = registry.list_instances()
        names = [f"{id} ({i.get('binary_name', '?')})" for id, i in available.items()]
        return {
            "error": f"Instance '{instance_id}' not found.",
            "available": names
        }
    registry.set_active(instance_id)
    return {
        "active": instance_id,
        "binary_name": info.get("binary_name", "unknown"),
    }


def refresh_tools() -> dict:
    """Re-discover tools from IDA Pro instances.

    Call this after connecting new IDA instances or if tools appear stale.
    Forces a fresh query of tools/list from the active IDA instance.
    """
    if _refresh_callback:
        count = _refresh_callback()
        return {"refreshed": True, "tools_count": count}
    return {"refreshed": False, "error": "Refresh callback not set"}
