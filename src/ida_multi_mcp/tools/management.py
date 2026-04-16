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
    and registration time for each running IDA Pro instance.
    """
    registry = _get_registry()
    instances = registry.list_instances()
    result = []
    for id, info in instances.items():
        result.append({
            "id": id,
            "type": info.get("type", "gui"),
            "binary_name": info.get("binary_name", "unknown"),
            "binary_path": info.get("binary_path", "unknown"),
            "arch": info.get("arch", "unknown"),
            "host": info.get("host", "127.0.0.1"),
            "port": info.get("port", 0),
            "pid": info.get("pid", 0),
            "registered_at": info.get("registered_at", ""),
        })
    return {
        "count": len(result),
        "instances": result,
    }


def refresh_tools() -> dict:
    """Re-discover tools from IDA Pro instances.

    Call this after connecting new IDA instances or if tools appear stale.
    Forces a fresh query of tools/list from available IDA instances.
    """
    if _refresh_callback:
        count = _refresh_callback()
        return {"refreshed": True, "tools_count": count}
    return {"refreshed": False, "error": "Refresh callback not set"}


# Module-level router reference for compare_binaries
_router = None


def set_router(router) -> None:
    global _router
    _router = router


def compare_binaries(arguments: dict) -> dict:
    """Compare two IDA instances by diffing their survey_binary results.

    Returns added/removed/common functions, imports, and strings.
    """
    id_a = arguments.get("instance_id_a", "")
    id_b = arguments.get("instance_id_b", "")
    if not id_a or not id_b:
        return {"error": "Both instance_id_a and instance_id_b are required"}
    if id_a == id_b:
        return {"error": "instance_id_a and instance_id_b must be different"}
    if _router is None:
        return {"error": "Router not initialized"}

    def _call_survey(instance_id: str) -> dict | None:
        resp = _router.route_request("tools/call", {
            "name": "survey_binary",
            "arguments": {"detail_level": "minimal", "instance_id": instance_id},
        })
        if "error" in resp:
            return None
        # Parse content wrapper
        content = resp.get("content", [])
        if content:
            import json
            try:
                return json.loads(content[0].get("text", "{}"))
            except Exception:
                pass
        return resp.get("structuredContent")

    survey_a = _call_survey(id_a)
    survey_b = _call_survey(id_b)
    if survey_a is None:
        return {"error": f"Failed to survey instance {id_a}"}
    if survey_b is None:
        return {"error": f"Failed to survey instance {id_b}"}

    def _diff_sets(items_a: list[str], items_b: list[str]) -> dict:
        set_a, set_b = set(items_a), set(items_b)
        return {
            "only_a": sorted(set_a - set_b)[:200],
            "only_b": sorted(set_b - set_a)[:200],
            "common": len(set_a & set_b),
            "total_a": len(set_a),
            "total_b": len(set_b),
        }

    # Extract function names from statistics
    stats_a = survey_a.get("statistics", {})
    stats_b = survey_b.get("statistics", {})

    # Extract entry point names
    entries_a = [e.get("name", "") for e in survey_a.get("entrypoints", [])]
    entries_b = [e.get("name", "") for e in survey_b.get("entrypoints", [])]

    # Extract segment names
    segs_a = [s.get("name", "") for s in survey_a.get("segments", [])]
    segs_b = [s.get("name", "") for s in survey_b.get("segments", [])]

    return {
        "instance_a": {"id": id_a, "module": survey_a.get("metadata", {}).get("module", "?")},
        "instance_b": {"id": id_b, "module": survey_b.get("metadata", {}).get("module", "?")},
        "statistics": {"a": stats_a, "b": stats_b},
        "entrypoints": _diff_sets(entries_a, entries_b),
        "segments": _diff_sets(segs_a, segs_b),
    }
