"""Registration logic for ida-multi-mcp plugin.

Handles instance registration with the central registry.
"""

import os
import sys
import json
import http.client
from pathlib import Path


def register_instance(pid: int, port: int, idb_path: str, **metadata) -> str:
    """Register this IDA instance with the central registry.

    Uses file-based registry at ~/.ida-mcp/instances.json.

    Args:
        pid: Process ID
        port: MCP server port
        idb_path: Path to the IDB file being analyzed
        **metadata: Additional metadata (binary_name, binary_path, arch, host)

    Returns:
        Generated instance ID
    """
    # Import here to avoid circular dependencies
    registry_path = str(Path.home() / ".ida-mcp" / "instances.json")

    # We need to add parent directory to path to import from ida_multi_mcp
    parent_dir = str(Path(__file__).parent.parent.parent)
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)

    from ida_multi_mcp.registry import InstanceRegistry

    registry = InstanceRegistry(registry_path)
    instance_id = registry.register(pid, port, idb_path, **metadata)

    print(f"[ida-multi-mcp] Registered as instance '{instance_id}'")
    return instance_id


def unregister_instance(instance_id: str) -> None:
    """Unregister this IDA instance from the central registry.

    Args:
        instance_id: Instance ID to unregister
    """
    registry_path = str(Path.home() / ".ida-mcp" / "instances.json")

    parent_dir = str(Path(__file__).parent.parent.parent)
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)

    from ida_multi_mcp.registry import InstanceRegistry

    registry = InstanceRegistry(registry_path)
    success = registry.unregister(instance_id)

    if success:
        print(f"[ida-multi-mcp] Unregistered instance '{instance_id}'")
    else:
        print(f"[ida-multi-mcp] Failed to unregister instance '{instance_id}'")


def update_heartbeat(instance_id: str) -> None:
    """Update the heartbeat timestamp for this instance.

    Args:
        instance_id: Instance ID
    """
    registry_path = str(Path.home() / ".ida-mcp" / "instances.json")

    parent_dir = str(Path(__file__).parent.parent.parent)
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)

    from ida_multi_mcp.registry import InstanceRegistry

    registry = InstanceRegistry(registry_path)
    registry.update_heartbeat(instance_id)


def get_binary_metadata():
    """Get metadata about the current IDA database.

    Returns:
        Dict with binary_name, binary_path, arch
    """
    try:
        import idaapi
        import idc

        binary_path = idaapi.get_input_file_path() or "unknown"
        binary_name = os.path.basename(binary_path)

        # Get IDB path (the .idb/.i64 database file)
        idb_path = None
        if hasattr(idc, 'get_idb_path'):
            idb_path = idc.get_idb_path()
        if not idb_path:
            try:
                idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)
            except AttributeError:
                pass
        if not idb_path:
            idb_path = binary_path  # Fallback to binary path

        # Get architecture (IDA 9.x removed get_inf_structure)
        try:
            # IDA 9.x+
            import ida_ida
            is_64bit = ida_ida.inf_is_64bit()
            procname = ida_ida.inf_get_procname() or "unknown"
        except (ImportError, AttributeError):
            try:
                # IDA 8.x
                inf = idaapi.get_inf_structure()
                is_64bit = inf.is_64bit()
                procname = inf.procname or "unknown"
            except AttributeError:
                is_64bit = False
                procname = "unknown"

        arch = f"{procname}-{'64' if is_64bit else '32'}"

        return {
            "binary_name": binary_name,
            "binary_path": binary_path,
            "idb_path": idb_path,
            "arch": arch
        }
    except Exception as e:
        print(f"[ida-multi-mcp] Failed to get binary metadata: {e}")
        return {
            "binary_name": "unknown",
            "binary_path": "unknown",
            "idb_path": "unknown",
            "arch": "unknown"
        }
