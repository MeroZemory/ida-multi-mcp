"""Health check module for ida-multi-mcp.

Detects dead/stale IDA instances via process alive check and HTTP ping.
"""

import os
import sys
import json
import http.client
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .registry import InstanceRegistry


def is_process_alive(pid: int) -> bool:
    """Check if a process is still running (cross-platform).

    Args:
        pid: Process ID to check

    Returns:
        True if process exists
    """
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if handle:
                kernel32.CloseHandle(handle)
                return True
            return False
        except Exception:
            return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True  # Process exists but we can't signal it


def ping_instance(host: str, port: int, timeout: float = 5.0) -> bool:
    """Ping an IDA instance via HTTP MCP ping.

    Args:
        host: Instance hostname
        port: Instance port
        timeout: Connection timeout in seconds

    Returns:
        True if instance responds to ping
    """
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        request = json.dumps({
            "jsonrpc": "2.0",
            "method": "ping",
            "id": 1
        })
        conn.request("POST", "/mcp", request, {"Content-Type": "application/json"})
        response = conn.getresponse()
        conn.close()
        return response.status == 200
    except Exception:
        return False


def check_instance_health(instance: dict) -> bool:
    """Check if an IDA instance is alive and responsive.

    Performs two checks:
    1. Process alive (OS-level)
    2. HTTP ping (application-level)

    Args:
        instance: Instance info dict with pid, host, port

    Returns:
        True if instance is healthy
    """
    # Check 1: Process alive
    if not is_process_alive(instance["pid"]):
        return False

    # Check 2: HTTP ping
    return ping_instance(instance["host"], instance["port"])


def cleanup_stale_instances(registry: "InstanceRegistry", timeout_seconds: int = 120) -> list[str]:
    """Remove dead instances from registry.

    Called on MCP server startup and periodically.

    Args:
        registry: The instance registry
        timeout_seconds: Heartbeat timeout threshold

    Returns:
        List of removed instance IDs
    """
    removed = []
    instances = registry.list_instances()

    for instance_id, info in instances.items():
        if not check_instance_health(info):
            registry.expire_instance(instance_id, reason="stale_no_response")
            removed.append(instance_id)
            print(f"[ida-multi-mcp] Removed stale instance '{instance_id}' "
                  f"({info.get('binary_name', 'unknown')})")

    # Also clean up old expired entries
    registry.cleanup_expired()

    return removed


def query_binary_path(host: str, port: int, timeout: float = 5.0) -> str | None:
    """Query an IDA instance for its current binary path.

    Uses the ida://idb/metadata resource to get the current file path.
    This is the fallback mechanism for detecting binary changes when
    IDA hooks don't fire.

    Args:
        host: Instance hostname
        port: Instance port
        timeout: Connection timeout

    Returns:
        Binary file path, or None if query fails
    """
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        request = json.dumps({
            "jsonrpc": "2.0",
            "method": "resources/read",
            "params": {"uri": "ida://idb/metadata"},
            "id": 1
        })
        conn.request("POST", "/mcp", request, {"Content-Type": "application/json"})
        response = conn.getresponse()
        data = json.loads(response.read().decode())
        conn.close()

        # Extract path from metadata resource response
        result = data.get("result", {})
        contents = result.get("contents", [])
        if contents:
            text = contents[0].get("text", "{}")
            metadata = json.loads(text)
            return metadata.get("path")
    except Exception:
        pass
    return None
