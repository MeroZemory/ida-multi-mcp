"""Health check module for ida-multi-mcp.

Detects dead/stale IDA instances via process alive check and HTTP ping.
Supports auto-rediscovery of live IDA MCP servers on proxy restart.
"""

import os
import sys
import json
import http.client
import subprocess
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


def ping_instance(host: str, port: int, timeout: float = 15.0) -> bool:
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

    Only removes instances whose IDA process is no longer running.
    If the process is alive but not responding to ping (e.g. busy with
    a long decompilation), the instance is kept — IDA runs on a single
    main thread, so it cannot answer pings while processing a request.

    Args:
        registry: The instance registry
        timeout_seconds: Heartbeat timeout threshold

    Returns:
        List of removed instance IDs
    """
    removed = []
    instances = registry.list_instances()

    for instance_id, info in instances.items():
        pid = info.get("pid")
        # Only expire if the IDA process itself is dead
        if pid is not None and not is_process_alive(pid):
            registry.expire_instance(instance_id, reason="process_dead")
            removed.append(instance_id)
            print(f"[ida-multi-mcp] Removed dead instance '{instance_id}' "
                  f"(pid {pid}, {info.get('binary_name', 'unknown')})")

    # Also clean up old expired entries
    registry.cleanup_expired()

    return removed


def query_binary_metadata(host: str, port: int, timeout: float = 5.0) -> dict | None:
    """Query an IDA instance for its current binary metadata.

    Uses the ida://idb/metadata resource to get the current file info.
    This is the fallback mechanism for detecting binary changes when
    IDA hooks don't fire.

    Args:
        host: Instance hostname
        port: Instance port
        timeout: Connection timeout

    Returns:
        Metadata dict with 'path' (IDB path) and 'module' (binary name),
        or None if query fails
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

        # Extract metadata from resource response
        result = data.get("result", {})
        contents = result.get("contents", [])
        if contents:
            text = contents[0].get("text", "{}")
            return json.loads(text)
    except Exception:
        pass
    return None


def _find_ida_listening_ports() -> list[tuple[int, int]]:
    """Find TCP ports owned by IDA processes (Windows and Unix).

    Returns:
        List of (pid, port) tuples for IDA processes with listening TCP ports
    """
    ida_names = {"ida.exe", "ida64.exe", "idat.exe", "idat64.exe",
                 "ida", "ida64", "idat", "idat64"}
    results = []

    if sys.platform == "win32":
        try:
            # Get IDA PIDs
            out = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"],
                text=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW,
            )
            ida_pids = set()
            for line in out.strip().splitlines():
                parts = line.strip('"').split('","')
                if len(parts) >= 2 and parts[0].lower() in ida_names:
                    try:
                        ida_pids.add(int(parts[1]))
                    except ValueError:
                        pass

            if not ida_pids:
                return []

            # Get listening ports for those PIDs
            out = subprocess.check_output(
                ["netstat", "-ano", "-p", "TCP"],
                text=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW,
            )
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[3] == "LISTENING":
                    try:
                        pid = int(parts[4])
                    except ValueError:
                        continue
                    if pid in ida_pids:
                        # Parse local address (e.g. 127.0.0.1:57079)
                        addr = parts[1]
                        port_str = addr.rsplit(":", 1)[-1]
                        try:
                            results.append((pid, int(port_str)))
                        except ValueError:
                            pass
        except (subprocess.SubprocessError, OSError):
            pass
    else:
        # Unix: use lsof
        try:
            out = subprocess.check_output(
                ["lsof", "-iTCP", "-sTCP:LISTEN", "-nP", "-F", "pcn"],
                text=True, timeout=10,
            )
            current_pid = None
            current_name = None
            for line in out.splitlines():
                if line.startswith("p"):
                    current_pid = int(line[1:])
                elif line.startswith("c"):
                    current_name = line[1:]
                elif line.startswith("n") and current_pid and current_name:
                    if current_name.lower() in ida_names:
                        port_str = line.rsplit(":", 1)[-1]
                        try:
                            results.append((current_pid, int(port_str)))
                        except ValueError:
                            pass
        except (subprocess.SubprocessError, OSError, FileNotFoundError):
            # lsof not available, try ss
            try:
                out = subprocess.check_output(
                    ["ss", "-tlnp"],
                    text=True, timeout=10,
                )
                for line in out.splitlines():
                    for name in ida_names:
                        if name in line:
                            # Extract port and pid
                            parts = line.split()
                            for part in parts:
                                if ":" in part:
                                    port_str = part.rsplit(":", 1)[-1]
                                    try:
                                        port = int(port_str)
                                        # Extract pid from pid=NNNN
                                        import re
                                        m = re.search(r"pid=(\d+)", line)
                                        if m:
                                            results.append((int(m.group(1)), port))
                                        break
                                    except ValueError:
                                        continue
            except (subprocess.SubprocessError, OSError, FileNotFoundError):
                pass

    return results


def rediscover_instances(registry: "InstanceRegistry") -> list[str]:
    """Auto-discover live IDA MCP servers and register them.

    Scans for running IDA processes, finds their listening TCP ports,
    pings each to confirm it's an MCP server, queries metadata, and
    registers any that aren't already in the registry.

    Called on proxy startup when the registry has no active instances.

    Args:
        registry: The instance registry

    Returns:
        List of newly registered instance IDs
    """
    registered = []
    existing = registry.list_instances()

    # Build set of already-known (pid, port) pairs to skip
    known_ports = {(info["pid"], info["port"]) for info in existing.values()
                   if "pid" in info and "port" in info}

    candidates = _find_ida_listening_ports()
    if not candidates:
        return []

    for pid, port in candidates:
        if (pid, port) in known_ports:
            continue

        host = "127.0.0.1"

        # Ping to confirm it's an MCP server
        if not ping_instance(host, port, timeout=5.0):
            continue

        # Query metadata to get binary info
        metadata = query_binary_metadata(host, port, timeout=5.0)
        if not metadata:
            continue

        idb_path = metadata.get("path", "")
        binary_name = metadata.get("module", "unknown")

        instance_id = registry.register(
            pid=pid,
            port=port,
            idb_path=idb_path,
            binary_name=binary_name,
            binary_path=metadata.get("input_file", ""),
            arch=metadata.get("arch", "unknown"),
            host=host,
        )
        registered.append(instance_id)
        print(f"[ida-multi-mcp] Auto-discovered instance '{instance_id}' "
              f"(pid {pid}, port {port}, {binary_name})", file=sys.stderr)

    return registered
