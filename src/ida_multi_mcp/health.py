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
            STILL_ACTIVE = 259  # GetExitCodeProcess return for a running process
            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not handle:
                return False
            try:
                # OpenProcess succeeds for a just-exited process whose handle is
                # not yet released (a zombie). Confirm liveness via exit code.
                exit_code = ctypes.c_ulong(0)
                if kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                    return exit_code.value == STILL_ACTIVE
                # Could not read exit code — assume alive (benefit of the doubt).
                return True
            finally:
                kernel32.CloseHandle(handle)
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


_ALLOWED_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def ping_instance(host: str, port: int, timeout: float = 15.0) -> bool:
    """Ping an IDA instance via HTTP MCP ping.

    Args:
        host: Instance hostname
        port: Instance port
        timeout: Connection timeout in seconds

    Returns:
        True if instance responds to ping
    """
    # Security: only allow localhost connections (prevent SSRF)
    if host not in _ALLOWED_HOSTS:
        return False
    conn = None
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        request = json.dumps({
            "jsonrpc": "2.0",
            "method": "ping",
            "id": 1
        })
        conn.request("POST", "/mcp", request, {"Content-Type": "application/json"})
        response = conn.getresponse()
        return response.status == 200
    except Exception:
        return False
    finally:
        if conn is not None:
            conn.close()  # always release the socket, even on error


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
    # Security: only allow localhost connections (prevent SSRF)
    if host not in _ALLOWED_HOSTS:
        return None
    conn = None
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

        # Extract metadata from resource response
        result = data.get("result", {})
        contents = result.get("contents", [])
        if contents:
            text = contents[0].get("text", "{}")
            return json.loads(text)
    except Exception:
        pass
    finally:
        if conn is not None:
            conn.close()  # always release the socket, even on error
    return None


_IDA_PROCESS_NAMES = {
    "ida.exe", "ida64.exe", "idat.exe", "idat64.exe",
    "ida", "ida64", "idat", "idat64",
}
_LISTEN_STATES = {"LISTENING", "侦听"}


def _console_output(cmd: list[str], timeout: int = 10) -> str:
    """Run a console utility and return decoded stdout.

    Windows ``tasklist`` / ``netstat`` emit OEM/GBK. Python UTF-8 mode
    (``PYTHONUTF8=1``, common in MCP clients) makes ``text=True`` decode
    as UTF-8. The reader thread then raises ``UnicodeDecodeError``,
    ``check_output`` returns ``None``, and callers crash on ``.strip()``
    before MCP ``initialize`` — the client sees
    ``handshake failed: connection closed: initialize response``.
    """
    kwargs: dict = {
        "timeout": timeout,
        "stderr": subprocess.DEVNULL,
        "errors": "replace",
    }
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        kwargs["encoding"] = "oem"
    else:
        kwargs["encoding"] = "utf-8"
    try:
        out = subprocess.check_output(cmd, **kwargs)
    except (subprocess.SubprocessError, OSError, UnicodeError):
        return ""
    return out or ""


def _find_ida_listening_ports() -> list[tuple[int, int]]:
    """Find TCP ports owned by IDA processes (Windows and Unix).

    Returns:
        List of (pid, port) tuples for IDA processes with listening TCP ports
    """
    results: list[tuple[int, int]] = []

    if sys.platform == "win32":
        out = _console_output(["tasklist", "/FO", "CSV", "/NH"])
        ida_pids: set[int] = set()
        for line in out.strip().splitlines():
            parts = line.strip('"').split('","')
            if len(parts) >= 2 and parts[0].lower() in _IDA_PROCESS_NAMES:
                try:
                    ida_pids.add(int(parts[1]))
                except ValueError:
                    continue
        if not ida_pids:
            return []

        netstat = _console_output(["netstat", "-ano", "-p", "TCP"])
        for line in netstat.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            if parts[3].upper() not in _LISTEN_STATES:
                continue
            try:
                pid = int(parts[4])
            except ValueError:
                continue
            if pid not in ida_pids:
                continue
            # Local address, e.g. 127.0.0.1:57079 or [::1]:57079
            port_str = parts[1].rsplit(":", 1)[-1]
            try:
                results.append((pid, int(port_str)))
            except ValueError:
                continue
        return results

    out = _console_output(["lsof", "-iTCP", "-sTCP:LISTEN", "-nP", "-F", "pcn"])
    if out:
        current_pid = None
        current_name = None
        for line in out.splitlines():
            if line.startswith("p"):
                current_pid = int(line[1:])
            elif line.startswith("c"):
                current_name = line[1:]
            elif line.startswith("n") and current_pid and current_name:
                if current_name.lower() in _IDA_PROCESS_NAMES:
                    port_str = line.rsplit(":", 1)[-1]
                    try:
                        results.append((current_pid, int(port_str)))
                    except ValueError:
                        continue
        return results

    out = _console_output(["ss", "-tlnp"])
    import re
    for line in out.splitlines():
        if not any(name in line for name in _IDA_PROCESS_NAMES):
            continue
        match = re.search(r"pid=(\d+)", line)
        if not match:
            continue
        for part in line.split():
            if ":" not in part:
                continue
            port_str = part.rsplit(":", 1)[-1]
            try:
                results.append((int(match.group(1)), int(port_str)))
            except ValueError:
                continue
            break
    return results


def rediscover_instances(registry: "InstanceRegistry") -> list[str]:
    """Auto-discover live IDA MCP servers and register them.

    Scans for running IDA processes, finds their listening TCP ports,
    pings each to confirm it's an MCP server, queries metadata, and
    registers any that aren't already in the registry.

    Called on proxy startup when the registry has no registered instances.
    Discovery failures must not prevent MCP initialize / stdio serve.

    Args:
        registry: The instance registry

    Returns:
        List of newly registered instance IDs
    """
    try:
        return _rediscover_instances(registry)
    except Exception as exc:
        print(f"[ida-multi-mcp] instance rediscovery skipped: {exc}", file=sys.stderr)
        return []


def _rediscover_instances(registry: "InstanceRegistry") -> list[str]:
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
