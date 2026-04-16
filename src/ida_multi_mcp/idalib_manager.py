"""idalib subprocess lifecycle manager.

Spawns, monitors, and terminates headless idalib worker processes.
Each worker opens one binary and listens on a unique localhost port.
Does NOT depend on ``idapro`` — purely manages subprocesses.
"""

from __future__ import annotations

import atexit
import os
import socket
import subprocess
import sys
import time
from typing import TYPE_CHECKING

from .health import is_process_alive, ping_instance

if TYPE_CHECKING:
    from .registry import InstanceRegistry

# Default timeout (seconds) waiting for worker to become ready.
_READY_TIMEOUT = 120
# Poll interval while waiting for worker readiness.
_READY_POLL_INTERVAL = 0.5

# idalib library file name per platform.
_IDALIB_NAMES = {
    "win32": "idalib.dll",
    "darwin": "libidalib.dylib",
    "linux": "libidalib.so",
}


def is_idalib_available() -> bool:
    """Check whether the detected IDA installation includes idalib (Pro only).

    Returns True if idalib.dll / libidalib.* exists in the IDA directory
    resolved from IDADIR or ida-config.json.
    """
    ida_dir = _resolve_ida_dir()
    if not ida_dir:
        return False
    lib_name = _IDALIB_NAMES.get(sys.platform, "libidalib.so")
    return os.path.isfile(os.path.join(ida_dir, lib_name))


def _resolve_ida_dir() -> str | None:
    """Resolve IDA dir from IDADIR env or ida-config.json (no filesystem scan)."""
    env_dir = os.environ.get("IDADIR", "").strip()
    if env_dir and os.path.isdir(env_dir):
        return env_dir
    # ida-config.json
    if sys.platform == "win32":
        cfg_path = os.path.join(os.environ.get("APPDATA", ""), "Hex-Rays", "IDA Pro", "ida-config.json")
    else:
        cfg_path = os.path.join(os.path.expanduser("~"), ".idapro", "ida-config.json")
    try:
        import json
        with open(cfg_path, "r") as f:
            cfg = json.load(f)
        d = cfg.get("Paths", {}).get("ida-install-dir", "").strip()
        if d and os.path.isdir(d):
            return d
    except Exception:
        pass
    return None


def _find_free_port(host: str = "127.0.0.1") -> int:
    """Bind an ephemeral port, release it, return the number.

    There is a small TOCTOU race, but acceptable for localhost-only use.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


class IdalibManager:
    """Manages headless idalib worker subprocesses.

    Each call to :meth:`spawn_session` starts a new Python subprocess
    that opens one binary via ``idapro``, starts an HTTP MCP server on
    a unique port, and registers itself in the shared
    :class:`InstanceRegistry` so the router can forward tool calls.
    """

    def __init__(
        self,
        registry: InstanceRegistry,
        python_executable: str | None = None,
    ):
        self.registry = registry
        self.python_executable = python_executable or sys.executable
        # instance_id -> subprocess.Popen
        self._processes: dict[str, subprocess.Popen] = {}
        # Register cleanup on interpreter shutdown
        atexit.register(self.close_all_sessions)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def spawn_session(
        self,
        input_path: str,
        *,
        host: str = "127.0.0.1",
        timeout: int = _READY_TIMEOUT,
        unsafe: bool = False,
    ) -> dict:
        """Spawn a headless idalib worker for *input_path*.

        Returns a dict with ``instance_id``, ``host``, ``port``, ``pid``,
        ``binary`` on success, or ``error`` on failure.
        """
        if not is_idalib_available():
            return {
                "error": (
                    "idalib is not available. Headless mode requires IDA Pro "
                    "(IDA Home/Free do not include idalib). "
                    "Ensure IDADIR points to an IDA Pro installation."
                )
            }

        resolved_path = os.path.realpath(input_path)
        if not os.path.isfile(resolved_path):
            return {"error": f"File not found: {input_path}"}

        port = _find_free_port(host)

        cmd = [
            self.python_executable,
            "-m", "ida_multi_mcp.idalib_worker",
            "--host", host,
            "--port", str(port),
        ]
        if unsafe:
            cmd.append("--unsafe")
        cmd.append(resolved_path)

        creation_flags = 0
        if sys.platform == "win32":
            creation_flags = subprocess.CREATE_NO_WINDOW

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=creation_flags,
            )
        except FileNotFoundError:
            return {
                "error": (
                    f"Python executable not found: {self.python_executable}. "
                    "Set --idalib-python to the correct Python with idapro installed."
                )
            }
        except Exception as exc:
            return {"error": f"Failed to spawn idalib worker: {exc}"}

        # Wait for the worker to become ready.
        if not self._wait_for_ready(host, port, proc, timeout):
            # Worker didn't come up — collect stderr for diagnostics.
            stderr_text = ""
            try:
                proc.terminate()
                _, stderr_bytes = proc.communicate(timeout=5)
                stderr_text = stderr_bytes.decode(errors="replace")[-500:]
            except Exception:
                proc.kill()
            return {
                "error": (
                    f"idalib worker did not become ready within {timeout}s. "
                    f"Last stderr: {stderr_text}"
                )
            }

        # Register in the shared registry.
        binary_name = os.path.basename(resolved_path)
        instance_id = self.registry.register(
            pid=proc.pid,
            port=port,
            idb_path=resolved_path,
            host=host,
            binary_name=binary_name,
            binary_path=resolved_path,
            type="idalib",
        )

        self._processes[instance_id] = proc
        return {
            "instance_id": instance_id,
            "host": host,
            "port": port,
            "pid": proc.pid,
            "binary": binary_name,
        }

    def close_session(self, instance_id: str) -> dict:
        """Terminate the worker for *instance_id* and unregister it.

        Returns ``{"ok": True}`` on success or ``{"error": ...}`` on failure.
        """
        proc = self._processes.get(instance_id)
        if proc is None:
            # Not managed by us (might be GUI or already closed).
            info = self.registry.get_instance(instance_id)
            if info is not None and info.get("type") == "idalib":
                # Orphaned idalib entry — clean it up from registry.
                self.registry.unregister(instance_id)
                return {"ok": True, "note": "orphaned entry removed"}
            return {"error": f"Instance '{instance_id}' is not a managed idalib session"}

        # Terminate the subprocess.
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

        del self._processes[instance_id]
        self.registry.unregister(instance_id)
        return {"ok": True}

    def close_all_sessions(self) -> int:
        """Terminate all managed idalib workers. Returns count closed."""
        ids = list(self._processes.keys())
        for iid in ids:
            self.close_session(iid)
        return len(ids)

    def list_sessions(self) -> list[dict]:
        """Return info about all managed idalib sessions."""
        result = []
        for iid, proc in list(self._processes.items()):
            info = self.registry.get_instance(iid)
            alive = is_process_alive(proc.pid)
            if not alive:
                # Clean up dead workers.
                del self._processes[iid]
                self.registry.unregister(iid)
                continue
            result.append({
                "instance_id": iid,
                "pid": proc.pid,
                "host": info.get("host", "127.0.0.1") if info else "127.0.0.1",
                "port": info.get("port", 0) if info else 0,
                "binary_name": info.get("binary_name", "unknown") if info else "unknown",
                "binary_path": info.get("binary_path", "") if info else "",
                "type": "idalib",
            })
        return result

    def get_status(self, instance_id: str) -> dict:
        """Health / readiness check for a specific idalib session."""
        proc = self._processes.get(instance_id)
        if proc is None:
            return {"error": f"Instance '{instance_id}' is not a managed idalib session"}

        info = self.registry.get_instance(instance_id)
        alive = is_process_alive(proc.pid)
        if not alive:
            del self._processes[instance_id]
            self.registry.unregister(instance_id)
            return {
                "instance_id": instance_id,
                "alive": False,
                "reachable": False,
                "error": "Worker process is dead",
            }

        host = info.get("host", "127.0.0.1") if info else "127.0.0.1"
        port = info.get("port", 0) if info else 0
        reachable = ping_instance(host, port, timeout=5.0)

        return {
            "instance_id": instance_id,
            "pid": proc.pid,
            "alive": True,
            "reachable": reachable,
            "binary_name": info.get("binary_name", "unknown") if info else "unknown",
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _wait_for_ready(
        self,
        host: str,
        port: int,
        proc: subprocess.Popen,
        timeout: int,
    ) -> bool:
        """Poll until the worker responds to ping or until timeout/death."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            # Check if process died.
            if proc.poll() is not None:
                return False
            if ping_instance(host, port, timeout=2.0):
                return True
            time.sleep(_READY_POLL_INTERVAL)
        return False
