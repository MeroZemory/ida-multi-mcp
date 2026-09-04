"""idalib subprocess lifecycle manager.

Spawns, monitors, and terminates headless idalib worker processes.
Each worker opens one binary and listens on a unique localhost port.
Does NOT depend on ``idapro`` — purely manages subprocesses.
"""

from __future__ import annotations

import atexit
import http.client
import json
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from typing import TYPE_CHECKING

from .health import is_process_alive, ping_instance, query_binary_metadata

if TYPE_CHECKING:
    from .registry import InstanceRegistry

# Default timeout (seconds) waiting for worker to become ready.
_READY_TIMEOUT = 120
# Poll interval while waiting for worker readiness.
_READY_POLL_INTERVAL = 0.5
# A worker can answer the readiness ping a fraction of a second before its
# resource endpoint is ready.  That matters for IDB inputs: their file name is
# not necessarily the original module name, so registering the lexical `.i64`
# or `.idb` name makes every later router identity check fail.
_IDB_METADATA_QUERY_ATTEMPTS = 4
_IDB_METADATA_QUERY_INTERVAL = 0.25
_IDB_SUFFIXES = frozenset({".i64", ".idb"})
_WORKER_SHUTDOWN_METHOD = "ida-multi-mcp/shutdown"
_WORKER_SHUTDOWN_TOKEN_ENV = "IDA_MULTI_MCP_WORKER_SHUTDOWN_TOKEN"
_WORKER_SHUTDOWN_TIMEOUT = 60

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
        with open(cfg_path, "r", encoding="utf-8") as f:
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
    family = socket.AF_INET6 if host == "::1" else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def _preferred_loopback_host() -> str:
    """Return the most reliable local transport for a managed worker.

    Some Windows network-filter stacks intermittently reset IPv4 loopback
    connections even though the server successfully handled the request.
    Prefer the independent IPv6 loopback path when it can actually bind; keep
    the historical IPv4 endpoint everywhere else and when IPv6 is disabled.
    """
    if sys.platform != "win32":
        return "127.0.0.1"
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
            probe.bind(("::1", 0))
    except OSError:
        return "127.0.0.1"
    return "::1"


def _request_worker_shutdown(
    host: str,
    port: int,
    token: str,
    timeout: float = 10.0,
) -> bool:
    """Request one authenticated, graceful worker shutdown over loopback."""
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": _WORKER_SHUTDOWN_METHOD,
            "params": {"token": token},
            "id": 1,
        }
    )
    try:
        connection.request(
            "POST",
            "/mcp",
            body,
            {"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        return response.status == 200 and payload.get("result", {}).get("accepted") is True
    except Exception:
        return False
    finally:
        connection.close()


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
        self._shutdown_tokens: dict[str, str] = {}
        # Register cleanup on interpreter shutdown
        atexit.register(self.close_all_sessions)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def spawn_session(
        self,
        input_path: str,
        *,
        host: str | None = None,
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

        selected_host = host or _preferred_loopback_host()
        port = _find_free_port(selected_host)

        shutdown_token = secrets.token_urlsafe(32)
        cmd = [
            self.python_executable,
            "-m", "ida_multi_mcp.idalib_worker",
            "--host", selected_host,
            "--port", str(port),
        ]
        if unsafe:
            cmd.append("--unsafe")
        cmd.append(resolved_path)

        creation_flags = 0
        if sys.platform == "win32":
            # NEW_PROCESS_GROUP lets us send CTRL_BREAK_EVENT for graceful
            # shutdown (TerminateProcess cannot be caught to close the IDB).
            creation_flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP

        try:
            # stdin MUST be DEVNULL: when the MCP server runs as a stdio child
            # of an MCP client (Claude, Trae, Cursor, etc.), its stdin is the
            # MCP protocol pipe. Without stdin=DEVNULL the worker inherits
            # this pipe, and idalib.dll's initialization blocks reading from
            # it — the worker never reaches serve(), causing the persistent
            # "did not become ready" timeout.
            # stdout=DEVNULL discards IDA's analysis output.
            # stderr=PIPE is drained by a background thread (see below) to
            # prevent pipe buffer deadlock.
            worker_env = os.environ.copy()
            worker_env[_WORKER_SHUTDOWN_TOKEN_ENV] = shutdown_token
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                creationflags=creation_flags,
                env=worker_env,
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

        # Drain stderr in background to prevent pipe buffer deadlock.
        # Without this, IDA's analysis logs fill the OS pipe and the worker
        # blocks forever on stderr.write(), never starting its HTTP server.
        # Bounded deque so a chatty worker cannot grow memory without limit.
        stderr_chunks: deque[bytes] = deque(maxlen=64)

        def _drain_stderr():
            try:
                for chunk in iter(lambda: proc.stderr.read(4096), b""):
                    stderr_chunks.append(chunk)
            except Exception:
                pass

        stderr_thread = threading.Thread(target=_drain_stderr, daemon=True)
        stderr_thread.start()

        # Wait for the worker to become ready.
        if not self._wait_for_ready(selected_host, port, proc, timeout):
            # Worker didn't come up — terminate first so its dying stderr is
            # captured by the drain thread, then collect it for diagnostics.
            self._terminate_gracefully(
                proc,
                host=selected_host,
                port=port,
                shutdown_token=shutdown_token,
            )
            stderr_thread.join(timeout=1)
            stderr_text = b"".join(stderr_chunks).decode(errors="replace")[-500:]
            return {
                "error": (
                    f"idalib worker did not become ready within {timeout}s. "
                    f"Last stderr: {stderr_text}"
                )
            }

        # Ask the worker for its canonical module name so the registry matches
        # what the metadata resource reports. A newly listening worker can
        # transiently reset this first resource request. Retry only for IDB
        # inputs, where falling back to the lexical database name would create
        # a permanently unroutable instance (foo.exe.i64 != foo.exe).
        is_idb_input = os.path.splitext(resolved_path)[1].casefold() in _IDB_SUFFIXES
        metadata = None
        module_name = None
        attempts = _IDB_METADATA_QUERY_ATTEMPTS if is_idb_input else 1
        for attempt in range(attempts):
            metadata = query_binary_metadata(selected_host, port, timeout=5.0)
            candidate = (metadata or {}).get("module") if metadata else None
            if isinstance(candidate, str) and candidate.strip():
                module_name = candidate.strip()
                break
            if proc.poll() is not None:
                break
            if attempt + 1 < attempts:
                time.sleep(_IDB_METADATA_QUERY_INTERVAL)

        if is_idb_input and module_name is None:
            self._terminate_gracefully(
                proc,
                host=selected_host,
                port=port,
                shutdown_token=shutdown_token,
            )
            stderr_thread.join(timeout=1)
            return {
                "error": (
                    "idalib worker became ready, but canonical IDB module metadata "
                    f"was unavailable after {attempts} attempts; worker stopped "
                    "without registering an ambiguous instance"
                )
            }

        binary_name = module_name or os.path.basename(resolved_path)
        instance_id = self.registry.register(
            pid=proc.pid,
            port=port,
            idb_path=resolved_path,
            host=selected_host,
            binary_name=binary_name,
            binary_path=resolved_path,
            type="idalib",
        )

        self._processes[instance_id] = proc
        self._shutdown_tokens[instance_id] = shutdown_token
        return {
            "instance_id": instance_id,
            "host": selected_host,
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

        # Terminate the subprocess, preferring a graceful shutdown so the
        # worker can close its IDB cleanly.
        info = self.registry.get_instance(instance_id)
        token = self._shutdown_tokens.get(instance_id)
        self._terminate_gracefully(
            proc,
            host=info.get("host") if info else None,
            port=info.get("port") if info else None,
            shutdown_token=token,
        )

        del self._processes[instance_id]
        self._shutdown_tokens.pop(instance_id, None)
        self.registry.unregister(instance_id)
        return {"ok": True}

    @staticmethod
    def _terminate_gracefully(
        proc: subprocess.Popen,
        *,
        host: str | None = None,
        port: int | None = None,
        shutdown_token: str | None = None,
    ) -> None:
        """Ask the worker to shut down cleanly, then force-kill if it lingers.

        On Windows, ``proc.terminate()`` maps to TerminateProcess, which the
        worker cannot intercept to close its IDB. Send CTRL_BREAK_EVENT first
        (handled as SIGBREAK by the worker) and fall back to terminate/kill.
        On POSIX, SIGTERM already triggers the worker's clean-shutdown handler.
        """
        if proc.poll() is not None:
            return

        # Preferred path: an authenticated loopback request makes the HTTP
        # server return normally, so the worker can pack and close its IDB.
        # Windows CREATE_NO_WINDOW workers cannot reliably receive CTRL_BREAK.
        if host and port and shutdown_token:
            requested = _request_worker_shutdown(host, port, shutdown_token)
            try:
                proc.wait(timeout=_WORKER_SHUTDOWN_TIMEOUT if requested else 5)
                return
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass

        # Step 1: graceful request (CTRL_BREAK on Windows, SIGTERM on POSIX).
        try:
            if sys.platform == "win32":
                import signal as _signal
                proc.send_signal(_signal.CTRL_BREAK_EVENT)
            else:
                proc.terminate()
            proc.wait(timeout=10)
            return
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        # Step 2 (Windows only): TerminateProcess, since CTRL_BREAK may be
        # ignored. On POSIX the graceful step already sent SIGTERM, so go
        # straight to the hard kill below instead of repeating terminate().
        if sys.platform == "win32":
            try:
                proc.terminate()
                proc.wait(timeout=5)
                return
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass

        # Step 3: hard kill.
        try:
            proc.kill()
        except Exception:
            pass

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
                self._shutdown_tokens.pop(iid, None)
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
