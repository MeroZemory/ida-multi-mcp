"""Headless idalib worker subprocess.

This module is launched by :class:`IdalibManager` as a child process.
It opens one binary via ``idapro``, registers all MCP tools from
:mod:`ida_multi_mcp.ida_mcp`, then serves them over HTTP JSON-RPC on
the given port.

Usage::

    python -m ida_multi_mcp.idalib_worker --host 127.0.0.1 --port 12345 /path/to/binary

**This is the only module that requires the ``idapro`` package.**
"""

from __future__ import annotations

import argparse
import atexit
import logging
import os
import secrets
import signal
import sys
import threading
from pathlib import Path


def _http_origin(host: str, port: int) -> str:
    display_host = f"[{host}]" if ":" in host else host
    return f"http://{display_host}:{port}"


logger = logging.getLogger("idalib-worker")
_WORKER_SHUTDOWN_METHOD = "ida-multi-mcp/shutdown"
_WORKER_SHUTDOWN_TOKEN_ENV = "IDA_MULTI_MCP_WORKER_SHUTDOWN_TOKEN"


def _close_database_packed(idapro_module) -> bool:
    """Persist one packed IDB and close without recreating loose work files.

    Returns ``True`` when the explicit packed save succeeded. If it cannot be
    completed, fall back to idapro's normal save-on-close behavior so edits are
    not discarded merely to keep the directory tidy.
    """
    try:
        import ida_loader

        current_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        flags = ida_loader.DBFL_KILL | ida_loader.DBFL_COMP
        if current_path and ida_loader.save_database(current_path, flags):
            idapro_module.close_database(save=False)
            return True
    except Exception as exc:
        logger.warning("Packed IDB save failed; using normal close: %s", exc)

    idapro_module.close_database(save=True)
    return False


def _register_shutdown_rpc(mcp_server, expected_token: str) -> None:
    """Register a manager-only RPC that lets the server exit cleanly."""
    def _shutdown(token: str) -> dict:
        if not secrets.compare_digest(token, expected_token):
            raise PermissionError("invalid worker shutdown token")
        threading.Thread(target=mcp_server.stop, daemon=True).start()
        return {"accepted": True}

    mcp_server.registry.method(_shutdown, name=_WORKER_SHUTDOWN_METHOD)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Headless idalib MCP worker (one binary per process)"
    )
    parser.add_argument("--host", type=str, default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--unsafe", action="store_true",
                        help="Enable unsafe / destructive tools")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("input_path", type=Path, help="Binary or IDB to open")

    args = parser.parse_args()

    # --- Configure logging ---------------------------------------------------
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="[idalib-worker %(process)d] %(levelname)s %(message)s",
    )

    # --- Validate input path before heavy imports ----------------------------
    if not args.input_path.exists():
        logger.error("File not found: %s", args.input_path)
        sys.exit(1)

    # --- Initialize idalib (must happen before any ida_* import) -------------
    try:
        import idapro  # noqa: F401 — side-effect: initialises headless IDA
    except ImportError:
        logger.error(
            "The 'idapro' package is not installed in this Python (%s). "
            "Install it or point --idalib-python at the correct interpreter.",
            sys.executable,
        )
        sys.exit(1)

    # Suppress console noise unless verbose
    idapro.enable_console_messages(args.verbose)

    # --- Open the database ---------------------------------------------------
    import ida_auto

    resolved = str(args.input_path.resolve())
    logger.info("Opening database: %s", resolved)

    # idapro.open_database opens (or creates) an IDB for the given binary.
    try:
        idapro.open_database(resolved, run_auto_analysis=True)
    except Exception as exc:
        logger.error("Failed to open database: %s", exc)
        sys.exit(1)

    logger.info("Waiting for auto-analysis to complete...")
    ida_auto.auto_wait()
    logger.info("Auto-analysis done.")

    # --- Import tool package (triggers @tool registration) -------------------
    skipped_methods = {
        value.strip()
        for value in os.environ.get("IDA_MCP_LOG_SKIP_METHODS", "tools/call").split(",")
        if value.strip()
    }
    skipped_methods.add(_WORKER_SHUTDOWN_METHOD)
    os.environ["IDA_MCP_LOG_SKIP_METHODS"] = ",".join(sorted(skipped_methods))
    from ida_multi_mcp.ida_mcp import MCP_SERVER, MCP_UNSAFE  # noqa: E402

    shutdown_token = os.environ.pop(_WORKER_SHUTDOWN_TOKEN_ENV, "")
    if shutdown_token:
        _register_shutdown_rpc(MCP_SERVER, shutdown_token)

    # Gate unsafe tools unless --unsafe.
    if not args.unsafe:
        for name in list(MCP_UNSAFE):
            MCP_SERVER.tools.methods.pop(name, None)
        if MCP_UNSAFE:
            logger.info("Unsafe tools disabled (start with --unsafe to enable)")

    # --- Clean shutdown -------------------------------------------------------
    # close_database persists the IDB and releases the idalib lock. Register it
    # via atexit so it also runs on normal interpreter exit. On Windows,
    # proc.terminate() maps to TerminateProcess, which kills the process without
    # delivering SIGTERM — so the signal handler alone is not enough there.
    _closed = False

    def _close_db_once():
        nonlocal _closed
        if _closed:
            return
        _closed = True
        try:
            _close_database_packed(idapro)
        except Exception:
            pass

    atexit.register(_close_db_once)

    def _shutdown(signum, frame):
        logger.info("Received signal %s — shutting down...", signum)
        _close_db_once()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    # Windows: the manager sends CTRL_BREAK_EVENT for graceful shutdown,
    # which arrives as SIGBREAK. TerminateProcess (proc.terminate) cannot be
    # caught, so CTRL_BREAK is the only way to close the IDB cleanly there.
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, _shutdown)

    # --- Serve ---------------------------------------------------------------
    # Truncated tool output hands back a download URL, and only this process can
    # serve it — the cache lives here, in rpc's module state. Without this the URL
    # keeps rpc's default (port 13337), which nothing listens on.
    from ida_multi_mcp.ida_mcp.rpc import set_download_base_url
    set_download_base_url(_http_origin(args.host, args.port))

    logger.info("Serving on %s:%d", args.host, args.port)
    MCP_SERVER.serve(host=args.host, port=args.port, background=False)
    _close_db_once()


if __name__ == "__main__":
    main()
