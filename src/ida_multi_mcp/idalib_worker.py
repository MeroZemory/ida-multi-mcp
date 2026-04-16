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
import logging
import signal
import sys
from pathlib import Path

logger = logging.getLogger("idalib-worker")


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
    from ida_multi_mcp.ida_mcp import MCP_SERVER, MCP_UNSAFE  # noqa: E402

    # Gate unsafe tools unless --unsafe.
    if not args.unsafe:
        for name in list(MCP_UNSAFE):
            MCP_SERVER.tools.methods.pop(name, None)
        if MCP_UNSAFE:
            logger.info("Unsafe tools disabled (start with --unsafe to enable)")

    # --- Signal handling for clean shutdown -----------------------------------
    def _shutdown(signum, frame):
        logger.info("Received signal %s — shutting down...", signum)
        try:
            idapro.close_database()
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # --- Serve ---------------------------------------------------------------
    logger.info("Serving on %s:%d", args.host, args.port)
    MCP_SERVER.serve(host=args.host, port=args.port, background=False)


if __name__ == "__main__":
    main()
