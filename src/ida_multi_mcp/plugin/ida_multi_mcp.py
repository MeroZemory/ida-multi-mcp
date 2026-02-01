"""IDA Pro plugin for ida-multi-mcp.

Replaces the original ida_mcp.py plugin loader. Does everything the original
does (starts MCP HTTP server with all 71+ tools) PLUS auto-registers with
the central instance registry for multi-instance support.

The ida_mcp package is bundled with ida-multi-mcp and provides all IDA tools.
"""

import os
import sys
import threading
from pathlib import Path

import idaapi

# Import registration functions (add parent to path for ida_multi_mcp imports)
_pkg_dir = str(Path(__file__).parent.parent.parent)
if _pkg_dir not in sys.path:
    sys.path.insert(0, _pkg_dir)

from ida_multi_mcp.plugin.registration import (
    register_instance,
    unregister_instance,
    update_heartbeat,
    get_binary_metadata,
)


def _load_ida_mcp():
    """Load the ida_mcp package (bundled with ida-multi-mcp).

    Returns:
        Tuple of (MCP_SERVER, IdaMcpHttpRequestHandler, init_caches)

    Raises:
        ImportError: If ida_mcp package is not available
    """
    from ida_multi_mcp.ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches
    return MCP_SERVER, IdaMcpHttpRequestHandler, init_caches


class IdaMultiMcpPlugin(idaapi.plugin_t):
    """IDA plugin that runs MCP server and registers with central registry.

    This plugin replaces the original ida_mcp.py loader. It:
    1. Loads the ida_mcp package (all 71+ tools and 24 resources)
    2. Starts an HTTP server on an OS-assigned port (port 0)
    3. Registers with the central instance registry (~/.ida-mcp/instances.json)
    4. Sends periodic heartbeats
    5. Unregisters on database close or plugin termination
    """

    flags = idaapi.PLUGIN_FIX  # Auto-load on startup
    comment = "Multi-instance MCP server plugin"
    help = "Runs MCP server and registers with ida-multi-mcp"
    wanted_name = "ida-multi-mcp"
    wanted_hotkey = ""

    def __init__(self):
        super().__init__()
        self.mcp_server = None
        self.stop_event = threading.Event()
        self.heartbeat_thread = None
        self.instance_id = None
        self.server_port = None
        self.hooks_installed = False

    def init(self):
        """Plugin initialization — install hooks, start if DB already open."""
        print("[ida-multi-mcp] Plugin loaded (PLUGIN_FIX)")

        # Install hooks for database lifecycle events
        self.idb_hooks = IdbHooks(self)
        self.ui_hooks = UiHooks(self)
        self.idb_hooks.hook()
        self.ui_hooks.hook()
        self.hooks_installed = True

        # If database is already open, start immediately
        if idaapi.get_input_file_path():
            self.start_server()

        return idaapi.PLUGIN_KEEP

    def start_server(self):
        """Start the MCP server with all IDA tools and register with registry."""
        if self.mcp_server and self.mcp_server._running:
            print("[ida-multi-mcp] Server already running")
            return

        print("[ida-multi-mcp] Starting MCP server...")

        # Get binary metadata for registration
        metadata = get_binary_metadata()

        try:
            # Load the ida_mcp package (provides MCP_SERVER with 71+ tools)
            mcp_server, handler_class, init_caches = _load_ida_mcp()
        except ImportError as e:
            print(f"[ida-multi-mcp] ERROR: ida_mcp package failed to load: {e}")
            print("[ida-multi-mcp] This indicates a broken installation. Reinstall ida-multi-mcp.")
            return

        try:
            # Initialize caches (function cache, etc.)
            init_caches()
        except Exception as e:
            print(f"[ida-multi-mcp] Cache init warning: {e}")

        try:
            # Start HTTP server on port 0 (OS-assigned) — key difference from original!
            mcp_server.serve(
                host="127.0.0.1",
                port=0,
                background=True,
                request_handler=handler_class,
            )
            self.mcp_server = mcp_server

            # Get the actual port assigned by the OS
            if self.mcp_server._http_server:
                self.server_port = self.mcp_server._http_server.server_address[1]
                print(f"[ida-multi-mcp] Server listening on 127.0.0.1:{self.server_port}")

                # Update download base URL to reflect the actual dynamic port
                from ida_multi_mcp.ida_mcp.rpc import set_download_base_url
                set_download_base_url(f"http://127.0.0.1:{self.server_port}")

                # Register with central instance registry
                self.instance_id = register_instance(
                    pid=os.getpid(),
                    port=self.server_port,
                    idb_path=metadata["idb_path"],
                    binary_path=metadata["binary_path"],
                    binary_name=metadata["binary_name"],
                    arch=metadata["arch"],
                    host="127.0.0.1",
                )
                print(f"[ida-multi-mcp] Registered as instance '{self.instance_id}' "
                      f"({metadata['binary_name']})")

                # Start heartbeat thread
                self.stop_event.clear()
                self.heartbeat_thread = threading.Thread(
                    target=self._heartbeat_loop,
                    daemon=True,
                )
                self.heartbeat_thread.start()
            else:
                print("[ida-multi-mcp] Failed to get server port")

        except OSError as e:
            if e.errno in (48, 98, 10048):  # Address already in use
                print(f"[ida-multi-mcp] Error: Port binding failed")
            else:
                print(f"[ida-multi-mcp] Failed to start server: {e}")
                import traceback
                traceback.print_exc()

    def _heartbeat_loop(self):
        """Send periodic heartbeats to the central registry (every 60s)."""
        while not self.stop_event.is_set():
            try:
                if self.instance_id:
                    update_heartbeat(self.instance_id)
            except Exception as e:
                print(f"[ida-multi-mcp] Heartbeat error: {e}")
            self.stop_event.wait(timeout=60.0)

    def stop_server(self):
        """Stop the MCP server and unregister from the central registry."""
        if not self.mcp_server:
            return

        print("[ida-multi-mcp] Stopping server...")

        # Stop heartbeat
        self.stop_event.set()
        if self.heartbeat_thread:
            self.heartbeat_thread.join(timeout=2.0)
            self.heartbeat_thread = None

        # Unregister from central registry
        if self.instance_id:
            try:
                unregister_instance(self.instance_id)
                print(f"[ida-multi-mcp] Unregistered instance '{self.instance_id}'")
            except Exception as e:
                print(f"[ida-multi-mcp] Failed to unregister: {e}")
            self.instance_id = None

        # Stop MCP HTTP server
        if self.mcp_server:
            self.mcp_server.stop()
            self.mcp_server = None

        self.server_port = None

    def run(self, arg):
        """Toggle server on/off when activated via menu or hotkey."""
        if self.mcp_server and self.mcp_server._running:
            self.stop_server()
        else:
            self.start_server()

    def term(self):
        """Plugin termination — cleanup everything."""
        print("[ida-multi-mcp] Plugin terminating")

        if self.hooks_installed:
            self.idb_hooks.unhook()
            self.ui_hooks.unhook()
            self.hooks_installed = False

        self.stop_server()


class IdbHooks(idaapi.IDB_Hooks):
    """IDB hooks for detecting database close (binary change detection)."""

    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def closebase(self):
        """Called when database is being closed — stop server and unregister."""
        print("[ida-multi-mcp] Database closing")
        self.plugin.stop_server()
        return 0


class UiHooks(idaapi.UI_Hooks):
    """UI hooks for detecting database initialization."""

    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def database_inited(self, is_new_database, idc_script):
        """Called when a new database is initialized — start server."""
        print("[ida-multi-mcp] Database initialized")
        self.plugin.start_server()
        return 0


def PLUGIN_ENTRY():
    """IDA plugin entry point."""
    return IdaMultiMcpPlugin()
