"""IDA Pro plugin for ida-multi-mcp.

Auto-registers with the central registry and runs an MCP HTTP server.
"""

import os
import sys
import threading
import time
from pathlib import Path

import idaapi
import idc

# Add vendor directory to path for zeromcp
_vendor_dir = Path(__file__).parent.parent / "vendor"
if str(_vendor_dir) not in sys.path:
    sys.path.insert(0, str(_vendor_dir))

from zeromcp.mcp import McpServer

# Import registration functions
from .registration import (
    register_instance,
    unregister_instance,
    update_heartbeat,
    get_binary_metadata
)


class IdaMultiMcpPlugin(idaapi.plugin_t):
    """IDA plugin that registers with the multi-instance MCP server."""

    flags = idaapi.PLUGIN_FIX  # Auto-load on startup
    comment = "Multi-instance MCP server plugin"
    help = "Registers this IDA instance with ida-multi-mcp"
    wanted_name = "ida-multi-mcp"
    wanted_hotkey = ""

    def __init__(self):
        """Initialize the plugin."""
        super().__init__()
        self.mcp_server = None
        self.stop_event = threading.Event()
        self.heartbeat_thread = None
        self.instance_id = None
        self.server_port = None
        self.hooks_installed = False

    def init(self):
        """Plugin initialization."""
        print("[ida-multi-mcp] Plugin loaded")

        # Don't start server yet - wait for database to be ready
        # Install hooks to detect when database is ready
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
        """Start the MCP server and register with the central registry."""
        if self.mcp_server and self.mcp_server._running:
            print("[ida-multi-mcp] Server already running")
            return

        print("[ida-multi-mcp] Starting MCP server...")

        # Get binary metadata
        metadata = get_binary_metadata()

        # Create MCP server instance
        self.mcp_server = McpServer(
            name="ida-multi-mcp",
            version="1.0.0"
        )

        # TODO: Register MCP tools/resources here
        # For now, we have a minimal server that just handles the protocol

        try:
            # Start HTTP server on port 0 (OS-assigned)
            # The serve() method binds synchronously, so we can get the port immediately
            self.mcp_server.serve(
                host="127.0.0.1",
                port=0,
                background=True
            )

            # Get the actual port assigned by the OS
            if self.mcp_server._http_server:
                self.server_port = self.mcp_server._http_server.server_address[1]
                print(f"[ida-multi-mcp] Server listening on port {self.server_port}")

                # Register with central registry
                self.instance_id = register_instance(
                    pid=os.getpid(),
                    port=self.server_port,
                    idb_path=metadata["idb_path"],
                    binary_path=metadata["binary_path"],
                    binary_name=metadata["binary_name"],
                    arch=metadata["arch"],
                    host="127.0.0.1"
                )

                print(f"[ida-multi-mcp] Registered as instance '{self.instance_id}'")

                # Start heartbeat thread
                self.heartbeat_thread = threading.Thread(
                    target=self._heartbeat_loop,
                    daemon=True
                )
                self.heartbeat_thread.start()

            else:
                print("[ida-multi-mcp] Failed to get server port")

        except Exception as e:
            print(f"[ida-multi-mcp] Failed to start server: {e}")
            import traceback
            traceback.print_exc()

    def _heartbeat_loop(self):
        """Send periodic heartbeats to the central registry."""
        while not self.stop_event.is_set():
            try:
                if self.instance_id:
                    update_heartbeat(self.instance_id)
            except Exception as e:
                print(f"[ida-multi-mcp] Heartbeat error: {e}")

            # Wait 60 seconds or until stop event
            self.stop_event.wait(timeout=60.0)

    def stop_server(self):
        """Stop the server and unregister from the central registry."""
        print("[ida-multi-mcp] Stopping server...")

        # Stop heartbeat
        self.stop_event.set()
        if self.heartbeat_thread:
            self.heartbeat_thread.join(timeout=2.0)

        # Unregister from central registry
        if self.instance_id:
            try:
                unregister_instance(self.instance_id)
            except Exception as e:
                print(f"[ida-multi-mcp] Failed to unregister: {e}")

        # Stop MCP server
        if self.mcp_server:
            self.mcp_server.stop()
            self.mcp_server = None

    def run(self, arg):
        """Plugin run method (called by hotkey, not used here)."""
        pass

    def term(self):
        """Plugin termination."""
        print("[ida-multi-mcp] Plugin terminating")

        # Unhook
        if self.hooks_installed:
            self.idb_hooks.unhook()
            self.ui_hooks.unhook()

        # Stop server
        self.stop_server()


class IdbHooks(idaapi.IDB_Hooks):
    """IDB hooks for detecting database close."""

    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def closebase(self):
        """Called when database is closed."""
        print("[ida-multi-mcp] Database closing")
        self.plugin.stop_server()
        return 0


class UiHooks(idaapi.UI_Hooks):
    """UI hooks for detecting database open."""

    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def database_inited(self, is_new_database, idc_script):
        """Called when database is initialized."""
        print("[ida-multi-mcp] Database initialized")
        self.plugin.start_server()
        return 0


def PLUGIN_ENTRY():
    """Plugin entry point."""
    return IdaMultiMcpPlugin()
