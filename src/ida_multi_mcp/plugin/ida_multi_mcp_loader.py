"""IDA plugin loader for ida-multi-mcp.

This file is placed in the IDA plugins directory (e.g., ~/.idapro/plugins/).
It bootstraps the actual plugin from the installed ida-multi-mcp package.

Installation:
  pip install ida-multi-mcp
  ida-multi-mcp install
"""

import sys
import importlib


def PLUGIN_ENTRY():
    """IDA plugin entry point — delegates to ida_multi_mcp.plugin."""
    try:
        # Try importing from the installed package first
        mod = importlib.import_module("ida_multi_mcp.plugin.ida_multi_mcp")
        return mod.PLUGIN_ENTRY()
    except ImportError:
        # Fallback: try adding common paths
        import os
        from pathlib import Path

        # Try site-packages via pip install location
        for path in [
            # pip install --user location
            str(Path.home() / ".local" / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"),
            # Windows pip install location
            str(Path.home() / "AppData" / "Roaming" / "Python" / f"Python{sys.version_info.major}{sys.version_info.minor}" / "site-packages"),
        ]:
            if os.path.isdir(path) and path not in sys.path:
                sys.path.insert(0, path)

        try:
            mod = importlib.import_module("ida_multi_mcp.plugin.ida_multi_mcp")
            return mod.PLUGIN_ENTRY()
        except ImportError as e:
            print(f"[ida-multi-mcp] ERROR: Could not load plugin: {e}")
            print("[ida-multi-mcp] Install with: pip install ida-multi-mcp")
            # Return a dummy plugin that does nothing
            import idaapi

            class _DummyPlugin(idaapi.plugin_t):
                flags = idaapi.PLUGIN_SKIP
                comment = "ida-multi-mcp (not installed)"
                help = ""
                wanted_name = "ida-multi-mcp"
                wanted_hotkey = ""

                def init(self):
                    return idaapi.PLUGIN_SKIP

                def run(self, arg):
                    pass

                def term(self):
                    pass

            return _DummyPlugin()
