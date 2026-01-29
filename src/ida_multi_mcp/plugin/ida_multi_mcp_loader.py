"""IDA plugin loader for ida-multi-mcp.

This file should be placed in the IDA plugins directory.
It loads the actual plugin from the installed package.
"""

import sys
from pathlib import Path

# Add the plugin directory to sys.path
# This allows importing from the ida_multi_mcp package
plugin_dir = Path(__file__).parent
src_dir = plugin_dir.parent.parent

if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

# Now import the plugin entry point
from ida_multi_mcp.plugin import PLUGIN_ENTRY

# IDA will call this function to load the plugin
# Re-export it at module level
__all__ = ["PLUGIN_ENTRY"]
