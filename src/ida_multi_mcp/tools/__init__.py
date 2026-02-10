"""Management tools package for ida-multi-mcp.

These tools are implemented directly by the MCP server and handle:
- Instance listing and discovery
- Tool schema refresh
"""

from .management import (
    list_instances,
    refresh_tools,
    set_registry,
    set_refresh_callback,
)

__all__ = [
    "list_instances",
    "refresh_tools",
    "set_registry",
    "set_refresh_callback",
]
