"""Management tools package for ida-multi-mcp.

These tools are implemented directly by the MCP server and handle:
- Instance listing and discovery
- Active instance switching
- Tool schema refresh
"""

from .management import (
    list_instances,
    get_active_instance,
    set_active_instance,
    refresh_tools,
    set_registry,
    set_refresh_callback,
)

__all__ = [
    "list_instances",
    "get_active_instance",
    "set_active_instance",
    "refresh_tools",
    "set_registry",
    "set_refresh_callback",
]
