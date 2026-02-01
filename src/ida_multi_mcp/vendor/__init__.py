"""Vendored dependencies for ida-multi-mcp.

This package contains vendored third-party code to minimize external dependencies
and ensure version compatibility.

Vendored packages:
- zeromcp 1.3.0: Minimal MCP server implementation with stdio transport
  Used by the proxy-side MCP server in server.py for stdio communication.
  Source: https://github.com/mrexodia/ida-pro-mcp

Note: The full ida_mcp package has been absorbed into ida_multi_mcp.ida_mcp
(not in vendor/). This provides the core MCP protocol implementation and
IDA Pro integration.
"""
