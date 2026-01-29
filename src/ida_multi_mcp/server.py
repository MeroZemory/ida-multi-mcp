"""MCP server for ida-multi-mcp.

Aggregates tools from multiple IDA instances and routes requests.
"""

import sys
import json
from typing import Any

from .vendor.zeromcp import McpServer
from .registry import InstanceRegistry
from .router import InstanceRouter
from .health import cleanup_stale_instances
from .tools import management


class IdaMultiMcpServer:
    """MCP server that aggregates multiple IDA Pro instances.

    Discovers tools dynamically from registered IDA instances and routes
    tool calls to the appropriate instance.
    """

    def __init__(self, registry_path: str | None = None):
        """Initialize the multi-instance MCP server.

        Args:
            registry_path: Path to registry JSON file (default: ~/.ida-mcp/instances.json)
        """
        self.registry = InstanceRegistry(registry_path)
        self.router = InstanceRouter(self.registry)
        self.server = McpServer("ida-multi-mcp", version="1.0.0")

        # Tool cache
        self._tool_cache: dict[str, dict] = {}
        self._cache_valid = False

        # Set up management tools
        management.set_registry(self.registry)
        management.set_refresh_callback(self._refresh_tools)

        # Register handlers
        self._register_handlers()

    def _register_handlers(self):
        """Register MCP protocol handlers."""

        # Override tools/list to return cached tools
        original_tools_list = self.server._mcp_tools_list

        def custom_tools_list(_meta: dict | None = None) -> dict:
            """List all available tools (management + IDA tools)."""
            # Ensure tool cache is fresh
            if not self._cache_valid:
                self._refresh_tools()

            # Return all cached tools
            return {"tools": list(self._tool_cache.values())}

        self.server.registry.methods["tools/list"] = custom_tools_list

        # Override tools/call to route requests
        def custom_tools_call(name: str, arguments: dict[str, Any] | None = None, _meta: dict | None = None) -> dict:
            """Route tool call to appropriate handler."""
            if arguments is None:
                arguments = {}

            # Management tools (local)
            if name == "list_instances":
                result = management.list_instances()
                return {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                    "isError": False
                }

            elif name == "get_active_instance":
                result = management.get_active_instance()
                return {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                    "isError": False
                }

            elif name == "set_active_instance":
                result = management.set_active_instance(arguments.get("instance_id", ""))
                return {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                    "isError": False
                }

            elif name == "refresh_tools":
                result = management.refresh_tools()
                return {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                    "isError": False
                }

            # IDA tools (proxied)
            else:
                result = self.router.route_request("tools/call", {
                    "name": name,
                    "arguments": arguments
                })

                # Format response
                if "error" in result:
                    return {
                        "content": [{"type": "text", "text": f"Error: {json.dumps(result, indent=2)}"}],
                        "isError": True
                    }
                else:
                    return {
                        "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                        "isError": False
                    }

        self.server.registry.methods["tools/call"] = custom_tools_call

    def _refresh_tools(self) -> int:
        """Refresh tool cache from IDA instances.

        Returns:
            Number of tools discovered
        """
        self._tool_cache = {}

        # Add management tools
        self._tool_cache["list_instances"] = {
            "name": "list_instances",
            "description": "List all registered IDA Pro instances with their metadata.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }

        self._tool_cache["get_active_instance"] = {
            "name": "get_active_instance",
            "description": "Get the currently active IDA Pro instance.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }

        self._tool_cache["set_active_instance"] = {
            "name": "set_active_instance",
            "description": "Set the active IDA Pro instance for subsequent tool calls.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "instance_id": {
                        "type": "string",
                        "description": "Instance ID to set as active (e.g., 'k7m2')"
                    }
                },
                "required": ["instance_id"]
            }
        }

        self._tool_cache["refresh_tools"] = {
            "name": "refresh_tools",
            "description": "Re-discover tools from IDA Pro instances.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }

        # Discover IDA tools from active instance
        active_id = self.registry.get_active()
        if active_id:
            instance_info = self.registry.get_instance(active_id)
            if instance_info:
                ida_tools = self._discover_ida_tools(instance_info)
                for tool in ida_tools:
                    # Inject instance_id parameter
                    tool_schema = tool.copy()
                    input_schema = tool_schema.get("inputSchema", {})
                    properties = input_schema.get("properties", {})

                    # Add instance_id parameter (optional)
                    properties["instance_id"] = {
                        "type": "string",
                        "description": "Target IDA instance ID (defaults to active instance)"
                    }

                    input_schema["properties"] = properties
                    tool_schema["inputSchema"] = input_schema

                    self._tool_cache[tool["name"]] = tool_schema

        self._cache_valid = True
        return len(self._tool_cache)

    def _discover_ida_tools(self, instance_info: dict) -> list[dict]:
        """Discover tools from an IDA instance.

        Args:
            instance_info: Instance metadata

        Returns:
            List of tool schemas
        """
        import http.client

        host = instance_info.get("host", "127.0.0.1")
        port = instance_info.get("port")

        try:
            conn = http.client.HTTPConnection(host, port, timeout=10.0)
            request_body = json.dumps({
                "jsonrpc": "2.0",
                "method": "tools/list",
                "id": 1
            })
            conn.request("POST", "/mcp", request_body, {"Content-Type": "application/json"})
            response = conn.getresponse()
            response_data = json.loads(response.read().decode())
            conn.close()

            if "result" in response_data:
                tools = response_data["result"].get("tools", [])
                return tools
            else:
                return []

        except Exception as e:
            print(f"[ida-multi-mcp] Failed to discover tools from instance: {e}", file=sys.stderr)
            return []

    def run(self):
        """Run the MCP server with stdio transport."""
        # Clean up stale instances on startup
        removed = cleanup_stale_instances(self.registry)
        if removed:
            print(f"[ida-multi-mcp] Cleaned up {len(removed)} stale instances on startup",
                  file=sys.stderr)

        # Refresh tools
        self._refresh_tools()
        print(f"[ida-multi-mcp] Server starting with {len(self._tool_cache)} tools",
              file=sys.stderr)

        # Run server with stdio transport
        self.server.stdio()


def serve(registry_path: str | None = None):
    """Start the ida-multi-mcp server.

    Args:
        registry_path: Optional custom registry path
    """
    server = IdaMultiMcpServer(registry_path)
    server.run()
