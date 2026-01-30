"""MCP server for ida-multi-mcp.

Aggregates tools from multiple IDA instances and routes requests.
"""

import os
import re
import sys
import json
from typing import Any

from .vendor.zeromcp import McpServer
from .registry import InstanceRegistry
from .router import InstanceRouter
from .health import cleanup_stale_instances
from .tools import management
from .cache import get_cache, DEFAULT_MAX_OUTPUT_CHARS


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

            elif name == "get_cached_output":
                cache = get_cache()
                cache_id = arguments.get("cache_id", "")
                offset = arguments.get("offset", 0)
                size = arguments.get("size", DEFAULT_MAX_OUTPUT_CHARS)

                try:
                    result = cache.get(cache_id, offset, size)
                    return {
                        "content": [{"type": "text", "text": result["chunk"]}],
                        "structuredContent": result,
                        "isError": False
                    }
                except KeyError as e:
                    return {
                        "content": [{"type": "text", "text": f"Error: {str(e)}"}],
                        "isError": True
                    }

            elif name == "decompile_to_file":
                result = self._handle_decompile_to_file(arguments)
                return {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                    "isError": "error" in result
                }

            # IDA tools (proxied)
            else:
                # Extract max_output_chars if provided (0 = unlimited)
                max_output = arguments.pop("max_output_chars", DEFAULT_MAX_OUTPUT_CHARS)

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

                # Serialize result
                result_text = json.dumps(result, indent=2)
                total_chars = len(result_text)

                # Check if truncation needed (max_output=0 means unlimited)
                if max_output > 0 and total_chars > max_output:
                    # Cache full response
                    cache = get_cache()
                    instance_id = arguments.get("instance_id") or self.registry.get_active()
                    cache_id = cache.store(result_text, tool_name=name, instance_id=instance_id)

                    # Truncate for return
                    truncated_text = result_text[:max_output]

                    # Add truncation notice to text output
                    truncation_notice = (
                        f"\n\n--- TRUNCATED ---\n"
                        f"Showing {max_output:,} of {total_chars:,} chars ({total_chars - max_output:,} remaining)\n"
                        f"cache_id: {cache_id}\n"
                        f"To get more: get_cached_output(cache_id='{cache_id}', offset={max_output})"
                    )

                    return {
                        "content": [{"type": "text", "text": truncated_text + truncation_notice}],
                        "structuredContent": {
                            "result": result,
                            "_truncated": {
                                "cache_id": cache_id,
                                "total_chars": total_chars,
                                "returned_chars": max_output,
                                "remaining_chars": total_chars - max_output,
                                "hint": f"Use get_cached_output(cache_id='{cache_id}', offset={max_output}) to get more"
                            }
                        },
                        "isError": False
                    }
                else:
                    return {
                        "content": [{"type": "text", "text": result_text}],
                        "isError": False
                    }

        self.server.registry.methods["tools/call"] = custom_tools_call

    def _handle_decompile_to_file(self, arguments: dict) -> dict:
        """Decompile functions and save results to local files.

        Orchestrates list_funcs + decompile calls via IDA, writes to disk locally.
        """
        decompile_all = arguments.get("all", False)
        addrs = arguments.get("addrs", [])
        output_dir = arguments.get("output_dir", ".")
        mode = arguments.get("mode", "single")
        instance_id = arguments.get("instance_id")

        # Fetch all function addresses via paginated list_funcs calls
        if decompile_all:
            addrs = []
            offset = 0
            page_size = 500
            while True:
                list_result = self.router.route_request("tools/call", {
                    "name": "list_funcs",
                    "arguments": {
                        "queries": json.dumps({"count": page_size, "offset": offset}),
                        **({"instance_id": instance_id} if instance_id else {})
                    }
                })
                if "error" in list_result:
                    return {"error": f"Failed to list functions: {list_result['error']}"}

                try:
                    content = list_result.get("content", [])
                    if not content:
                        break
                    raw = json.loads(content[0]["text"])
                    if not isinstance(raw, list) or not raw:
                        break
                    page_data = raw[0].get("data", [])
                    if not page_data:
                        break
                    for f in page_data:
                        if "addr" in f:
                            addrs.append(f["addr"])
                    # Check if there are more pages
                    next_offset = raw[0].get("next_offset")
                    if next_offset is None or len(page_data) < page_size:
                        break
                    offset = next_offset
                except (json.JSONDecodeError, KeyError, IndexError, TypeError):
                    return {"error": "Failed to parse list_funcs response"}

            if not addrs:
                return {"error": "No functions found in binary"}

        if not addrs:
            return {"error": "No addresses provided. Pass 'addrs' array or set 'all' to true."}

        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

        success = 0
        failed = 0
        failed_addrs = []
        files_written = []

        def _call_decompile(addr: str) -> dict:
            """Call decompile and parse MCP content wrapper."""
            raw = self.router.route_request("tools/call", {
                "name": "decompile",
                "arguments": {
                    "addr": addr,
                    **({"instance_id": instance_id} if instance_id else {})
                }
            })
            # Router returns {"content": [{"text": "{\"addr\":...,\"code\":...}"}]}
            try:
                content = raw.get("content", [])
                if content:
                    return json.loads(content[0]["text"])
            except (json.JSONDecodeError, KeyError, IndexError, TypeError):
                pass
            return raw

        if mode == "merged":
            merged_path = os.path.join(output_dir, "decompiled.c")
            with open(merged_path, "w", encoding="utf-8") as f:
                for addr in addrs:
                    decomp = _call_decompile(addr)
                    code = decomp.get("code")
                    if code:
                        name = decomp.get("name", addr)
                        f.write(f"// {name} @ {addr}\n")
                        f.write(code)
                        f.write("\n\n")
                        success += 1
                    else:
                        failed += 1
                        failed_addrs.append(addr)
            files_written.append("decompiled.c")
        else:
            # single mode: one file per function
            for addr in addrs:
                decomp = _call_decompile(addr)
                code = decomp.get("code")
                if code:
                    name = decomp.get("name", addr)
                    safe_name = re.sub(r'[<>:"/\\|?*]', "_", name)
                    filename = f"{safe_name}.c"
                    filepath = os.path.join(output_dir, filename)
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(f"// {name} @ {addr}\n")
                        f.write(code)
                        f.write("\n")
                    files_written.append(filename)
                    success += 1
                else:
                    failed += 1
                    failed_addrs.append(addr)

        return {
            "output_dir": output_dir,
            "mode": mode,
            "total": len(addrs),
            "success": success,
            "failed": failed,
            "failed_addrs": failed_addrs[:50],
            "files": files_written[:50],
            "files_total": len(files_written),
        }

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

        self._tool_cache["get_cached_output"] = {
            "name": "get_cached_output",
            "description": "Retrieve cached output from a previous tool call that was truncated. Use this to get additional chunks of large responses.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cache_id": {
                        "type": "string",
                        "description": "Cache ID from the _truncated metadata of a previous response"
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Starting character position (default: 0)"
                    },
                    "size": {
                        "type": "integer",
                        "description": "Number of characters to return (default: 20000, 0 = all remaining)"
                    }
                },
                "required": ["cache_id"]
            }
        }

        self._tool_cache["decompile_to_file"] = {
            "name": "decompile_to_file",
            "description": "Decompile functions and save results directly to files on disk.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "addrs": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Function addresses to decompile (e.g. ['0x1800011A0', '0x180004B20']). Required unless 'all' is true."
                    },
                    "all": {
                        "type": "boolean",
                        "description": "Decompile all functions in the binary (default: false). Uses paginated queries to avoid blocking IDA. When true, 'addrs' is ignored."
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Directory to save decompiled files"
                    },
                    "mode": {
                        "type": "string",
                        "description": "Output mode: 'single' = one .c file per function (default), 'merged' = all in one file"
                    },
                    "instance_id": {
                        "type": "string",
                        "description": "Target IDA instance ID (defaults to active instance)"
                    }
                },
                "required": ["output_dir"]
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

                    # Append warnings to specific tool descriptions
                    _SINGLE_THREAD_WARNING = (
                        " WARNING: IDA executes on a single main thread. "
                        "Long-running operations will block ALL subsequent requests and make IDA unresponsive."
                    )
                    if tool["name"] == "py_eval":
                        tool_schema["description"] = (
                            tool_schema.get("description", "") +
                            _SINGLE_THREAD_WARNING +
                            " Do NOT iterate all functions, bulk decompile, or run heavy loops. "
                            "Use decompile_to_file for batch decompilation instead."
                        )
                    elif tool["name"] == "list_funcs":
                        tool_schema["description"] = (
                            tool_schema.get("description", "") +
                            _SINGLE_THREAD_WARNING +
                            " For large binaries (100K+ functions), use count/offset pagination. "
                            "Avoid count=0 (all) with glob filters on large binaries."
                        )

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
