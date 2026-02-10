"""Request routing for ida-multi-mcp.

Routes MCP requests to the appropriate IDA instance with fallback verification.
"""

import json
import http.client
import time
from typing import Any

from .registry import InstanceRegistry
from .health import query_binary_metadata


class InstanceRouter:
    """Routes MCP tool requests to IDA instances.

    Handles instance_id extraction, fallback verification, and error handling.
    """

    def __init__(self, registry: InstanceRegistry):
        """Initialize the router.

        Args:
            registry: The instance registry
        """
        self.registry = registry
        self._binary_path_cache: dict[str, tuple[str | None, float]] = {}
        self._cache_timeout = 5.0  # seconds

    def route_request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Route a tool request to the appropriate IDA instance.

        Args:
            method: MCP method name (e.g., "tools/call")
            params: Method parameters (may include instance_id)

        Returns:
            Response dict from the IDA instance
        """
        # Extract instance_id from params
        instance_id = params.get("arguments", {}).get("instance_id")

        # Require explicit instance_id to avoid cross-agent contention on shared registries.
        if not instance_id:
            instances = self.registry.list_instances()
            return {
                "error": "Missing required parameter 'instance_id'.",
                "hint": "Call list_instances() and pass instance_id explicitly for every IDA tool call.",
                "available_instances": [
                    {"id": id, "binary_name": info.get("binary_name", "unknown")}
                    for id, info in instances.items()
                ],
            }

        # Get instance info
        instance_info = self.registry.get_instance(instance_id)

        # Check if instance exists
        if instance_info is None:
            # Check if it was expired
            expired_info = self.registry.get_expired(instance_id)
            if expired_info is not None:
                return self._handle_expired_instance(instance_id, expired_info)
            else:
                return self._handle_missing_instance(instance_id)

        # Verify binary path (fallback check)
        if not self._verify_binary_path(instance_id, instance_info):
            return {
                "error": f"Instance '{instance_id}' binary path changed. Instance may be stale.",
                "hint": "Use list_instances() to see current instances."
            }

        # Remove instance_id from arguments before forwarding to IDA
        forward_params = params.copy()
        if "arguments" in forward_params:
            forward_args = forward_params["arguments"].copy()
            forward_args.pop("instance_id", None)
            forward_params["arguments"] = forward_args

        # Route the request
        return self._send_request(instance_info, method, forward_params)

    def _verify_binary_path(self, instance_id: str, instance_info: dict) -> bool:
        """Verify instance is still analyzing the same binary.

        Compares by binary name (module) since the metadata resource returns
        the IDB path, not the original binary path.
        Uses 5-second cache to avoid excessive queries.

        Args:
            instance_id: Instance ID
            instance_info: Instance metadata

        Returns:
            True if binary matches or cannot be verified
        """
        now = time.time()

        # Check cache
        if instance_id in self._binary_path_cache:
            cached_name, cached_time = self._binary_path_cache[instance_id]
            if now - cached_time < self._cache_timeout:
                return cached_name == instance_info.get("binary_name")

        # Query fresh binary metadata
        host = instance_info.get("host", "127.0.0.1")
        port = instance_info.get("port")
        metadata = query_binary_metadata(host, port)

        # Extract binary name (module) from metadata
        current_name = metadata.get("module") if metadata else None

        # Update cache
        self._binary_path_cache[instance_id] = (current_name, now)

        # If we couldn't query, assume it's valid (benefit of doubt)
        if current_name is None:
            return True

        # Compare by binary name
        return current_name == instance_info.get("binary_name")

    def _send_request(self, instance_info: dict, method: str, params: dict) -> dict[str, Any]:
        """Send HTTP request to IDA instance.

        Args:
            instance_info: Instance metadata
            method: MCP method name
            params: Method parameters

        Returns:
            Response dict
        """
        host = instance_info.get("host", "127.0.0.1")
        port = instance_info.get("port")

        try:
            conn = http.client.HTTPConnection(host, port, timeout=300.0)
            request_body = json.dumps({
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
                "id": 1
            })
            conn.request("POST", "/mcp", request_body, {"Content-Type": "application/json"})
            response = conn.getresponse()
            response_data = json.loads(response.read().decode())
            conn.close()

            # Return result or error
            if "result" in response_data:
                return response_data["result"]
            elif "error" in response_data:
                return {"error": response_data["error"]}
            else:
                return response_data

        except Exception as e:
            return {
                "error": f"Failed to connect to instance: {str(e)}",
                "instance_id": instance_info.get("id", "unknown"),
                "host": host,
                "port": port
            }

    def _handle_expired_instance(self, instance_id: str, expired_info: dict) -> dict[str, Any]:
        """Handle request for an expired instance.

        Args:
            instance_id: Expired instance ID
            expired_info: Expired instance metadata

        Returns:
            Error response with replacement suggestions
        """
        # Find replacement: same binary name
        binary_name = expired_info.get("binary_name", "")
        instances = self.registry.list_instances()
        replacements = [
            (id, info) for id, info in instances.items()
            if info.get("binary_name") == binary_name
        ]

        if replacements:
            return {
                "error": f"Instance '{instance_id}' expired at {expired_info.get('expired_at')}",
                "reason": expired_info.get("expire_reason", "unknown"),
                "replacements": [
                    {"id": id, "binary_name": info.get("binary_name")}
                    for id, info in replacements
                ],
                "hint": f"Use instance_id='{replacements[0][0]}' for subsequent calls."
            }
        else:
            return {
                "error": f"Instance '{instance_id}' expired and no replacement found.",
                "reason": expired_info.get("expire_reason", "unknown"),
                "available_instances": list(instances.keys())
            }

    def _handle_missing_instance(self, instance_id: str) -> dict[str, Any]:
        """Handle request for a missing instance.

        Args:
            instance_id: Missing instance ID

        Returns:
            Error response with available instances
        """
        instances = self.registry.list_instances()
        return {
            "error": f"Instance '{instance_id}' not found.",
            "available_instances": [
                {"id": id, "binary_name": info.get("binary_name", "unknown")}
                for id, info in instances.items()
            ],
            "hint": "Use list_instances() to see all available instances."
        }
