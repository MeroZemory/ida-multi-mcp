"""Request routing for ida-multi-mcp.

Routes MCP requests to the appropriate IDA instance with fallback verification.
"""

import json
import http.client
import os
import threading
import time
from typing import Any

from .registry import InstanceRegistry, ALLOWED_HOSTS
from .health import query_binary_identity
from .identity import normalize_fingerprint


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
        self._binary_path_cache: dict[str, tuple[tuple, dict, float]] = {}
        self._cache_lock = threading.Lock()
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

        # Auto-select when exactly one instance is registered; require explicit
        # instance_id when 0 or 2+ to avoid cross-agent contention.
        if not instance_id:
            instances = self.registry.list_instances()
            if len(instances) == 1:
                instance_id = next(iter(instances))
            else:
                return {
                    "error": "Missing required parameter 'instance_id'.",
                    "hint": (
                        "Call list_instances() and pass instance_id explicitly."
                        if len(instances) != 0
                        else "No IDA instances registered. Start IDA with the MCP plugin first."
                    ),
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
                "error": f"Instance '{instance_id}' input identity changed or could not be verified.",
                "hint": (
                    "Retry if the instance is busy. Otherwise update the package, restart IDA, "
                    "and re-register the database, or reopen the managed session. "
                    "An IDB-stored SHA-256 or MD5 input digest is required."
                ),
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
        """Compare registration identity with the loaded input; unknown is unsafe.

        Successful identity reads are cached for five seconds. A cache entry is
        bound to the registration and endpoint, never just the short instance ID.
        """
        expected = normalize_fingerprint(instance_info.get("input_fingerprint"))
        if expected is None:
            return False
        now = time.monotonic()

        def _normalize_binary_name(name: str | None) -> str | None:
            if not isinstance(name, str) or not name:
                return None
            # Normalize both Windows and POSIX-like paths, then compare case-insensitively.
            normalized = os.path.basename(name.replace("\\", "/")).strip()
            return normalized.casefold() if normalized else None

        signature = (
            instance_info.get("host", "127.0.0.1"), instance_info.get("port"),
            instance_info.get("pid"), instance_info.get("registered_at"),
            instance_info.get("idb_path"), instance_info.get("binary_name"),
            expected["algorithm"], expected["digest"],
        )
        with self._cache_lock:
            entry = self._binary_path_cache.get(instance_id)
        if entry and entry[0] == signature and now - entry[2] < self._cache_timeout:
            identity = entry[1]
        else:
            identity = query_binary_identity(signature[0], signature[1])
            if not isinstance(identity, dict):
                return False
            # Do not cache failures: a busy endpoint should be retryable immediately.
            if normalize_fingerprint(identity.get("input_fingerprint")) is None:
                return False
            with self._cache_lock:
                self._binary_path_cache[instance_id] = (signature, identity, now)
        current = normalize_fingerprint(identity.get("input_fingerprint"))
        current_name = _normalize_binary_name(identity.get("module"))
        return (
            current == expected
            and current_name is not None
            and current_name == _normalize_binary_name(instance_info.get("binary_name"))
        )

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

        # Security: validate host is localhost only (prevent SSRF)
        if host not in ALLOWED_HOSTS:
            return {"error": "Connection refused: only localhost instances allowed"}

        conn = None
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

            # Return result or error
            if "result" in response_data:
                return response_data["result"]
            elif "error" in response_data:
                return {"error": response_data["error"]}
            else:
                return response_data

        except Exception as e:
            # Security: don't leak host/port in error messages
            return {
                "error": f"Failed to connect to instance: {type(e).__name__}",
            }
        finally:
            if conn is not None:
                conn.close()  # always release the socket, even on error

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

        reason = expired_info.get("reason", expired_info.get("expire_reason", "unknown"))
        if replacements:
            return {
                "error": f"Instance '{instance_id}' expired at {expired_info.get('expired_at')}",
                "reason": reason,
                "replacements": [
                    {"id": id, "binary_name": info.get("binary_name")}
                    for id, info in replacements
                ],
                "hint": f"Use instance_id='{replacements[0][0]}' for subsequent calls."
            }
        else:
            return {
                "error": f"Instance '{instance_id}' expired and no replacement found.",
                "reason": reason,
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
