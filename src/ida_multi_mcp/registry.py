"""Instance registry for ida-multi-mcp.

Manages the global registry of IDA Pro instances with atomic file operations.
"""

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .filelock import FileLock
from .instance_id import generate_instance_id, resolve_collision


class InstanceRegistry:
    """Thread-safe registry of IDA Pro instances.

    Stores instance metadata in ~/.ida-mcp/instances.json with file locking.
    Tracks active instances, expired instances, and the currently active instance.
    """

    def __init__(self, registry_path: str | None = None):
        """Initialize the registry.

        Args:
            registry_path: Path to registry JSON file (default: ~/.ida-mcp/instances.json)
        """
        if registry_path is None:
            registry_path = str(Path.home() / ".ida-mcp" / "instances.json")

        self.registry_path = registry_path
        self.lock_path = registry_path + ".lock"

        # Ensure parent directory exists
        os.makedirs(os.path.dirname(self.registry_path), exist_ok=True)

    def _iso_timestamp(self) -> str:
        """Generate ISO 8601 timestamp string."""
        return datetime.now(timezone.utc).isoformat()

    def _parse_timestamp(self, timestamp_str: str) -> float:
        """Parse ISO 8601 timestamp to Unix epoch time.

        Args:
            timestamp_str: ISO 8601 formatted timestamp

        Returns:
            Unix timestamp (seconds since epoch)
        """
        try:
            # Try parsing ISO format with timezone
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            return dt.timestamp()
        except (ValueError, AttributeError):
            # Fallback: treat as very old (epoch 0)
            return 0.0

    def _load(self) -> dict[str, Any]:
        """Load registry data from disk (assumes lock held)."""
        if not os.path.exists(self.registry_path):
            return {"instances": {}, "active_instance": None, "expired": {}}

        with open(self.registry_path, 'r') as f:
            return json.load(f)

    def _save(self, data: dict[str, Any]) -> None:
        """Save registry data to disk atomically (assumes lock held)."""
        # Write to temp file first
        temp_path = self.registry_path + ".tmp"
        with open(temp_path, 'w') as f:
            json.dump(data, f, indent=2)

        # Atomic rename
        os.replace(temp_path, self.registry_path)

    def register(self, pid: int, port: int, idb_path: str, **metadata) -> str:
        """Register a new IDA instance.

        Args:
            pid: Process ID
            port: MCP server port
            idb_path: Path to the IDB file being analyzed
            **metadata: Additional metadata (binary_name, binary_path, arch, host, etc.)

        Returns:
            Generated instance ID
        """
        with FileLock(self.lock_path):
            data = self._load()
            existing_ids = set(data["instances"].keys())

            # Generate instance ID
            candidate_id = generate_instance_id(pid, port, idb_path)
            instance_id = resolve_collision(candidate_id, existing_ids, pid, port, idb_path)

            # Store instance info with required fields
            instance_info = {
                "pid": pid,
                "host": metadata.get("host", "127.0.0.1"),
                "port": port,
                "binary_name": metadata.get("binary_name", "unknown"),
                "binary_path": metadata.get("binary_path", ""),
                "idb_path": idb_path,
                "arch": metadata.get("arch", "unknown"),
                "registered_at": self._iso_timestamp(),
                "last_heartbeat": self._iso_timestamp(),
            }
            # Add any extra metadata
            for key, value in metadata.items():
                if key not in instance_info:
                    instance_info[key] = value

            data["instances"][instance_id] = instance_info

            # Set as active if no active instance
            if data["active_instance"] is None:
                data["active_instance"] = instance_id

            self._save(data)
            return instance_id

    def unregister(self, instance_id: str) -> bool:
        """Remove an instance from the registry.

        Args:
            instance_id: Instance ID to remove

        Returns:
            True if instance was found and removed
        """
        with FileLock(self.lock_path):
            data = self._load()

            if instance_id not in data["instances"]:
                return False

            del data["instances"][instance_id]

            # Clear active if this was the active instance
            if data["active_instance"] == instance_id:
                # Set first remaining instance as active, or None
                remaining = list(data["instances"].keys())
                data["active_instance"] = remaining[0] if remaining else None

            self._save(data)
            return True

    def get_instance(self, instance_id: str) -> dict[str, Any] | None:
        """Get metadata for a specific instance.

        Args:
            instance_id: Instance ID

        Returns:
            Instance metadata dict, or None if not found
        """
        with FileLock(self.lock_path):
            data = self._load()
            return data["instances"].get(instance_id)

    def list_instances(self) -> dict[str, dict[str, Any]]:
        """List all registered instances.

        Returns:
            Dict mapping instance_id -> metadata
        """
        with FileLock(self.lock_path):
            data = self._load()
            return data["instances"].copy()

    def update_heartbeat(self, instance_id: str) -> bool:
        """Update the last heartbeat timestamp for an instance.

        Args:
            instance_id: Instance ID

        Returns:
            True if instance was found and updated
        """
        with FileLock(self.lock_path):
            data = self._load()

            if instance_id not in data["instances"]:
                return False

            data["instances"][instance_id]["last_heartbeat"] = self._iso_timestamp()
            self._save(data)
            return True

    def get_active(self) -> str | None:
        """Get the currently active instance ID.

        Returns:
            Active instance ID, or None if no active instance
        """
        with FileLock(self.lock_path):
            data = self._load()
            return data["active_instance"]

    def set_active(self, instance_id: str) -> bool:
        """Set the active instance.

        Args:
            instance_id: Instance ID to make active

        Returns:
            True if instance exists and was set active
        """
        with FileLock(self.lock_path):
            data = self._load()

            if instance_id not in data["instances"]:
                return False

            data["active_instance"] = instance_id
            self._save(data)
            return True

    def expire_instance(self, instance_id: str, reason: str, replaced_by: str | None = None) -> bool:
        """Move an instance to the expired list.

        Args:
            instance_id: Instance ID to expire
            reason: Reason for expiration (e.g., "binary_changed", "ida_closed", "stale_heartbeat")
            replaced_by: ID of the instance that replaced this one (if any)

        Returns:
            True if instance was found and expired
        """
        with FileLock(self.lock_path):
            data = self._load()

            if instance_id not in data["instances"]:
                return False

            # Move to expired with required fields from spec
            instance = data["instances"][instance_id]
            expired_info = {
                "binary_name": instance.get("binary_name", "unknown"),
                "binary_path": instance.get("binary_path", ""),
                "expired_at": self._iso_timestamp(),
                "reason": reason,
            }
            if replaced_by is not None:
                expired_info["replaced_by"] = replaced_by

            data["expired"][instance_id] = expired_info
            del data["instances"][instance_id]

            # Clear active if this was the active instance
            if data["active_instance"] == instance_id:
                remaining = list(data["instances"].keys())
                data["active_instance"] = remaining[0] if remaining else None

            self._save(data)
            return True

    def get_expired(self, instance_id: str) -> dict[str, Any] | None:
        """Get metadata for a specific expired instance.

        Args:
            instance_id: Expired instance ID to look up

        Returns:
            Expired instance metadata dict, or None if not found
        """
        with FileLock(self.lock_path):
            data = self._load()
            return data.get("expired", {}).get(instance_id)

    def cleanup_expired(self, max_age_seconds: int = 3600) -> int:
        """Remove expired instances older than max_age.

        Args:
            max_age_seconds: Maximum age in seconds (default: 3600 = 1 hour, per spec)

        Returns:
            Number of removed instances
        """
        with FileLock(self.lock_path):
            data = self._load()
            expired = data.get("expired", {})
            now = time.time()
            removed_count = 0

            for instance_id, info in list(expired.items()):
                expired_at_str = info.get("expired_at", "")
                expired_at = self._parse_timestamp(expired_at_str)

                if now - expired_at > max_age_seconds:
                    del expired[instance_id]
                    removed_count += 1

            data["expired"] = expired
            self._save(data)
            return removed_count

    def cleanup_stale(self, timeout_seconds: int = 120) -> list[str]:
        """Mark instances with stale heartbeats as expired.

        Args:
            timeout_seconds: Heartbeat timeout threshold (default: 120 seconds)

        Returns:
            List of expired instance IDs
        """
        with FileLock(self.lock_path):
            data = self._load()
            now = time.time()
            stale = []

            for instance_id, info in list(data["instances"].items()):
                last_heartbeat_str = info.get("last_heartbeat", "")
                last_heartbeat = self._parse_timestamp(last_heartbeat_str)

                if now - last_heartbeat > timeout_seconds:
                    # Move to expired with proper schema
                    expired_info = {
                        "binary_name": info.get("binary_name", "unknown"),
                        "binary_path": info.get("binary_path", ""),
                        "expired_at": self._iso_timestamp(),
                        "reason": "stale_heartbeat",
                    }
                    data["expired"][instance_id] = expired_info
                    del data["instances"][instance_id]
                    stale.append(instance_id)

            # Clear active if it became stale
            if data["active_instance"] in stale:
                remaining = list(data["instances"].keys())
                data["active_instance"] = remaining[0] if remaining else None

            self._save(data)
            return stale
