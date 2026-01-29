"""Response cache for large IDA tool outputs.

Provides in-memory LRU caching with TTL for tool responses that exceed
the default output limit, enabling pagination via offset/size.
"""

import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any


# Configuration
DEFAULT_MAX_OUTPUT_CHARS = 20000  # Default truncation limit
CACHE_MAX_ENTRIES = 200          # Maximum cached responses
CACHE_TTL_SECONDS = 600          # 10 minutes


@dataclass
class CacheEntry:
    """A cached response entry."""
    content: str
    created_at: float
    tool_name: str
    instance_id: str | None


class ResponseCache:
    """In-memory LRU cache for large IDA tool responses.

    Stores full responses when they exceed the output limit,
    allowing clients to retrieve chunks via offset/size pagination.
    """

    def __init__(
        self,
        max_entries: int = CACHE_MAX_ENTRIES,
        ttl_seconds: int = CACHE_TTL_SECONDS
    ):
        """Initialize the cache.

        Args:
            max_entries: Maximum number of cached responses
            ttl_seconds: Time-to-live for cache entries in seconds
        """
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()

    def store(
        self,
        content: str,
        tool_name: str = "",
        instance_id: str | None = None
    ) -> str:
        """Store content in the cache.

        Args:
            content: The full response content to cache
            tool_name: Name of the tool that produced the response
            instance_id: IDA instance ID (if applicable)

        Returns:
            cache_id: 8-character hex identifier for retrieval
        """
        # Evict expired entries first
        self._evict_expired()

        # Evict oldest if at capacity
        while len(self._cache) >= self.max_entries:
            self._cache.popitem(last=False)

        # Generate short cache ID
        cache_id = uuid.uuid4().hex[:8]

        # Store entry
        self._cache[cache_id] = CacheEntry(
            content=content,
            created_at=time.time(),
            tool_name=tool_name,
            instance_id=instance_id
        )

        # Move to end (most recently used)
        self._cache.move_to_end(cache_id)

        return cache_id

    def get(
        self,
        cache_id: str,
        offset: int = 0,
        size: int = DEFAULT_MAX_OUTPUT_CHARS
    ) -> dict[str, Any]:
        """Retrieve cached content by offset and size.

        Args:
            cache_id: The cache identifier
            offset: Starting character position (0-indexed)
            size: Number of characters to return (0 = all remaining)

        Returns:
            dict with:
                - chunk: The requested content slice
                - offset: Actual offset used
                - size: Actual size returned
                - total_chars: Total cached content length
                - remaining_chars: Characters remaining after this chunk
                - cache_id: The cache ID
                - tool_name: Original tool name
                - instance_id: Original instance ID

        Raises:
            KeyError: If cache_id not found or expired
        """
        # Evict expired first
        self._evict_expired()

        if cache_id not in self._cache:
            raise KeyError(f"Cache entry '{cache_id}' not found or expired")

        entry = self._cache[cache_id]

        # Move to end (LRU update)
        self._cache.move_to_end(cache_id)

        total_chars = len(entry.content)

        # Validate offset
        if offset < 0:
            offset = 0
        if offset >= total_chars:
            # Return empty chunk if offset beyond content
            return {
                "chunk": "",
                "offset": offset,
                "size": 0,
                "total_chars": total_chars,
                "remaining_chars": 0,
                "cache_id": cache_id,
                "tool_name": entry.tool_name,
                "instance_id": entry.instance_id
            }

        # Calculate actual size
        if size <= 0:
            # Return all remaining
            actual_size = total_chars - offset
        else:
            actual_size = min(size, total_chars - offset)

        chunk = entry.content[offset:offset + actual_size]
        remaining = total_chars - offset - actual_size

        return {
            "chunk": chunk,
            "offset": offset,
            "size": actual_size,
            "total_chars": total_chars,
            "remaining_chars": remaining,
            "cache_id": cache_id,
            "tool_name": entry.tool_name,
            "instance_id": entry.instance_id
        }

    def exists(self, cache_id: str) -> bool:
        """Check if a cache entry exists and is not expired.

        Args:
            cache_id: The cache identifier

        Returns:
            True if entry exists and is valid
        """
        self._evict_expired()
        return cache_id in self._cache

    def delete(self, cache_id: str) -> bool:
        """Delete a cache entry.

        Args:
            cache_id: The cache identifier

        Returns:
            True if entry was deleted, False if not found
        """
        if cache_id in self._cache:
            del self._cache[cache_id]
            return True
        return False

    def clear(self) -> int:
        """Clear all cache entries.

        Returns:
            Number of entries cleared
        """
        count = len(self._cache)
        self._cache.clear()
        return count

    def stats(self) -> dict[str, Any]:
        """Get cache statistics.

        Returns:
            dict with entry_count, max_entries, ttl_seconds
        """
        self._evict_expired()
        return {
            "entry_count": len(self._cache),
            "max_entries": self.max_entries,
            "ttl_seconds": self.ttl_seconds
        }

    def _evict_expired(self) -> int:
        """Remove entries older than TTL.

        Returns:
            Number of entries evicted
        """
        now = time.time()
        expired = [
            cache_id
            for cache_id, entry in self._cache.items()
            if now - entry.created_at > self.ttl_seconds
        ]

        for cache_id in expired:
            del self._cache[cache_id]

        return len(expired)


# Global cache instance
_response_cache: ResponseCache | None = None


def get_cache() -> ResponseCache:
    """Get the global response cache instance.

    Returns:
        The singleton ResponseCache instance
    """
    global _response_cache
    if _response_cache is None:
        _response_cache = ResponseCache()
    return _response_cache
