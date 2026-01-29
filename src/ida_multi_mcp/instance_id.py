"""Instance ID generation for ida-multi-mcp.

Generates 4-character base36 IDs (a-z, 0-9) from pid:port:idb_path.
This ensures IDs change when the binary changes (generation-based).
"""

import hashlib

BASE36_CHARS = "0123456789abcdefghijklmnopqrstuvwxyz"
DEFAULT_ID_LENGTH = 4


def generate_instance_id(pid: int, port: int, idb_path: str, length: int = DEFAULT_ID_LENGTH) -> str:
    """Generate a base36 instance ID from pid, port, and IDB path.

    Args:
        pid: Process ID of the IDA instance
        port: Port number the HTTP server is bound to
        idb_path: Path to the IDB/binary being analyzed
        length: ID length (default 4, use 5 for collision fallback)

    Returns:
        Base36 string of specified length (e.g., "k7m2")
    """
    raw = hashlib.sha256(f"{pid}:{port}:{idb_path}".encode()).digest()
    n = int.from_bytes(raw[:4], "big") % (36 ** length)
    result = ""
    for _ in range(length):
        result = BASE36_CHARS[n % 36] + result
        n //= 36
    return result


def resolve_collision(candidate: str, existing_ids: set[str], pid: int, port: int, idb_path: str) -> str:
    """If candidate ID collides, expand to 5 characters.

    Args:
        candidate: The initial 4-char ID
        existing_ids: Set of currently registered IDs
        pid: Process ID
        port: Port number
        idb_path: IDB path

    Returns:
        A unique ID (original if no collision, or 5-char expanded)
    """
    if candidate not in existing_ids:
        return candidate
    # Expand to 5 characters
    expanded = generate_instance_id(pid, port, idb_path, length=DEFAULT_ID_LENGTH + 1)
    if expanded not in existing_ids:
        return expanded
    # Last resort: append incrementing suffix
    for i in range(36):
        suffixed = candidate + BASE36_CHARS[i]
        if suffixed not in existing_ids:
            return suffixed
    # Extremely unlikely: all combinations exhausted
    raise RuntimeError(f"Cannot generate unique instance ID (tried {36} suffixes)")
