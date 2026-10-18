"""Identity of the original input recorded in an IDA database.

These digests identify the loaded input, not edits to the IDB or the current
contents of a file that may have been replaced on disk.
"""


def normalize_fingerprint(value: object) -> dict[str, str] | None:
    if not isinstance(value, dict):
        return None
    algorithm = value.get("algorithm")
    lengths = {"sha256": 64, "md5": 32}
    if not isinstance(algorithm, str) or algorithm not in lengths:
        return None
    digest = value.get("digest")
    if not isinstance(digest, str):
        return None
    digest = digest.lower()
    if len(digest) != lengths[algorithm] or any(c not in "0123456789abcdef" for c in digest):
        return None
    return {"algorithm": algorithm, "digest": digest}


def read_input_fingerprint() -> dict[str, str] | None:
    """Read IDB-stored digests on the IDA thread, without reading the input file."""
    try:
        import ida_nalt
    except ImportError:
        return None
    for algorithm in ("sha256", "md5"):
        try:
            raw = getattr(ida_nalt, f"retrieve_input_file_{algorithm}")()
            if isinstance(raw, bytes):
                value = normalize_fingerprint({"algorithm": algorithm, "digest": raw.hex()})
                if value:
                    return value
        except Exception:
            continue
    return None
