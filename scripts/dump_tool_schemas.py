"""Regenerate src/ida_multi_mcp/ida_tool_schemas.json from a live IDA instance.

The router falls back to this file for tools/list when no IDA instance is
connected - which is exactly when an agent is deciding what to do. The schemas
themselves come from the @tool docstrings and type hints inside IDA, so this
file drifts silently every time one of those is edited. Regenerate it whenever
you change a tool's signature or docstring.

Usage:
    # with at least one IDA instance running the plugin
    python scripts/dump_tool_schemas.py
    python scripts/dump_tool_schemas.py --instance k7m2
    python scripts/dump_tool_schemas.py --check      # CI-style drift check
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

OUT_PATH = SRC / "ida_multi_mcp" / "ida_tool_schemas.json"

from ida_multi_mcp.registry import InstanceRegistry  # noqa: E402
from ida_multi_mcp.server import IdaMultiMcpServer  # noqa: E402


def fetch_schemas(instance_id: str | None) -> list[dict]:
    registry = InstanceRegistry()
    instances = registry.list_instances()
    if not instances:
        raise SystemExit(
            "No IDA instances registered. Start IDA with the ida-multi-mcp plugin "
            "and load a binary first."
        )
    if instance_id is None:
        instance_id = next(iter(instances))
    info = instances.get(instance_id)
    if info is None:
        raise SystemExit(
            f"Instance {instance_id!r} not found. Available: {', '.join(instances)}"
        )

    server = IdaMultiMcpServer()
    schemas = server._discover_ida_tools(info)
    if not schemas:
        raise SystemExit(f"Instance {instance_id!r} returned no tools.")

    # Strip instance_id: the router injects it per tool, and baking it in here
    # would double up when the static entry is merged with a discovered one.
    cleaned = []
    for schema in schemas:
        s = json.loads(json.dumps(schema))
        props = s.get("inputSchema", {}).get("properties", {})
        props.pop("instance_id", None)
        required = s.get("inputSchema", {}).get("required", [])
        s["inputSchema"]["required"] = [r for r in required if r != "instance_id"]
        cleaned.append(s)
    cleaned.sort(key=lambda t: t["name"])
    return cleaned


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--instance", help="instance_id to read schemas from")
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero if the file is out of date instead of writing it")
    args = ap.parse_args()

    schemas = fetch_schemas(args.instance)
    rendered = json.dumps(schemas, indent=2, ensure_ascii=False) + "\n"

    if args.check:
        current = OUT_PATH.read_text(encoding="utf-8") if OUT_PATH.exists() else ""
        if current != rendered:
            print(
                f"{OUT_PATH.relative_to(REPO_ROOT)} is out of date "
                f"({len(json.loads(current or '[]'))} tools on disk vs {len(schemas)} live). "
                f"Run: python scripts/dump_tool_schemas.py",
                file=sys.stderr,
            )
            return 1
        print(f"{OUT_PATH.relative_to(REPO_ROOT)} is up to date ({len(schemas)} tools).")
        return 0

    OUT_PATH.write_text(rendered, encoding="utf-8")
    print(f"Wrote {len(schemas)} tool schemas to {OUT_PATH.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
