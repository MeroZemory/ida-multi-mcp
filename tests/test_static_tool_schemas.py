"""Tests for the static tools/list fallback.

ida_tool_schemas.json is what a client sees when no IDA instance is connected --
exactly when an agent is deciding what to do. It is loaded with a bare open(),
which on a non-UTF-8 default locale (cp949 on Korean Windows, cp1252, ...) fails
on the first non-ASCII byte. _load_static_ida_tools swallows that and returns [],
so the entire IDA tool catalogue silently disappears offline: 76 advertised
tools drop to 15, and nothing says why.

That is not hypothetical -- it fired the moment a tool docstring gained an
em dash.
"""

import json
from pathlib import Path

import pytest

from ida_multi_mcp import server as server_mod

SCHEMA_PATH = Path(server_mod.__file__).parent / "ida_tool_schemas.json"


@pytest.fixture(autouse=True)
def _clear_cache():
    server_mod._STATIC_IDA_TOOLS = None
    yield
    server_mod._STATIC_IDA_TOOLS = None


def test_static_schemas_load():
    tools = server_mod._load_static_ida_tools()
    assert tools, "static tool catalogue failed to load"
    assert len(tools) > 40


def test_static_schemas_survive_a_non_utf8_default_locale(monkeypatch):
    """The real failure mode: locale-dependent decoding of a UTF-8 file."""
    real_open = open

    def cp949_open(file, mode="r", *args, **kwargs):
        # Simulate a machine whose preferred encoding is cp949 by forcing it
        # whenever the caller did not pin one explicitly.
        if "b" not in mode and "encoding" not in kwargs:
            kwargs["encoding"] = "cp949"
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", cp949_open)
    tools = server_mod._load_static_ida_tools()
    assert tools, "static catalogue lost under a cp949 default locale"


def test_static_schema_file_is_valid_and_non_ascii_safe():
    raw = SCHEMA_PATH.read_bytes()
    tools = json.loads(raw.decode("utf-8"))
    assert isinstance(tools, list) and tools
    for t in tools:
        assert {"name", "description", "inputSchema"} <= set(t)
        # instance_id is injected by the router; baking it in would double up
        assert "instance_id" not in t["inputSchema"].get("properties", {})


def test_static_catalogue_advertises_the_analysis_gate():
    """An agent choosing what to do offline still has to learn about these."""
    names = {t["name"] for t in server_mod._load_static_ida_tools()}
    assert "analysis_status" in names
    assert "list_funcs" in names
