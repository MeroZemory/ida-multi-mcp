"""Tests for vendor/zeromcp/mcp.py — MCP server protocol."""

import io
import json
from typing import Annotated, Union
from unittest.mock import patch

import pytest

from ida_multi_mcp.vendor.zeromcp.mcp import McpServer, McpToolError


@pytest.fixture
def mcp():
    server = McpServer("test-server", version="0.1.0")

    @server.tool
    def echo(text: str) -> str:
        """Echo back the input."""
        return text

    @server.tool
    def add(a: int, b: int = 0) -> int:
        """Add two numbers."""
        return a + b

    @server.tool
    def info() -> dict:
        """Return structured object data."""
        return {"status": "ok", "count": 1}

    @server.tool
    def failing():
        """Always fails."""
        raise McpToolError("Something went wrong")

    return server


def _dispatch(server, method, params=None):
    """Helper to dispatch a JSON-RPC request and return the result."""
    request = {"jsonrpc": "2.0", "method": method, "id": 1}
    if params is not None:
        request["params"] = params
    return server.registry.dispatch(request)


class TestToolRegistration:
    def test_tool_listed(self, mcp):
        resp = _dispatch(mcp, "tools/list")
        tool_names = [t["name"] for t in resp["result"]["tools"]]
        assert "echo" in tool_names
        assert "add" in tool_names


class TestSchemaGeneration:
    def test_basic_types(self, mcp):
        resp = _dispatch(mcp, "tools/list")
        tools = {t["name"]: t for t in resp["result"]["tools"]}
        echo_schema = tools["echo"]["inputSchema"]
        assert echo_schema["properties"]["text"]["type"] == "string"
        assert "text" in echo_schema["required"]

    def test_optional_params(self, mcp):
        resp = _dispatch(mcp, "tools/list")
        tools = {t["name"]: t for t in resp["result"]["tools"]}
        add_schema = tools["add"]["inputSchema"]
        assert "a" in add_schema["required"]
        assert "b" not in add_schema["required"]

    def test_union_and_annotated(self):
        server = McpServer("test")

        @server.tool
        def fancy(x: Annotated[int | str, "A number or string"]) -> str:
            """Fancy tool."""
            return str(x)

        resp = _dispatch(server, "tools/list")
        tools = {t["name"]: t for t in resp["result"]["tools"]}
        prop = tools["fancy"]["inputSchema"]["properties"]["x"]
        assert "anyOf" in prop
        assert prop["description"] == "A number or string"

    def test_list_and_dict_generics(self):
        server = McpServer("test")

        @server.tool
        def generic(items: list[str], mapping: dict[str, int]) -> dict:
            """Generic tool."""
            return {}

        resp = _dispatch(server, "tools/list")
        tools = {t["name"]: t for t in resp["result"]["tools"]}
        schema = tools["generic"]["inputSchema"]
        assert schema["properties"]["items"]["type"] == "array"
        assert schema["properties"]["mapping"]["type"] == "object"


class TestToolCall:
    def test_success(self, mcp):
        resp = _dispatch(mcp, "tools/call", {"name": "echo", "arguments": {"text": "hi"}})
        result = resp["result"]
        assert result["isError"] is False
        assert "hi" in result["content"][0]["text"]

    def test_structured_content_is_compact_json(self, mcp):
        resp = _dispatch(mcp, "tools/call", {"name": "info"})
        result = resp["result"]
        assert result["isError"] is False
        assert result["content"][0]["text"] == '{"status":"ok","count":1}'

    def test_mcp_tool_error(self, mcp):
        resp = _dispatch(mcp, "tools/call", {"name": "failing"})
        result = resp["result"]
        assert result["isError"] is True
        assert "Something went wrong" in result["content"][0]["text"]


class TestCorsLocalhost:
    def test_allows_localhost(self, mcp):
        assert mcp.cors_localhost("http://localhost:3000") is True
        assert mcp.cors_localhost("http://127.0.0.1:8080") is True

    def test_rejects_external(self, mcp):
        assert mcp.cors_localhost("http://evil.com") is False
        assert mcp.cors_localhost("http://10.0.0.1:80") is False


class TestStdio:
    def test_roundtrip(self, mcp):
        request = json.dumps({
            "jsonrpc": "2.0", "method": "tools/call",
            "params": {"name": "add", "arguments": {"a": 3, "b": 4}},
            "id": 1,
        })
        stdin = io.BytesIO(request.encode() + b"\n")
        stdout = io.BytesIO()
        mcp.stdio(stdin=stdin, stdout=stdout)
        stdout.seek(0)
        response = json.loads(stdout.readline())
        assert response["result"]["isError"] is False
        parsed = json.loads(response["result"]["content"][0]["text"])
        assert parsed == 7


class TestExtensionGating:
    def test_tool_hidden_when_extension_not_enabled(self):
        server = McpServer("test", extensions={"debug": {"dbg_tool"}})

        @server.tool
        def dbg_tool() -> str:
            """Debug tool."""
            return "debug"

        @server.tool
        def normal_tool() -> str:
            """Normal tool."""
            return "normal"

        # Simulate no extensions enabled (default)
        server._enabled_extensions.data = set()
        resp = _dispatch(server, "tools/list")
        tool_names = [t["name"] for t in resp["result"]["tools"]]
        assert "normal_tool" in tool_names
        assert "dbg_tool" not in tool_names

        # Simulate extension enabled
        server._enabled_extensions.data = {"debug"}
        resp = _dispatch(server, "tools/list")
        tool_names = [t["name"] for t in resp["result"]["tools"]]
        assert "dbg_tool" in tool_names
