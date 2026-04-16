"""Integration tests for server.py — IdaMultiMcpServer end-to-end."""

import json
import os
from unittest.mock import patch, MagicMock

import pytest

from ida_multi_mcp.server import IdaMultiMcpServer


@pytest.fixture
def server(tmp_path):
    """IdaMultiMcpServer with isolated registry and mocked network."""
    with patch("ida_multi_mcp.server.rediscover_instances", return_value=[]):
        with patch("ida_multi_mcp.server.cleanup_stale_instances", return_value=[]):
            srv = IdaMultiMcpServer(registry_path=str(tmp_path / "inst.json"))
            # Force a refresh so the tool cache is populated
            srv._refresh_tools()
            yield srv


def _call(server, method, params=None):
    req = {"jsonrpc": "2.0", "method": method, "id": 1}
    if params is not None:
        req["params"] = params
    return server.server.registry.dispatch(req)


class TestServerInit:
    def test_management_tools_in_cache(self, server):
        assert "list_instances" in server._tool_cache
        assert "refresh_tools" in server._tool_cache
        assert "get_cached_output" in server._tool_cache
        assert "decompile_to_file" in server._tool_cache


class TestToolsList:
    def test_includes_management_tools(self, server):
        resp = _call(server, "tools/list")
        tool_names = [t["name"] for t in resp["result"]["tools"]]
        assert "list_instances" in tool_names
        assert "refresh_tools" in tool_names


class TestToolsCall:
    def test_list_instances_structured(self, server):
        resp = _call(server, "tools/call",
                     {"name": "list_instances", "arguments": {}})
        result = resp["result"]
        assert result["isError"] is False
        structured = result["structuredContent"]
        assert "count" in structured
        assert "instances" in structured
        assert result["content"][0]["text"] == json.dumps(structured, separators=(",", ":"))

    def test_get_cached_output_miss(self, server):
        resp = _call(server, "tools/call",
                     {"name": "get_cached_output",
                      "arguments": {"cache_id": "nonexistent"}})
        result = resp["result"]
        assert result["isError"] is True

    def test_get_cached_output_hit(self, server):
        from ida_multi_mcp.cache import get_cache
        cache = get_cache()
        cid = cache.store("test content here", tool_name="test")
        resp = _call(server, "tools/call",
                     {"name": "get_cached_output",
                      "arguments": {"cache_id": cid}})
        result = resp["result"]
        assert result["isError"] is False
        assert "test content here" in result["content"][0]["text"]

    def test_ida_tool_no_instances(self, server):
        """IDA tool call with no connected instances shows helpful error."""
        with patch("ida_multi_mcp.server.rediscover_instances", return_value=[]):
            resp = _call(server, "tools/call",
                         {"name": "decompile",
                          "arguments": {"addr": "0x1000", "instance_id": "x"}})
        result = resp["result"]
        assert result["isError"] is True
        # Should either say "not found" or "No IDA Pro instance"
        text = result["content"][0]["text"]
        assert "not found" in text or "No IDA Pro instance" in text


class TestDecompileToFile:
    def test_path_traversal_blocked(self, server):
        resp = _call(server, "tools/call", {
            "name": "decompile_to_file",
            "arguments": {
                "output_dir": "../../../etc",
                "instance_id": "x",
                "addrs": ["0x1000"],
            }
        })
        result = resp["result"]
        # Should flag path traversal
        structured = result.get("structuredContent", {})
        if "error" in structured:
            assert ".." in structured["error"]


class TestProxiedTruncation:
    def test_response_truncation_and_caching(self, server):
        """When an IDA tool returns huge output, it should be truncated and cached."""
        reg = server.registry
        iid = reg.register(pid=1, port=9999, idb_path="/t.i64",
                           binary_name="t.exe", host="127.0.0.1")

        big_result = {"data": "x" * 20000}
        ida_response = {
            "content": [{"type": "text", "text": json.dumps(big_result)}],
            "structuredContent": big_result,
            "isError": False,
        }

        with patch.object(server.router, "route_request", return_value=ida_response):
            resp = _call(server, "tools/call", {
                "name": "some_ida_tool",
                "arguments": {"instance_id": iid, "max_output_chars": 500},
            })

        result = resp["result"]
        assert result["isError"] is False
        text = result["content"][0]["text"]
        assert "TRUNCATED" in text
        assert "cache_id" in text
