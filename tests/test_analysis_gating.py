"""Tests for the analysis-incomplete guidance the router attaches to results.

Telling an agent in a tool description to wait for auto-analysis only works if
it reads the description first. These cover the belt-and-braces path: when an
instance is still analysing, the router appends the warning to the result of
tools whose output would be silently partial.
"""

from unittest.mock import MagicMock

import pytest

from ida_multi_mcp import server as server_mod
from ida_multi_mcp.server import (
    _ANALYSIS_SENSITIVE_TOOLS,
    _SERVER_INSTRUCTIONS,
    IdaMultiMcpServer,
)


@pytest.fixture
def srv(tmp_path):
    s = IdaMultiMcpServer(registry_path=str(tmp_path / "instances.json"))
    s.router = MagicMock()
    return s


def _status(finished):
    return {"structuredContent": {"finished": finished}}


def test_incomplete_analysis_is_detected(srv):
    srv.router.route_request.return_value = _status(False)
    assert srv._analysis_incomplete("k7m2") is True


def test_finished_analysis_is_not_flagged(srv):
    srv.router.route_request.return_value = _status(True)
    assert srv._analysis_incomplete("k7m2") is False


def test_result_is_cached_so_every_call_does_not_probe(srv):
    srv.router.route_request.return_value = _status(False)
    for _ in range(5):
        assert srv._analysis_incomplete("k7m2") is True
    assert srv.router.route_request.call_count == 1


def test_cache_is_per_instance(srv):
    def route(_method, params):
        return _status(params["arguments"]["instance_id"] == "busy")
    srv.router.route_request.side_effect = lambda m, p: _status(
        p["arguments"]["instance_id"] != "busy"
    )
    assert srv._analysis_incomplete("busy") is True
    assert srv._analysis_incomplete("idle") is False


def test_expired_cache_reprobes(srv, monkeypatch):
    srv.router.route_request.return_value = _status(False)
    assert srv._analysis_incomplete("k7m2") is True
    # Age the entry past the TTL rather than sleeping through it.
    incomplete, ts = srv._analysis_state_cache["k7m2"]
    srv._analysis_state_cache["k7m2"] = (incomplete, ts - server_mod._ANALYSIS_STATE_TTL_SEC - 1)
    srv.router.route_request.return_value = _status(True)
    assert srv._analysis_incomplete("k7m2") is False


def test_missing_instance_id_is_not_flagged(srv):
    assert srv._analysis_incomplete(None) is False
    assert srv._analysis_incomplete("") is False
    srv.router.route_request.assert_not_called()


def test_probe_failure_stays_silent(srv):
    """A spurious warning on every result would train the caller to ignore it."""
    srv.router.route_request.side_effect = RuntimeError("instance down")
    assert srv._analysis_incomplete("k7m2") is False


def test_malformed_probe_response_stays_silent(srv):
    srv.router.route_request.return_value = {"error": "nope"}
    assert srv._analysis_incomplete("k7m2") is False
    srv.router.route_request.return_value = {"structuredContent": "not a dict"}
    assert srv._analysis_incomplete("z9z9") is False


def _call_tool(srv, name, ida_response, incomplete, max_output=None):
    """Drive custom_tools_call with a canned IDA response."""
    srv.registry.get_active = MagicMock(return_value={"k7m2": {}})
    srv.router.route_request.return_value = ida_response
    srv._analysis_state_cache["k7m2"] = (incomplete, float("inf"))
    args = {"instance_id": "k7m2"}
    if max_output is not None:
        args["max_output_chars"] = max_output
    return srv.server.registry.methods["tools/call"](name=name, arguments=args)


def _has_warning(result):
    return any("auto-analysis has NOT finished" in c.get("text", "")
               for c in result.get("content", []))


def test_warning_is_attached_to_a_normal_result(srv):
    out = _call_tool(srv, "list_funcs", {"structuredContent": {"fns": [1, 2]}}, incomplete=True)
    assert _has_warning(out)


def test_warning_survives_truncation(srv):
    """The regression: the truncation branch rebuilt content from scratch.

    A big, still-analysing binary always takes that branch, so the warning was
    dropped in exactly the case it exists for. Caught live on a 23MB DLL with
    61k functions, where list_funcs came back with no warning attached.
    """
    big = {"structuredContent": {"fns": [{"addr": i, "name": f"sub_{i}"} for i in range(4000)]}}
    out = _call_tool(srv, "list_funcs", big, incomplete=True, max_output=500)
    assert "TRUNCATED" in out["content"][0]["text"], "expected the truncation path"
    assert _has_warning(out), "warning was dropped by the truncation branch"


def test_warning_is_attached_to_error_results(srv):
    out = _call_tool(srv, "list_funcs",
                     {"structuredContent": {"x": 1}, "isError": True}, incomplete=True)
    assert _has_warning(out)


def test_no_warning_once_analysis_is_finished(srv):
    out = _call_tool(srv, "list_funcs", {"structuredContent": {"fns": []}}, incomplete=False)
    assert not _has_warning(out)


def test_no_warning_for_insensitive_tools(srv):
    out = _call_tool(srv, "int_convert", {"structuredContent": {"v": 1}}, incomplete=True)
    assert not _has_warning(out)


def test_sensitive_set_covers_the_discovery_tools():
    """These are what an agent reaches for first on a new binary."""
    for name in ("list_funcs", "survey_binary", "func_query", "xrefs_to",
                 "similar_functions", "callgraph"):
        assert name in _ANALYSIS_SENSITIVE_TOOLS


def test_sensitive_set_excludes_tools_that_do_not_depend_on_analysis():
    """Warning on everything would make it noise."""
    for name in ("int_convert", "analysis_status", "analysis_wait",
                 "list_instances", "idb_save", "get_cached_output"):
        assert name not in _ANALYSIS_SENSITIVE_TOOLS


def test_server_instructions_lead_with_the_analysis_gate():
    assert "analysis_wait" in _SERVER_INSTRUCTIONS
    assert "INCOMPLETE" in _SERVER_INSTRUCTIONS
    # and the other rules an agent needs up front
    assert "instance_id" in _SERVER_INSTRUCTIONS
    assert "idb_save" in _SERVER_INSTRUCTIONS


def test_instructions_are_advertised_on_initialize(srv):
    result = srv.server.registry.methods["initialize"](
        protocolVersion="2025-06-18", capabilities={}, clientInfo={"name": "t", "version": "0"}
    )
    assert result["instructions"] == _SERVER_INSTRUCTIONS
