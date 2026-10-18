"""Tests for router.py — Request routing with mock HTTP."""

import json
import time
from unittest.mock import patch, MagicMock

import pytest

from ida_multi_mcp.registry import InstanceRegistry
from ida_multi_mcp.router import InstanceRouter

FP = {"algorithm": "sha256", "digest": "a" * 64}


@pytest.fixture
def router_env(tmp_path):
    """Return (registry, router, instance_id) with one registered instance."""
    reg = InstanceRegistry(str(tmp_path / "inst.json"))
    iid = reg.register(
        pid=42, port=7000, idb_path="/test.i64",
        binary_name="test.exe", host="127.0.0.1", input_fingerprint=FP,
    )
    router = InstanceRouter(reg)
    return reg, router, iid


class TestMissingInstanceId:
    def test_auto_selects_single_instance(self, router_env):
        """With 1 instance, missing instance_id should auto-select (not error)."""
        reg, router, iid = router_env
        resp = router.route_request("tools/call", {"arguments": {}})
        # Should NOT get "Missing instance_id" — may get connection error instead
        if "error" in resp:
            assert "instance_id" not in str(resp["error"]).lower()

    def test_error_with_multiple_instances(self, tmp_path):
        """With 2+ instances, missing instance_id should error."""
        reg = InstanceRegistry(str(tmp_path / "inst.json"))
        reg.register(pid=42, port=7000, idb_path="/a.i64",
                     binary_name="a.exe", host="127.0.0.1")
        reg.register(pid=43, port=7001, idb_path="/b.i64",
                     binary_name="b.exe", host="127.0.0.1")
        router = InstanceRouter(reg)
        resp = router.route_request("tools/call", {"arguments": {}})
        assert "error" in resp
        assert "instance_id" in resp["error"]


class TestNonexistentInstance:
    def test_nonexistent_instance_error(self, router_env):
        _, router, _ = router_env
        resp = router.route_request("tools/call",
                                    {"arguments": {"instance_id": "nope"}})
        assert "error" in resp
        assert "not found" in resp["error"]


class TestExpiredInstance:
    def test_expired_with_reason_and_replacements(self, router_env):
        reg, router, iid = router_env
        # Register a replacement then expire the original
        iid2 = reg.register(pid=43, port=7001, idb_path="/test2.i64",
                            binary_name="test.exe", host="127.0.0.1")
        reg.expire_instance(iid, reason="binary_changed", replaced_by=iid2)
        resp = router.route_request("tools/call",
                                    {"arguments": {"instance_id": iid}})
        assert "error" in resp
        assert resp["reason"] == "binary_changed"
        assert any(r["id"] == iid2 for r in resp.get("replacements", []))


class TestBinaryPathVerification:
    def _mock_metadata(self, module_name):
        return {"module": module_name, "input_fingerprint": FP}

    def test_match(self, router_env):
        _, router, iid = router_env
        with patch("ida_multi_mcp.router.query_binary_identity",
                   return_value=self._mock_metadata("test.exe")):
            result = router._verify_binary_path(
                iid, {"binary_name": "test.exe", "host": "127.0.0.1", "port": 7000, "input_fingerprint": FP})
        assert result is True

    def test_mismatch(self, router_env):
        _, router, iid = router_env
        with patch("ida_multi_mcp.router.query_binary_identity",
                   return_value=self._mock_metadata("other.exe")):
            result = router._verify_binary_path(
                iid, {"binary_name": "test.exe", "host": "127.0.0.1", "port": 7000, "input_fingerprint": FP})
        assert result is False

    def test_query_fails_returns_false(self, router_env):
        """When identity cannot be verified, do not forward requests."""
        _, router, iid = router_env
        with patch("ida_multi_mcp.router.query_binary_identity",
                   return_value=None):
            result = router._verify_binary_path(
                iid, {"binary_name": "test.exe", "host": "127.0.0.1", "port": 7000, "input_fingerprint": FP})
        assert result is False


class TestVerificationCache:
    def test_cache_hit(self, router_env):
        _, router, iid = router_env
        with patch("ida_multi_mcp.router.query_binary_identity",
                   return_value={"module": "test.exe", "input_fingerprint": FP}) as mock_query:
            info = {"binary_name": "test.exe", "host": "127.0.0.1", "port": 7000, "input_fingerprint": FP}
            router._verify_binary_path(iid, info)
            router._verify_binary_path(iid, info)
            assert mock_query.call_count == 1  # cached

    def test_cache_expiry(self, router_env):
        _, router, iid = router_env
        router._cache_timeout = 0  # expire immediately
        with patch("ida_multi_mcp.router.query_binary_identity",
                   return_value={"module": "test.exe", "input_fingerprint": FP}) as mock_query:
            info = {"binary_name": "test.exe", "host": "127.0.0.1", "port": 7000, "input_fingerprint": FP}
            router._verify_binary_path(iid, info)
            time.sleep(0.01)
            router._verify_binary_path(iid, info)
            assert mock_query.call_count == 2  # cache expired

    def test_failed_identity_read_stays_blocked(self, router_env):
        """Failed queries must not grant a window of unchecked routing."""
        _, router, iid = router_env
        info = {"binary_name": "test.exe", "host": "127.0.0.1", "port": 7000, "input_fingerprint": FP}
        with patch("ida_multi_mcp.router.query_binary_identity",
                   return_value=None):
            first = router._verify_binary_path(iid, info)
            second = router._verify_binary_path(iid, info)
        assert first is False
        assert second is False


class TestSendRequest:
    def test_strips_instance_id(self, router_env):
        _, router, iid = router_env
        response_data = json.dumps({
            "jsonrpc": "2.0",
            "result": {"data": "ok"},
            "id": 1,
        }).encode()

        mock_response = MagicMock()
        mock_response.read.return_value = response_data
        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_response

        with patch("ida_multi_mcp.router.query_binary_identity",
                   return_value={"module": "test.exe", "input_fingerprint": FP}):
            with patch("http.client.HTTPConnection", return_value=mock_conn):
                resp = router.route_request("tools/call", {
                    "arguments": {"instance_id": iid, "addr": "0x1000"}
                })

        # Verify instance_id was stripped from the forwarded request
        call_args = mock_conn.request.call_args
        body = json.loads(call_args[0][2])
        assert "instance_id" not in body["params"]["arguments"]

    def test_ssrf_blocked(self, router_env):
        _, router, _ = router_env
        resp = router._send_request(
            {"host": "10.0.0.1", "port": 80}, "tools/call", {})
        assert "error" in resp
        assert "refused" in resp["error"]

    def test_connection_failure(self, router_env):
        _, router, iid = router_env
        with patch("ida_multi_mcp.router.query_binary_identity",
                   return_value={"module": "test.exe", "input_fingerprint": FP}):
            with patch("http.client.HTTPConnection",
                       side_effect=ConnectionRefusedError):
                resp = router.route_request("tools/call", {
                    "arguments": {"instance_id": iid}
                })
        assert "error" in resp

    def test_connection_closed_on_error(self, router_env):
        """The socket must be released even when the request raises."""
        _, router, _ = router_env
        mock_conn = MagicMock()
        mock_conn.request.side_effect = OSError("boom")
        with patch("http.client.HTTPConnection", return_value=mock_conn):
            resp = router._send_request(
                {"host": "127.0.0.1", "port": 7000}, "tools/call", {})
        assert "error" in resp
        mock_conn.close.assert_called_once()

    def test_connection_closed_on_success(self, router_env):
        _, router, _ = router_env
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"result": {"ok": True}}).encode()
        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_response
        with patch("http.client.HTTPConnection", return_value=mock_conn):
            resp = router._send_request(
                {"host": "127.0.0.1", "port": 7000}, "tools/call", {})
        assert resp == {"ok": True}
        mock_conn.close.assert_called_once()
