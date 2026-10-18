"""Content identity regressions, including a real loopback resource response."""

import hashlib
import ast
import importlib.util
import json
from pathlib import Path
import sys
import threading
import types
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

import pytest

from ida_multi_mcp.health import query_binary_identity, rediscover_instances
from ida_multi_mcp.identity import normalize_fingerprint, read_input_fingerprint
from ida_multi_mcp.registry import InstanceRegistry
from ida_multi_mcp.router import InstanceRouter
from ida_multi_mcp.tools import similarity


def fingerprint(data):
    return {"algorithm": "sha256", "digest": hashlib.sha256(data).hexdigest()}


ORIGINAL = fingerprint(b"first executable")
REPLACEMENT = fingerprint(b"second executable")


@pytest.fixture
def registered(tmp_path):
    registry = InstanceRegistry(str(tmp_path / "instances.json"))
    iid = registry.register(pid=123, port=12345, idb_path="sample.i64",
                            binary_name="sample.exe", input_fingerprint=ORIGINAL)
    return registry, InstanceRouter(registry), iid


def test_same_name_different_content_never_forwards(registered):
    registry, router, iid = registered
    # The registration baseline survives a server/registry restart.
    registry = InstanceRegistry(registry.registry_path)
    router = InstanceRouter(registry)
    with patch("ida_multi_mcp.router.query_binary_identity", return_value={
        "module": "sample.exe", "input_fingerprint": REPLACEMENT,
    }), patch.object(router, "_send_request") as forward:
        result = router.route_request("tools/call", {"arguments": {"instance_id": iid}})
    assert "error" in result
    forward.assert_not_called()


def test_unavailable_identity_is_retryable_without_forwarding(registered):
    _, router, iid = registered
    with patch("ida_multi_mcp.router.query_binary_identity", side_effect=[None, {
        "module": "sample.exe", "input_fingerprint": ORIGINAL,
    }]) as query, patch.object(router, "_send_request", return_value={"ok": True}) as forward:
        params = {"arguments": {"instance_id": iid}}
        assert "error" in router.route_request("tools/call", params)
        assert router.route_request("tools/call", params) == {"ok": True}
    assert query.call_count == 2
    forward.assert_called_once()


def test_legacy_registration_requires_reregistration(registered):
    registry, router, iid = registered
    info = registry.get_instance(iid)
    info.pop("input_fingerprint")
    with patch("ida_multi_mcp.router.query_binary_identity") as query:
        assert router._verify_binary_path(iid, info) is False
    query.assert_not_called()


@pytest.mark.parametrize("field,value", [
    ("host", "::1"), ("port", 12346), ("pid", 124),
    ("registered_at", "later"), ("idb_path", "other.i64"),
    ("input_fingerprint", REPLACEMENT),
])
def test_cached_identity_is_bound_to_registration(registered, field, value):
    registry, router, iid = registered
    info = registry.get_instance(iid)
    with patch("ida_multi_mcp.router.query_binary_identity", side_effect=[
        {"module": "sample.exe", "input_fingerprint": ORIGINAL},
        {"module": "sample.exe", "input_fingerprint": REPLACEMENT},
    ]) as query:
        assert router._verify_binary_path(iid, info)
        changed = {**info, field: value}
        assert router._verify_binary_path(iid, changed) is (field == "input_fingerprint")
    assert query.call_count == 2


def test_cache_refresh_detects_same_name_swap(registered):
    registry, router, iid = registered
    info = registry.get_instance(iid)
    with patch("ida_multi_mcp.router.time.monotonic", side_effect=[100, 106]), patch(
        "ida_multi_mcp.router.query_binary_identity", side_effect=[
            {"module": "sample.exe", "input_fingerprint": ORIGINAL},
            {"module": "sample.exe", "input_fingerprint": REPLACEMENT},
        ],
    ):
        assert router._verify_binary_path(iid, info)
        assert not router._verify_binary_path(iid, info)


@pytest.mark.parametrize("value", [None, {}, {"algorithm": [], "digest": "x"},
                                    {"algorithm": "sha256", "digest": "unavailable"}])
def test_invalid_digest_is_not_identity(value):
    assert normalize_fingerprint(value) is None


def test_stored_digest_does_not_require_original_file(monkeypatch):
    ida = types.SimpleNamespace(retrieve_input_file_sha256=lambda: bytes.fromhex(ORIGINAL["digest"]))
    monkeypatch.setitem(sys.modules, "ida_nalt", ida)
    with patch("builtins.open", side_effect=AssertionError("must not read disk input")):
        assert read_input_fingerprint() == ORIGINAL


def test_md5_fallback_when_sha256_unavailable(monkeypatch):
    ida = types.SimpleNamespace(retrieve_input_file_md5=lambda: bytes.fromhex("ab" * 16))
    monkeypatch.setitem(sys.modules, "ida_nalt", ida)
    assert read_input_fingerprint() == {"algorithm": "md5", "digest": "ab" * 16}


def test_similarity_refuses_path_and_count_fallback():
    with patch.object(similarity, "_call_ida", return_value={"function_count": 10}):
        key, _ = similarity._instance_key("aaaa")
    assert key is None


def test_gui_registration_captures_idb_digest(monkeypatch):
    path = Path(__file__).resolve().parents[1] / "src/ida_multi_mcp/plugin/registration.py"
    spec = importlib.util.spec_from_file_location("registration_under_test", path)
    registration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(registration)

    monkeypatch.setitem(sys.modules, "idaapi", types.SimpleNamespace(get_input_file_path=lambda: "sample.exe"))
    monkeypatch.setitem(sys.modules, "idc", types.SimpleNamespace(get_idb_path=lambda: "sample.i64"))
    monkeypatch.setitem(sys.modules, "ida_ida", types.SimpleNamespace(
        inf_is_64bit=lambda: True, inf_get_procname=lambda: "metapc"))
    monkeypatch.setitem(sys.modules, "ida_nalt", types.SimpleNamespace(
        retrieve_input_file_sha256=lambda: bytes.fromhex(ORIGINAL["digest"])))
    assert registration.get_binary_metadata()["input_fingerprint"] == ORIGINAL


def test_rediscovery_captures_identity(tmp_path):
    registry = InstanceRegistry(str(tmp_path / "instances.json"))
    with patch("ida_multi_mcp.health._find_ida_listening_ports", return_value=[(42, 12345)]), patch(
        "ida_multi_mcp.health.ping_instance", return_value=True,
    ), patch("ida_multi_mcp.health.query_binary_metadata", return_value={
        "module": "sample.exe", "path": "sample.i64",
    }), patch("ida_multi_mcp.health.query_binary_identity", return_value={
        "module": "sample.exe", "input_fingerprint": ORIGINAL,
    }):
        ids = rediscover_instances(registry)
    assert len(ids) == 1
    assert registry.get_instance(ids[0])["input_fingerprint"] == ORIGINAL


def test_ida_identity_resource_never_opens_original_file():
    # Load the actual resource body without importing unrelated IDA-only tools.
    path = Path(__file__).resolve().parents[1] / "src/ida_multi_mcp/ida_mcp/api_resources.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "idb_identity_resource")
    node.decorator_list = []
    namespace = {
        "ida_nalt": types.SimpleNamespace(get_root_filename=lambda: "sample.exe"),
        "read_input_fingerprint": lambda: ORIGINAL,
    }
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec"), namespace)
    with patch("builtins.open", side_effect=AssertionError("must not read disk input")):
        assert namespace["idb_identity_resource"]() == {
            "module": "sample.exe", "input_fingerprint": ORIGINAL,
        }


def test_identity_round_trip_and_route_over_real_http(tmp_path):
    state = {"input_fingerprint": ORIGINAL, "module": "sample.exe"}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert request["params"]["uri"] == "ida://idb/identity"
            body = json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": {
                "contents": [{"type": "text", "text": json.dumps(state)}],
            }}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_port
        observed = query_binary_identity("127.0.0.1", port)
        assert observed == state
        registry = InstanceRegistry(str(tmp_path / "instances.json"))
        iid = registry.register(pid=42, port=port, idb_path="sample.i64",
                                binary_name=observed["module"], input_fingerprint=observed["input_fingerprint"])
        router = InstanceRouter(registry)
        router._cache_timeout = 0
        assert router._verify_binary_path(iid, registry.get_instance(iid))
        state["input_fingerprint"] = REPLACEMENT
        with patch.object(router, "_send_request") as forward:
            assert "error" in router.route_request("tools/call", {"arguments": {"instance_id": iid}})
        forward.assert_not_called()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
