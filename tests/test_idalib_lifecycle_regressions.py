"""Real loopback transport regressions; no IDA installation or database writes."""

import json
import subprocess
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace
from unittest.mock import MagicMock

from ida_multi_mcp import idalib_manager as manager
from ida_multi_mcp.idalib_worker import _register_shutdown_rpc


@contextmanager
def http_server(handler):
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=7)
        assert not thread.is_alive()


def test_slow_identity_is_not_replaced_by_repeated_expensive_metadata(
    monkeypatch, tmp_path, tmp_registry,
):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            uri = request["params"]["uri"]
            seen.append(uri)
            time.sleep(5.1)  # A healthy response beyond the previous five-second budget.
            body = json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": {
                "contents": [{"text": json.dumps({"module": "original.exe", "input_fingerprint": {
                    "algorithm": "sha256", "digest": "ab" * 32,
                }})}],
            }}).encode()
            try:
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass  # Old code abandons a valid response; retain the test outcome.

    proc = MagicMock()
    proc.pid = 123456
    proc.poll.return_value = None
    proc.stderr.read.return_value = b""
    stopped = MagicMock()
    monkeypatch.setattr(manager, "is_idalib_available", lambda: True)
    monkeypatch.setattr(manager.atexit, "register", lambda *_args: None)
    monkeypatch.setattr(manager.subprocess, "Popen", lambda *_args, **_kw: proc)
    monkeypatch.setattr(manager.IdalibManager, "_wait_for_ready", lambda *_args: True)
    monkeypatch.setattr(manager.IdalibManager, "_terminate_gracefully", stopped)
    database = tmp_path / "renamed.i64"
    database.write_bytes(b"synthetic")
    with http_server(Handler) as port:
        monkeypatch.setattr(manager, "_find_free_port", lambda _host: port)
        result = manager.IdalibManager(tmp_registry).spawn_session(str(database), host="127.0.0.1")
    assert "error" not in result
    assert seen == ["ida://idb/identity"]
    info = tmp_registry.get_instance(result["instance_id"])
    assert info["binary_name"] == "original.exe"
    assert info["input_fingerprint"] == {"algorithm": "sha256", "digest": "ab" * 32}
    stopped.assert_not_called()


def test_delivered_shutdown_with_lost_response_keeps_save_grace(monkeypatch):
    accepted = threading.Event()
    methods = {}

    class Registry:
        def method(self, function, *, name):
            methods[name] = function

    worker = SimpleNamespace(registry=Registry(), stop=accepted.set)
    _register_shutdown_rpc(worker, "test-only-token")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            methods[request["method"]](**request["params"])
            assert accepted.wait(1)
            self.close_connection = True  # Delivered RPC, deliberately lost acknowledgement.

    proc = MagicMock()
    proc.poll.return_value = None

    def wait(*, timeout):
        assert accepted.is_set()
        # Simulate a 20-second packed save without making the suite sleep 20 seconds.
        if timeout < 20:
            raise subprocess.TimeoutExpired("worker", timeout)

    proc.wait.side_effect = wait
    with http_server(Handler) as port:
        manager.IdalibManager._terminate_gracefully(
            proc, host="127.0.0.1", port=port, shutdown_token="test-only-token",
        )
    assert accepted.is_set()
    proc.send_signal.assert_not_called()
    proc.terminate.assert_not_called()
    proc.kill.assert_not_called()


def test_status_removes_dead_worker_shutdown_token(monkeypatch, tmp_registry):
    monkeypatch.setattr(manager.atexit, "register", lambda *_args: None)
    monkeypatch.setattr(manager, "is_process_alive", lambda _pid: False)
    instance = manager.IdalibManager(tmp_registry)
    iid = tmp_registry.register(pid=123456, port=1, idb_path="a.i64", type="idalib")
    instance._processes[iid] = SimpleNamespace(pid=123456)
    instance._shutdown_tokens[iid] = "test-only-token"
    instance.get_status(iid)
    assert iid not in instance._shutdown_tokens


def test_unknown_shutdown_uses_one_drain_and_save_deadline(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(manager.time, "monotonic", lambda: clock[0])
    calls = []

    def lost_ack(host, port, token, *, timeout):
        calls.append((host, port, token, timeout))
        clock[0] = 295.0  # RPC was queued behind a supported long-running call.
        return False

    monkeypatch.setattr(manager, "_request_worker_shutdown", lost_ack)
    proc = MagicMock()
    proc.poll.return_value = None
    manager.IdalibManager._terminate_gracefully(
        proc, host="::1", port=1, shutdown_token="test-only-token",
    )
    assert calls == [("::1", 1, "test-only-token", 300.0)]
    proc.wait.assert_called_once_with(timeout=65.0)
    proc.terminate.assert_not_called()
    proc.kill.assert_not_called()


def test_identity_timeout_does_not_queue_another_full_budget(
    monkeypatch, tmp_path, tmp_registry,
):
    clock = [0.0]
    monkeypatch.setattr(manager.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(manager.time, "sleep", lambda _delay: None)
    monkeypatch.setattr(manager, "is_idalib_available", lambda: True)
    monkeypatch.setattr(manager.atexit, "register", lambda *_args: None)
    monkeypatch.setattr(manager, "_find_free_port", lambda _host: 12345)
    monkeypatch.setattr(manager.IdalibManager, "_wait_for_ready", lambda *_args: True)
    stopped = MagicMock()
    monkeypatch.setattr(manager.IdalibManager, "_terminate_gracefully", stopped)
    proc = MagicMock()
    proc.pid = 123456
    proc.poll.return_value = None
    proc.stderr.read.return_value = b""
    monkeypatch.setattr(manager.subprocess, "Popen", lambda *_args, **_kw: proc)
    calls = []

    def timeout_identity(host, port, *, timeout):
        calls.append((host, port, timeout))
        clock[0] += timeout
        return None

    monkeypatch.setattr(manager, "query_binary_identity", timeout_identity)
    database = tmp_path / "slow.i64"
    database.write_bytes(b"synthetic")
    result = manager.IdalibManager(tmp_registry).spawn_session(str(database), host="127.0.0.1")
    assert "error" in result
    assert calls == [("127.0.0.1", 12345, 30.0)]
    assert tmp_registry.list_instances() == {}
    stopped.assert_called_once()
