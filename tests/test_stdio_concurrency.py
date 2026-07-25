"""Tests for concurrent stdio dispatch in vendor/zeromcp.

The router proxies to N IDA instances that are separate processes and can serve
in parallel. Dispatching inline on the reader thread made the router a global
bottleneck: one slow tool call blocked every other instance's calls behind it.
These tests pin the properties that fix depends on.
"""

import io
import json
import threading
import time

import pytest

from ida_multi_mcp.vendor.zeromcp import McpServer


class _BlockingStdin(io.RawIOBase):
    """stdin whose readline() returns queued lines, then blocks until released.

    A plain BytesIO would hit EOF immediately and shut the pool down before the
    test could observe overlap.
    """

    def __init__(self, lines):
        self._lines = list(lines)
        self._eof = threading.Event()

    def readline(self, _limit=-1):
        if self._lines:
            return self._lines.pop(0)
        self._eof.wait(10)
        return b""

    def release(self):
        self._eof.set()


class _LockCheckingStdout(io.RawIOBase):
    """stdout that records writes and flags any interleaving between them."""

    def __init__(self):
        self.chunks = []
        self.interleaved = False
        self._writer = None
        self._guard = threading.Lock()

    def write(self, data):
        with self._guard:
            if self._writer is not None:
                self.interleaved = True
            self._writer = threading.current_thread().name
        time.sleep(0.001)  # widen the window for a real interleave to show up
        with self._guard:
            self.chunks.append(bytes(data))
            self._writer = None
        return len(data)

    def flush(self):
        pass

    def payload(self):
        return b"".join(self.chunks)


def _request(req_id, method, params=None):
    body = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        body["params"] = params
    return json.dumps(body).encode() + b"\n"


def _responses(stdout):
    lines = [l for l in stdout.payload().split(b"\n") if l.strip()]
    return [json.loads(l) for l in lines]


def _serve(server, stdin, stdout, **kwargs):
    thread = threading.Thread(
        target=server.stdio, args=(stdin, stdout), kwargs=kwargs, daemon=True
    )
    thread.start()
    return thread


def test_slow_request_does_not_block_a_later_one():
    """The regression: a slow call must not hold up an unrelated one."""
    server = McpServer("test")
    started = threading.Event()
    release = threading.Event()

    def slow() -> dict:
        started.set()
        release.wait(5)
        return {"who": "slow"}

    def fast() -> dict:
        return {"who": "fast"}

    server.registry.method(slow, "slow")
    server.registry.method(fast, "fast")

    stdin = _BlockingStdin([_request(1, "slow"), _request(2, "fast")])
    stdout = _LockCheckingStdout()
    thread = _serve(server, stdin, stdout, max_workers=4)

    assert started.wait(5), "slow request never started"

    # fast must complete while slow is still parked.
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        ids = [r.get("id") for r in _responses(stdout)]
        if 2 in ids:
            break
        time.sleep(0.01)
    else:
        pytest.fail("fast request was blocked behind the slow one")

    assert 1 not in [r.get("id") for r in _responses(stdout)], "slow finished early"

    release.set()
    stdin.release()
    thread.join(5)

    ids = sorted(r["id"] for r in _responses(stdout))
    assert ids == [1, 2]


def test_concurrent_writes_are_serialized_and_framing_holds():
    """Many simultaneous responses must not interleave on stdout."""
    server = McpServer("test")
    gate = threading.Barrier(6, timeout=5)

    def synchronized() -> dict:
        # Release all workers at once so they race toward stdout together.
        gate.wait()
        return {"payload": "x" * 500}

    server.registry.method(synchronized, "synchronized")

    stdin = _BlockingStdin([_request(i, "synchronized") for i in range(6)])
    stdout = _LockCheckingStdout()
    thread = _serve(server, stdin, stdout, max_workers=6)

    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and len(_responses(stdout)) < 6:
        time.sleep(0.01)

    stdin.release()
    thread.join(5)

    assert not stdout.interleaved, "stdout writes interleaved despite the lock"
    responses = _responses(stdout)
    assert sorted(r["id"] for r in responses) == list(range(6))
    assert all(r["result"]["payload"] == "x" * 500 for r in responses)


def test_notification_is_handled_inline_while_pool_is_saturated():
    """notifications/cancelled must reach an in-flight request, not queue behind it."""
    server = McpServer("test")
    observed = []
    release = threading.Event()
    started = threading.Event()

    def blocker() -> dict:
        started.set()
        release.wait(5)
        return {}

    def note() -> None:
        observed.append("delivered")

    server.registry.method(blocker, "blocker")
    server.registry.method(note, "notifications/note")

    notification = json.dumps(
        {"jsonrpc": "2.0", "method": "notifications/note"}
    ).encode() + b"\n"

    # One worker, already occupied: a pooled notification could never run.
    stdin = _BlockingStdin([_request(1, "blocker"), notification])
    stdout = _LockCheckingStdout()
    thread = _serve(server, stdin, stdout, max_workers=1)

    assert started.wait(5), "blocker never started"

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not observed:
        time.sleep(0.01)
    assert observed == ["delivered"], "notification queued behind the busy pool"

    release.set()
    stdin.release()
    thread.join(5)


def test_malformed_line_still_gets_a_parse_error():
    server = McpServer("test")
    stdin = _BlockingStdin([b"{not json\n"])
    stdout = _LockCheckingStdout()
    thread = _serve(server, stdin, stdout, max_workers=2)

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not _responses(stdout):
        time.sleep(0.01)

    stdin.release()
    thread.join(5)

    responses = _responses(stdout)
    assert responses and responses[0]["error"]["code"] == -32700


def test_oversized_line_is_rejected():
    server = McpServer("test")
    huge = b"{" + b"a" * (server._STDIO_MAX_LINE + 10) + b"}\n"
    stdin = _BlockingStdin([huge])
    stdout = _LockCheckingStdout()
    thread = _serve(server, stdin, stdout, max_workers=2)

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not _responses(stdout):
        time.sleep(0.01)

    stdin.release()
    thread.join(5)

    responses = _responses(stdout)
    assert responses and responses[0]["error"]["code"] == -32600


def test_worker_count_respects_env(monkeypatch):
    monkeypatch.setenv("IDA_MCP_STDIO_WORKERS", "3")
    assert McpServer._stdio_max_workers() == 3
    monkeypatch.setenv("IDA_MCP_STDIO_WORKERS", "garbage")
    assert McpServer._stdio_max_workers() == 8
    monkeypatch.delenv("IDA_MCP_STDIO_WORKERS")
    assert McpServer._stdio_max_workers() == 8
