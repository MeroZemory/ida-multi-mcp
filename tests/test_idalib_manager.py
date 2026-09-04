"""Tests for IdalibManager — subprocess lifecycle manager.

All tests mock subprocesses; no idapro required.
"""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from ida_multi_mcp.idalib_manager import (
    IdalibManager,
    _find_free_port,
    _preferred_loopback_host,
    _request_worker_shutdown,
)


class TestFindFreePort:
    def test_returns_positive_int(self):
        port = _find_free_port()
        assert isinstance(port, int)
        assert port > 0

    def test_returns_different_ports(self):
        ports = {_find_free_port() for _ in range(5)}
        # At least 2 unique ports (unlikely all 5 collide)
        assert len(ports) >= 2

    def test_supports_ipv6_loopback_when_available(self):
        try:
            port = _find_free_port("::1")
        except OSError:
            pytest.skip("IPv6 loopback is disabled")
        assert isinstance(port, int)
        assert port > 0


class TestPreferredLoopbackHost:
    @patch("ida_multi_mcp.idalib_manager.sys.platform", "win32")
    def test_windows_prefers_ipv6_when_bind_succeeds(self):
        fake_socket = MagicMock()
        fake_socket.__enter__.return_value = fake_socket
        with patch("ida_multi_mcp.idalib_manager.socket.socket", return_value=fake_socket):
            assert _preferred_loopback_host() == "::1"
        fake_socket.bind.assert_called_once_with(("::1", 0))

    @patch("ida_multi_mcp.idalib_manager.sys.platform", "win32")
    def test_windows_falls_back_when_ipv6_is_unavailable(self):
        fake_socket = MagicMock()
        fake_socket.__enter__.return_value = fake_socket
        fake_socket.bind.side_effect = OSError("IPv6 disabled")
        with patch("ida_multi_mcp.idalib_manager.socket.socket", return_value=fake_socket):
            assert _preferred_loopback_host() == "127.0.0.1"

    @patch("ida_multi_mcp.idalib_manager.sys.platform", "linux")
    def test_non_windows_preserves_ipv4_default(self):
        assert _preferred_loopback_host() == "127.0.0.1"


class TestWorkerShutdownRequest:
    @patch("ida_multi_mcp.idalib_manager.http.client.HTTPConnection")
    def test_accepts_only_explicit_success_response(self, mock_connection):
        response = MagicMock()
        response.status = 200
        response.read.return_value = b'{"jsonrpc":"2.0","result":{"accepted":true},"id":1}'
        mock_connection.return_value.getresponse.return_value = response

        assert _request_worker_shutdown("::1", 54321, "secret") is True
        request_body = mock_connection.return_value.request.call_args.args[2]
        assert '"ida-multi-mcp/shutdown"' in request_body
        assert '"secret"' in request_body
        mock_connection.return_value.close.assert_called_once()


@pytest.fixture(autouse=True)
def _mock_idalib_available():
    """Assume IDA Pro (idalib) is available in all manager tests."""
    with (
        patch("ida_multi_mcp.idalib_manager.is_idalib_available", return_value=True),
        patch("ida_multi_mcp.idalib_manager.atexit.register"),
    ):
        yield


class TestIdalibManagerSpawn:
    def test_spawn_rejected_without_ida_pro(self, tmp_path, tmp_registry):
        """Without IDA Pro, spawn_session should return a clear error."""
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00" * 16)
        with patch("ida_multi_mcp.idalib_manager.is_idalib_available", return_value=False):
            mgr = IdalibManager(tmp_registry)
            result = mgr.spawn_session(str(binary))
            assert "error" in result
            assert "IDA Pro" in result["error"]

    def test_spawn_file_not_found(self, tmp_path, tmp_registry):
        mgr = IdalibManager(tmp_registry)
        result = mgr.spawn_session(str(tmp_path / "nonexistent.exe"))
        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_spawn_bad_python_executable(self, tmp_path, tmp_registry):
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00" * 16)
        mgr = IdalibManager(tmp_registry, python_executable="/no/such/python")
        result = mgr.spawn_session(str(binary))
        assert "error" in result

    @patch("ida_multi_mcp.idalib_manager.subprocess.Popen")
    @patch("ida_multi_mcp.idalib_manager.ping_instance")
    def test_spawn_success(self, mock_ping, mock_popen, tmp_path, tmp_registry):
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00" * 16)

        mock_proc = MagicMock()
        mock_proc.pid = 99999
        mock_proc.poll.return_value = None  # still running
        mock_proc.stderr.read.return_value = b""  # drain thread sentinel
        mock_popen.return_value = mock_proc
        mock_ping.return_value = True

        mgr = IdalibManager(tmp_registry)
        result = mgr.spawn_session(str(binary))

        assert "error" not in result
        assert "instance_id" in result
        assert result["pid"] == 99999
        assert result["binary"] == "test.bin"

        # Verify registered in registry
        info = tmp_registry.get_instance(result["instance_id"])
        assert info is not None
        assert info["type"] == "idalib"

    @patch("ida_multi_mcp.idalib_manager.subprocess.Popen")
    @patch("ida_multi_mcp.idalib_manager.ping_instance")
    def test_spawn_uses_devnull_stdin(self, mock_ping, mock_popen, tmp_path, tmp_registry):
        """The worker must inherit stdin=DEVNULL, otherwise idalib.dll blocks
        reading the MCP protocol pipe when the server is a stdio child."""
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00" * 16)

        mock_proc = MagicMock()
        mock_proc.pid = 99999
        mock_proc.poll.return_value = None
        mock_proc.stderr.read.return_value = b""  # drain thread sentinel
        mock_popen.return_value = mock_proc
        mock_ping.return_value = True

        mgr = IdalibManager(tmp_registry)
        mgr.spawn_session(str(binary))

        assert mock_popen.call_args.kwargs["stdin"] == subprocess.DEVNULL
        assert "IDA_MULTI_MCP_WORKER_SHUTDOWN_TOKEN" in mock_popen.call_args.kwargs["env"]

    @patch("ida_multi_mcp.idalib_manager.query_binary_metadata",
           return_value={"module": "test.exe", "path": "/tmp/test.exe.i64"})
    @patch("ida_multi_mcp.idalib_manager.subprocess.Popen")
    @patch("ida_multi_mcp.idalib_manager.ping_instance", return_value=True)
    def test_spawn_on_idb_uses_canonical_module_name(
        self, mock_ping, mock_popen, mock_meta, tmp_path, tmp_registry,
    ):
        """Opening an IDB (.i64) must register the original binary name so the
        router's metadata-resource check doesn't flag the instance as stale."""
        idb = tmp_path / "test.exe.i64"
        idb.write_bytes(b"\x00" * 16)

        mock_proc = MagicMock()
        mock_proc.pid = 77777
        mock_proc.poll.return_value = None
        mock_proc.stderr.read.return_value = b""  # drain thread sentinel
        mock_popen.return_value = mock_proc

        mgr = IdalibManager(tmp_registry)
        result = mgr.spawn_session(str(idb))

        assert "error" not in result
        info = tmp_registry.get_instance(result["instance_id"])
        assert info["binary_name"] == "test.exe"

    @patch("ida_multi_mcp.idalib_manager.time.sleep")
    @patch(
        "ida_multi_mcp.idalib_manager.query_binary_metadata",
        side_effect=[None, {"module": "test.exe", "path": "/tmp/test.exe.i64"}],
    )
    @patch("ida_multi_mcp.idalib_manager.subprocess.Popen")
    @patch("ida_multi_mcp.idalib_manager.ping_instance", return_value=True)
    def test_spawn_on_idb_retries_transient_metadata_reset(
        self, mock_ping, mock_popen, mock_meta, mock_sleep, tmp_path, tmp_registry,
    ):
        idb = tmp_path / "test.exe.i64"
        idb.write_bytes(b"\x00" * 16)

        mock_proc = MagicMock()
        mock_proc.pid = 77778
        mock_proc.poll.return_value = None
        mock_proc.stderr.read.return_value = b""
        mock_popen.return_value = mock_proc

        mgr = IdalibManager(tmp_registry)
        result = mgr.spawn_session(str(idb))

        assert "error" not in result
        assert mock_meta.call_count == 2
        mock_sleep.assert_called_once()
        info = tmp_registry.get_instance(result["instance_id"])
        assert info["binary_name"] == "test.exe"

    @patch("ida_multi_mcp.idalib_manager.IdalibManager._terminate_gracefully")
    @patch("ida_multi_mcp.idalib_manager.time.sleep")
    @patch("ida_multi_mcp.idalib_manager.query_binary_metadata", return_value=None)
    @patch("ida_multi_mcp.idalib_manager.subprocess.Popen")
    @patch("ida_multi_mcp.idalib_manager.ping_instance", return_value=True)
    def test_spawn_on_idb_fails_closed_without_canonical_metadata(
        self,
        mock_ping,
        mock_popen,
        mock_meta,
        mock_sleep,
        mock_terminate,
        tmp_path,
        tmp_registry,
    ):
        idb = tmp_path / "renamed.i64"
        idb.write_bytes(b"\x00" * 16)

        mock_proc = MagicMock()
        mock_proc.pid = 77779
        mock_proc.poll.return_value = None
        mock_proc.stderr.read.return_value = b""
        mock_popen.return_value = mock_proc

        mgr = IdalibManager(tmp_registry)
        result = mgr.spawn_session(str(idb), host="127.0.0.1")

        assert "canonical IDB module metadata was unavailable" in result["error"]
        assert mock_meta.call_count == 4
        assert mock_sleep.call_count == 3
        assert mock_terminate.call_args.args == (mock_proc,)
        assert mock_terminate.call_args.kwargs["host"] == "127.0.0.1"
        assert mock_terminate.call_args.kwargs["port"] > 0
        assert mock_terminate.call_args.kwargs["shutdown_token"]
        assert tmp_registry.list_instances() == {}

    @patch("ida_multi_mcp.idalib_manager.subprocess.Popen")
    @patch("ida_multi_mcp.idalib_manager.ping_instance", return_value=False)
    def test_spawn_timeout(self, mock_ping, mock_popen, tmp_path, tmp_registry):
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00" * 16)

        mock_proc = MagicMock()
        mock_proc.pid = 99999
        mock_proc.poll.return_value = None
        # Simulate the worker writing to stderr before the drain thread reads
        # it: first read returns the data, second read returns b"" (EOF) which
        # stops the iter() in _drain_stderr.
        mock_proc.stderr.read.side_effect = [b"analysis failed", b""]
        mock_popen.return_value = mock_proc

        mgr = IdalibManager(tmp_registry)
        result = mgr.spawn_session(str(binary), timeout=1)

        assert "error" in result
        assert "ready" in result["error"].lower()
        # The drain thread must have captured the worker's stderr and surfaced
        # it in the diagnostic — this verifies the terminate→wait→join→read
        # ordering produces the worker's dying output, not an empty string.
        assert "analysis failed" in result["error"]


class TestIdalibManagerClose:
    @patch("ida_multi_mcp.idalib_manager.subprocess.Popen")
    @patch("ida_multi_mcp.idalib_manager.ping_instance", return_value=True)
    def test_close_session(self, mock_ping, mock_popen, tmp_path, tmp_registry):
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00" * 16)

        mock_proc = MagicMock()
        mock_proc.pid = 99999
        mock_proc.poll.return_value = None
        mock_proc.stderr.read.return_value = b""  # drain thread sentinel
        mock_popen.return_value = mock_proc

        mgr = IdalibManager(tmp_registry)
        spawn_result = mgr.spawn_session(str(binary))
        iid = spawn_result["instance_id"]

        close_result = mgr.close_session(iid)
        assert close_result.get("ok") is True

        # Verify unregistered
        assert tmp_registry.get_instance(iid) is None

    def test_close_nonexistent_session(self, tmp_registry):
        mgr = IdalibManager(tmp_registry)
        result = mgr.close_session("nonexistent")
        assert "error" in result


class TestGracefulTermination:
    @patch("ida_multi_mcp.idalib_manager._request_worker_shutdown", return_value=True)
    def test_authenticated_rpc_allows_clean_exit(self, mock_shutdown):
        proc = MagicMock()
        proc.poll.return_value = None

        IdalibManager._terminate_gracefully(
            proc,
            host="::1",
            port=54321,
            shutdown_token="secret",
        )

        mock_shutdown.assert_called_once_with("::1", 54321, "secret")
        proc.wait.assert_called_once_with(timeout=60)
        proc.send_signal.assert_not_called()
        proc.terminate.assert_not_called()
        proc.kill.assert_not_called()

    def test_skips_already_exited(self):
        proc = MagicMock()
        proc.poll.return_value = 0  # already exited
        IdalibManager._terminate_gracefully(proc)
        proc.wait.assert_not_called()
        proc.kill.assert_not_called()

    def test_graceful_signal_then_wait(self):
        proc = MagicMock()
        proc.poll.return_value = None
        IdalibManager._terminate_gracefully(proc)
        # Graceful path: no force-kill needed.
        proc.wait.assert_called_once()
        proc.kill.assert_not_called()

    def test_falls_back_to_kill_on_timeout(self):
        proc = MagicMock()
        proc.poll.return_value = None
        # Both graceful and terminate waits time out → hard kill.
        proc.wait.side_effect = subprocess.TimeoutExpired(cmd="worker", timeout=10)
        IdalibManager._terminate_gracefully(proc)
        proc.terminate.assert_called_once()
        proc.kill.assert_called_once()

    @patch("ida_multi_mcp.idalib_manager.sys.platform", "win32")
    def test_windows_uses_ctrl_break(self):
        import signal
        # CTRL_BREAK_EVENT only exists on Windows; create it so the win32 code
        # path is exercisable on Linux/macOS CI runners too.
        sentinel = getattr(signal, "CTRL_BREAK_EVENT", 1)
        with patch.object(signal, "CTRL_BREAK_EVENT", sentinel, create=True):
            proc = MagicMock()
            proc.poll.return_value = None
            IdalibManager._terminate_gracefully(proc)
            proc.send_signal.assert_called_once_with(sentinel)


class TestIdalibManagerList:
    @patch("ida_multi_mcp.idalib_manager.subprocess.Popen")
    @patch("ida_multi_mcp.idalib_manager.ping_instance", return_value=True)
    @patch("ida_multi_mcp.idalib_manager.is_process_alive", return_value=True)
    def test_list_sessions(self, mock_alive, mock_ping, mock_popen, tmp_path, tmp_registry):
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00" * 16)

        mock_proc = MagicMock()
        mock_proc.pid = 99999
        mock_proc.poll.return_value = None
        mock_proc.stderr.read.return_value = b""  # drain thread sentinel
        mock_popen.return_value = mock_proc

        mgr = IdalibManager(tmp_registry)
        mgr.spawn_session(str(binary))

        sessions = mgr.list_sessions()
        assert len(sessions) == 1
        assert sessions[0]["type"] == "idalib"
        assert sessions[0]["binary_name"] == "test.bin"


class TestIdalibManagerStatus:
    @patch("ida_multi_mcp.idalib_manager.subprocess.Popen")
    @patch("ida_multi_mcp.idalib_manager.ping_instance", return_value=True)
    @patch("ida_multi_mcp.idalib_manager.is_process_alive", return_value=True)
    def test_status_healthy(self, mock_alive, mock_ping, mock_popen, tmp_path, tmp_registry):
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00" * 16)

        mock_proc = MagicMock()
        mock_proc.pid = 99999
        mock_proc.poll.return_value = None
        mock_proc.stderr.read.return_value = b""  # drain thread sentinel
        mock_popen.return_value = mock_proc

        mgr = IdalibManager(tmp_registry)
        spawn_result = mgr.spawn_session(str(binary))
        iid = spawn_result["instance_id"]

        status = mgr.get_status(iid)
        assert status["alive"] is True
        assert status["reachable"] is True


class TestListInstancesTypeField:
    """Verify that list_instances includes the 'type' field."""

    def test_gui_instance_defaults_to_gui(self, tmp_registry):
        """Existing instances without explicit type should default to 'gui'."""
        from ida_multi_mcp.tools.management import list_instances, set_registry
        set_registry(tmp_registry)

        tmp_registry.register(pid=1, port=100, idb_path="/a.i64",
                              binary_name="a.exe", host="127.0.0.1")
        result = list_instances()
        assert result["count"] == 1
        assert result["instances"][0]["type"] == "gui"

    def test_idalib_instance_shows_idalib(self, tmp_registry):
        from ida_multi_mcp.tools.management import list_instances, set_registry
        set_registry(tmp_registry)

        tmp_registry.register(pid=2, port=200, idb_path="/b.i64",
                              binary_name="b.exe", host="127.0.0.1",
                              type="idalib")
        result = list_instances()
        assert result["count"] == 1
        assert result["instances"][0]["type"] == "idalib"
