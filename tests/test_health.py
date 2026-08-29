"""Tests for health.py — Process alive checks and HTTP ping."""

import json
import sys
from unittest.mock import patch, MagicMock

import pytest

from ida_multi_mcp.health import (
    is_process_alive,
    ping_instance,
    check_instance_health,
    cleanup_stale_instances,
    query_binary_metadata,
    rediscover_instances,
    _console_output,
    _find_ida_listening_ports,
)


# ---------------------------------------------------------------------------
# is_process_alive
# ---------------------------------------------------------------------------

class TestIsProcessAlive:
    @pytest.mark.skipif(sys.platform == "win32", reason="Unix-only test")
    def test_unix_success(self):
        with patch("os.kill") as mock_kill:
            mock_kill.return_value = None
            assert is_process_alive(1234) is True

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix-only test")
    def test_unix_not_found(self):
        with patch("os.kill", side_effect=ProcessLookupError):
            assert is_process_alive(1234) is False

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix-only test")
    def test_unix_permission_error(self):
        with patch("os.kill", side_effect=PermissionError):
            assert is_process_alive(1234) is True

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_windows_alive(self):
        """Running process: handle opens and exit code is STILL_ACTIVE."""
        mock_kernel32 = MagicMock()
        mock_kernel32.OpenProcess.return_value = 1234  # non-zero = handle found

        def _set_still_active(handle, exit_code_ptr):
            exit_code_ptr._obj.value = 259  # STILL_ACTIVE
            return 1

        mock_kernel32.GetExitCodeProcess.side_effect = _set_still_active
        with patch("ctypes.windll") as mock_windll:
            mock_windll.kernel32 = mock_kernel32
            assert is_process_alive(5678) is True
        mock_kernel32.CloseHandle.assert_called_once()

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_windows_not_alive(self):
        mock_kernel32 = MagicMock()
        mock_kernel32.OpenProcess.return_value = 0  # zero = not found
        with patch("ctypes.windll") as mock_windll:
            mock_windll.kernel32 = mock_kernel32
            assert is_process_alive(5678) is False

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_windows_zombie_reports_dead(self):
        """Exited process whose handle is still open must report dead."""
        mock_kernel32 = MagicMock()
        mock_kernel32.OpenProcess.return_value = 1234  # handle still openable

        def _set_exited(handle, exit_code_ptr):
            exit_code_ptr._obj.value = 0  # process exited with code 0
            return 1

        mock_kernel32.GetExitCodeProcess.side_effect = _set_exited
        with patch("ctypes.windll") as mock_windll:
            mock_windll.kernel32 = mock_kernel32
            assert is_process_alive(5678) is False
        mock_kernel32.CloseHandle.assert_called_once()


# ---------------------------------------------------------------------------
# ping_instance
# ---------------------------------------------------------------------------

class TestPingInstance:
    def test_success(self):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_response

        with patch("http.client.HTTPConnection", return_value=mock_conn):
            assert ping_instance("127.0.0.1", 5000) is True

    def test_failure(self):
        with patch("http.client.HTTPConnection", side_effect=ConnectionRefusedError):
            assert ping_instance("127.0.0.1", 5000) is False

    def test_rejects_non_localhost(self):
        assert ping_instance("10.0.0.1", 5000) is False


# ---------------------------------------------------------------------------
# check_instance_health
# ---------------------------------------------------------------------------

class TestCheckInstanceHealth:
    def test_short_circuits_on_dead_process(self):
        instance = {"pid": 99999, "host": "127.0.0.1", "port": 5000}
        with patch("ida_multi_mcp.health.is_process_alive", return_value=False):
            assert check_instance_health(instance) is False


# ---------------------------------------------------------------------------
# cleanup_stale_instances
# ---------------------------------------------------------------------------

class TestCleanupStaleInstances:
    def test_removes_dead_keeps_alive(self, populated_registry):
        instances = populated_registry.list_instances()
        ids = list(instances.keys())

        def fake_alive(pid):
            return pid != 100  # pid=100 is "dead"

        with patch("ida_multi_mcp.health.is_process_alive", side_effect=fake_alive):
            removed = cleanup_stale_instances(populated_registry)

        assert len(removed) == 1
        # Remaining should be alive
        remaining = populated_registry.list_instances()
        assert len(remaining) == 2


# ---------------------------------------------------------------------------
# query_binary_metadata
# ---------------------------------------------------------------------------

class TestQueryBinaryMetadata:
    def test_parses_response(self):
        metadata = {"path": "/test.i64", "module": "test.exe"}
        response_body = json.dumps({
            "result": {
                "contents": [{
                    "text": json.dumps(metadata),
                }]
            }
        }).encode()

        mock_response = MagicMock()
        mock_response.read.return_value = response_body
        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_response

        with patch("http.client.HTTPConnection", return_value=mock_conn):
            result = query_binary_metadata("127.0.0.1", 5000)

        assert result == metadata

    def test_rejects_non_localhost(self):
        assert query_binary_metadata("10.0.0.1", 5000) is None


# ---------------------------------------------------------------------------
# Windows console discovery (PYTHONUTF8 / OEM)
# ---------------------------------------------------------------------------

class TestConsoleOutput:
    def test_windows_uses_oem_and_replace(self):
        with patch("ida_multi_mcp.health.sys.platform", "win32"):
            with patch("subprocess.check_output", return_value=None) as mock_output:
                assert _console_output(["tasklist", "/FO", "CSV", "/NH"]) == ""
        kwargs = mock_output.call_args.kwargs
        assert kwargs["encoding"] == "oem"
        assert kwargs["errors"] == "replace"

    def test_none_stdout_becomes_empty_string(self):
        with patch("subprocess.check_output", return_value=None):
            assert _console_output(["tasklist"]) == ""

    def test_unicode_decode_error_becomes_empty_string(self):
        err = UnicodeDecodeError("utf-8", b"\xb1", 0, 1, "invalid start byte")
        with patch("subprocess.check_output", side_effect=err):
            assert _console_output(["tasklist"]) == ""


class TestFindIdaListeningPorts:
    def test_empty_console_output_does_not_crash(self):
        with patch("ida_multi_mcp.health.sys.platform", "win32"):
            with patch("ida_multi_mcp.health._console_output", return_value=""):
                assert _find_ida_listening_ports() == []

    def test_parses_english_listen_state(self):
        def fake_output(cmd, timeout=10):
            if cmd[0] == "tasklist":
                return '"ida.exe","4242","Console","1","100,000 K"\n'
            return "  TCP    127.0.0.1:57079         0.0.0.0:0              LISTENING       4242\n"

        with patch("ida_multi_mcp.health.sys.platform", "win32"):
            with patch("ida_multi_mcp.health._console_output", side_effect=fake_output):
                assert _find_ida_listening_ports() == [(4242, 57079)]

    def test_parses_localized_listen_state_and_session_name(self):
        def fake_output(cmd, timeout=10):
            if cmd[0] == "tasklist":
                return '"ida64.exe","4242","控制台","1","100,000 K"\n'
            return "  TCP    127.0.0.1:57079         0.0.0.0:0              侦听            4242\n"

        with patch("ida_multi_mcp.health.sys.platform", "win32"):
            with patch("ida_multi_mcp.health._console_output", side_effect=fake_output):
                assert _find_ida_listening_ports() == [(4242, 57079)]

    def test_parses_ipv6_local_address(self):
        def fake_output(cmd, timeout=10):
            if cmd[0] == "tasklist":
                return '"ida.exe","99","Console","1","8 K"\n'
            return "  TCP    [::1]:12345            [::]:0                 LISTENING       99\n"

        with patch("ida_multi_mcp.health.sys.platform", "win32"):
            with patch("ida_multi_mcp.health._console_output", side_effect=fake_output):
                assert _find_ida_listening_ports() == [(99, 12345)]


class TestRediscoverInstances:
    def test_swallows_unexpected_errors(self):
        registry = MagicMock()
        registry.list_instances.side_effect = RuntimeError("boom")
        assert rediscover_instances(registry) == []
