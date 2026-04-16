"""Tests for IdalibManager — subprocess lifecycle manager.

All tests mock subprocesses; no idapro required.
"""

import subprocess
import time
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from ida_multi_mcp.idalib_manager import IdalibManager, _find_free_port


class TestFindFreePort:
    def test_returns_positive_int(self):
        port = _find_free_port()
        assert isinstance(port, int)
        assert port > 0

    def test_returns_different_ports(self):
        ports = {_find_free_port() for _ in range(5)}
        # At least 2 unique ports (unlikely all 5 collide)
        assert len(ports) >= 2


class TestIdalibManagerSpawn:
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
    @patch("ida_multi_mcp.idalib_manager.ping_instance", return_value=False)
    def test_spawn_timeout(self, mock_ping, mock_popen, tmp_path, tmp_registry):
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00" * 16)

        mock_proc = MagicMock()
        mock_proc.pid = 99999
        mock_proc.poll.return_value = None
        mock_proc.communicate.return_value = (b"", b"analysis failed")
        mock_popen.return_value = mock_proc

        mgr = IdalibManager(tmp_registry)
        result = mgr.spawn_session(str(binary), timeout=1)

        assert "error" in result
        assert "ready" in result["error"].lower()


class TestIdalibManagerClose:
    @patch("ida_multi_mcp.idalib_manager.subprocess.Popen")
    @patch("ida_multi_mcp.idalib_manager.ping_instance", return_value=True)
    def test_close_session(self, mock_ping, mock_popen, tmp_path, tmp_registry):
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00" * 16)

        mock_proc = MagicMock()
        mock_proc.pid = 99999
        mock_proc.poll.return_value = None
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
