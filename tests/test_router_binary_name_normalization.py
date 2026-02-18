import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))


class TestRouterBinaryNameNormalization(unittest.TestCase):
    def test_verify_binary_path_accepts_windows_path_style_name(self):
        from ida_multi_mcp.registry import InstanceRegistry
        from ida_multi_mcp.router import InstanceRouter

        with tempfile.TemporaryDirectory() as td:
            registry = InstanceRegistry(os.path.join(td, "instances.json"))
            instance_id = registry.register(
                pid=1,
                port=2222,
                idb_path="/tmp/claude.exe.i64",
                binary_name=r"D:\1_Project\ultra-codex\references\claude.exe",
                binary_path=r"D:\1_Project\ultra-codex\references\claude.exe",
                arch="x64",
                host="127.0.0.1",
            )

            router = InstanceRouter(registry)
            instance = registry.get_instance(instance_id)

            with patch("ida_multi_mcp.router.query_binary_metadata", return_value={"module": "claude.exe"}):
                self.assertTrue(router._verify_binary_path(instance_id, instance))

    def test_verify_binary_path_is_case_insensitive(self):
        from ida_multi_mcp.registry import InstanceRegistry
        from ida_multi_mcp.router import InstanceRouter

        with tempfile.TemporaryDirectory() as td:
            registry = InstanceRegistry(os.path.join(td, "instances.json"))
            instance_id = registry.register(
                pid=2,
                port=3333,
                idb_path="/tmp/claude.exe.i64",
                binary_name="CLAUDE.EXE",
                binary_path="/tmp/claude.exe",
                arch="x64",
                host="127.0.0.1",
            )

            router = InstanceRouter(registry)
            instance = registry.get_instance(instance_id)

            with patch("ida_multi_mcp.router.query_binary_metadata", return_value={"module": "claude.exe"}):
                self.assertTrue(router._verify_binary_path(instance_id, instance))


if __name__ == "__main__":
    unittest.main()
