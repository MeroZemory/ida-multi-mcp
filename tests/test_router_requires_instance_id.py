import os
import sys
import unittest
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))


class TestRouterRequiresInstanceId(unittest.TestCase):
    def test_auto_selects_when_single_instance(self):
        """With exactly 1 instance, omitting instance_id should auto-select it
        (may fail connecting, but should NOT return 'Missing instance_id' error)."""
        from ida_multi_mcp.registry import InstanceRegistry
        from ida_multi_mcp.router import InstanceRouter

        with tempfile.TemporaryDirectory() as td:
            registry_path = os.path.join(td, "instances.json")
            registry = InstanceRegistry(registry_path)
            registry.register(
                pid=123, port=4567, idb_path="C:/tmp/sample.i64",
                binary_name="sample.exe", host="127.0.0.1",
            )

            router = InstanceRouter(registry)
            resp = router.route_request("tools/call", {"name": "list_funcs", "arguments": {"queries": "{}"}})

            # Should NOT get "Missing required parameter 'instance_id'" error
            if "error" in resp:
                self.assertNotIn("instance_id", str(resp["error"]))

    def test_route_request_errors_without_instance_id_multiple(self):
        """With 2+ instances, omitting instance_id should return an error."""
        from ida_multi_mcp.registry import InstanceRegistry
        from ida_multi_mcp.router import InstanceRouter

        with tempfile.TemporaryDirectory() as td:
            registry_path = os.path.join(td, "instances.json")
            registry = InstanceRegistry(registry_path)
            registry.register(
                pid=123, port=4567, idb_path="C:/tmp/a.i64",
                binary_name="a.exe", host="127.0.0.1",
            )
            registry.register(
                pid=456, port=4568, idb_path="C:/tmp/b.i64",
                binary_name="b.exe", host="127.0.0.1",
            )

            router = InstanceRouter(registry)
            resp = router.route_request("tools/call", {"name": "list_funcs", "arguments": {"queries": "{}"}})

            self.assertIn("error", resp)
            self.assertIn("instance_id", resp["error"])
            self.assertIn("available_instances", resp)


if __name__ == "__main__":
    unittest.main()
