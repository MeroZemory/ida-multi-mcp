import os
import sys
import unittest
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))


class TestRouterRequiresInstanceId(unittest.TestCase):
    def test_route_request_errors_without_instance_id(self):
        from ida_multi_mcp.registry import InstanceRegistry
        from ida_multi_mcp.router import InstanceRouter

        with tempfile.TemporaryDirectory() as td:
            registry_path = os.path.join(td, "instances.json")
            registry = InstanceRegistry(registry_path)
            instance_id = registry.register(
                pid=123,
                port=4567,
                idb_path="C:/tmp/sample.i64",
                binary_name="sample.exe",
                binary_path="C:/tmp/sample.exe",
                arch="x64",
                host="127.0.0.1",
            )

            router = InstanceRouter(registry)
            resp = router.route_request("tools/call", {"name": "list_funcs", "arguments": {"queries": "{}"}})

            self.assertIn("error", resp)
            self.assertIn("instance_id", resp["error"])
            self.assertIn("available_instances", resp)
            self.assertTrue(any(i.get("id") == instance_id for i in resp["available_instances"]))


if __name__ == "__main__":
    unittest.main()

