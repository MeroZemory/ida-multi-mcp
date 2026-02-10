import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))


class _DummyRegistry:
    def __init__(self):
        self._instances = {
            "siod": {
                "binary_name": "iMax.exe",
                "binary_path": "C:/bin/iMax.exe",
                "arch": "x64",
                "host": "127.0.0.1",
                "port": 12345,
                "pid": 999,
                "registered_at": "2026-02-03T00:00:00Z",
            }
        }

    def list_instances(self):
        return dict(self._instances)


class TestListInstancesStructuredContent(unittest.TestCase):
    def test_list_instances_returns_object_not_array(self):
        from ida_multi_mcp.tools import management

        management.set_registry(_DummyRegistry())
        payload = management.list_instances()

        self.assertIsInstance(payload, dict)
        self.assertIn("instances", payload)
        self.assertIsInstance(payload["instances"], list)


if __name__ == "__main__":
    unittest.main()
