import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))


class TestInstallMcpServersFactoryDroid(unittest.TestCase):
    def test_install_and_uninstall_factory_droid(self):
        from ida_multi_mcp.__main__ import SERVER_NAME, install_mcp_servers

        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            (home / ".factory").mkdir(parents=True, exist_ok=True)

            old_env = dict(os.environ)
            try:
                os.environ["HOME"] = str(home)
                os.environ["USERPROFILE"] = str(home)
                os.environ["APPDATA"] = str(home / "AppData" / "Roaming")

                with mock.patch("ida_multi_mcp.__main__.os.path.expanduser", return_value=str(home)):
                    install_mcp_servers(quiet=True)

                config_path = home / ".factory" / "mcp.json"
                self.assertTrue(config_path.exists())
                config = json.loads(config_path.read_text(encoding="utf-8"))
                self.assertIn("mcpServers", config)
                self.assertIn(SERVER_NAME, config["mcpServers"])
                self.assertEqual(
                    config["mcpServers"][SERVER_NAME]["args"], ["-m", "ida_multi_mcp"]
                )

                with mock.patch("ida_multi_mcp.__main__.os.path.expanduser", return_value=str(home)):
                    install_mcp_servers(uninstall=True, quiet=True)

                config = json.loads(config_path.read_text(encoding="utf-8"))
                self.assertIn("mcpServers", config)
                self.assertNotIn(SERVER_NAME, config["mcpServers"])
            finally:
                os.environ.clear()
                os.environ.update(old_env)


if __name__ == "__main__":
    unittest.main()
