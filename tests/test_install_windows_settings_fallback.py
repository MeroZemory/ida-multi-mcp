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


class TestInstallMcpServersWindowsSettingsFallback(unittest.TestCase):
    def test_windows_access_denied_rename_falls_back_to_overwrite(self):
        from ida_multi_mcp.__main__ import SERVER_NAME, install_mcp_servers

        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            appdata = home / "AppData" / "Roaming"
            (home / ".factory").mkdir(parents=True, exist_ok=True)

            vscode_dir = appdata / "Code" / "User"
            vscode_dir.mkdir(parents=True, exist_ok=True)
            settings_path = vscode_dir / "settings.json"
            settings_path.write_text("{}", encoding="utf-8")

            old_env = dict(os.environ)
            try:
                os.environ["HOME"] = str(home)
                os.environ["USERPROFILE"] = str(home)
                os.environ["APPDATA"] = str(appdata)

                real_replace = os.replace

                def fake_replace(src, dst):
                    if Path(dst) == settings_path:
                        raise PermissionError(5, "Access is denied", src, dst)
                    return real_replace(src, dst)

                with (
                    mock.patch("ida_multi_mcp.__main__.sys.platform", "win32"),
                    mock.patch("ida_multi_mcp.__main__.time.sleep", lambda *_: None),
                    mock.patch("ida_multi_mcp.__main__.os.path.expanduser", return_value=str(home)),
                    mock.patch("ida_multi_mcp.__main__.os.replace", side_effect=fake_replace),
                ):
                    install_mcp_servers(quiet=True)

                # Factory Droid should still be installed.
                factory_path = home / ".factory" / "mcp.json"
                self.assertTrue(factory_path.exists())

                # VS Code settings should be updated via fallback overwrite.
                settings = json.loads(settings_path.read_text(encoding="utf-8"))
                in_vscode_key = (
                    "mcp" in settings
                    and "servers" in settings["mcp"]
                    and SERVER_NAME in settings["mcp"]["servers"]
                )
                in_default_key = "mcpServers" in settings and SERVER_NAME in settings["mcpServers"]
                self.assertTrue(in_vscode_key or in_default_key)
            finally:
                os.environ.clear()
                os.environ.update(old_env)


if __name__ == "__main__":
    unittest.main()
