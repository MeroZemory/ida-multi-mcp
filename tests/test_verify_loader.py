"""`--verify` must judge the installed loader by content, not by file size.

Windows reports a symlink's own length as 0 bytes, so a correctly symlinked
loader looks empty to anything inspecting the link instead of its target. These
tests pin that both install modes verify identically, and that a stale or
dangling loader is reported as such rather than as "present".
"""

from pathlib import Path

import pytest

import ida_multi_mcp
from ida_multi_mcp.__main__ import _loader_install_state


@pytest.fixture
def ida_dir(tmp_path):
    """A fake IDA directory; _loader_install_state appends `plugins/` itself."""
    (tmp_path / "plugins").mkdir()
    return tmp_path


def _packaged_bytes() -> bytes:
    src = Path(ida_multi_mcp.__file__).parent / "plugin" / "ida_multi_mcp_loader.py"
    return src.read_bytes()


def _try_symlink(link, target):
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlinks unavailable here: {exc}")


class TestNotInstalled:
    def test_missing_loader_is_reported_as_missing(self, ida_dir):
        state = _loader_install_state(str(ida_dir))

        assert state["mode"] == "missing"
        assert state["exists"] is False
        assert state["installed_sha256"] is None
        assert state["match"] is False


class TestCopyInstall:
    def test_matching_copy_verifies(self, ida_dir):
        (ida_dir / "plugins" / "ida_multi_mcp.py").write_bytes(_packaged_bytes())

        state = _loader_install_state(str(ida_dir))

        assert state["mode"] == "copy"
        assert state["match"] is True
        assert state["installed_sha256"] == state["packaged_sha256"]

    def test_stale_copy_does_not_verify(self, ida_dir):
        (ida_dir / "plugins" / "ida_multi_mcp.py").write_bytes(
            _packaged_bytes() + b"\n# left over from an older version\n"
        )

        state = _loader_install_state(str(ida_dir))

        assert state["mode"] == "copy"
        assert state["exists"] is True
        assert state["match"] is False


class TestSymlinkInstall:
    def test_symlink_verifies_by_content_not_size(self, ida_dir, tmp_path):
        target = tmp_path / "loader_source.py"
        target.write_bytes(_packaged_bytes())
        link = ida_dir / "plugins" / "ida_multi_mcp.py"
        _try_symlink(link, target)

        state = _loader_install_state(str(ida_dir))

        assert state["mode"] == "symlink"
        assert state["link_target"] is not None
        # The check that a size-based test would get wrong.
        assert state["match"] is True

    def test_dangling_symlink_is_not_reported_as_present(self, ida_dir, tmp_path):
        link = ida_dir / "plugins" / "ida_multi_mcp.py"
        _try_symlink(link, tmp_path / "gone.py")

        state = _loader_install_state(str(ida_dir))

        assert state["mode"] == "symlink"
        assert state["exists"] is False
        assert state["installed_sha256"] is None
        assert state["match"] is False
