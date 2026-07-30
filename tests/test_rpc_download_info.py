"""Truncated-output metadata must never advertise a URL nobody answers.

The remainder of a truncated result lives in rpc's `_output_cache`, reachable
only over the `/output/<id>.json` route on the process that holds it. A wrong
base URL therefore loses the data rather than merely misaddressing it, so an
unset base URL has to say so instead of guessing a port.
"""

import importlib
import sys
import types
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Stubs so `ida_multi_mcp.ida_mcp.__init__` can run without IDA. rpc itself is
# left real -- it only depends on the bundled zeromcp copy. setdefault keeps
# this idempotent when another test module has already installed stubs.
# ---------------------------------------------------------------------------

for _name in ("ida_bytes", "ida_funcs", "ida_hexrays", "ida_kernwin", "ida_nalt",
              "ida_typeinf", "ida_ida", "ida_lines", "idaapi", "idautils", "idc"):
    sys.modules.setdefault(_name, MagicMock())

_PKG = "ida_multi_mcp.ida_mcp"

if f"{_PKG}.sync" not in sys.modules:
    _sync = types.ModuleType(f"{_PKG}.sync")
    _sync.IDAError = type("IDAError", (Exception,), {})
    _sync.IDASyncError = type("IDASyncError", (Exception,), {})
    _sync.CancelledError = type("CancelledError", (Exception,), {})
    _sync.idasync = lambda f: f
    _sync.ida_major = 9
    sys.modules[f"{_PKG}.sync"] = _sync

# Only the api_* modules and http need faking: utils and compat load fine once the
# ida_* stubs above are in place, and other test modules import the real ones.
for _sub in ("http", "framework",
             "api_core", "api_analysis", "api_memory", "api_types", "api_modify",
             "api_stack", "api_debug", "api_python", "api_resources", "api_survey",
             "api_composite", "api_similarity"):
    sys.modules.setdefault(f"{_PKG}.{_sub}", MagicMock())


@pytest.fixture
def rpc():
    mod = importlib.import_module(f"{_PKG}.rpc")
    # A MagicMock would satisfy every assertion below by accident.
    assert isinstance(mod, types.ModuleType), "expected the real rpc module, got a stub"
    return mod


class TestDownloadInfoWithBaseUrl:
    def test_url_and_hint_use_the_configured_base(self, rpc, monkeypatch):
        monkeypatch.setattr(rpc, "_download_base_url", "http://127.0.0.1:54321")

        info = rpc._add_download_info({"data": "x"}, "abc123", 90_000)

        assert info["_download_url"] == "http://127.0.0.1:54321/output/abc123.json"
        assert "curl" in info["_download_hint"]
        assert "_download_error" not in info

    def test_set_download_base_url_strips_trailing_slash(self, rpc, monkeypatch):
        monkeypatch.setattr(rpc, "_download_base_url", None)
        rpc.set_download_base_url("http://127.0.0.1:54321/")

        assert rpc.get_download_base_url() == "http://127.0.0.1:54321"


class TestDownloadInfoWithoutBaseUrl:
    def test_no_url_is_advertised(self, rpc, monkeypatch):
        monkeypatch.setattr(rpc, "_download_base_url", None)

        info = rpc._add_download_info({"data": "x"}, "abc123", 90_000)

        assert "_download_url" not in info
        assert "_download_hint" not in info

    def test_it_says_the_output_is_unreachable(self, rpc, monkeypatch):
        monkeypatch.setattr(rpc, "_download_base_url", None)

        info = rpc._add_download_info({"data": "x"}, "abc123", 90_000)

        assert "_download_error" in info
        assert "90,000" in info["_download_error"]

    def test_output_id_survives_so_the_truncation_is_still_traceable(
        self, rpc, monkeypatch,
    ):
        monkeypatch.setattr(rpc, "_download_base_url", None)

        info = rpc._add_download_info({"data": "x"}, "abc123", 90_000)

        assert info["_output_id"] == "abc123"
        assert info["_output_truncated"] is True
        assert info["_total_chars"] == 90_000
