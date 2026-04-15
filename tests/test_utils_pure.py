"""Tests for ida_mcp/utils.py — Pure Python helpers (IDA modules stubbed).

The utils module lives inside ida_multi_mcp.ida_mcp, whose __init__.py
eagerly imports many IDA-dependent submodules.  We pre-populate sys.modules
with MagicMock stubs for every IDA and internal module so that only the pure
Python helpers in utils.py actually execute.
"""

import importlib
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Build stubs BEFORE any ida_multi_mcp.ida_mcp import
# ---------------------------------------------------------------------------

_IDA_MODULES = [
    "ida_funcs", "ida_hexrays", "ida_kernwin", "ida_nalt", "ida_typeinf",
    "ida_ida", "ida_lines", "idaapi", "idautils", "idc",
]

for _name in _IDA_MODULES:
    if _name not in sys.modules:
        sys.modules[_name] = MagicMock()

# Stub the ida_mcp sub-package and all its submodules that __init__.py imports.
_PKG = "ida_multi_mcp.ida_mcp"
_SUBMODULES = [
    "rpc", "http", "framework",
    "api_core", "api_analysis", "api_memory", "api_types",
    "api_modify", "api_stack", "api_debug", "api_python", "api_resources",
    "api_survey", "api_composite",
]

# Create a real sync stub with IDAError
class IDAError(Exception):
    pass

_sync_stub = types.ModuleType(f"{_PKG}.sync")
_sync_stub.IDAError = IDAError
_sync_stub.IDASyncError = type("IDASyncError", (Exception,), {})
_sync_stub.CancelledError = type("CancelledError", (Exception,), {})
_sync_stub.idasync = lambda f: f  # no-op decorator
_sync_stub.ida_major = 9
sys.modules[f"{_PKG}.sync"] = _sync_stub

for _sub in _SUBMODULES:
    fqn = f"{_PKG}.{_sub}"
    if fqn not in sys.modules:
        sys.modules[fqn] = MagicMock()

# Now we can safely import utils — it will resolve its `from .sync import IDAError`
# through our real _sync_stub above, and all ida_* modules are MagicMocks.
# The __init__.py imports of api_* etc. will hit our MagicMock stubs harmlessly.
from ida_multi_mcp.ida_mcp.utils import (
    parse_address,
    normalize_list_input,
    normalize_dict_list,
    looks_like_address,
    pattern_filter,
    paginate,
)


# ---------------------------------------------------------------------------
# parse_address
# ---------------------------------------------------------------------------

class TestParseAddress:
    def test_hex_string(self):
        assert parse_address("0x1000") == 0x1000

    def test_bare_hex_rejected(self):
        """Bare hex without 0x prefix should raise."""
        with pytest.raises(IDAError, match="missing 0x prefix"):
            parse_address("DEADBEEF")

    def test_int_passthrough(self):
        assert parse_address(42) == 42

    def test_invalid_raises(self):
        with pytest.raises(IDAError):
            parse_address("not_an_address")

    def test_out_of_range(self):
        with pytest.raises(IDAError, match="out of range"):
            parse_address(-1)


# ---------------------------------------------------------------------------
# normalize_list_input
# ---------------------------------------------------------------------------

class TestNormalizeListInput:
    def test_list_passthrough(self):
        assert normalize_list_input(["a", "b"]) == ["a", "b"]

    def test_comma_string(self):
        assert normalize_list_input("a, b, c") == ["a", "b", "c"]

    def test_exceeds_max(self):
        with pytest.raises(ValueError, match="Batch too large"):
            normalize_list_input(list(range(10)), max_items=5)


# ---------------------------------------------------------------------------
# normalize_dict_list
# ---------------------------------------------------------------------------

class TestNormalizeDictList:
    def test_single_dict(self):
        assert normalize_dict_list({"a": 1}) == [{"a": 1}]

    def test_json_string(self):
        result = normalize_dict_list('{"x": 1}')
        assert result == [{"x": 1}]

    def test_list_of_dicts(self):
        data = [{"a": 1}, {"b": 2}]
        assert normalize_dict_list(data) == data

    def test_exceeds_max(self):
        with pytest.raises(ValueError, match="Batch too large"):
            normalize_dict_list([{"x": i} for i in range(10)], max_items=5)


# ---------------------------------------------------------------------------
# looks_like_address
# ---------------------------------------------------------------------------

class TestLooksLikeAddress:
    def test_0x_prefix(self):
        assert looks_like_address("0x1234") is True

    def test_long_hex(self):
        assert looks_like_address("DEADBEEF") is True

    def test_short_string(self):
        assert looks_like_address("AB") is False

    def test_non_hex(self):
        assert looks_like_address("hello") is False


# ---------------------------------------------------------------------------
# pattern_filter
# ---------------------------------------------------------------------------

class TestPatternFilter:
    def test_glob(self):
        data = [{"name": "foo_bar"}, {"name": "baz_qux"}]
        result = pattern_filter(data, "foo*", "name")
        assert len(result) == 1
        assert result[0]["name"] == "foo_bar"

    def test_regex(self):
        data = [{"name": "func_123"}, {"name": "func_abc"}]
        result = pattern_filter(data, "/func_\\d+/", "name")
        assert len(result) == 1
        assert result[0]["name"] == "func_123"

    def test_substring(self):
        data = [{"name": "hello_world"}, {"name": "goodbye"}]
        result = pattern_filter(data, "ello", "name")
        assert len(result) == 1

    def test_max_length_rejection(self):
        with pytest.raises(IDAError, match="Pattern too long"):
            pattern_filter([], "x" * 600, "name")


# ---------------------------------------------------------------------------
# paginate
# ---------------------------------------------------------------------------

class TestPaginate:
    def test_basic_offset_count(self):
        data = list(range(10))
        page = paginate(data, offset=2, count=3)
        assert page["data"] == [2, 3, 4]
        assert page["next_offset"] == 5

    def test_end_of_data(self):
        data = list(range(5))
        page = paginate(data, offset=3, count=10)
        assert page["data"] == [3, 4]
        assert page["next_offset"] is None
