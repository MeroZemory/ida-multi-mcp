"""Tests for ida_mcp/compat.py version fallbacks (IDA modules stubbed).

The fallback branches exist for IDA 8.3/8.4 and for IDA 9.0 SP0, none of which
can be exercised on a modern IDA install. They are therefore driven here with
stubs that present or withhold the specific attributes each wrapper probes.
"""

import sys
import types
from unittest.mock import MagicMock

import pytest

_PKG = "ida_multi_mcp.ida_mcp"
_ABSENT = object()

_IDA_MODULES = ["idaapi", "ida_funcs", "ida_nalt", "ida_typeinf",
                "ida_ida", "ida_hexrays", "ida_entry", "idc", "idautils"]


def _load_compat(saved, *, kernel_version="9.3", present=(), absent=()):
    """Import a fresh compat with a synthetic IDA surface.

    present/absent name attributes to force onto or off the stub modules,
    as "module.attr".
    """
    def _stub(name, value):
        if name not in saved:
            saved[name] = sys.modules.get(name, _ABSENT)
        sys.modules[name] = value

    for name in _IDA_MODULES:
        _stub(name, MagicMock(name=name))

    sys.modules["idaapi"].get_kernel_version.return_value = kernel_version

    for spec in absent:
        mod, _, attr = spec.partition(".")
        # `del` on a MagicMock marks the attribute as absent, so hasattr() is
        # False, while leaving every other auto-created attribute intact.
        delattr(sys.modules[mod], attr)

    for spec in present:
        mod, _, attr = spec.partition(".")
        setattr(sys.modules[mod], attr, MagicMock(name=spec))

    saved.setdefault(f"{_PKG}.compat", sys.modules.get(f"{_PKG}.compat", _ABSENT))
    sys.modules.pop(f"{_PKG}.compat", None)
    # compat imports only IDA modules, so it can be loaded straight from file
    # without dragging in the package __init__.
    import importlib.util
    import pathlib

    path = pathlib.Path(__file__).resolve().parents[1] / "src" / "ida_multi_mcp" / "ida_mcp" / "compat.py"
    spec = importlib.util.spec_from_file_location(f"{_PKG}.compat", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def load():
    saved = {}
    made = []

    def _factory(**kw):
        mod = _load_compat(saved, **kw)
        made.append(mod)
        return mod

    try:
        yield _factory
    finally:
        for name, previous in saved.items():
            if previous is _ABSENT:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous


def test_version_parsing_handles_service_packs(load):
    compat = load(kernel_version="9.0sp1")
    assert compat.IDA_VERSION[:2] == (9, 0)
    assert compat.IDA_GE_90 and compat.IDA_GE_85 and compat.IDA_GE_84


def test_unparseable_version_does_not_crash_import(load):
    """get_kernel_version() is an SDK call; a surprising value must not brick us."""
    compat = load(kernel_version="not-a-version")
    assert compat.IDA_VERSION == (0, 0, 0)
    # Dispatch is by hasattr, so a modern API is still selected.
    compat.inf_get_min_ea()
    sys.modules["ida_ida"].inf_get_min_ea.assert_called_once()


def test_inf_accessors_prefer_ida_ida(load):
    compat = load()
    compat.inf_get_min_ea()
    compat.inf_get_max_ea()
    compat.inf_get_omin_ea()
    compat.inf_get_omax_ea()
    for name in ("inf_get_min_ea", "inf_get_max_ea", "inf_get_omin_ea", "inf_get_omax_ea"):
        getattr(sys.modules["ida_ida"], name).assert_called_once()


def test_inf_accessors_fall_back_to_inf_structure_on_pre_85(load):
    """IDA < 8.5 has no ida_ida.inf_get_*; the legacy struct carries the fields."""
    compat = load(kernel_version="8.3", absent=("ida_ida.inf_get_min_ea",))
    idaapi = sys.modules["idaapi"]
    idaapi.get_inf_structure.return_value.min_ea = 0x400000
    assert compat.inf_get_min_ea() == 0x400000


def test_get_ordinal_limit_falls_back_to_ordinal_qty(load):
    """get_ordinal_limit arrived in 8.4; before that it was get_ordinal_qty."""
    compat = load(kernel_version="8.3", absent=("ida_typeinf.get_ordinal_limit",))
    sys.modules["ida_typeinf"].get_ordinal_qty.return_value = 42
    assert compat.get_ordinal_limit() == 42


def test_get_func_name_falls_back_when_method_missing(load):
    """func_t.get_name arrived in 8.5 and is absent in IDA 9.0 SP0."""
    compat = load()
    func = MagicMock(spec=["start_ea"])
    func.start_ea = 0x1000
    sys.modules["ida_funcs"].get_func_name.return_value = "sub_1000"
    assert compat.get_func_name(func) == "sub_1000"
    sys.modules["ida_funcs"].get_func_name.assert_called_once_with(0x1000)


def test_tinfo_get_udm_uses_modern_api_when_present(load):
    compat = load()
    tif = MagicMock()
    tif.get_udm.return_value = (3, "udm")
    assert compat.tinfo_get_udm(tif, "field") == (3, "udm")


def test_tinfo_get_udm_falls_back_to_find_udm(load):
    """IDA 9.0 SP0 dropped tinfo_t.get_udm; find_udm + get_udm_by_tid stands in."""
    compat = load()
    tif = MagicMock(spec=["find_udm", "get_udm_tid", "get_udm_by_tid"])
    tif.find_udm.return_value = 2
    tif.get_udm_tid.return_value = 0xAB

    udm = sys.modules["ida_typeinf"].udm_t.return_value
    udm.name = "field"

    idx, got = compat.tinfo_get_udm(tif, "field")
    assert idx == 2 and got is udm
    tif.get_udm_by_tid.assert_called_once_with(udm, 0xAB)


def test_tinfo_get_udm_reports_missing_member(load):
    compat = load()
    tif = MagicMock(spec=["find_udm"])
    tif.find_udm.return_value = -1
    assert compat.tinfo_get_udm(tif, "nope") == (-1, None)


def test_tinfo_get_udm_treats_unpopulated_udm_as_missing(load):
    """get_udm_by_tid returns 0 on success, so trust udm.name, not the rc."""
    compat = load()
    tif = MagicMock(spec=["find_udm", "get_udm_tid", "get_udm_by_tid"])
    tif.find_udm.return_value = 1
    sys.modules["ida_typeinf"].udm_t.return_value.name = ""
    assert compat.tinfo_get_udm(tif, "field") == (-1, None)


def test_missing_required_apis_flags_ida_90_sp0(load):
    """9.0 SP0 shipped without methods 8.5 added and 9.0 SP1 restored."""
    compat = load(
        kernel_version="9.0",
        absent=("ida_typeinf.tinfo_t",),
    )
    sys.modules["ida_typeinf"].tinfo_t = lambda: MagicMock(spec=[])
    sys.modules["ida_funcs"].func_t = lambda: MagicMock(spec=[])
    missing = compat.missing_required_apis()
    assert set(missing) == {"func_t.get_name", "func_t.get_prototype", "tinfo_t.get_udm"}
    with pytest.raises(RuntimeError, match="9.0 SP1"):
        compat.assert_supported_ida()


def test_missing_required_apis_silent_on_old_ida(load):
    """Pre-9.0 legitimately lacks these; the fallbacks cover it, so stay quiet."""
    compat = load(kernel_version="8.3")
    sys.modules["ida_funcs"].func_t = lambda: MagicMock(spec=[])
    sys.modules["ida_typeinf"].tinfo_t = lambda: MagicMock(spec=[])
    assert compat.missing_required_apis() == []
    compat.assert_supported_ida()


def test_missing_required_apis_silent_on_healthy_ida(load):
    compat = load(kernel_version="9.3")
    assert compat.missing_required_apis() == []
    compat.assert_supported_ida()
