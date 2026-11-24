"""IDA SDK version compatibility shims.

Provides unified wrappers for APIs that moved or changed shape between IDA 8.3
and 9.3. Import from this module instead of from version-specific ``ida_*``
modules, so a call site does not silently pin us to one IDA generation.

The version-gating strategy below is ported from upstream ida-pro-mcp's
``ida_mcp/compat.py`` by Duncan Ogilvie (MIT); the wrappers here cover the call
sites this fork actually has.

Known migrations:
- Entry point functions (get_entry_qty, get_entry_ordinal, get_entry,
  get_entry_name): ida_nalt (8.x) -> ida_entry (8.4+, exclusive in 9.3+).
- inf_* accessors: idaapi.get_inf_structure() (<8.5) -> ida_ida.inf_get_* (8.5+).
- Type ordinal count: ida_typeinf.get_ordinal_qty (<8.4) -> get_ordinal_limit (8.4+).
- func_t.get_name / func_t.get_prototype: added in 8.5.
- tinfo_t.get_udm: added in 8.5.

IDA 9.0 SP0 (build 240925) is a special case: it shipped *without* several
methods that 8.5 had introduced and that 9.0 SP1 reinstated. The wrappers below
fall back where they can; :func:`assert_supported_ida` reports the rest loudly
rather than letting a tool fail deep in a call stack.
"""

from __future__ import annotations

import re
import idaapi
import ida_funcs
import ida_nalt
import ida_typeinf

# ---------------------------------------------------------------------------
# Version detection
# ---------------------------------------------------------------------------


def _parse_kernel_version(v) -> tuple[int, int, int]:
    """Parse "9.2", "9.2.0", "9.2sp1" and friends into a comparable tuple.

    Defensive about the input: get_kernel_version() is an SDK call, and under
    test it is a stub. An unparseable value yields (0, 0, 0), which is safe
    because every wrapper below dispatches on hasattr rather than on version —
    the constants are advisory.
    """
    nums = [int(x) for x in re.findall(r"\d+", str(v))]
    return (
        nums[0] if len(nums) > 0 else 0,
        nums[1] if len(nums) > 1 else 0,
        nums[2] if len(nums) > 2 else 0,
    )


_kernel_version = idaapi.get_kernel_version()  # e.g. "9.3"
IDA_VERSION = _parse_kernel_version(_kernel_version)
IDA_GE_90 = IDA_VERSION >= (9, 0, 0)
IDA_GE_85 = IDA_VERSION >= (8, 5, 0)
IDA_GE_84 = IDA_VERSION >= (8, 4, 0)

# Retained for callers that imported these before this module grew up.
_major, _minor = IDA_VERSION[0], IDA_VERSION[1]

# ---------------------------------------------------------------------------
# Optional module imports
# ---------------------------------------------------------------------------
#
# Imported unconditionally and probed with hasattr rather than gated on the
# parsed version. Feature detection is what actually decides which API exists,
# and it keeps a surprising version string from routing a modern IDA down the
# legacy path (where idaapi.get_inf_structure no longer exists at all).

try:
    import ida_ida
except ImportError:  # pragma: no cover - only on very old IDA
    ida_ida = None

try:
    import ida_hexrays
except ImportError:  # pragma: no cover - Hex-Rays not licensed
    ida_hexrays = None


# ---------------------------------------------------------------------------
# Entry point API (ida_nalt in early 8.x, ida_entry in 8.4+)
# ---------------------------------------------------------------------------

try:
    import ida_entry as _entry_mod
    if not hasattr(_entry_mod, "get_entry_qty"):
        raise ImportError
except ImportError:
    import ida_nalt as _entry_mod  # type: ignore[no-redef]


def get_entry_qty() -> int:
    return _entry_mod.get_entry_qty()


def get_entry_ordinal(index: int) -> int:
    return _entry_mod.get_entry_ordinal(index)


def get_entry(ordinal: int) -> int:
    return _entry_mod.get_entry(ordinal)


def get_entry_name(ordinal: int) -> str:
    return _entry_mod.get_entry_name(ordinal)


# ---------------------------------------------------------------------------
# inf_* accessors (idaapi.get_inf_structure() before 8.5, ida_ida.inf_* after)
# ---------------------------------------------------------------------------


def _inf_attr(name: str):
    """Read one field off the legacy inf structure."""
    return getattr(idaapi.get_inf_structure(), name)


def inf_get_min_ea() -> int:
    if ida_ida is not None and hasattr(ida_ida, "inf_get_min_ea"):
        return ida_ida.inf_get_min_ea()
    return _inf_attr("min_ea")


def inf_get_max_ea() -> int:
    if ida_ida is not None and hasattr(ida_ida, "inf_get_max_ea"):
        return ida_ida.inf_get_max_ea()
    return _inf_attr("max_ea")


def inf_get_omin_ea() -> int:
    if ida_ida is not None and hasattr(ida_ida, "inf_get_omin_ea"):
        return ida_ida.inf_get_omin_ea()
    return _inf_attr("omin_ea")


def inf_get_omax_ea() -> int:
    if ida_ida is not None and hasattr(ida_ida, "inf_get_omax_ea"):
        return ida_ida.inf_get_omax_ea()
    return _inf_attr("omax_ea")


def inf_is_64bit() -> bool:
    if ida_ida is not None and hasattr(ida_ida, "inf_is_64bit"):
        return ida_ida.inf_is_64bit()
    if hasattr(idaapi, "inf_is_64bit"):
        return idaapi.inf_is_64bit()
    return bool(idaapi.get_inf_structure().is_64bit())


# ---------------------------------------------------------------------------
# Type ordinal count (get_ordinal_qty before 8.4, get_ordinal_limit after)
# ---------------------------------------------------------------------------


def get_ordinal_limit(til: "ida_typeinf.til_t | None" = None) -> int:
    fn = getattr(ida_typeinf, "get_ordinal_limit", None)
    if fn is None:
        fn = ida_typeinf.get_ordinal_qty
    return fn(til) if til is not None else fn()


# ---------------------------------------------------------------------------
# func_t helpers (get_name / get_prototype added in 8.5, absent in 9.0 SP0)
# ---------------------------------------------------------------------------


def get_func_name(func: "ida_funcs.func_t") -> str | None:
    if hasattr(func, "get_name"):
        return func.get_name()
    return ida_funcs.get_func_name(func.start_ea)


def get_func_prototype(func: "ida_funcs.func_t"):
    if hasattr(func, "get_prototype"):
        return func.get_prototype()
    tif = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(tif, func.start_ea) and tif.is_func():
        return tif
    return None


# ---------------------------------------------------------------------------
# UDM (struct / union / frame member) lookup
# ---------------------------------------------------------------------------


def tinfo_get_udm(
    tif: "ida_typeinf.tinfo_t", name: str
) -> tuple[int, "ida_typeinf.udm_t | None"]:
    """Look up a member on a tinfo_t by name.

    ``tinfo_t.get_udm()`` arrived in 8.5 and is missing from IDA 9.0 SP0
    (build 240925). Fall back to find_udm() + get_udm_by_tid().

    Returns (index, udm); udm is None when the member does not exist.
    """
    if hasattr(tif, "get_udm"):
        return tif.get_udm(name)

    idx = tif.find_udm(name)
    if idx == -1:
        return -1, None

    udm = ida_typeinf.udm_t()
    tid = tif.get_udm_tid(idx)
    # get_udm_by_tid returns 0 on success (C convention), so check whether the
    # struct actually got populated rather than trusting the return value.
    tif.get_udm_by_tid(udm, tid)
    if udm.name:
        return idx, udm
    return -1, None


# ---------------------------------------------------------------------------
# Type guessing (moved out of ida_hexrays)
# ---------------------------------------------------------------------------


def guess_tinfo(tif: "ida_typeinf.tinfo_t", ea: int) -> bool:
    try:
        rc = ida_typeinf.guess_tinfo(tif, ea)
        if isinstance(rc, bool):
            if rc:
                return True
        elif int(rc) > 0:
            return True
    except Exception:
        pass

    if ida_hexrays is not None:
        try:
            if ida_hexrays.init_hexrays_plugin() and ida_hexrays.guess_tinfo(tif, ea):
                return True
        except Exception:
            pass

    return False


# ---------------------------------------------------------------------------
# Startup check
# ---------------------------------------------------------------------------


def missing_required_apis() -> list[str]:
    """Return names of 8.5-era APIs this IDA build is missing.

    Only meaningful on 9.0+: IDA 9.0 SP0 (build 240925) dropped methods that
    8.5 had added and 9.0 SP1 restored. Older builds legitimately lack them and
    are served by the fallbacks above, so they are not reported here.
    """
    if not IDA_GE_90:
        return []

    missing = []
    try:
        func = ida_funcs.func_t()
        if not hasattr(func, "get_name"):
            missing.append("func_t.get_name")
        if not hasattr(func, "get_prototype"):
            missing.append("func_t.get_prototype")
        tif = ida_typeinf.tinfo_t()
        if not hasattr(tif, "get_udm"):
            missing.append("tinfo_t.get_udm")
    except Exception:
        return []
    return missing


def assert_supported_ida() -> None:
    """Raise if running on an IDA build known to break tools in confusing ways."""
    missing = missing_required_apis()
    if missing:
        raise RuntimeError(
            f"IDA Pro {_kernel_version} is missing required Python API methods: "
            f"{', '.join(missing)}. If this is IDA 9.0, upgrade to 9.0 SP1 "
            f"(build 241217) or later."
        )


# ---------------------------------------------------------------------------
# Binary search (ida_bytes.bin_search signature/return drifted in IDA 9.0)
# ---------------------------------------------------------------------------
#
# IDA 9.0 changed ida_bytes.bin_search in two ways that silently broke every
# caller written against the 8.x API:
#   1. The compiled_binpat_vec_t overload now returns a tuple
#      ``(match_ea, index)`` instead of a scalar ``ea_t``. Old code that did
#      ``ea = bin_search(...)`` then ``hex(ea)`` raises TypeError on the tuple.
#   2. The raw bytes+mask overload
#      ``bin_search(start, end, image, mask, len, flags)`` -- though still
#      listed in the docstring -- raises "Wrong number or type of arguments"
#      from the SWIG layer on 9.3. Confirmed empirically on IDA 9.3 SP2.
#
# The user-friendly ``ida_bytes.find_bytes`` (added in 9.0) returns a scalar
# ``ea_t`` (BADADDR on miss) and internally handles both bytes+mask searches
# and wildcard pattern strings (accepting both ``?`` and ``??``), so we route
# through it on 9.0+ and fall back to legacy ``bin_search`` on 8.x. The tuple
# guard in the fallback keeps it correct even if a 9.x build ever reaches it.
#
# See the regression note in api_analysis.find_bytes for the full trace.

import ida_bytes

DEFAULT_SEARCH_FLAGS = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW


def _unwrap_bin_search(res: "int | tuple[int, int]") -> int:
    """bin_search returns (ea, index) on 9.x, scalar ea on 8.x. Normalize."""
    if isinstance(res, tuple):
        return res[0]
    return res


def find_bytes_masked(
    ea: int,
    max_ea: int,
    data: bytes,
    mask: bytes | None,
    flags: int = DEFAULT_SEARCH_FLAGS,
) -> int:
    """Search for raw bytes with an optional per-byte 0xFF/0x00 mask.
    Returns the match address, or idaapi.BADADDR if not found.
    Works across IDA 8.x and 9.x."""
    if IDA_GE_90:
        return ida_bytes.find_bytes(data, ea, range_end=max_ea, mask=mask, flags=flags)
    # The legacy overload needs an explicit mask; None means every byte counts.
    full_mask = mask if mask is not None else b"\xFF" * len(data)
    return _unwrap_bin_search(
        ida_bytes.bin_search(ea, max_ea, data, full_mask, len(data), flags)
    )


def find_pattern(
    ea: int,
    max_ea: int,
    pattern: str,
    flags: int = DEFAULT_SEARCH_FLAGS,
) -> int:
    """Search for a wildcard byte pattern string, e.g. '48 8B ?? ??'.
    Returns the match address, or idaapi.BADADDR if not found.
    Works across IDA 8.x and 9.x."""
    if IDA_GE_90:
        # find_bytes parses the pattern string itself and accepts both the
        # '?' and '??' wildcard spellings.
        return ida_bytes.find_bytes(pattern, ea, range_end=max_ea, flags=flags)
    binpat = ida_bytes.compiled_binpat_vec_t()
    ida_bytes.parse_binpat_str(binpat, ea, pattern, 16)
    if len(binpat) == 0:  # parse failure: return value is unreliable, length is not
        return idaapi.BADADDR
    return _unwrap_bin_search(ida_bytes.bin_search(ea, max_ea, binpat, flags))
