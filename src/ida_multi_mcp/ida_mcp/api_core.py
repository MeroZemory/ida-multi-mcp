"""Core API Functions - IDB metadata and basic queries"""

import re
import time
from typing import Annotated, Optional

import ida_auto
import ida_funcs
import ida_hexrays
import ida_loader
import idaapi
import idautils
import ida_nalt
import ida_typeinf
import ida_segment
import idc

from .rpc import tool
from .sync import idasync

# Cached strings list: [(ea, text), ...]
_strings_cache: list[tuple[int, str]] | None = None


def _get_strings_cache() -> list[tuple[int, str]]:
    """Get cached strings, building cache on first access."""
    global _strings_cache
    if _strings_cache is None:
        _strings_cache = [(s.ea, str(s)) for s in idautils.Strings() if s is not None]
    return _strings_cache


def invalidate_strings_cache():
    """Clear the strings cache (call after IDB changes)."""
    global _strings_cache
    _strings_cache = None


def init_caches():
    """Build caches on plugin startup (called from Ctrl+M)."""
    t0 = time.perf_counter()
    strings = _get_strings_cache()
    t1 = time.perf_counter()
    print(f"[MCP] Cached {len(strings)} strings in {(t1-t0)*1000:.0f}ms")


from .utils import (
    Metadata,
    Function,
    ConvertedNumber,
    Global,
    Import,
    String,
    Segment,
    Page,
    NumberConversion,
    ListQuery,
    get_image_size,
    parse_address,
    normalize_list_input,
    normalize_dict_list,
    get_function,
    paginate,
    pattern_filter,
)
from .sync import IDAError


# ============================================================================
# Core API Functions
# ============================================================================


def _parse_func_query(query: str) -> int:
    """Fast path for common function query patterns. Returns ea or BADADDR."""
    q = query.strip()

    # 0x<hex> - direct address
    if q.startswith("0x") or q.startswith("0X"):
        try:
            return int(q, 16)
        except ValueError:
            pass

    # sub_<hex> - IDA auto-named function
    if q.startswith("sub_"):
        try:
            return int(q[4:], 16)
        except ValueError:
            pass

    return idaapi.BADADDR


@tool
@idasync
def lookup_funcs(
    queries: Annotated[list[str] | str, "Address(es) or name(s)"],
) -> list[dict]:
    """Get functions by address or name (auto-detects)"""
    queries = normalize_list_input(queries)

    # Treat empty/"*" as "all functions" - but add limit
    if not queries or (len(queries) == 1 and queries[0] in ("*", "")):
        all_funcs = []
        for addr in idautils.Functions():
            all_funcs.append(get_function(addr))
            if len(all_funcs) >= 1000:
                break
        return [{"query": "*", "fn": fn, "error": None} for fn in all_funcs]

    results = []
    for query in queries:
        try:
            # Fast path: 0x<ea> or sub_<ea>
            ea = _parse_func_query(query)

            # Slow path: name lookup
            if ea == idaapi.BADADDR:
                ea = idaapi.get_name_ea(idaapi.BADADDR, query)

            if ea != idaapi.BADADDR:
                func = get_function(ea, raise_error=False)
                if func:
                    results.append({"query": query, "fn": func, "error": None})
                else:
                    results.append(
                        {"query": query, "fn": None, "error": "Not a function"}
                    )
            else:
                results.append({"query": query, "fn": None, "error": "Not found"})
        except Exception as e:
            results.append({"query": query, "fn": None, "error": str(e)})

    return results


@tool
def int_convert(
    inputs: Annotated[
        list[NumberConversion] | NumberConversion,
        "Convert numbers to various formats (hex, decimal, binary, ascii)",
    ],
) -> list[dict]:
    """Convert numbers to different formats"""
    inputs = normalize_dict_list(inputs, lambda s: {"text": s, "size": 64})

    results = []
    for item in inputs:
        text = item.get("text", "")
        size = item.get("size")

        try:
            value = int(text, 0)
        except ValueError:
            results.append(
                {"input": text, "result": None, "error": f"Invalid number: {text}"}
            )
            continue

        if not size:
            size = 0
            n = abs(value)
            while n:
                size += 1
                n >>= 1
            size += 7
            size //= 8

        try:
            bytes_data = value.to_bytes(size, "little", signed=True)
        except OverflowError:
            results.append(
                {
                    "input": text,
                    "result": None,
                    "error": f"Number {text} is too big for {size} bytes",
                }
            )
            continue

        ascii_str = ""
        for byte in bytes_data.rstrip(b"\x00"):
            if byte >= 32 and byte <= 126:
                ascii_str += chr(byte)
            else:
                ascii_str = None
                break

        results.append(
            {
                "input": text,
                "result": ConvertedNumber(
                    decimal=str(value),
                    hexadecimal=hex(value),
                    bytes=bytes_data.hex(" "),
                    ascii=ascii_str,
                    binary=bin(value),
                ),
                "error": None,
            }
        )

    return results


@tool
@idasync
def list_funcs(
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "List functions with optional filtering and pagination",
    ],
) -> list[Page[Function]]:
    """List functions"""
    queries = normalize_dict_list(
        queries, lambda s: {"offset": 0, "count": 50, "filter": s}
    )
    all_functions = [get_function(addr) for addr in idautils.Functions()]

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            filter_pattern = ""

        filtered = pattern_filter(all_functions, filter_pattern, "name")
        results.append(paginate(filtered, offset, count))

    return results


@tool
@idasync
def list_globals(
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "List global variables with optional filtering and pagination",
    ],
) -> list[Page[Global]]:
    """List globals"""
    queries = normalize_dict_list(
        queries, lambda s: {"offset": 0, "count": 50, "filter": s}
    )
    all_globals: list[Global] = []
    for addr, name in idautils.Names():
        if not idaapi.get_func(addr) and name is not None:
            all_globals.append(Global(addr=hex(addr), name=name))

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            filter_pattern = ""

        filtered = pattern_filter(all_globals, filter_pattern, "name")
        results.append(paginate(filtered, offset, count))

    return results


@tool
@idasync
def imports(
    offset: Annotated[int, "Offset"],
    count: Annotated[int, "Count (0=all)"],
) -> Page[Import]:
    """List imports"""
    nimps = ida_nalt.get_import_module_qty()

    rv = []
    for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i)
        if not module_name:
            module_name = "<unnamed>"

        def imp_cb(ea, symbol_name, ordinal, acc):
            if not symbol_name:
                symbol_name = f"#{ordinal}"
            acc += [Import(addr=hex(ea), imported_name=symbol_name, module=module_name)]
            return True

        def imp_cb_w_context(ea, symbol_name, ordinal):
            return imp_cb(ea, symbol_name, ordinal, rv)

        ida_nalt.enum_import_names(i, imp_cb_w_context)

    return paginate(rv, offset, count)


@tool
@idasync
def find_regex(
    pattern: Annotated[str, "Regex pattern to search for in strings"],
    limit: Annotated[int, "Max matches (default: 30, max: 500)"] = 30,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> dict:
    """Search strings with case-insensitive regex patterns"""
    if limit <= 0:
        limit = 30
    if limit > 500:
        limit = 500

    # Security: limit regex pattern length to prevent ReDoS
    if len(pattern) > 500:
        from .sync import IDAError
        raise IDAError("Regex pattern too long: maximum 500 characters")

    matches = []
    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        from .sync import IDAError
        raise IDAError(f"Invalid regex pattern: {e}")
    strings = _get_strings_cache()

    skipped = 0
    more = False
    for ea, text in strings:
        if regex.search(text):
            if skipped < offset:
                skipped += 1
                continue
            if len(matches) >= limit:
                more = True
                break
            matches.append({"addr": hex(ea), "string": text})

    return {
        "n": len(matches),
        "matches": matches,
        "cursor": {"next": offset + limit} if more else {"done": True},
    }


# ============================================================================
# Server Health & Warmup
# ============================================================================


_SERVER_START_TIME = time.time()


def _build_health_payload() -> dict:
    """Build health/readiness snapshot."""
    path = idc.get_idb_path() if hasattr(idc, "get_idb_path") else ""
    module = ida_nalt.get_root_filename() or ""
    return {
        "status": "ok",
        "uptime_sec": round(time.time() - _SERVER_START_TIME, 1),
        "idb_path": path,
        "module": module,
        "auto_analysis_ready": not ida_auto.auto_is_ok(),
        "hexrays_ready": bool(ida_hexrays.init_hexrays_plugin()),
        "strings_cache_ready": _strings_cache is not None,
        "strings_cache_size": len(_strings_cache) if _strings_cache else 0,
    }


@tool
@idasync
def server_health() -> dict:
    """Health/ready probe for MCP server and current IDB state. Returns
    uptime, IDB path, auto-analysis status, Hex-Rays availability, and
    strings cache state."""
    return _build_health_payload()


@tool
@idasync
def server_warmup(
    wait_auto_analysis: Annotated[bool, "Wait for auto analysis queue"] = True,
    build_caches: Annotated[bool, "Build core caches (currently strings)"] = True,
    init_hexrays: Annotated[bool, "Initialize Hex-Rays decompiler plugin"] = True,
) -> dict:
    """Warm up IDA subsystems to reduce first-call latency. Call after
    connecting to a new instance to ensure analysis is complete and caches
    are populated before running tools."""
    steps = []

    if wait_auto_analysis:
        t0 = time.perf_counter()
        ida_auto.auto_wait()
        steps.append({"step": "auto_wait", "ok": True,
                       "ms": round((time.perf_counter() - t0) * 1000, 2)})

    if build_caches:
        t0 = time.perf_counter()
        init_caches()
        steps.append({"step": "init_caches", "ok": True,
                       "ms": round((time.perf_counter() - t0) * 1000, 2)})

    if init_hexrays:
        t0 = time.perf_counter()
        ok = bool(ida_hexrays.init_hexrays_plugin())
        step: dict = {"step": "init_hexrays", "ok": ok,
                       "ms": round((time.perf_counter() - t0) * 1000, 2)}
        if not ok:
            step["error"] = "Hex-Rays unavailable"
        steps.append(step)

    return {
        "ok": all(bool(s.get("ok")) for s in steps),
        "steps": steps,
        "health": _build_health_payload(),
    }


# ============================================================================
# Rich Queries
# ============================================================================


def _collect_imports() -> list[dict]:
    """Collect all imports into a flat list for filtering."""
    rv: list[dict] = []
    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i) or "<unnamed>"
        collected: list[tuple[int, str]] = []

        def imp_cb(ea: int, symbol_name: str | None, ordinal: int) -> bool:
            name = symbol_name if symbol_name else f"#{ordinal}"
            collected.append((ea, name))
            return True

        ida_nalt.enum_import_names(i, imp_cb)
        for ea, name in collected:
            rv.append({"addr": hex(ea), "imported_name": name, "module": module_name})
    return rv


@tool
@idasync
def func_query(
    queries: Annotated[list[dict] | dict,
        "Function query: filter, name_regex, min_size, max_size, has_type, sort_by, descending, offset, count"],
) -> list[dict]:
    """Query functions with richer filtering than list_funcs. Supports regex
    name filter, size range, type filter, sort by size/name/addr, and pagination.
    Example: {name_regex: 'crypt', min_size: 100, sort_by: 'size', descending: true}"""
    queries = normalize_dict_list(queries)

    all_functions: list[dict] = []
    for addr in idautils.Functions():
        fn = idaapi.get_func(addr)
        if not fn:
            continue
        size_int = fn.end_ea - fn.start_ea
        fn_name = ida_funcs.get_func_name(fn.start_ea) or "<unnamed>"
        has_type = bool(ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), fn.start_ea))
        all_functions.append({
            "addr": hex(fn.start_ea), "name": fn_name,
            "size": hex(size_int), "size_int": size_int, "has_type": has_type,
        })

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 50)
        sort_by = query.get("sort_by", "addr")
        descending = bool(query.get("descending", False))
        if sort_by not in ("addr", "name", "size"):
            sort_by = "addr"

        filtered = all_functions
        name_filter = query.get("filter", "")
        if name_filter:
            filtered = pattern_filter(filtered, name_filter, "name")

        name_regex = query.get("name_regex", "")
        if name_regex:
            try:
                compiled = re.compile(name_regex)
                filtered = [f for f in filtered if compiled.search(f["name"])]
            except re.error:
                pass

        min_size = query.get("min_size")
        if min_size is not None:
            filtered = [f for f in filtered if f["size_int"] >= int(min_size)]
        max_size = query.get("max_size")
        if max_size is not None:
            filtered = [f for f in filtered if f["size_int"] <= int(max_size)]

        if "has_type" in query:
            filtered = [f for f in filtered if f["has_type"] is bool(query["has_type"])]

        if sort_by == "name":
            filtered.sort(key=lambda f: f["name"].lower(), reverse=descending)
        elif sort_by == "size":
            filtered.sort(key=lambda f: f["size_int"], reverse=descending)
        else:
            filtered.sort(key=lambda f: int(f["addr"], 16), reverse=descending)

        page = paginate(filtered, offset, count)
        page["data"] = [{k: v for k, v in item.items() if k != "size_int"} for item in page["data"]]
        results.append(page)

    return results


@tool
@idasync
def imports_query(
    queries: Annotated[list[dict] | dict,
        "Import query: filter (import name pattern), module (module name pattern), offset, count"],
) -> list[dict]:
    """Query imports with module and name filters. Example:
    {module: 'kernel32', filter: '*File*'} to find all kernel32 file I/O imports."""
    queries = normalize_dict_list(queries)
    all_imports = _collect_imports()
    results = []

    for query in queries:
        filtered = all_imports
        name_filter = query.get("filter", "")
        module_filter = query.get("module", "")

        if name_filter:
            filtered = pattern_filter(filtered, name_filter, "imported_name")
        if module_filter:
            filtered = pattern_filter(filtered, module_filter, "module")

        results.append(paginate(filtered, query.get("offset", 0), query.get("count", 100)))

    return results


@tool
@idasync
def idb_save(
    path: Annotated[str, "Optional destination path (default: current IDB path)"] = "",
) -> dict:
    """Save active IDB to disk. Call after renaming, retyping, or commenting
    to persist changes. Optionally specify a custom output path."""
    try:
        save_path = path.strip() if path else ""
        if not save_path:
            save_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if not save_path:
            return {"ok": False, "path": None, "error": "Could not resolve IDB path"}

        ok = bool(ida_loader.save_database(save_path, 0))
        result: dict = {"ok": ok, "path": save_path}
        if not ok:
            result["error"] = "save_database returned false"
        return result
    except Exception as e:
        return {"ok": False, "path": path or None, "error": str(e)}

