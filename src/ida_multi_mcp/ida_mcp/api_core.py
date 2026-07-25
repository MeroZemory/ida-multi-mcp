"""Core API Functions - IDB metadata and basic queries"""

import re
import time
from typing import Annotated, Optional

import ida_auto
import ida_funcs
import ida_hexrays
import ida_loader
import ida_kernwin
import idaapi
import idautils
import ida_nalt
import ida_typeinf
import ida_segment
import idc

from .rpc import tool
from .sync import idasync, tool_timeout

# Cached strings list: [(ea, text), ...]
_strings_cache: list[tuple[int, str]] | None = None

# Cached function list: [Function(...), ...]
_funcs_cache: list["Function"] | None = None

# Cached function query metadata: [{addr, name, size, size_int, has_type}, ...]
_funcs_query_cache: list[dict] | None = None

# Cached globals list: [Global(...), ...]
_globals_cache: list["Global"] | None = None


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


def _get_funcs_cache() -> list["Function"]:
    """Get cached function list, building cache on first access."""
    global _funcs_cache
    if _funcs_cache is None:
        _funcs_cache = [get_function(addr) for addr in idautils.Functions()]
    return _funcs_cache


def _get_funcs_query_cache() -> list[dict]:
    """Lightweight func_query rows derived from the warm functions cache.

    Reuses _funcs_cache (addr/name/size) and only adds size_int, so it does
    NO per-function IDA calls and stays fast even on 100K+ function binaries.
    has_type is intentionally NOT precomputed here (a get_tinfo() per function
    would re-introduce a full scan that times out); func_query computes it
    lazily only for the rows it actually returns or filters on. Invalidated
    together with _funcs_cache.
    """
    global _funcs_query_cache
    if _funcs_query_cache is None:
        rows: list[dict] = []
        for fn in _get_funcs_cache():
            try:
                size_int = int(fn["size"], 16)
            except (KeyError, ValueError, TypeError):
                size_int = 0
            rows.append({
                "addr": fn["addr"], "name": fn["name"],
                "size": fn["size"], "size_int": size_int,
            })
        _funcs_query_cache = rows
    return _funcs_query_cache


def invalidate_funcs_cache():
    """Clear the function caches (call after function changes)."""
    global _funcs_cache, _funcs_query_cache
    _funcs_cache = None
    _funcs_query_cache = None


def _get_globals_cache() -> list["Global"]:
    """Get cached globals list, building cache on first access."""
    global _globals_cache
    if _globals_cache is None:
        _globals_cache = []
        for addr, name in idautils.Names():
            if not idaapi.get_func(addr) and name is not None:
                _globals_cache.append(Global(addr=hex(addr), name=name))
    return _globals_cache


def invalidate_globals_cache():
    """Clear the globals cache (call after data changes)."""
    global _globals_cache
    _globals_cache = None


def init_caches():
    """Build caches on plugin startup."""
    t0 = time.perf_counter()
    strings = _get_strings_cache()
    t1 = time.perf_counter()
    print(f"[MCP] Cached {len(strings)} strings in {(t1-t0)*1000:.0f}ms")

    funcs = _get_funcs_cache()
    t2 = time.perf_counter()
    print(f"[MCP] Cached {len(funcs)} functions in {(t2-t1)*1000:.0f}ms")

    globals_ = _get_globals_cache()
    t3 = time.perf_counter()
    print(f"[MCP] Cached {len(globals_)} globals in {(t3-t2)*1000:.0f}ms")


@tool
@idasync
@tool_timeout(120.0)
def refresh_caches() -> dict:
    """Force-refresh all caches (strings, functions, globals)."""
    invalidate_strings_cache()
    invalidate_funcs_cache()
    invalidate_globals_cache()

    t0 = time.perf_counter()
    strings = _get_strings_cache()
    t1 = time.perf_counter()
    funcs = _get_funcs_cache()
    t2 = time.perf_counter()
    globals_ = _get_globals_cache()
    t3 = time.perf_counter()

    return {
        "strings": len(strings),
        "functions": len(funcs),
        "globals": len(globals_),
        "time_ms": round((t3 - t0) * 1000),
    }


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
    all_functions = _get_funcs_cache()

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
    all_globals = _get_globals_cache()

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
        # auto_is_ok() is "are all queues empty", i.e. True once analysis has
        # finished. This was negated, so the field reported the opposite of the
        # truth in both directions and agents proceeded on a half-analysed IDB.
        "auto_analysis_ready": bool(ida_auto.auto_is_ok()),
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


_AUTO_STATE_NAMES = {
    "AU_NONE": "idle",
    "AU_UNK": "reanalysing unexplored bytes",
    "AU_CODE": "converting to instructions",
    "AU_WEAK": "converting to instructions (weak)",
    "AU_PROC": "creating functions",
    "AU_TAIL": "adding function tails",
    "AU_FCHUNK": "finding function chunks",
    "AU_USED": "reanalysing dependent instructions",
    "AU_TYPE": "applying type information",
    "AU_LIBF": "identifying library functions",
    "AU_CHLB": "identifying library functions (delayed)",
    "AU_FINAL": "final analysis pass",
}


def _auto_state_label(finished: bool) -> str:
    """Human-readable name of whatever the autoanalyser is doing right now.

    Note this runs on the IDA main thread, which is exactly what IDA borrows
    back from the analyser to service our request — so get_auto_state() very
    often reads AU_NONE even with work still queued. Report that as "queued"
    rather than "idle", which would contradict finished=False.
    """
    if finished:
        return "idle"
    try:
        state = ida_auto.get_auto_state()
    except Exception:
        return "unknown"
    if state == getattr(ida_auto, "AU_NONE", 0):
        return "queued (paused while servicing this request)"
    for const, label in _AUTO_STATE_NAMES.items():
        if const == "AU_NONE":
            continue
        value = getattr(ida_auto, const, None)
        if value is not None and state == value:
            return label
    return f"running (state={state})"


@tool
@idasync
def analysis_status() -> dict:
    """Check whether IDA's initial auto-analysis has finished. Returns
    immediately without blocking.

    IMPORTANT: on a freshly opened binary, analysis runs in the background and
    function lists, xrefs, and decompilation are INCOMPLETE until it finishes.
    Check this before drawing conclusions from a first pass over a new binary,
    and use analysis_wait() to block until it is done."""
    finished = bool(ida_auto.auto_is_ok())
    return {
        "finished": finished,
        "state": _auto_state_label(finished),
        "function_count": ida_funcs.get_func_qty(),
        "hint": (
            "Analysis is complete; results are trustworthy."
            if finished
            else "Analysis is still running — call analysis_wait() before relying on results."
        ),
    }


@tool
@idasync
@tool_timeout(300.0)
def analysis_wait(
    timeout_sec: Annotated[float, "Seconds to wait before returning (default 120)"] = 120.0,
) -> dict:
    """Block until IDA's auto-analysis finishes, then return.

    Call this once after opening a binary, before any analysis work. If it
    returns finished=false the wait timed out rather than failed — call it
    again to keep waiting.

    Returns the elapsed wait and the resulting function count, so a caller can
    see analysis actually progressing across successive calls."""
    t0 = time.perf_counter()
    before = ida_funcs.get_func_qty()

    if ida_auto.auto_is_ok():
        return {
            "finished": True,
            "waited_sec": 0.0,
            "function_count": before,
            "functions_added": 0,
            "note": "Analysis had already finished.",
        }

    deadline = time.monotonic() + max(0.0, float(timeout_sec))
    # auto_wait() processes the queues and returns False if it was cancelled —
    # which is exactly what the tool deadline's set_cancelled() does. Loop so a
    # cancelled slice resumes rather than aborting the whole wait.
    while time.monotonic() < deadline:
        ida_auto.auto_wait()
        if ida_auto.auto_is_ok():
            break

    finished = bool(ida_auto.auto_is_ok())
    after = ida_funcs.get_func_qty()
    return {
        "finished": finished,
        "waited_sec": round(time.perf_counter() - t0, 2),
        "function_count": after,
        "functions_added": after - before,
        "state": _auto_state_label(finished),
        "note": (
            "Analysis complete."
            if finished
            else "Timed out while analysis was still running — call analysis_wait() again to continue."
        ),
    }


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
@tool_timeout(60.0)
def func_query(
    queries: Annotated[list[dict] | dict,
        "Function query: filter, name_regex, min_size, max_size, has_type, sort_by, descending, offset, count"],
) -> list[dict]:
    """Query functions with richer filtering than list_funcs. Supports regex
    name filter, size range, type filter, sort by size/name/addr, and pagination.
    Example: {name_regex: 'crypt', min_size: 100, sort_by: 'size', descending: true}"""
    queries = normalize_dict_list(queries)

    # Shared, cached metadata — must not be mutated in place below.
    all_functions = _get_funcs_query_cache()

    # has_type is resolved lazily: a get_tinfo() per function over the whole
    # binary would time out on 100K+ function targets. Reuse one tinfo_t.
    _tif = ida_typeinf.tinfo_t()

    def _has_type(row: dict) -> bool:
        try:
            return bool(ida_nalt.get_tinfo(_tif, int(row["addr"], 16)))
        except (ValueError, TypeError):
            return False

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

        # has_type filter: compute only for the already name/size-narrowed set.
        if "has_type" in query:
            want = bool(query["has_type"])
            filtered = [f for f in filtered if _has_type(f) is want]

        # Copy before sorting in place when no filter narrowed the shared cache.
        if filtered is all_functions:
            filtered = list(filtered)

        if sort_by == "name":
            filtered.sort(key=lambda f: f["name"].lower(), reverse=descending)
        elif sort_by == "size":
            filtered.sort(key=lambda f: f["size_int"], reverse=descending)
        else:
            filtered.sort(key=lambda f: int(f["addr"], 16), reverse=descending)

        page = paginate(filtered, offset, count)
        # Resolve has_type only for the returned page (≤ count rows).
        page["data"] = [
            {**{k: v for k, v in item.items() if k != "size_int"},
             "has_type": _has_type(item)}
            for item in page["data"]
        ]
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
    """Save active IDB to disk, with no dialogs. Call after renaming, retyping,
    or commenting to persist changes. Optionally specify a custom output path
    to write a copy instead, leaving the open database untouched."""
    try:
        requested = path.strip() if path else ""
        current = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        save_path = requested or current
        if not save_path:
            return {"ok": False, "path": None, "error": "Could not resolve IDB path"}

        try:
            is_gui = bool(ida_kernwin.is_idaq())
        except Exception:
            is_gui = False

        saving_copy = bool(requested) and requested != current

        if saving_copy:
            # Explicit different destination: write a compressed snapshot and
            # leave the live working files alone.
            flags = getattr(ida_loader, "DBFL_COMP", 0)
            ok = bool(ida_loader.save_database(save_path, flags))
        elif is_gui:
            # In the GUI the open database is backed by loose .id0/.id1/.id2/
            # .nam/.til files that IDA is actively using. Pass None for the
            # in-place save IDA itself performs on Ctrl+W; handing it an
            # explicit path takes the save-as route instead.
            ok = bool(ida_loader.save_database(None, 0))
        else:
            # Headless: nothing else holds the working files, so pack into one
            # compressed database.
            flags = getattr(ida_loader, "DBFL_KILL", 0) | getattr(ida_loader, "DBFL_COMP", 0)
            ok = bool(ida_loader.save_database(save_path, flags))

        result: dict = {
            "ok": ok,
            "path": save_path,
            "mode": "copy" if saving_copy else ("gui-in-place" if is_gui else "headless-packed"),
        }
        if not ok:
            result["error"] = "save_database returned false"
        return result
    except Exception as e:
        return {"ok": False, "path": path or None, "error": str(e)}

