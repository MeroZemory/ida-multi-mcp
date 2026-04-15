"""Composite analysis tools that aggregate multiple data sources.

Ported from upstream `ida-pro-mcp` `api_composite.py` (v2.0.0). Adapted:
- No `_parse_function_tinfo` helper in this project's `api_types`; `diff_before_after`
  uses `ida_typeinf.tinfo_t(text, None, PT_SIL)` directly, matching this project's
  `set_type` style (api_types.py:314).
- `get_stack_frame_variables_internal` import dropped (unused upstream as well).
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Annotated, Any, TypedDict

import ida_hexrays
import ida_typeinf
import idaapi
import idautils
import idc

from .rpc import tool, unsafe
from .sync import idasync, tool_timeout, IDAError
from .utils import (
    decompile_function_safe,
    extract_function_constants,
    extract_function_strings,
    get_all_comments,
    get_all_xrefs,
    get_assembly_lines,
    get_callees,
    get_callers,
    get_prototype,
    normalize_list_input,
    parse_address,
)


_DECOMPILE_LINE_CAP = 100
_TOP_STRINGS = 10
_TOP_CONSTANTS = 10
# Cap on the shared-string map returned by analyze_component. Sorted by
# accessor count desc so the most-shared strings surface first. Mirrors
# the bounded-output style used by survey_binary (e.g. root_functions[:100]).
_MAX_STRING_USAGE = 50
_BORING_CONSTANTS = frozenset({0, 1, -1, 0xFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF})


class BasicBlockSummary(TypedDict):
    count: int
    cyclomatic_complexity: int


class AnalyzeFunctionResult(TypedDict, total=False):
    addr: str
    name: str
    prototype: str | None
    size: int
    decompiled: str | None
    decompile_truncated: int
    assembly: str | None
    strings: list[str]
    constants: list[dict[str, Any]]
    callees: list[str]
    callers: list[str]
    xrefs: dict[str, Any]
    comments: dict[str, Any]
    basic_blocks: BasicBlockSummary
    error: str | None


class ComponentFunctionSummary(TypedDict, total=False):
    addr: str
    name: str
    prototype: str | None
    size: int
    callees: list[str]
    strings: list[str]
    basic_blocks: int
    complexity: int
    error: str


ComponentGraphEdge = TypedDict(
    "ComponentGraphEdge",
    {"from": str, "to": str, "name": str},
)


class InternalCallGraph(TypedDict):
    nodes: list[str]
    edges: list[ComponentGraphEdge]


class SharedGlobalInfo(TypedDict):
    addr: str
    name: str
    accessed_by: list[str]


class AnalyzeComponentResult(TypedDict, total=False):
    functions: list[ComponentFunctionSummary]
    internal_call_graph: InternalCallGraph
    shared_globals: list[SharedGlobalInfo]
    interface_functions: list[str]
    internal_only: list[str]
    string_usage: dict[str, list[str]]
    error: str


class DiffBeforeAfterResult(TypedDict, total=False):
    before: str | None
    after: str | None
    action_applied: str
    changes_detected: bool
    error: str


class TraceDataFlowNode(TypedDict):
    addr: str
    func: str | None
    instruction: str | None
    type: str
    name: str | None
    depth: int


TraceDataFlowEdge = TypedDict(
    "TraceDataFlowEdge",
    {"from": str, "to": str, "type": str},
)


class TraceDataFlowResult(TypedDict, total=False):
    start: str
    direction: str
    depth_reached: int
    nodes: list[TraceDataFlowNode]
    edges: list[TraceDataFlowEdge]
    error: str


# ---------------------------------------------------------------------------
# Internal helpers (called from within @idasync context)
# ---------------------------------------------------------------------------


def _resolve_addr(addr: str) -> int:
    """Resolve hex/decimal/symbol to ea. Raises IDAError if not found."""
    try:
        return parse_address(addr)
    except IDAError:
        ea = idaapi.get_name_ea(idaapi.BADADDR, addr)
        if ea == idaapi.BADADDR:
            raise IDAError(f"Address/name not found: {addr!r}")
        return ea


def _basic_block_info(ea: int) -> BasicBlockSummary:
    func = idaapi.get_func(ea)
    if func is None:
        return {"count": 0, "cyclomatic_complexity": 0}

    fc = idaapi.FlowChart(func)
    nodes = 0
    edges = 0
    for block in fc:
        nodes += 1
        for _ in block.succs():
            edges += 1

    return {"count": nodes, "cyclomatic_complexity": edges - nodes + 2}


def _filter_constants(raw: list[dict], limit: int = _TOP_CONSTANTS) -> list[dict]:
    """Drop boring constants, return top N by absolute value."""
    out = []
    for c in raw:
        val = c.get("value", 0)
        if not isinstance(val, int):
            continue
        if abs(val) < 0x100 or val in _BORING_CONSTANTS:
            continue
        out.append(c)
    out.sort(
        key=lambda c: abs(c.get("value", 0)) if isinstance(c.get("value"), int) else 0,
        reverse=True,
    )
    return out[:limit]


def _cap_decompile(code: str | None) -> tuple[str | None, int | None]:
    """Cap decompiled output at _DECOMPILE_LINE_CAP lines.

    Returns (possibly_truncated_code, total_lines_or_None)."""
    if code is None:
        return None, None
    lines = code.split("\n")
    total = len(lines)
    if total <= _DECOMPILE_LINE_CAP:
        return code, None
    truncated = "\n".join(lines[:_DECOMPILE_LINE_CAP])
    return truncated, total


def _compact_strings(raw: list[dict], limit: int = _TOP_STRINGS) -> list[str]:
    """Return just the string values, deduplicated, capped at limit."""
    seen: set[str] = set()
    out: list[str] = []
    for s in raw:
        val = s.get("value") or s.get("string", "")
        if val and val not in seen:
            seen.add(val)
            out.append(val)
            if len(out) >= limit:
                break
    return out


def _compact_callees(raw: list[dict]) -> list[str]:
    return [c.get("name") or c.get("addr", "?") for c in raw]


def _analyze_function_internal(
    ea: int, *, include_asm: bool = False
) -> AnalyzeFunctionResult:
    """Compact per-function analysis. Must be called inside an @idasync context."""
    result: AnalyzeFunctionResult = {"addr": hex(ea), "error": None}

    try:
        func = idaapi.get_func(ea)
        if func is None:
            result["error"] = f"No function at {hex(ea)}"
            return result

        result["name"] = idaapi.get_func_name(ea) or ""
        result["prototype"] = get_prototype(func)
        result["size"] = func.end_ea - func.start_ea

        try:
            raw_code = decompile_function_safe(ea)
            code, total_lines = _cap_decompile(raw_code)
            result["decompiled"] = code
            if total_lines is not None:
                result["decompile_truncated"] = total_lines
        except Exception:
            result["decompiled"] = None

        if include_asm:
            try:
                result["assembly"] = get_assembly_lines(ea)
            except Exception:
                result["assembly"] = None

        result["strings"] = _compact_strings(extract_function_strings(ea))
        result["constants"] = _filter_constants(extract_function_constants(ea))
        result["callees"] = _compact_callees(get_callees(hex(ea)))
        result["callers"] = _compact_callees(get_callers(hex(ea)))
        result["xrefs"] = get_all_xrefs(ea)
        result["comments"] = get_all_comments(ea)
        result["basic_blocks"] = _basic_block_info(ea)

    except Exception as exc:
        result["error"] = str(exc)

    return result


# ---------------------------------------------------------------------------
# Tool 1 — analyze_function
# ---------------------------------------------------------------------------


@tool
@idasync
@tool_timeout(120.0)
def analyze_function(
    addr: Annotated[str, "Function address or name"],
    include_asm: Annotated[bool, "Include full disassembly (default: false, saves tokens)"] = False,
) -> AnalyzeFunctionResult:
    """Compact single-function analysis: pseudocode (capped at 100 lines), top
    strings, top non-trivial constants, callers, callees, xrefs, comments, and
    basic block summary. Use this for "tell me everything about function X" in
    one call instead of chaining decompile + callees + xrefs_to separately."""
    try:
        ea = _resolve_addr(addr)
    except IDAError as exc:
        return {"addr": addr, "error": str(exc)}

    return _analyze_function_internal(ea, include_asm=include_asm)


# ---------------------------------------------------------------------------
# Tool 2 — analyze_component
# ---------------------------------------------------------------------------


@tool
@idasync
@tool_timeout(180.0)
def analyze_component(
    addrs: Annotated[list[str] | str, "Function addresses (comma-separated or list)"],
) -> AnalyzeComponentResult:
    """Analyze related functions as a group: per-function compact summaries,
    internal call graph (edges only between supplied functions), shared globals,
    interface vs internal classification, and strings used by multiple members."""
    raw = normalize_list_input(addrs)
    if not raw:
        return {"error": "Empty address list"}

    ea_map: dict[int, str] = {}
    for a in raw:
        try:
            ea_map[_resolve_addr(a)] = a
        except IDAError:
            return {"error": f"Cannot resolve address: {a!r}"}

    ea_set = set(ea_map.keys())

    # --- Per-function compact summary ---
    functions: list[ComponentFunctionSummary] = []
    for ea in ea_set:
        func = idaapi.get_func(ea)
        if func is None:
            functions.append({"addr": hex(ea), "error": "No function"})
            continue
        name = idaapi.get_func_name(ea) or ""
        top_strings = _compact_strings(extract_function_strings(ea), limit=5)
        callee_list = _compact_callees(get_callees(hex(ea)))
        bb = _basic_block_info(ea)
        functions.append({
            "addr": hex(ea),
            "name": name,
            "prototype": get_prototype(func),
            "size": func.end_ea - func.start_ea,
            "callees": callee_list,
            "strings": top_strings,
            "basic_blocks": bb["count"],
            "complexity": bb["cyclomatic_complexity"],
        })

    # --- Internal call graph ---
    nodes = [hex(ea) for ea in ea_set]
    edges: list[ComponentGraphEdge] = []
    for ea in ea_set:
        for callee in (get_callees(hex(ea)) or []):
            callee_ea = callee.get("addr")
            if isinstance(callee_ea, str):
                try:
                    callee_ea = int(callee_ea, 16)
                except (ValueError, TypeError):
                    continue
            if callee_ea in ea_set:
                edges.append({
                    "from": hex(ea),
                    "to": hex(callee_ea),
                    "name": callee.get("name", ""),
                })

    # --- Shared globals ---
    func_globals: dict[int, set[int]] = {}
    for ea in ea_set:
        accessed: set[int] = set()
        func = idaapi.get_func(ea)
        if func is None:
            func_globals[ea] = accessed
            continue
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for xref in idautils.XrefsFrom(head, 0):
                if xref.iscode:
                    continue
                ref_func = idaapi.get_func(xref.to)
                if ref_func is None and idaapi.is_loaded(xref.to):
                    accessed.add(xref.to)
        func_globals[ea] = accessed

    global_refcount: dict[int, list[str]] = defaultdict(list)
    for ea, gset in func_globals.items():
        fname = idaapi.get_func_name(ea) or hex(ea)
        for g in gset:
            global_refcount[g].append(fname)

    shared_globals: list[SharedGlobalInfo] = []
    for g_ea, accessors in sorted(global_refcount.items()):
        if len(accessors) >= 2:
            shared_globals.append({
                "addr": hex(g_ea),
                "name": idaapi.get_name(g_ea) or hex(g_ea),
                "accessed_by": sorted(accessors),
            })

    # --- Interface vs internal ---
    # Use raw xrefs instead of get_callers() to avoid its default 50-caller cap,
    # which could misclassify a function with >50 callers if all inspected ones
    # are internal but a later one is external. Short-circuits on first external.
    # A function with zero call xrefs (entry point, exported, indirect-call
    # target via data xref) is treated as interface — it cannot be reached
    # from within the component, so by definition it is externally reachable.
    interface_functions: list[str] = []
    internal_only: list[str] = []
    for ea in ea_set:
        has_external = False
        has_internal = False
        for xref in idautils.XrefsTo(ea, 0):
            if not xref.iscode:
                continue
            if xref.type not in (idaapi.fl_CF, idaapi.fl_CN):
                continue
            caller_func = idaapi.get_func(xref.frm)
            if caller_func is None or caller_func.start_ea not in ea_set:
                has_external = True
                break
            has_internal = True
        if has_external or not has_internal:
            interface_functions.append(hex(ea))
        else:
            internal_only.append(hex(ea))

    # --- String usage across functions ---
    string_funcs: dict[str, set[str]] = defaultdict(set)
    for ea in ea_set:
        fname = idaapi.get_func_name(ea) or hex(ea)
        for s in (extract_function_strings(ea) or []):
            sval = s.get("value") or s.get("string", "")
            if sval:
                string_funcs[sval].add(fname)

    # Sort by accessor count desc (most-shared first), break ties alphabetically.
    # Capped at _MAX_STRING_USAGE to keep the response bounded for large components.
    sorted_items = sorted(
        ((s, fnames) for s, fnames in string_funcs.items() if len(fnames) >= 2),
        key=lambda kv: (-len(kv[1]), kv[0]),
    )
    string_usage = {
        s: sorted(fnames) for s, fnames in sorted_items[:_MAX_STRING_USAGE]
    }

    return {
        "functions": functions,
        "internal_call_graph": {"nodes": nodes, "edges": edges},
        "shared_globals": shared_globals,
        "interface_functions": interface_functions,
        "internal_only": internal_only,
        "string_usage": string_usage,
    }


# ---------------------------------------------------------------------------
# Tool 3 — diff_before_after
# ---------------------------------------------------------------------------

_VALID_ACTIONS = frozenset({"rename_func", "set_type", "set_comment"})


def _parse_func_tinfo(signature_text: str) -> ida_typeinf.tinfo_t:
    """Parse a function-type declaration. Mirrors the style used by set_type in
    api_types.py (tinfo_t constructor with PT_SIL)."""
    text = signature_text.strip()
    if not text:
        raise ValueError("Function signature is required")
    tif = ida_typeinf.tinfo_t(text, None, ida_typeinf.PT_SIL)
    if not tif.is_func():
        raise ValueError(f"Not a function type: {signature_text!r}")
    return tif


@tool
@unsafe
@idasync
@tool_timeout(120.0)
def diff_before_after(
    addr: Annotated[str, "Function address"],
    action: Annotated[str, "Action: 'rename_func', 'set_type', 'set_comment'"],
    action_args: Annotated[dict, "Arguments for the action"],
) -> DiffBeforeAfterResult:
    """Apply a rename/type/comment action and return the before/after decompilation
    side by side. Actions: 'rename_func' ({name}), 'set_type' ({type}),
    'set_comment' ({comment}). Useful to verify a rename or type change actually
    improved readability. Returns {before, after, action_applied, changes_detected}."""
    if action not in _VALID_ACTIONS:
        return {"error": f"Invalid action {action!r}. Must be one of: {', '.join(sorted(_VALID_ACTIONS))}"}

    try:
        ea = _resolve_addr(addr)
    except IDAError as exc:
        return {"error": str(exc)}

    func = idaapi.get_func(ea)
    if func is None:
        return {"error": f"No function at {hex(ea)}"}

    before = decompile_function_safe(ea)

    try:
        if action == "rename_func":
            name = action_args.get("name")
            if not name:
                return {"error": "action_args must contain 'name'"}
            ok = idaapi.set_name(ea, name, idaapi.SN_CHECK)
            if not ok:
                return {"error": f"set_name failed for {name!r}"}
            applied = f"Renamed to {name!r}"

        elif action == "set_type":
            type_str = action_args.get("type")
            if not type_str:
                return {"error": "action_args must contain 'type'"}
            try:
                tif = _parse_func_tinfo(type_str)
            except ValueError as exc:
                return {"error": str(exc)}
            ok = ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
            if not ok:
                return {"error": f"apply_tinfo failed for {type_str!r}"}
            applied = f"Set type to {type_str!r}"

        elif action == "set_comment":
            comment = action_args.get("comment")
            if comment is None:
                return {"error": "action_args must contain 'comment'"}
            idaapi.set_cmt(ea, comment, False)
            applied = f"Set comment: {comment!r}"

        else:
            return {"error": f"Unhandled action {action!r}"}
    except Exception as exc:
        return {"error": f"Action {action!r} failed: {exc}"}

    ida_hexrays.mark_cfunc_dirty(ea)
    after = decompile_function_safe(ea)

    return {
        "before": before,
        "after": after,
        "action_applied": applied,
        "changes_detected": before != after,
    }


# ---------------------------------------------------------------------------
# Tool 4 — trace_data_flow
# ---------------------------------------------------------------------------

_MAX_TRACE_NODES = 200
_MAX_TRACE_EDGES = 500


@tool
@idasync
@tool_timeout(120.0)
def trace_data_flow(
    addr: Annotated[str, "Starting address"],
    direction: Annotated[str, "'forward' (xrefs from) or 'backward' (xrefs to)"] = "forward",
    max_depth: Annotated[int, "Maximum traversal depth (default 5, max 20)"] = 5,
) -> TraceDataFlowResult:
    """Follow cross-references from or to an address, automatically traversing
    multiple hops. 'forward' follows xrefs-from, 'backward' follows xrefs-to.
    Returns nodes (with function name, instruction, code/data classification) and
    edges. Do not use for call graph traversal — use callgraph for that."""
    if direction not in ("forward", "backward"):
        return {"error": f"direction must be 'forward' or 'backward', got {direction!r}"}

    try:
        start_ea = _resolve_addr(addr)
    except IDAError as exc:
        return {"error": str(exc)}

    if max_depth < 1:
        max_depth = 1
    if max_depth > 20:
        max_depth = 20

    visited: set[int] = set()
    nodes: list[TraceDataFlowNode] = []
    edges: list[TraceDataFlowEdge] = []
    depth_reached = 0

    queue: deque[tuple[int, int]] = deque()
    queue.append((start_ea, 0))
    visited.add(start_ea)

    while queue and len(nodes) < _MAX_TRACE_NODES:
        ea, depth = queue.popleft()
        if depth > max_depth:
            continue
        if depth > depth_reached:
            depth_reached = depth

        func = idaapi.get_func(ea)
        func_name = idaapi.get_func_name(ea) if func else None
        insn_text = idc.GetDisasm(ea) if idaapi.is_loaded(ea) else None

        name_at = idaapi.get_name(ea)
        node_type = "code"
        if func is None and idaapi.is_loaded(ea):
            node_type = "data"

        nodes.append({
            "addr": hex(ea),
            "func": func_name,
            "instruction": insn_text,
            "type": node_type,
            "name": name_at if name_at else None,
            "depth": depth,
        })

        if depth >= max_depth:
            continue

        if direction == "forward":
            xrefs = list(idautils.XrefsFrom(ea, 0))
        else:
            xrefs = list(idautils.XrefsTo(ea, 0))

        for xref in xrefs:
            if len(edges) >= _MAX_TRACE_EDGES:
                break
            target = xref.to if direction == "forward" else xref.frm
            xtype = "code" if xref.iscode else "data"

            edges.append({
                "from": hex(ea) if direction == "forward" else hex(target),
                "to": hex(target) if direction == "forward" else hex(ea),
                "type": xtype,
            })

            if target not in visited and len(nodes) + len(queue) < _MAX_TRACE_NODES:
                visited.add(target)
                queue.append((target, depth + 1))

    return {
        "start": hex(start_ea),
        "direction": direction,
        "depth_reached": depth_reached,
        "nodes": nodes,
        "edges": edges,
    }
