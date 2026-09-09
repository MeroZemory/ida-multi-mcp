from typing import Annotated
import ast
import io
import sys
import idaapi
import idc
import ida_bytes
import ida_dbg
import ida_entry
import ida_frame
import ida_funcs
import ida_hexrays
import ida_ida
import ida_kernwin
import ida_lines
import ida_nalt
import ida_name
import ida_segment
import ida_typeinf
import ida_xref

from .rpc import tool, unsafe
from .sync import idasync
from .utils import parse_address, get_function

# ============================================================================
# Python Evaluation
# ============================================================================


_IDA_MODULE_CACHE: dict[str, object | None] = {}


def _lazy_ida_import(module_name, globals=None, locals=None, fromlist=(), level=0):
    # Security: only allow IDA-related module imports.
    allowed_prefixes = ("ida_", "idaapi", "idautils", "idc")
    if level != 0 or not any(module_name.startswith(p) for p in allowed_prefixes):
        raise ImportError(
            f"Module '{module_name}' is not allowed in py_eval. "
            "Only IDA modules (ida_*, idaapi, idautils, idc) are permitted."
        )
    if module_name in _IDA_MODULE_CACHE:
        return _IDA_MODULE_CACHE[module_name]
    try:
        module = __import__(module_name, globals, locals, fromlist, level)
        _IDA_MODULE_CACHE[module_name] = module
        return module
    except ImportError:
        # Module not available in this IDA build — bind None so user code can
        # guard with `if mod is not None`. This is expected for optional
        # modules. Cache the miss so every py_eval call does not repeat the
        # import probe. Expected misses remain silent; explicit user code can
        # still test the prebound module for None.
        _IDA_MODULE_CACHE[module_name] = None
        return None


def _execute_py_eval_code(code: str, exec_globals: dict) -> str | None:
    tree = ast.parse(code, mode="exec")

    def _eval_expr(expr_node: ast.expr) -> str | None:
        expr = ast.Expression(expr_node)
        ast.fix_missing_locations(expr)
        value = eval(compile(expr, "<py_eval>", "eval"), exec_globals)
        # Return None (not "None") so py_eval's `result_value or ""` renders
        # a None result as "" — preserving the original output contract where
        # a statement that produces no value yields an empty result string.
        return None if value is None else str(value)

    if len(tree.body) == 1 and isinstance(tree.body[0], ast.Expr):
        return _eval_expr(tree.body[0].value)

    before_keys = set(exec_globals.keys())
    if tree.body and isinstance(tree.body[-1], ast.Expr):
        prefix = ast.Module(body=tree.body[:-1], type_ignores=tree.type_ignores)
        ast.fix_missing_locations(prefix)
        if prefix.body:
            exec(compile(prefix, "<py_eval>", "exec"), exec_globals)
        return _eval_expr(tree.body[-1].value)

    exec(compile(tree, "<py_eval>", "exec"), exec_globals)
    if "result" in exec_globals:
        return str(exec_globals["result"])

    new_keys = [
        key
        for key in exec_globals.keys()
        if key not in before_keys and not key.startswith("__")
    ]
    if new_keys:
        return str(exec_globals[new_keys[-1]])
    return None


@tool
@idasync
@unsafe
def py_eval(
    code: Annotated[str, "Python code"],
) -> dict:
    """Execute Python code in IDA context.
    Returns dict with result/stdout/stderr.
    Has access to all IDA API modules.
    Supports Jupyter-style evaluation."""
    # Capture stdout/stderr
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    old_stdout = sys.stdout
    old_stderr = sys.stderr

    try:
        sys.stdout = stdout_capture
        sys.stderr = stderr_capture

        # Security: restricted builtins - remove dangerous functions that enable
        # arbitrary file/network/process access outside IDA's analysis context.

        # Wrap getattr/setattr to block dunder attribute access (sandbox escape prevention)
        def _safe_getattr(obj, name, *default):
            if isinstance(name, str) and name.startswith("__") and name.endswith("__"):
                raise AttributeError(f"Access to dunder attribute '{name}' is blocked in py_eval")
            return getattr(obj, name, *default)

        def _safe_setattr(obj, name, value):
            if isinstance(name, str) and name.startswith("__") and name.endswith("__"):
                raise AttributeError(f"Setting dunder attribute '{name}' is blocked in py_eval")
            return setattr(obj, name, value)

        _safe_builtins = {
            # Core types and conversions
            "True": True, "False": False, "None": None,
            "int": int, "float": float, "str": str, "bool": bool,
            "bytes": bytes, "bytearray": bytearray, "complex": complex,
            "list": list, "tuple": tuple, "dict": dict, "set": set, "frozenset": frozenset,
            # Utility functions
            "abs": abs, "all": all, "any": any, "bin": bin, "chr": chr, "ord": ord,
            "divmod": divmod, "enumerate": enumerate, "filter": filter,
            "format": format, "getattr": _safe_getattr, "hasattr": hasattr,
            "hash": hash, "hex": hex, "id": id, "isinstance": isinstance,
            "issubclass": issubclass, "iter": iter, "len": len, "map": map,
            "max": max, "min": min, "next": next, "oct": oct, "pow": pow,
            "print": print, "range": range, "repr": repr, "reversed": reversed,
            "round": round, "setattr": _safe_setattr, "slice": slice, "sorted": sorted,
            "sum": sum, "zip": zip,
            "callable": callable, "property": property,
            "staticmethod": staticmethod, "classmethod": classmethod,
            # Exceptions (needed for try/except)
            "Exception": Exception, "ValueError": ValueError, "TypeError": TypeError,
            "KeyError": KeyError, "IndexError": IndexError, "AttributeError": AttributeError,
            "RuntimeError": RuntimeError, "StopIteration": StopIteration,
            "NotImplementedError": NotImplementedError, "ZeroDivisionError": ZeroDivisionError,
            # Restricted import - only IDA modules allowed
            "__import__": _lazy_ida_import,
        }

        exec_globals = {
            "__builtins__": _safe_builtins,
            "__name__": "__py_eval__",
            "idaapi": idaapi,
            "idc": idc,
            "idautils": _lazy_ida_import("idautils"),
            "ida_allins": _lazy_ida_import("ida_allins"),
            "ida_auto": _lazy_ida_import("ida_auto"),
            "ida_bitrange": _lazy_ida_import("ida_bitrange"),
            "ida_bytes": ida_bytes,
            "ida_dbg": ida_dbg,
            "ida_dirtree": _lazy_ida_import("ida_dirtree"),
            "ida_diskio": _lazy_ida_import("ida_diskio"),
            "ida_entry": ida_entry,
            "ida_expr": _lazy_ida_import("ida_expr"),
            "ida_fixup": _lazy_ida_import("ida_fixup"),
            "ida_fpro": _lazy_ida_import("ida_fpro"),
            "ida_frame": ida_frame,
            "ida_funcs": ida_funcs,
            "ida_gdl": _lazy_ida_import("ida_gdl"),
            "ida_graph": _lazy_ida_import("ida_graph"),
            "ida_hexrays": ida_hexrays,
            "ida_ida": ida_ida,
            "ida_idd": _lazy_ida_import("ida_idd"),
            "ida_idp": _lazy_ida_import("ida_idp"),
            "ida_ieee": _lazy_ida_import("ida_ieee"),
            "ida_kernwin": ida_kernwin,
            "ida_libfuncs": _lazy_ida_import("ida_libfuncs"),
            "ida_lines": ida_lines,
            "ida_loader": _lazy_ida_import("ida_loader"),
            "ida_merge": _lazy_ida_import("ida_merge"),
            "ida_mergemod": _lazy_ida_import("ida_mergemod"),
            "ida_moves": _lazy_ida_import("ida_moves"),
            "ida_nalt": ida_nalt,
            "ida_name": ida_name,
            "ida_netnode": _lazy_ida_import("ida_netnode"),
            "ida_offset": _lazy_ida_import("ida_offset"),
            "ida_pro": _lazy_ida_import("ida_pro"),
            "ida_problems": _lazy_ida_import("ida_problems"),
            "ida_range": _lazy_ida_import("ida_range"),
            "ida_regfinder": _lazy_ida_import("ida_regfinder"),
            "ida_registry": _lazy_ida_import("ida_registry"),
            "ida_search": _lazy_ida_import("ida_search"),
            "ida_segment": ida_segment,
            "ida_segregs": _lazy_ida_import("ida_segregs"),
            "ida_srclang": _lazy_ida_import("ida_srclang"),
            "ida_strlist": _lazy_ida_import("ida_strlist"),
            "ida_struct": _lazy_ida_import("ida_struct"),
            "ida_tryblks": _lazy_ida_import("ida_tryblks"),
            "ida_typeinf": ida_typeinf,
            "ida_ua": _lazy_ida_import("ida_ua"),
            "ida_undo": _lazy_ida_import("ida_undo"),
            "ida_xref": ida_xref,
            "ida_enum": _lazy_ida_import("ida_enum"),
            "parse_address": parse_address,
            "get_function": get_function,
        }

        result_value = _execute_py_eval_code(code, exec_globals)

        # Collect output
        stdout_text = stdout_capture.getvalue()
        stderr_text = stderr_capture.getvalue()

        return {
            "result": result_value or "",
            "stdout": stdout_text,
            "stderr": stderr_text,
        }

    except Exception:
        import traceback

        return {
            "result": "",
            "stdout": stdout_capture.getvalue(),
            "stderr": stderr_capture.getvalue() + traceback.format_exc(),
        }
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
