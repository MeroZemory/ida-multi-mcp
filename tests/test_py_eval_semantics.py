import importlib.util
import sys
import tempfile
import types
import unittest
from contextlib import contextmanager
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
API_PYTHON = REPO_ROOT / "src" / "ida_multi_mcp" / "ida_mcp" / "api_python.py"


def _module(name: str, **attrs):
    mod = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(mod, key, value)
    return mod


@contextmanager
def _loaded_api_python():
    touched_prefixes = ("ida_multi_mcp.ida_mcp",)
    ida_modules = [
        "idaapi",
        "idc",
        "ida_bytes",
        "ida_dbg",
        "ida_entry",
        "ida_frame",
        "ida_funcs",
        "ida_hexrays",
        "ida_ida",
        "ida_kernwin",
        "ida_lines",
        "ida_nalt",
        "ida_name",
        "ida_segment",
        "ida_typeinf",
        "ida_xref",
        # Modules imported lazily via _lazy_ida_import in api_python.py.
        # All must be mocked so ImportError warnings don't pollute stderr.
        "idautils",
        "ida_allins",
        "ida_auto",
        "ida_bitrange",
        "ida_dirtree",
        "ida_diskio",
        "ida_expr",
        "ida_fixup",
        "ida_fpro",
        "ida_gdl",
        "ida_graph",
        "ida_idd",
        "ida_idp",
        "ida_ieee",
        "ida_libfuncs",
        "ida_loader",
        "ida_merge",
        "ida_mergemod",
        "ida_moves",
        "ida_netnode",
        "ida_offset",
        "ida_pro",
        "ida_problems",
        "ida_range",
        "ida_regfinder",
        "ida_registry",
        "ida_search",
        "ida_segregs",
        "ida_srclang",
        "ida_strlist",
        "ida_struct",
        "ida_tryblks",
        "ida_ua",
        "ida_undo",
        "ida_enum",
    ]
    touched_names = set(ida_modules)
    touched_names.update(
        name for name in sys.modules if name.startswith(touched_prefixes)
    )

    saved = {name: sys.modules[name] for name in touched_names if name in sys.modules}
    try:
        for name in list(touched_names):
            sys.modules.pop(name, None)

        pkg = _module("ida_multi_mcp.ida_mcp")
        pkg.__path__ = []
        sys.modules[pkg.__name__] = pkg
        sys.modules["ida_multi_mcp.ida_mcp.rpc"] = _module(
            "ida_multi_mcp.ida_mcp.rpc",
            tool=lambda f: f,
            unsafe=lambda f: f,
        )
        sys.modules["ida_multi_mcp.ida_mcp.sync"] = _module(
            "ida_multi_mcp.ida_mcp.sync",
            idasync=lambda f: f,
        )
        sys.modules["ida_multi_mcp.ida_mcp.utils"] = _module(
            "ida_multi_mcp.ida_mcp.utils",
            parse_address=lambda value: int(str(value), 0),
            get_function=lambda value: None,
        )
        for name in ida_modules:
            sys.modules[name] = _module(name, MARKER=name)

        spec = importlib.util.spec_from_file_location(
            "ida_multi_mcp.ida_mcp.api_python",
            API_PYTHON,
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        yield module
    finally:
        for name in list(sys.modules):
            if name.startswith(touched_prefixes) or name in ida_modules:
                sys.modules.pop(name, None)
        sys.modules.update(saved)


class PyEvalSemanticsTest(unittest.TestCase):
    def test_lazy_import_accepts_standard_import_signature(self):
        with _loaded_api_python() as api_python:
            imported = api_python._lazy_ida_import("ida_gdl", {}, {}, (), 0)
            self.assertIs(imported, sys.modules["ida_gdl"])

            with self.assertRaises(ImportError):
                api_python._lazy_ida_import("os", {}, {}, (), 0)

    def test_optional_import_returns_none_without_repeated_warnings(self):
        """Missing optional prebindings bind None without noisy warnings."""
        with _loaded_api_python() as api_python:
            # Remove a module so the optional prebinding hits ImportError.
            saved_mod = sys.modules.pop("ida_fpro", None)
            try:
                result = api_python.py_eval("result = ida_fpro is None")
                repeated = api_python.py_eval("result = ida_fpro is None")
            finally:
                if saved_mod is not None:
                    sys.modules["ida_fpro"] = saved_mod

            self.assertEqual(result["result"], "True")
            self.assertEqual(repeated["result"], "True")
            self.assertEqual(result["stderr"], "")
            self.assertEqual(repeated["stderr"], "")

    def test_lazy_import_preserves_dotted_and_fromlist_imports_across_evals(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            package_dir = Path(temp_dir) / "ida_import_order"
            package_dir.mkdir()
            (package_dir / "__init__.py").write_text("", encoding="utf-8")
            (package_dir / "child.py").write_text("MARKER = 'child'\n", encoding="utf-8")
            sys.path.insert(0, temp_dir)
            try:
                dotted = "import ida_import_order.child\nresult = ida_import_order.child.MARKER"
                fromlist = "from ida_import_order.child import MARKER\nresult = MARKER"
                for codes in ((dotted, fromlist), (fromlist, dotted)):
                    with _loaded_api_python() as api_python:
                        self.assertNotIn("ida_import_order.child", sys.modules)
                        for code in codes:
                            result = api_python.py_eval(code)
                            self.assertEqual(result["result"], "child")
                            self.assertEqual(result["stderr"], "")
                    sys.modules.pop("ida_import_order.child", None)
                    sys.modules.pop("ida_import_order", None)
            finally:
                sys.path.remove(temp_dir)
                sys.modules.pop("ida_import_order.child", None)
                sys.modules.pop("ida_import_order", None)

    def test_lazy_import_imports_child_when_parent_is_prebound(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            package_dir = Path(temp_dir) / "ida_gdl"
            package_dir.mkdir()
            (package_dir / "__init__.py").write_text("", encoding="utf-8")
            (package_dir / "child.py").write_text("MARKER = 'child'\n", encoding="utf-8")
            sys.path.insert(0, temp_dir)
            try:
                with _loaded_api_python() as api_python:
                    sys.modules.pop("ida_gdl", None)
                    parent = __import__("ida_gdl")
                    self.assertNotIn("ida_gdl.child", sys.modules)
                    self.assertFalse(hasattr(parent, "child"))
                    result = api_python.py_eval(
                        "from ida_gdl import child\n"
                        "result = child.MARKER"
                    )
                    self.assertEqual(result["result"], "child")
                    self.assertEqual(result["stderr"], "")
            finally:
                sys.path.remove(temp_dir)
                sys.modules.pop("ida_gdl.child", None)
                sys.modules.pop("ida_gdl", None)

    def test_lazy_import_retries_explicit_import_after_missing_prebind(self):
        with _loaded_api_python() as api_python:
            saved_module = sys.modules.pop("ida_fpro", None)
            try:
                prebound = api_python.py_eval("result = ida_fpro is None")
                self.assertEqual(prebound["result"], "True")
                self.assertEqual(prebound["stderr"], "")

                available = _module("ida_fpro", MARKER="available")
                sys.modules["ida_fpro"] = available
                imported = api_python.py_eval(
                    "import ida_fpro\n"
                    "result = ida_fpro.MARKER"
                )
                self.assertEqual(imported["result"], "available")
                self.assertNotIn("could not be imported", imported["stderr"])
            finally:
                sys.modules.pop("ida_fpro", None)
                if saved_module is not None:
                    sys.modules["ida_fpro"] = saved_module

    def test_py_eval_supports_multi_module_import(self):
        with _loaded_api_python() as api_python:
            result = api_python.py_eval(
                "import ida_gdl, ida_funcs, idc\n"
                "result = ida_gdl.MARKER + ':' + ida_funcs.MARKER + ':' + idc.MARKER"
            )

        self.assertEqual(result["stderr"], "")
        self.assertEqual(result["result"], "ida_gdl:ida_funcs:idc")

    def test_py_eval_does_not_execute_last_expr_twice(self):
        with _loaded_api_python() as api_python:
            result = api_python.py_eval(
                "events = []\n"
                "events.append('body')\n"
                "events.append('last')"
            )

            self.assertEqual(result["stderr"], "")
            self.assertEqual(result["stdout"], "")
            self.assertEqual(result["result"], "")

            result = api_python.py_eval(
                "events = []\n"
                "events.append('body')\n"
                "events.append('last')\n"
                "len(events)"
            )

        self.assertEqual(result["stderr"], "")
        self.assertEqual(result["result"], "2")

    def test_py_eval_print_call_runs_once(self):
        with _loaded_api_python() as api_python:
            result = api_python.py_eval("print('first')\nprint('last')")

        self.assertEqual(result["stderr"], "")
        self.assertEqual(result["stdout"], "first\nlast\n")


if __name__ == "__main__":
    unittest.main()
