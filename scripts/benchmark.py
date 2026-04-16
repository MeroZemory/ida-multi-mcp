#!/usr/bin/env python3
"""MCP tool performance benchmark for ida-multi-mcp.

Measures latency of each tool category against a live IDA instance.
Run before and after plugin updates to compare.

Usage:
    # Direct to IDA instance (recommended for accurate per-tool timing):
    python scripts/benchmark.py --host 127.0.0.1 --port 53709

    # Via router (measures router overhead too):
    python scripts/benchmark.py --via-router --instance-id fawd

    # Compare two reports:
    python scripts/benchmark.py --compare before.json after.json

    # Save report:
    python scripts/benchmark.py --port 53709 -o before.json
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import statistics
import sys
import time
from typing import Any


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _call_tool(host: str, port: int, name: str, args: dict | None = None,
               timeout: float = 300.0) -> tuple[float, dict, int, int]:
    """Call a tool via HTTP JSON-RPC.

    Returns (elapsed_ms, result_or_error, request_bytes, response_bytes).
    """
    body = json.dumps({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": name, "arguments": args or {}},
        "id": 1,
    })
    req_bytes = len(body.encode())
    t0 = time.perf_counter()
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("POST", "/mcp", body, {"Content-Type": "application/json"})
        raw = conn.getresponse().read()
        conn.close()
        elapsed = (time.perf_counter() - t0) * 1000
        resp_bytes = len(raw)
        resp = json.loads(raw.decode())
        result = resp.get("result", resp)
        # Parse text content
        content = result.get("content", []) if isinstance(result, dict) else []
        if content and isinstance(content, list):
            try:
                parsed = json.loads(content[0].get("text", "{}"))
                return elapsed, parsed, req_bytes, resp_bytes
            except Exception:
                pass
        return elapsed, result, req_bytes, resp_bytes
    except Exception as e:
        elapsed = (time.perf_counter() - t0) * 1000
        return elapsed, {"error": str(e)}, req_bytes, 0


def _list_tools(host: str, port: int) -> list[str]:
    """Get the list of registered tool names."""
    body = json.dumps({"jsonrpc": "2.0", "method": "tools/list", "id": 1})
    try:
        conn = http.client.HTTPConnection(host, port, timeout=10)
        conn.request("POST", "/mcp", body, {"Content-Type": "application/json"})
        raw = json.loads(conn.getresponse().read().decode())
        conn.close()
        tools = raw.get("result", {}).get("tools", [])
        return [t["name"] for t in tools]
    except Exception:
        return []


def _get_sample_function(host: str, port: int) -> str | None:
    """Get a sample function address for benchmarking."""
    _, result, _, _ = _call_tool(host, port, "list_funcs", {"queries": '{"count":1}'})
    try:
        if isinstance(result, list) and result:
            return result[0]["data"][0]["addr"]
    except (KeyError, IndexError, TypeError):
        pass
    return None


def _get_sample_string_addr(host: str, port: int) -> str | None:
    """Get a sample string address."""
    _, result, _, _ = _call_tool(host, port, "find_regex", {"pattern": ".", "limit": 1})
    try:
        return result["matches"][0]["addr"]
    except (KeyError, IndexError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Benchmark definitions
# ---------------------------------------------------------------------------

def _build_benchmarks(func_addr: str, string_addr: str | None,
                      available_tools: set[str]) -> list[dict]:
    """Build list of benchmark specs. Each spec: {name, tool, args, category}."""
    benchmarks = []

    def _add(name: str, tool: str, args: dict, category: str):
        if tool in available_tools:
            benchmarks.append({"name": name, "tool": tool, "args": args, "category": category})

    # --- Triage ---
    _add("survey_binary(minimal)", "survey_binary",
         {"detail_level": "minimal"}, "triage")
    _add("survey_binary(standard)", "survey_binary",
         {"detail_level": "standard"}, "triage")

    # --- Analysis ---
    _add("decompile(1 func)", "decompile",
         {"addr": func_addr}, "analysis")
    _add("disasm(1 func, 100 insns)", "disasm",
         {"addr": func_addr, "max_instructions": 100}, "analysis")
    _add("analyze_function", "analyze_function",
         {"addr": func_addr}, "analysis")
    _add("analyze_batch(1 func)", "analyze_batch",
         {"addrs": [func_addr]}, "analysis")

    # --- Navigation ---
    _add("list_funcs(50)", "list_funcs",
         {"queries": '{"count":50}'}, "navigation")
    _add("list_globals(50)", "list_globals",
         {"queries": '{"count":50}'}, "navigation")
    _add("imports(50)", "imports",
         {"offset": 0, "count": 50}, "navigation")
    _add("find_regex(simple)", "find_regex",
         {"pattern": "error", "limit": 10}, "navigation")
    _add("find_bytes(short)", "find_bytes",
         {"patterns": "48 89 5C 24", "limit": 10}, "navigation")
    _add("xrefs_to(1 addr)", "xrefs_to",
         {"addrs": func_addr, "limit": 50}, "navigation")
    _add("xrefs_from(1 addr)", "xrefs_from",
         {"addrs": func_addr, "limit": 50}, "navigation")

    # --- Rich queries ---
    _add("func_query(size>100)", "func_query",
         {"queries": {"min_size": 100, "count": 20, "sort_by": "size", "descending": True}}, "query")
    _add("imports_query(kernel32)", "imports_query",
         {"queries": {"module": "kernel32", "count": 20}}, "query")
    _add("xref_query(to, code)", "xref_query",
         {"queries": {"addr": func_addr, "direction": "to", "type_filter": "code", "count": 20}}, "query")
    _add("insn_query(call)", "insn_query",
         {"queries": {"mnem": "call", "func": func_addr, "count": 20}}, "query")

    # --- Modification (non-destructive) ---
    _add("set_comments(1)", "set_comments",
         {"items": {"addr": func_addr, "comment": "__benchmark__"}}, "modification")
    _add("append_comments(1)", "append_comments",
         {"items": {"addr": func_addr, "comment": "__bench_append__"}}, "modification")

    # --- Memory ---
    _add("get_bytes(64B)", "get_bytes",
         {"regions": {"addr": func_addr, "size": 64}}, "memory")
    if string_addr:
        _add("get_string(1)", "get_string",
             {"addrs": string_addr}, "memory")

    # --- Type system ---
    _add("search_structs(*)", "search_structs",
         {"filter": "*"}, "types")

    # --- Profile / classify ---
    _add("func_profile(top 10)", "func_profile",
         {"addrs": "*", "count": 10, "sort_by": "size"}, "profile")
    _add("classify_functions(10)", "classify_functions",
         {"addrs": "*", "count": 10}, "profile")

    # --- Meta ---
    _add("server_health", "server_health", {}, "meta")
    _add("server_warmup(caches only)", "server_warmup",
         {"wait_auto_analysis": False, "build_caches": True, "init_hexrays": False}, "meta")

    # --- Composite ---
    _add("trace_data_flow(backward,depth=2)", "trace_data_flow",
         {"addr": func_addr, "direction": "backward", "max_depth": 2}, "composite")

    # --- Save ---
    _add("idb_save", "idb_save", {}, "meta")

    return benchmarks


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_benchmarks(host: str, port: int, iterations: int = 1) -> dict:
    """Run all benchmarks and return structured report."""
    print(f"Connecting to {host}:{port}...", file=sys.stderr)

    # Discover available tools
    available = set(_list_tools(host, port))
    print(f"  {len(available)} tools available", file=sys.stderr)

    # Get sample addresses
    func_addr = _get_sample_function(host, port)
    if not func_addr:
        print("  ERROR: Could not get sample function address", file=sys.stderr)
        return {"error": "No functions found"}
    print(f"  Sample function: {func_addr}", file=sys.stderr)

    string_addr = _get_sample_string_addr(host, port)
    print(f"  Sample string: {string_addr or 'none'}", file=sys.stderr)

    benchmarks = _build_benchmarks(func_addr, string_addr, available)
    skipped_tools = set()
    results = []

    print(f"\nRunning {len(benchmarks)} benchmarks (x{iterations} iterations)...\n",
          file=sys.stderr)
    print(f"  {'Benchmark':<38} {'Latency':>8}  {'Response':>8} {'~Tokens':>8}  {'Status'}",
          file=sys.stderr)
    print("  " + "-" * 76, file=sys.stderr)

    for bench in benchmarks:
        timings = []
        req_sizes = []
        resp_sizes = []
        last_error = None
        for _ in range(iterations):
            ms, resp, req_b, resp_b = _call_tool(host, port, bench["tool"], bench["args"])
            timings.append(ms)
            req_sizes.append(req_b)
            resp_sizes.append(resp_b)
            if isinstance(resp, dict) and resp.get("isError"):
                last_error = "IDA error"
            elif isinstance(resp, dict) and "error" in resp:
                err = resp["error"]
                if "Internal Error" in str(err):
                    last_error = "internal error"
                elif "AttributeError" in str(err):
                    last_error = "AttributeError"

        avg = statistics.mean(timings)
        mn = min(timings)
        avg_resp = round(statistics.mean(resp_sizes))
        est_tokens = avg_resp // 4  # rough estimate: ~4 bytes per token
        status = last_error or "ok"

        print(f"  {bench['name']:<38} {avg:>8.0f}ms {avg_resp:>8,}B ~{est_tokens:>6,}tok  {status}",
              file=sys.stderr)

        results.append({
            "name": bench["name"],
            "tool": bench["tool"],
            "category": bench["category"],
            "avg_ms": round(avg, 2),
            "min_ms": round(mn, 2),
            "max_ms": round(max(timings), 2),
            "req_bytes": round(statistics.mean(req_sizes)),
            "resp_bytes": avg_resp,
            "est_tokens": est_tokens,
            "iterations": iterations,
            "status": status,
        })

    # Summary by category
    cat_data: dict[str, list[dict]] = {}
    for r in results:
        if r["status"] == "ok":
            cat_data.setdefault(r["category"], []).append(r)

    summary = {}
    for cat, items in sorted(cat_data.items()):
        total_ms = sum(r["avg_ms"] for r in items)
        total_bytes = sum(r["resp_bytes"] for r in items)
        total_tokens = sum(r["est_tokens"] for r in items)
        summary[cat] = {
            "count": len(items),
            "total_ms": round(total_ms, 1),
            "avg_ms": round(total_ms / len(items), 1),
            "total_resp_bytes": total_bytes,
            "total_est_tokens": total_tokens,
        }

    print(f"\n  {'Category':<18} {'Tools':>6} {'Total ms':>10} {'Resp bytes':>12} {'~Tokens':>10}",
          file=sys.stderr)
    print("  " + "-" * 58, file=sys.stderr)
    for cat, s in summary.items():
        print(f"  {cat:<18} {s['count']:>6} {s['total_ms']:>10.1f} {s['total_resp_bytes']:>12,} {s['total_est_tokens']:>10,}",
              file=sys.stderr)

    total_ms = sum(s["total_ms"] for s in summary.values())
    total_bytes = sum(s["total_resp_bytes"] for s in summary.values())
    total_tokens = sum(s["total_est_tokens"] for s in summary.values())
    print(f"\n  Total: {total_ms:.0f} ms | {total_bytes:,} bytes | ~{total_tokens:,} tokens",
          file=sys.stderr)

    return {
        "host": host,
        "port": port,
        "tools_available": len(available),
        "benchmarks_run": len(results),
        "iterations": iterations,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "results": results,
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# Compare
# ---------------------------------------------------------------------------

def compare_reports(path_a: str, path_b: str):
    """Compare two benchmark JSON reports side-by-side."""
    with open(path_a) as f:
        a = json.load(f)
    with open(path_b) as f:
        b = json.load(f)

    results_a = {r["name"]: r for r in a["results"]}
    results_b = {r["name"]: r for r in b["results"]}
    all_names = sorted(set(results_a) | set(results_b))

    print(f"\n{'Benchmark':<38} {'Before':>8} {'After':>8} {'Delta':>8}  {'Before B':>9} {'After B':>9} {'Delta B':>9}")
    print("=" * 100)

    for name in all_names:
        ra = results_a.get(name)
        rb = results_b.get(name)

        if ra and rb and ra["status"] == "ok" and rb["status"] == "ok":
            bef_ms = ra["avg_ms"]
            aft_ms = rb["avg_ms"]
            d_ms = aft_ms - bef_ms
            bef_b = ra.get("resp_bytes", 0)
            aft_b = rb.get("resp_bytes", 0)
            d_b = aft_b - bef_b
            sign_ms = "+" if d_ms > 0 else ""
            sign_b = "+" if d_b > 0 else ""
            print(f"  {name:<36} {bef_ms:>7.0f}ms {aft_ms:>7.0f}ms {sign_ms}{d_ms:>7.0f}ms"
                  f"  {bef_b:>8,}B {aft_b:>8,}B {sign_b}{d_b:>8,}B")
        elif ra and not rb:
            print(f"  {name:<36} {ra['avg_ms']:>7.0f}ms {'---':>8} {'removed':>8}")
        elif rb and not ra:
            print(f"  {name:<36} {'---':>8} {rb['avg_ms']:>7.0f}ms {'new':>8}")
        else:
            sa = ra["status"] if ra else "?"
            sb = rb["status"] if rb else "?"
            print(f"  {name:<36} {sa:>8} {sb:>8}")

    # Category summary
    sum_a = a.get("summary", {})
    sum_b = b.get("summary", {})
    all_cats = sorted(set(sum_a) | set(sum_b))

    print(f"\n{'Category':<18} {'Before ms':>10} {'After ms':>10} {'Delta ms':>10}  {'Before tok':>10} {'After tok':>10}")
    print("-" * 72)
    for cat in all_cats:
        sa_ms = sum_a.get(cat, {}).get("total_ms", 0)
        sb_ms = sum_b.get(cat, {}).get("total_ms", 0)
        sa_tok = sum_a.get(cat, {}).get("total_est_tokens", 0)
        sb_tok = sum_b.get(cat, {}).get("total_est_tokens", 0)
        d = sb_ms - sa_ms
        sign = "+" if d > 0 else ""
        print(f"  {cat:<16} {sa_ms:>10.0f} {sb_ms:>10.0f} {sign}{d:>9.0f}  {sa_tok:>10,} {sb_tok:>10,}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Benchmark MCP tool performance against a live IDA instance"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0,
                        help="IDA instance HTTP port (required unless --compare)")
    parser.add_argument("--iterations", "-n", type=int, default=1,
                        help="Number of iterations per benchmark (default: 1)")
    parser.add_argument("-o", "--output", type=str, default="",
                        help="Save JSON report to file")
    parser.add_argument("--compare", nargs=2, metavar=("BEFORE", "AFTER"),
                        help="Compare two JSON reports")

    args = parser.parse_args()

    if args.compare:
        compare_reports(args.compare[0], args.compare[1])
        return

    if args.port == 0:
        # Try to auto-detect from running instances
        try:
            from ida_multi_mcp.registry import InstanceRegistry
            reg = InstanceRegistry()
            instances = reg.list_instances()
            if instances:
                first = next(iter(instances.values()))
                args.port = first["port"]
                print(f"Auto-detected port {args.port} from registry", file=sys.stderr)
            else:
                parser.error("No IDA instances found. Specify --port explicitly.")
        except Exception:
            parser.error("--port is required (could not auto-detect)")

    report = run_benchmarks(args.host, args.port, args.iterations)

    # Output
    report_json = json.dumps(report, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(report_json)
        print(f"\nReport saved to {args.output}", file=sys.stderr)
    else:
        print(report_json)


if __name__ == "__main__":
    main()
