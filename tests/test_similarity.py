"""End-to-end tests for the server-side similarity pipeline using a mock router.

Exercises index_functions -> similar_functions / compare_functions / index_status
WITHOUT a live IDA instance: a MockRouter serves synthetic func_features and
binary_fingerprint responses in the exact shape the real router returns.
"""

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_ROOT))

from ida_multi_mcp.tools import index_store, sim_score, similarity  # noqa: E402


# --- synthetic feature corpus -------------------------------------------------

# Distinct instruction-token streams (>= K tokens so MinHash is non-empty).
T_ENC = ["mov.rr", "xor.rr", "add.rm", "cmp.ri", "jne.c", "mov.mr",
         "call.c", "test.rr", "je.c", "inc.r", "mov.rm", "ret."]
T_PARSE = ["push.r", "mov.rr", "call.c", "test.rr", "je.c", "lea.rd",
           "call.c", "mov.rm", "add.ri", "jmp.c", "pop.r", "ret."]
T_SUM = ["xor.rr", "test.rr", "jle.c", "add.rm", "add.ri", "cmp.rr",
         "jne.c", "mov.rr", "ret.", "nop.", "lea.rd", "mov.rm"]
T_MISC = ["sub.ri", "mov.rm", "call.c", "mov.mr", "call.c", "test.rr",
          "jne.c", "mov.ri", "add.rr", "ret.", "push.r", "pop.r"]
T_OTHER = ["fld.m", "fmul.m", "fstp.m", "mov.rm", "shr.ri", "and.ri",
           "or.rr", "ret.", "jmp.c", "cmp.ri", "sete.r", "movzx.rr"]


def _feat(addr, name, tokens, apis, strings, consts, cfg, is_named, pseudo=None):
    f = {
        "addr": addr,
        "name": name,
        "is_named": is_named,
        "size": cfg.get("_size", 100),
        "cfg": {k: v for k, v in cfg.items() if not k.startswith("_")},
        "minhash": sim_score.compute_minhash(tokens),
        "apis": sorted(set(apis)),
        "strings": sorted(set(strings)),
        "consts": sorted(set(consts)),
    }
    if is_named:
        f["pseudo_tokens"] = pseudo or []
    return f


_CFG_A = {"bb_count": 6, "edge_count": 8, "complexity": 4, "loops": 1,
          "callee_count": 3, "caller_count": 2, "out_deg_seq": [2, 2, 1, 1, 0, 0], "_size": 213}
_CFG_B = {"bb_count": 3, "edge_count": 3, "complexity": 2, "loops": 0,
          "callee_count": 2, "caller_count": 5, "out_deg_seq": [1, 1, 0], "_size": 80}
_CFG_C = {"bb_count": 4, "edge_count": 5, "complexity": 3, "loops": 1,
          "callee_count": 0, "caller_count": 1, "out_deg_seq": [2, 1, 0, 0], "_size": 60}


def _corpus():
    """instance_id -> list[FunctionFeature]."""
    aaaa = [
        _feat("0x1001", "encrypt_a", T_ENC, ["CreateFileW", "WriteFile", "CryptEncrypt"],
              ["%s.enc"], ["0xdeadbeef"], _CFG_A, True, ["encrypt", "key", "buf"]),
        # near-duplicate of encrypt_a (Type-1): identical tokens + anchors + cfg
        _feat("0x1002", "encrypt_b", T_ENC, ["CreateFileW", "WriteFile", "CryptEncrypt"],
              ["%s.enc"], ["0xdeadbeef"], _CFG_A, True, ["encrypt", "key", "buf"]),
        _feat("0x1003", "parse_x", T_PARSE, ["strtol", "strchr"], [], [], _CFG_B, True, ["parse", "line"]),
        _feat("0x1004", "sub_1004", T_SUM, [], [], [], _CFG_C, False),
        _feat("0x1005", "misc_z", T_MISC, ["malloc", "free"], ["hello"], ["0x2a"], _CFG_B, True, ["misc"]),
        # tiny thunk: no shingles -> empty minhash, only an anchor
        _feat("0x1006", "sub_1006", ["jmp.c"], ["memcpy"], [], [], _CFG_C, False),
    ]
    bbbb = [
        # cross-instance twin of encrypt_a
        _feat("0x2001", "encrypt_twin", T_ENC, ["CreateFileW", "WriteFile", "CryptEncrypt"],
              ["%s.enc"], ["0xdeadbeef"], _CFG_A, True, ["encrypt", "key", "buf"]),
        _feat("0x2002", "unrelated", T_OTHER, ["printf"], ["world"], ["0x99"], _CFG_B, True, ["unrelated"]),
    ]
    return {"aaaa": aaaa, "bbbb": bbbb}


class MockRegistry:
    def __init__(self, registry_path, corpus):
        self.registry_path = registry_path
        self._corpus = corpus

    def list_instances(self):
        return {iid: {"binary_name": f"{iid}.exe", "binary_path": f"C:/x/{iid}.exe",
                      "arch": "x86_64"} for iid in self._corpus}

    def get_instance(self, iid):
        insts = self.list_instances()
        return insts.get(iid)


class MockRouter:
    """Serves func_features / binary_fingerprint in the real router's result shape."""

    def __init__(self, corpus):
        self._corpus = corpus

    def route_request(self, method, params):
        name = params.get("name")
        args = params.get("arguments", {})
        iid = args.get("instance_id")
        feats = self._corpus.get(iid)
        if feats is None:
            return {"error": f"no instance {iid}"}
        if name == "binary_fingerprint":
            payload = {"sha256": f"sha-{iid}", "md5": None,
                       "function_count": len(feats), "arch": "x86_64"}
        elif name == "func_features":
            addrs = args.get("addrs", "*")
            if addrs == "*":
                offset = int(args.get("offset", 0))
                count = int(args.get("count", 500))
                page = feats[offset:offset + count]
                nxt = offset + len(page)
                cursor = {"done": True} if nxt >= len(feats) else {"next": nxt}
                payload = {"functions": page, "total": len(feats), "cursor": cursor}
            else:
                match = [f for f in feats if f["addr"] == str(addrs) or f["name"] == str(addrs)]
                payload = {"functions": match[:1], "total": len(match),
                           "cursor": {"done": True}}
        else:
            return {"error": f"unknown tool {name}"}
        return {"content": [{"type": "text", "text": json.dumps(payload)}],
                "structuredContent": payload}


class SimilarityPipelineTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        registry_path = os.path.join(self._td.name, "instances.json")
        corpus = _corpus()
        similarity.set_registry(MockRegistry(registry_path, corpus))
        similarity.set_router(MockRouter(corpus))
        # reset module state between tests
        similarity._jobs.clear()
        similarity._loaded.clear()

    def tearDown(self):
        similarity._jobs.clear()
        similarity._loaded.clear()
        self._td.cleanup()

    def _index(self, iid):
        return similarity.index_functions({"instance_id": iid, "background": False})

    def test_index_build_and_status(self):
        res = self._index("aaaa")
        self.assertEqual(res["status"], "ready")
        self.assertEqual(res["function_count"], 6)
        st = similarity.index_status({"instance_id": "aaaa"})
        self.assertTrue(st["indexed"])
        self.assertEqual(st["function_count"], 6)
        # second call is a cached no-op
        again = self._index("aaaa")
        self.assertTrue(again.get("cached"))

    def test_similar_finds_duplicate_top1(self):
        self._index("aaaa")
        out = similarity.similar_functions({"instance_id": "aaaa", "func": "0x1001", "top_k": 5})
        self.assertTrue(out["results"], "expected at least one match")
        top = out["results"][0]
        self.assertEqual(top["addr"], "0x1002")           # encrypt_b is the twin
        self.assertGreater(top["score"], 0.75)
        self.assertEqual(top["confidence"], "high")
        # query itself excluded
        self.assertNotIn("0x1001", [r["addr"] for r in out["results"]])

    def test_cross_instance_search(self):
        self._index("aaaa")
        self._index("bbbb")
        out = similarity.similar_functions({
            "instance_id": "aaaa", "func": "0x1001",
            "scope": "instances", "instances": ["bbbb"], "top_k": 5,
        })
        addrs = [(r["instance_id"], r["addr"]) for r in out["results"]]
        self.assertIn(("bbbb", "0x2001"), addrs)          # cross-binary twin found
        self.assertGreater(out["results"][0]["score"], 0.75)

    def test_compare_high_and_low(self):
        self._index("aaaa")
        hi = similarity.compare_functions({
            "a": {"instance_id": "aaaa", "func": "0x1001"},
            "b": {"instance_id": "aaaa", "func": "0x1002"},
        })
        lo = similarity.compare_functions({
            "a": {"instance_id": "aaaa", "func": "0x1001"},
            "b": {"instance_id": "aaaa", "func": "0x1003"},
        })
        self.assertGreater(hi["score"], 0.75)
        self.assertGreater(hi["score"], lo["score"] + 0.3)

    def test_min_score_filters(self):
        self._index("aaaa")
        out = similarity.similar_functions({
            "instance_id": "aaaa", "func": "0x1001", "min_score": 0.99, "top_k": 20})
        # only the (near-)identical twin should survive a 0.99 threshold
        for r in out["results"]:
            self.assertGreaterEqual(r["score"], 0.99)

    def test_not_indexed_hint(self):
        # query instance indexed, gallery instance not
        self._index("aaaa")
        out = similarity.similar_functions({
            "instance_id": "aaaa", "func": "0x1001",
            "scope": "instances", "instances": ["bbbb"]})
        self.assertIn("bbbb", out.get("not_indexed", []))
        self.assertIn("hint", out)

    def test_missing_func_errors(self):
        self._index("aaaa")
        out = similarity.similar_functions({"instance_id": "aaaa", "func": "0xBADADDR"})
        self.assertIn("error", out)


class _ErrRouter:
    """Mirrors the REAL func_features behaviour the default MockRouter omits:
    a per-function ``{"addr","error"}`` stub is mixed into the ``*`` page, and an
    unresolvable single-function query returns such a stub (not an empty list).
    """

    def __init__(self, good):
        self._good = good

    def route_request(self, method, params):
        name = params.get("name")
        args = params.get("arguments", {})
        if name == "binary_fingerprint":
            payload = {"sha256": "sha-err", "md5": None,
                       "function_count": len(self._good) + 1, "arch": "x86_64"}
        elif name == "func_features":
            addrs = args.get("addrs", "*")
            if addrs == "*":
                page = list(self._good) + [{"addr": "0x9099", "error": "No function found"}]
                payload = {"functions": page, "total": len(page), "cursor": {"done": True}}
            else:
                m = [f for f in self._good
                     if f["addr"] == str(addrs) or f.get("name") == str(addrs)]
                payload = {
                    "functions": m[:1] if m else [{"addr": str(addrs), "error": "No function found"}],
                    "total": 1, "cursor": {"done": True},
                }
        else:
            return {"error": f"unknown tool {name}"}
        return {"content": [{"type": "text", "text": json.dumps(payload)}],
                "structuredContent": payload}


class SimilarityErrorRecordTest(unittest.TestCase):
    """Regression: a single un-analyzable function must not sink the index, and
    an unextractable query must return a clean error (not a leaked KeyError)."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        rp = os.path.join(self._td.name, "instances.json")
        self._good = _corpus()["aaaa"][:2]  # two complete records
        similarity.set_registry(MockRegistry(rp, {"err": self._good}))
        similarity.set_router(_ErrRouter(self._good))
        similarity._jobs.clear()
        similarity._loaded.clear()

    def tearDown(self):
        similarity._jobs.clear()
        similarity._loaded.clear()
        self._td.cleanup()

    def test_index_build_skips_error_records(self):
        res = similarity.index_functions({"instance_id": "err", "background": False})
        self.assertEqual(res["status"], "ready")
        self.assertEqual(res["function_count"], 2)   # error stub excluded, no crash
        self.assertEqual(res["skipped_count"], 1)

    def test_index_gallery_excludes_error_records(self):
        similarity.index_functions({"instance_id": "err", "background": False})
        # a good function still finds its twin; the error stub is not in the gallery
        out = similarity.similar_functions({"instance_id": "err", "func": "0x1001"})
        addrs = [r["addr"] for r in out["results"]]
        self.assertNotIn("0x9099", addrs)

    def test_query_extraction_error_is_clean(self):
        similarity.index_functions({"instance_id": "err", "background": False})
        out = similarity.similar_functions({"instance_id": "err", "func": "0xBAD"})
        self.assertIn("error", out)
        self.assertNotIn("KeyError", out["error"])   # clean message, not an exception leak

    def test_compare_extraction_error_is_clean(self):
        out = similarity.compare_functions({
            "a": {"instance_id": "err", "func": "0x1001"},
            "b": {"instance_id": "err", "func": "0xBAD"},
        })
        self.assertIn("error", out)
        self.assertNotIn("KeyError", out["error"])


def _wait_until(predicate, timeout=5.0, interval=0.01):
    """Poll `predicate()` until truthy or `timeout` elapses; raise on timeout.

    The background build genuinely runs on a separate thread (that is the
    behavior under test), so tests synchronize on job-state, not sleeps.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(interval)
    raise AssertionError(f"condition not met within {timeout}s")


class PausableRouter:
    """Serves func_features / binary_fingerprint like MockRouter, but each
    '*' (paginated) func_features call blocks on a counting semaphore until
    the test calls release_pages(n) — lets tests pause a background build
    mid-page and inspect/exercise partial state deterministically. Optional
    swap_after_pages flips the fingerprint after that many pages have been
    served, simulating a mid-build binary change.
    """

    def __init__(self, corpus):
        self._corpus = corpus
        self._budget = threading.Semaphore(0)
        self.pages_served = 0
        self.swap_after_pages = None
        self._swapped = False
        self.fail_fingerprint_times = 0

    def release_pages(self, n):
        for _ in range(n):
            self._budget.release()

    def route_request(self, method, params):
        name = params.get("name")
        args = params.get("arguments", {})
        iid = args.get("instance_id")
        feats = self._corpus.get(iid)
        if feats is None:
            return {"error": f"no instance {iid}"}
        if name == "binary_fingerprint":
            if self.fail_fingerprint_times > 0:
                self.fail_fingerprint_times -= 1
                return {"error": "transient routing failure"}
            sha = f"sha-{iid}-swapped" if self._swapped else f"sha-{iid}"
            payload = {"sha256": sha, "md5": None,
                       "function_count": len(feats), "arch": "x86_64"}
        elif name == "func_features":
            addrs = args.get("addrs", "*")
            if addrs == "*":
                self._budget.acquire()
                self.pages_served += 1
                if (self.swap_after_pages is not None
                        and self.pages_served > self.swap_after_pages):
                    self._swapped = True
                offset = int(args.get("offset", 0))
                count = int(args.get("count", 500))
                page = feats[offset:offset + count]
                nxt = offset + len(page)
                cursor = {"done": True} if nxt >= len(feats) else {"next": nxt}
                payload = {"functions": page, "total": len(feats), "cursor": cursor}
            else:
                match = [f for f in feats if f["addr"] == str(addrs) or f["name"] == str(addrs)]
                payload = {"functions": match[:1], "total": len(match),
                           "cursor": {"done": True}}
        else:
            return {"error": f"unknown tool {name}"}
        return {"content": [{"type": "text", "text": json.dumps(payload)}],
                "structuredContent": payload}


class PartialIndexTest(unittest.TestCase):
    """Background-build instrumentation, partial-serving, and their race/edge
    cases. Uses PausableRouter to deterministically pause a build mid-page —
    real threading is exercised (this is the behavior under test), so tests
    synchronize on `_jobs` state via `_wait_until`, never on sleeps alone.
    """

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self._registry_path = os.path.join(self._td.name, "instances.json")
        self._corpus = {"aaaa": _corpus()["aaaa"]}   # 6 functions
        self._router = PausableRouter(self._corpus)
        similarity.set_registry(MockRegistry(self._registry_path, self._corpus))
        similarity.set_router(self._router)
        similarity._jobs.clear()
        similarity._loaded.clear()
        self._orig_page = similarity.PAGE
        similarity.PAGE = 2   # 6 functions / 2-per-page = 3 pages, so tests can pause mid-build

    def tearDown(self):
        similarity.PAGE = self._orig_page
        similarity._jobs.clear()
        similarity._loaded.clear()
        self._td.cleanup()

    def test_background_build_exposes_gen_and_live_records(self):
        res = similarity.index_functions({"instance_id": "aaaa", "background": True})
        self.assertEqual(res["status"], "building")
        self._router.release_pages(1)
        _wait_until(lambda: similarity._jobs.get("aaaa", {}).get("pages_seen") == 1)

        job = similarity._jobs["aaaa"]
        self.assertIsInstance(job["gen"], int)
        self.assertEqual(len(job["live_records"]), 2)   # exactly page 1's functions
        self.assertEqual(job["status"], "building")

        self._router.release_pages(2)   # let the remaining 2 pages through
        _wait_until(lambda: similarity._jobs.get("aaaa", {}).get("status") == "ready")
        self.assertEqual(similarity._jobs["aaaa"]["pages_seen"], 3)

    def test_completion_clears_live_records_and_partial_cache(self):
        similarity.index_functions({"instance_id": "aaaa", "background": True})
        self._router.release_pages(3)
        _wait_until(lambda: similarity._jobs.get("aaaa", {}).get("status") == "ready")
        job = similarity._jobs["aaaa"]
        self.assertNotIn("live_records", job)
        self.assertNotIn("_partial_cache", job)

    def test_binary_change_mid_build_stops_and_does_not_persist(self):
        orig_key, _ = similarity._instance_key("aaaa")   # fingerprint BEFORE any swap
        orig_n = similarity._FP_CHECK_EVERY_N_PAGES
        similarity._FP_CHECK_EVERY_N_PAGES = 1   # check every page for a deterministic test
        self._router.swap_after_pages = 1        # fingerprint flips once page 2 is requested
        try:
            similarity.index_functions({"instance_id": "aaaa", "background": True})
            self._router.release_pages(3)
            _wait_until(lambda: similarity._jobs.get("aaaa", {}).get("status") == "error")
        finally:
            similarity._FP_CHECK_EVERY_N_PAGES = orig_n

        job = similarity._jobs["aaaa"]
        self.assertIn("binary changed", job["error"])
        self.assertLessEqual(job["pages_seen"], 2)   # detected within the checked bound
        rp = similarity._registry_path()
        self.assertFalse(index_store.has_index(orig_key, rp),
                          "an error/superseded build must not persist a final index")

    def test_load_partial_returns_none_with_no_build(self):
        self.assertIsNone(similarity._load_partial("aaaa"))

    def test_load_partial_reflects_pages_seen_so_far(self):
        similarity.index_functions({"instance_id": "aaaa", "background": True})
        self._router.release_pages(1)
        _wait_until(lambda: similarity._jobs.get("aaaa", {}).get("pages_seen") == 1)

        entry = similarity._load_partial("aaaa")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["index"]["function_count"], 2)
        self.assertIn("anchor_index", entry)

        self._router.release_pages(2)
        _wait_until(lambda: similarity._jobs.get("aaaa", {}).get("status") == "ready")

    def test_load_partial_returns_none_once_build_completes(self):
        similarity.index_functions({"instance_id": "aaaa", "background": True})
        self._router.release_pages(3)
        _wait_until(lambda: similarity._jobs.get("aaaa", {}).get("status") == "ready")
        self.assertIsNone(similarity._load_partial("aaaa"))

    def test_load_partial_debounces_within_ttl(self):
        similarity.index_functions({"instance_id": "aaaa", "background": True})
        self._router.release_pages(1)
        _wait_until(lambda: similarity._jobs.get("aaaa", {}).get("pages_seen") == 1)

        first = similarity._load_partial("aaaa")
        second = similarity._load_partial("aaaa")
        self.assertIs(first, second, "within the TTL, the cached entry object must be reused")

        self._router.release_pages(2)
        _wait_until(lambda: similarity._jobs.get("aaaa", {}).get("status") == "ready")

    def test_load_partial_still_serves_after_build_errors(self):
        similarity.index_functions({"instance_id": "aaaa", "background": True})
        self._router.release_pages(1)
        _wait_until(lambda: similarity._jobs.get("aaaa", {}).get("pages_seen") == 1)
        # Force the job into "error" directly (grey-box) rather than staging a
        # real IDA-call failure -- isolates the status-gate behavior under test.
        with similarity._jobs_lock:
            similarity._jobs["aaaa"]["status"] = "error"
            similarity._jobs["aaaa"]["error"] = "synthetic failure for this test"

        entry = similarity._load_partial("aaaa")
        self.assertIsNotNone(entry, "an errored build's last-known partial data must stay servable")
        self.assertEqual(entry["index"]["function_count"], 2)

    def test_load_partial_write_back_does_not_resurrect_cleared_state(self):
        similarity.index_functions({"instance_id": "aaaa", "background": True})
        self._router.release_pages(1)
        _wait_until(lambda: similarity._jobs.get("aaaa", {}).get("pages_seen") == 1)

        entered = threading.Event()
        resume = threading.Event()
        real_assemble = similarity._assemble_index
        call_count = {"n": 0}

        def blocking_assemble(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                entered.set()
                resume.wait(timeout=5)
            return real_assemble(*args, **kwargs)

        similarity._assemble_index = blocking_assemble
        try:
            t = threading.Thread(target=similarity._load_partial, args=("aaaa",))
            t.start()
            self.assertTrue(entered.wait(timeout=5), "_load_partial did not reach _assemble_index")

            # While _load_partial is blocked mid-computation, let the REAL
            # background build finish (its own _assemble_index call is #2,
            # which passes straight through).
            self._router.release_pages(2)
            _wait_until(lambda: similarity._jobs.get("aaaa", {}).get("status") == "ready")

            resume.set()   # let _load_partial's blocked call proceed and try to write back
            t.join(timeout=5)
        finally:
            similarity._assemble_index = real_assemble

        job = similarity._jobs["aaaa"]
        self.assertNotIn("live_records", job)
        self.assertNotIn("_partial_cache", job,
                          "a stale write-back must not resurrect cleared partial state")

    def test_load_partial_write_back_respects_generation_bump(self):
        # Directly inject a "building" job (grey-box) so this test isolates
        # the gen-mismatch guard itself, rather than staging a full realistic
        # error-then-retry sequence (which would be racy/slow to set up).
        similarity._jobs["aaaa"] = {
            "status": "building", "gen": 1, "key": "sha-aaaa",
            "live_records": _corpus()["aaaa"][:2],
        }

        entered = threading.Event()
        resume = threading.Event()
        real_assemble = similarity._assemble_index

        def blocking_assemble(*args, **kwargs):
            entered.set()
            resume.wait(timeout=5)
            return real_assemble(*args, **kwargs)

        similarity._assemble_index = blocking_assemble
        try:
            t = threading.Thread(target=similarity._load_partial, args=("aaaa",))
            t.start()
            self.assertTrue(entered.wait(timeout=5))

            # Simulate a retried build superseding this one (a fresh
            # _start_background call always bumps gen).
            with similarity._jobs_lock:
                similarity._jobs["aaaa"]["gen"] = 2

            resume.set()
            t.join(timeout=5)
        finally:
            similarity._assemble_index = real_assemble

        self.assertIsNone(similarity._jobs["aaaa"].get("_partial_cache"),
                           "a write-back for a superseded generation must be dropped")

    def test_similar_functions_serves_partial_results_mid_build(self):
        similarity.index_functions({"instance_id": "aaaa", "background": True})
        self._router.release_pages(1)   # page 1 = addrs 0x1001, 0x1002 (the encrypt twins)
        _wait_until(lambda: similarity._jobs.get("aaaa", {}).get("pages_seen") == 1)

        out = similarity.similar_functions({"instance_id": "aaaa", "func": "0x1001", "top_k": 5})
        self.assertTrue(out.get("partial"))
        self.assertEqual(out["coverage"]["aaaa"]["done"], 2)
        self.assertIsNone(out["coverage"]["aaaa"]["total"])
        addrs = [r["addr"] for r in out["results"]]
        self.assertIn("0x1002", addrs)          # its twin landed in page 1
        for a in addrs:
            self.assertIn(a, ("0x1001", "0x1002"))   # nothing from later pages

        self._router.release_pages(2)
        _wait_until(lambda: similarity._jobs.get("aaaa", {}).get("status") == "ready")

        out2 = similarity.similar_functions({"instance_id": "aaaa", "func": "0x1001", "top_k": 5})
        self.assertFalse(out2.get("partial", False))
        self.assertNotIn("coverage", out2)

    def test_similar_functions_query_not_yet_covered_does_not_crash(self):
        similarity.index_functions({"instance_id": "aaaa", "background": True})
        self._router.release_pages(1)   # page 1 only has 0x1001/0x1002
        _wait_until(lambda: similarity._jobs.get("aaaa", {}).get("pages_seen") == 1)

        # 0x1005 ("misc_z") is in page 3, not yet processed by the background
        # loop -- but func_features resolves single-address queries directly
        # (unrelated to the paginated '*' gate), so this must not crash.
        out = similarity.similar_functions({"instance_id": "aaaa", "func": "0x1005", "top_k": 5})
        self.assertNotIn("error", out)
        self.assertTrue(out.get("partial"))
        self.assertEqual(out["query"]["addr"], "0x1005")

        self._router.release_pages(2)
        _wait_until(lambda: similarity._jobs.get("aaaa", {}).get("status") == "ready")

    def test_similar_functions_serves_partial_after_build_error(self):
        similarity.index_functions({"instance_id": "aaaa", "background": True})
        self._router.release_pages(1)
        _wait_until(lambda: similarity._jobs.get("aaaa", {}).get("pages_seen") == 1)
        with similarity._jobs_lock:
            similarity._jobs["aaaa"]["status"] = "error"
            similarity._jobs["aaaa"]["error"] = "synthetic failure for this test"

        out = similarity.similar_functions({"instance_id": "aaaa", "func": "0x1001", "top_k": 5})
        self.assertTrue(out.get("partial"))
        self.assertNotIn("not_indexed", out)
        self.assertIn("0x1002", [r["addr"] for r in out["results"]])

    # --- code-review follow-up fixes --------------------------------------

    def test_transient_fingerprint_failure_does_not_abort_build(self):
        orig_n = similarity._FP_CHECK_EVERY_N_PAGES
        similarity._FP_CHECK_EVERY_N_PAGES = 1   # check every page for a deterministic test
        try:
            # index_functions() below makes its own synchronous fingerprint
            # call first (to resolve the index key) -- only fail the NEXT
            # one, which is the periodic mid-build recheck on page 1.
            similarity.index_functions({"instance_id": "aaaa", "background": True})
            self._router.fail_fingerprint_times = 1
            self._router.release_pages(3)
            _wait_until(lambda: similarity._jobs.get("aaaa", {}).get("status") == "ready")
        finally:
            similarity._FP_CHECK_EVERY_N_PAGES = orig_n

        self.assertEqual(similarity._jobs["aaaa"]["status"], "ready")
        self.assertEqual(similarity._jobs["aaaa"]["pages_seen"], 3)

    def test_cancel_prevents_final_write(self):
        orig_key, _ = similarity._instance_key("aaaa")
        similarity.index_functions({"instance_id": "aaaa", "background": True})
        self._router.release_pages(1)
        _wait_until(lambda: similarity._jobs.get("aaaa", {}).get("pages_seen") == 1)
        with similarity._jobs_lock:
            similarity._jobs["aaaa"]["cancel"] = True

        self._router.release_pages(2)   # let the background thread observe cancel on page 2
        _wait_until(lambda: self._router.pages_served == 2)
        _wait_until(lambda: similarity._jobs.get("aaaa", {}).get("pages_seen") == 2)
        time.sleep(0.05)   # let _run()'s post-loop guard check finish (no other observable hook)

        rp = similarity._registry_path()
        self.assertFalse(index_store.has_index(orig_key, rp),
                          "a cancelled build must not persist a final index")
        self.assertEqual(self._router.pages_served, 2, "page 3 must not be fetched after cancel")

    def test_load_partial_uses_the_jobs_recorded_key_not_a_live_refetch(self):
        similarity.index_functions({"instance_id": "aaaa", "background": True})
        self._router.release_pages(1)
        _wait_until(lambda: similarity._jobs.get("aaaa", {}).get("pages_seen") == 1)
        orig_key = similarity._jobs["aaaa"]["key"]

        self._router._swapped = True   # live fingerprint would now differ
        entry = similarity._load_partial("aaaa")
        self.assertEqual(entry["index"]["binary_sha256"], orig_key,
                          "_load_partial must tag the partial index with the build's own "
                          "recorded key, not whatever the live fingerprint currently reads")

        self._router._swapped = False
        self._router.release_pages(2)
        _wait_until(lambda: similarity._jobs.get("aaaa", {}).get("status") == "ready")

    def test_similar_functions_not_indexed_race_falls_back_to_completed_index(self):
        similarity.index_functions({"instance_id": "aaaa", "background": True})
        self._router.release_pages(1)
        _wait_until(lambda: similarity._jobs.get("aaaa", {}).get("pages_seen") == 1)

        real_load_partial = similarity._load_partial

        def load_partial_after_completion(iid):
            # Simulate the build finishing in the window between _load()
            # returning None and _load_partial() being consulted.
            self._router.release_pages(2)
            _wait_until(lambda: similarity._jobs.get(iid, {}).get("status") == "ready")
            return real_load_partial(iid)

        similarity._load_partial = load_partial_after_completion
        try:
            out = similarity.similar_functions({"instance_id": "aaaa", "func": "0x1001", "top_k": 5})
        finally:
            similarity._load_partial = real_load_partial

        self.assertNotIn("not_indexed", out)
        self.assertFalse(out.get("partial", False))
        self.assertIn("0x1002", [r["addr"] for r in out["results"]])


if __name__ == "__main__":
    unittest.main()
