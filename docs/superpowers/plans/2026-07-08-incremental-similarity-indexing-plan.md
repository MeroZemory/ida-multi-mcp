# Incremental / Partial Function-Similarity Indexing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **Note for this run**: tasks are executed sequentially in the main session (not fresh subagents per task) because every task edits the same tightly-coupled closures in one file (`_start_background`/`_on_page`/`_run`/`_load_partial`/`similar_functions`) — parallel/isolated-worktree execution would conflict. Use `superpowers:executing-plans`'s batch-with-checkpoints style, run inline.

**Goal:** Let `similar_functions()` serve results against whatever a background `index_functions()` build has processed so far, instead of returning `not_indexed` until the entire binary is done.

**Architecture:** No new files, no new persisted formats. Tag each background build with a monotonic generation counter; expose its growing (in-place-mutated) `records` list on the job dict; add a debounced (2s TTL) helper that reuses the existing from-scratch `_assemble_index`/`build_anchor_index` functions over that list to build an ephemeral partial index on demand; wire it into `similar_functions()` as a fallback when no persisted index exists yet; clear the heavy state on completion; bound (not eliminate) exposure to a mid-build binary swap with a periodic fingerprint recheck.

**Tech Stack:** Python 3.11+, stdlib only (`threading`, `itertools`, `time`) — no new dependencies. Tests: `unittest` (matches `tests/test_similarity.py`'s existing style, no pytest-specific features used).

## Global Constraints

- Zero new runtime dependencies (`pyproject.toml: dependencies = []` stays empty) — spec §Approach.
- No new files, no new persisted index/sidecar formats — spec §Approach, §Non-goals.
- `sim_score.py` and `index_store.py` are **not modified** — every partial-index computation reuses the existing from-scratch functions unchanged — spec §v1→v2 point 3, §Approach.
- All new/modified shared-state access goes through the existing `_jobs_lock` — no new locks — spec throughout.
- Every `_jobs[iid]` mutation or trust-based read after doing work off-lock must re-check `job.get("gen") == gen` (and `status` where noted) before acting — spec §v2→v3 finding 1, §Approach §1/§2/§4.
- Full existing test suite (`pytest tests/` or `python -m unittest discover tests`) must stay green throughout — the final-index code path (`_assemble_index`, `write_index`) must remain byte-for-byte the same as today for any completed (non-error, non-superseded) build — spec §Testing.
- Design spec of record: `docs/superpowers/specs/2026-07-08-incremental-similarity-indexing-design.md` (§Approach (v3) is authoritative for exact code shape; this plan mirrors it 1:1, including its post-review fix to `_load_partial`'s status check).
- Line numbers cited in `Files:` blocks (e.g. `similarity.py:487-592`) are from the file's state **before this plan's edits**. Because Task 1 and Task 2 add code above `similar_functions`, later tasks' actual line numbers will have shifted down by the time you reach them — locate code by the shown before/after snippets (exact string match) via each step's own `Before:`/`After:` blocks, not by re-trusting a stale line number.

---

## File Structure

- **Modify**: `src/ida_multi_mcp/tools/similarity.py` — all production code changes live here (module already owns `_jobs`, `_start_background`, `_load`, `similar_functions`).
- **Modify**: `tests/test_similarity.py` — extend with a `PausableRouter` test double (semaphore-gated page delivery, needed to deterministically pause a background build mid-page) and a new `PartialIndexTest` test class. No other file changes.

---

## Task 1: Instrument the background build — generation counter, live records, completion cleanup, bounded binary-change guard

**Files:**
- Modify: `src/ida_multi_mcp/tools/similarity.py:10-17` (imports), `:356-414` (`_start_background`/`_on_page`/`_run`)
- Test: `tests/test_similarity.py` (new `PausableRouter` class + new `PartialIndexTest` class)

**Interfaces:**
- Produces: `_jobs[iid]["gen"]` (int, monotonic per build), `_jobs[iid]["live_records"]` (the same `list` object `_build_records` is appending to — present once the first page lands, absent before), `_jobs[iid]["pages_seen"]` (int, count of pages processed by this build). On successful completion, `live_records`/`pages_seen`/`_partial_cache` (added in Task 2) are popped. `_FP_CHECK_EVERY_N_PAGES` (module constant, default 20, env-overridable via `IDA_MCP_SIM_FP_CHECK_EVERY_N_PAGES`) controls how often (in pages) a mid-build binary-fingerprint mismatch is detected; on mismatch, the job's `status` flips to `"error"` with a descriptive message, the page loop stops, and — new in this task — the final `_assemble_index`/`write_index` call is **skipped** (a build that errored or was superseded must never persist a final index from records it no longer trusts).
- Consumes: existing `_jobs_lock`, `_instance_key`, `_build_records`, `_assemble_index`, `index_store.write_index`, `index_store.clear_vectors`, `_invalidate_cache`, `_valid_records` — all unchanged.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_similarity.py`, at the **end of the file**, after `class SimilarityErrorRecordTest` and before the `if __name__ == "__main__":` block — mirroring the file's existing convention of a helper class (`_ErrRouter`) immediately preceding the `TestCase` that uses it:

```python
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
```

Add these two imports at the top of `tests/test_similarity.py` (alongside the existing `import os`/`sys`/`tempfile`/`unittest`):
```python
import threading
import time
```
And add this import alongside the existing `from ida_multi_mcp.tools import sim_score, similarity`:
```python
from ida_multi_mcp.tools import index_store, sim_score, similarity  # noqa: E402
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/merozemory/projects/MeroZemory/ida-multi-mcp
python -m pytest tests/test_similarity.py::PartialIndexTest -v
```
Expected: all three `PartialIndexTest` tests FAIL — `test_background_build_exposes_gen_and_live_records` and `test_completion_clears_live_records_and_partial_cache` with `KeyError: 'gen'` (or similar, since `_jobs[iid]` doesn't have `gen`/`live_records`/`pages_seen` yet); `test_binary_change_mid_build_stops_and_does_not_persist` with the job never reaching `status == "error"` (times out in `_wait_until`, since there is no fingerprint-recheck yet).

- [ ] **Step 3: Implement**

In `src/ida_multi_mcp/tools/similarity.py`, add `itertools` to the imports (`:12`, alphabetical):
```python
import hashlib
import itertools
import json
import os
import threading
import time
```

Add the new module-level constants right after `PAGE = int(os.environ.get("IDA_MCP_SIM_PAGE", "500"))` (`:33`):
```python
PAGE = int(os.environ.get("IDA_MCP_SIM_PAGE", "500"))

# Monotonic build-generation counter: next()'d only while holding _jobs_lock,
# in _start_background. Lets in-flight work (e.g. _load_partial, Task 2) tell
# whether the job it read from is still the one it started with, so a slow
# write-back from a superseded/finished build can never clobber newer state.
_gen_counter = itertools.count()

# How often (in pages) a background build re-verifies the instance's binary
# fingerprint still matches the one it started with. Every page would add a
# routed IDA round-trip per page (~262 for a 130K-function binary) contending
# with func_features calls on the same single-threaded IDA main thread; this
# bounds (does not eliminate) the window during which a mid-build binary swap
# can produce results attributed to the wrong binary. See design spec §5.
_FP_CHECK_EVERY_N_PAGES = int(os.environ.get("IDA_MCP_SIM_FP_CHECK_EVERY_N_PAGES", "20"))
```

Replace `_start_background` (`:356-414`) in full:
```python
def _start_background(iid: str, key: str, fp: dict, binary_name: str,
                      rp: str | None, features_ready: bool = False) -> dict:
    with _jobs_lock:
        existing = _jobs.get(iid)
        if existing and existing.get("status") == "building":
            return {"index_id": key, "status": "building",
                    "progress": existing.get("progress", 0.0), "note": "already building"}
        if existing and existing.get("embed_status") == "embedding":
            return {"index_id": key, "status": "ready", "embed_status": "embedding",
                    "embed_done": existing.get("embed_done", 0),
                    "embed_total": existing.get("embed_total", 0), "note": "already embedding"}
        gen = next(_gen_counter)
        _jobs[iid] = {"status": "ready" if features_ready else "building",
                      "progress": 1.0 if features_ready else 0.0,
                      "cancel": False, "error": None, "key": key,
                      "gen": gen, "pages_seen": 0}

    def _on_page(recs: list, total: int) -> bool:
        with _jobs_lock:
            job = _jobs.get(iid)
            if job is None or job.get("gen") != gen:
                return False   # a newer build superseded this one; stop
            if total:
                job["progress"] = min(len(recs) / total, 0.999)
            job.setdefault("live_records", recs)   # same list object every call; no-op after page 1
            job["pages_seen"] = n = job.get("pages_seen", 0) + 1
            if job.get("cancel"):
                return False
        if n % _FP_CHECK_EVERY_N_PAGES == 0:
            cur_key, _ = _instance_key(iid)
            if cur_key != key:
                with _jobs_lock:
                    j = _jobs.get(iid)
                    if j is not None and j.get("gen") == gen:
                        j.update(status="error",
                                 error=f"binary changed mid-build (was {key[:12]}…, now "
                                       f"{cur_key[:12] if cur_key else '?'}…)")
                return False
        return True

    def _run() -> None:
        try:
            if not features_ready:
                index_store.clear_vectors(key, rp)   # fresh build -> fresh vectors
                records = _build_records(iid, _on_page)
                with _jobs_lock:
                    job = _jobs.get(iid)
                    superseded_or_errored = (
                        job is None or job.get("gen") != gen or job.get("status") == "error"
                    )
                if superseded_or_errored:
                    # _on_page stopped the loop (supersession, cancel, or a
                    # detected binary-change mismatch) -- the collected
                    # `records` are not trustworthy as a final index and must
                    # not be persisted. Whatever partial results were already
                    # served stay served (error path keeps live_records); we
                    # just skip turning them into a bogus final write.
                    return
                index = _assemble_index(records, key, binary_name, fp)
                index_store.write_index(index, rp)
                _invalidate_cache(key)
                valid_addrs = [r["addr"] for r in _valid_records(records)]
                with _jobs_lock:
                    job = _jobs.get(iid)
                    if job is not None and job.get("gen") == gen:
                        job.pop("live_records", None)
                        job.pop("_partial_cache", None)
                        job.update(status="ready", progress=1.0,
                                  function_count=index["function_count"],
                                  skipped_count=index["skipped_count"])
            else:  # features already on disk -> resume embedding only
                idx = index_store.read_index(key, rp) or {}
                valid_addrs = list(idx.get("functions", {}).keys())
                with _jobs_lock:
                    _jobs[iid].update(status="ready", progress=1.0,
                                      function_count=idx.get("function_count", len(valid_addrs)))
            # Phase 2: neural vectors accrue in the background (non-blocking).
            if _neural_enabled():
                with _jobs_lock:
                    _jobs[iid].update(embed_status="embedding",
                                      embed_total=len(valid_addrs), embed_done=0)
                _embed_incremental(iid, key, rp, valid_addrs)
                with _jobs_lock:
                    if not _jobs[iid].get("cancel"):
                        _jobs[iid].update(embed_status="done")
        except Exception as exc:  # noqa: BLE001 - report, don't crash the thread
            with _jobs_lock:
                _jobs[iid].update(status="error", error=str(exc))

    threading.Thread(target=_run, daemon=True).start()
    return {"index_id": key,
            "status": "ready" if features_ready else "building",
            "progress": 1.0 if features_ready else 0.0,
            "embed_status": "embedding" if _neural_enabled() else None,
            "background": True}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_similarity.py::PartialIndexTest -v
python -m pytest tests/test_similarity.py -v   # existing tests must still pass unchanged
```
Expected: all `PartialIndexTest` tests PASS; every pre-existing test in the file still PASSES (the `not features_ready` branch's final behavior for a normal, uninterrupted build is unchanged — same `_assemble_index`/`write_index` call, same returned dict shape, just gated by the new `superseded_or_errored` check which is `False` in the normal case).

- [ ] **Step 5: Commit**

```bash
git add src/ida_multi_mcp/tools/similarity.py tests/test_similarity.py
git commit -m "feat: track build generation, expose live records, bound binary-change exposure

Tags each background similarity-index build with a monotonic generation,
stashes a reference to its growing records list on the job, clears that
state on completion, and periodically re-verifies the binary fingerprint
mid-build so a swap is caught (bounded window) instead of silently
corrupting the final index. Lays the groundwork for serving partial
similar_functions() results while a build is still in progress."
```

---

## Task 2: `_load_partial()` — debounced ephemeral partial index

**Files:**
- Modify: `src/ida_multi_mcp/tools/similarity.py` (new function, placed after `_load`, `:458-472`)
- Test: `tests/test_similarity.py` (extend `PartialIndexTest`)

**Interfaces:**
- Consumes: `_jobs`, `_jobs_lock` (from Task 1: `gen`, `live_records`, `status`), `_instance_key`, `_registry.get_instance`, `_assemble_index`, `sim_score.build_anchor_index` — all unchanged/existing.
- Produces: `_load_partial(iid: str) -> dict | None`. Returns `None` if no build is running or has ever errored for `iid` (`_jobs.get(iid)` absent or `status` not in `("building", "error")`) or if no page has landed yet (`live_records` absent/empty). Otherwise returns the same shape `_load()` produces: `{"index": <dict with functions/df/zstats/lsh/function_count/...>, "anchor_index": <dict>}`, built from whatever `live_records` currently holds, debounced for `_PARTIAL_TTL_S` seconds (module constant, default 2.0, env `IDA_MCP_SIM_PARTIAL_TTL_S`) via `_jobs[iid]["_partial_cache"]`. The `"error"` status is included deliberately: `_run()`'s error handler (unchanged) leaves `live_records` in place specifically so the last-known-good partial data keeps being served after a build stalls, per the design spec §4 — an errored job's `live_records` are frozen (the build will not progress further under that `gen`), so caching a computed snapshot of them is always safe.

- [ ] **Step 1: Write the failing tests**

Add to `PartialIndexTest` in `tests/test_similarity.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_similarity.py::PartialIndexTest -v -k load_partial
```
Expected: all five FAIL with `AttributeError: module 'ida_multi_mcp.tools.similarity' has no attribute '_load_partial'`.

- [ ] **Step 3: Implement**

In `src/ida_multi_mcp/tools/similarity.py`, add the TTL constant next to `_FP_CHECK_EVERY_N_PAGES` (added in Task 1):
```python
_FP_CHECK_EVERY_N_PAGES = int(os.environ.get("IDA_MCP_SIM_FP_CHECK_EVERY_N_PAGES", "20"))
_PARTIAL_TTL_S = float(os.environ.get("IDA_MCP_SIM_PARTIAL_TTL_S", "2.0"))
```

Add `_load_partial` immediately after `_load` (after `:472`, before `_cap_candidates`):
```python
def _load_partial(iid: str) -> dict | None:
    """Ephemeral, debounced index+anchor_index entry from a build in progress
    (or one that errored, serving its last-known-good state).

    Reuses the exact from-scratch functions `_assemble_index`/`build_anchor_index`
    already used for the final index, over whatever the background thread has
    accumulated so far (`_jobs[iid]["live_records"]`, Task 1). Returns None if
    no build is running/errored for `iid`, or none of its pages have landed yet.
    """
    with _jobs_lock:
        job = _jobs.get(iid)
        if not job or job.get("status") not in ("building", "error"):
            return None
        gen = job.get("gen")
        recs = job.get("live_records")
        cached = job.get("_partial_cache")
    if not recs:
        return None
    now = time.time()
    if cached and cached.get("gen") == gen and now - cached["at"] < _PARTIAL_TTL_S:
        return cached["entry"]
    key, fp = _instance_key(iid)
    if not key:
        return None
    info = (_registry.get_instance(iid) or {}) if _registry else {}
    idx = _assemble_index(list(recs), key, info.get("binary_name", ""), fp)
    funcs = list(idx["functions"].values())
    entry = {"index": idx, "anchor_index": sim_score.build_anchor_index(funcs)}
    with _jobs_lock:
        j = _jobs.get(iid)
        # Only cache back if this is STILL the same build (gen match) and
        # still in a state we're allowed to serve. A build that finished or
        # was superseded by a NEWER generation while we were off the lock
        # computing `entry` must not have its (now-stale, and for a finished
        # build, un-freed) result written back. The caller still gets the
        # freshly-computed `entry` for THIS call either way; only the cache
        # write is conditional. See design spec §v2->v3 finding 1 and the
        # "Post-review fix" note (error status must remain servable).
        if j is not None and j.get("gen") == gen and j.get("status") in ("building", "error"):
            j["_partial_cache"] = {"at": now, "gen": gen, "entry": entry}
    return entry
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_similarity.py::PartialIndexTest -v
python -m pytest tests/test_similarity.py -v
```
Expected: all `PartialIndexTest` tests PASS (8 so far); all pre-existing tests still PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ida_multi_mcp/tools/similarity.py tests/test_similarity.py
git commit -m "feat: add debounced ephemeral partial-index loader

_load_partial() reuses the existing from-scratch _assemble_index /
build_anchor_index functions over a build's in-progress records, cached
for 2s so repeated queries during a build don't each pay the assembly
cost. Not wired into similar_functions() yet."
```

---

## Task 3: Completion-race regression — `_load_partial`'s write-back must not resurrect cleared state

**Files:**
- Test only: `tests/test_similarity.py` (extend `PartialIndexTest`) — no production code change; this task proves Task 1 + Task 2's gen-guard actually closes the race the design spec calls out (§v2→v3 finding 1).

**Interfaces:**
- Consumes: `similarity._assemble_index` (monkeypatched for one call to make the race window observable and deterministic), `similarity._load_partial`, `similarity._jobs`.

- [ ] **Step 1: Write the failing test**

Add to `PartialIndexTest`:
```python
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
```

- [ ] **Step 2: Run test to verify it fails against a naive (unguarded) implementation**

This test validates the guard already implemented in Task 2. Run it now to confirm it PASSES against the real implementation:
```bash
python -m pytest tests/test_similarity.py::PartialIndexTest::test_load_partial_write_back_does_not_resurrect_cleared_state -v
```
Expected: PASS. (If you want to see it fail first to prove it's a real regression guard, temporarily remove the `j.get("gen") == gen and j.get("status") == "building"` condition in `_load_partial`'s write-back — replace with `if j is not None:` — rerun, observe FAIL with `AssertionError: '_partial_cache' unexpectedly found`, then restore the real condition.)

- [ ] **Step 3: N/A — no implementation step, this task is regression coverage for Task 2's existing guard.**

- [ ] **Step 4: Run full test file to confirm no regressions**

```bash
python -m pytest tests/test_similarity.py -v
```
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/test_similarity.py
git commit -m "test: regression-cover the _load_partial completion-race guard

Proves _load_partial's gen+status re-check before writing _partial_cache
back actually prevents a slow, in-flight computation from resurrecting
memory that the completing build already cleared."
```

---

## Task 4: Retry/generation regression — a superseded build's write-back must not leak into the new one

**Files:**
- Test only: `tests/test_similarity.py` (extend `PartialIndexTest`).

**Interfaces:**
- Consumes: `similarity._jobs`, `similarity._jobs_lock`, `similarity._load_partial`, `similarity._assemble_index` (monkeypatched).

- [ ] **Step 1: Write the failing test**

Add to `PartialIndexTest`:
```python
    def test_load_partial_write_back_respects_generation_bump(self):
        # Directly inject a "building" job (grey-box) so this test isolates
        # the gen-mismatch guard itself, rather than staging a full realistic
        # error-then-retry sequence (which would be racy/slow to set up).
        similarity._jobs["aaaa"] = {
            "status": "building", "gen": 1,
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
            # _start_background call always bumps gen -- Task 1).
            with similarity._jobs_lock:
                similarity._jobs["aaaa"]["gen"] = 2

            resume.set()
            t.join(timeout=5)
        finally:
            similarity._assemble_index = real_assemble

        self.assertIsNone(similarity._jobs["aaaa"].get("_partial_cache"),
                           "a write-back for a superseded generation must be dropped")
```

- [ ] **Step 2: Run test to verify it passes against the real implementation**

```bash
python -m pytest tests/test_similarity.py::PartialIndexTest::test_load_partial_write_back_respects_generation_bump -v
```
Expected: PASS (Task 2's `j.get("gen") == gen` check already covers this).

- [ ] **Step 3: N/A — regression coverage only, no implementation change.**

- [ ] **Step 4: Run full test file**

```bash
python -m pytest tests/test_similarity.py -v
```
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/test_similarity.py
git commit -m "test: regression-cover _load_partial's generation-mismatch write guard"
```

---

## Task 5: Wire `_load_partial` into `similar_functions()` — `partial` + `coverage`

**Files:**
- Modify: `src/ida_multi_mcp/tools/similarity.py:487-592` (`similar_functions`)
- Test: `tests/test_similarity.py` (extend `PartialIndexTest`)

**Interfaces:**
- Produces: `similar_functions()`'s return dict gains `"partial": True` and `"coverage": {instance_id: {"done": int, "total": None}}` when any gallery instance was served from `_load_partial` instead of a persisted index. `coverage[giid]["done"]` is read from the exact `entry["index"]["function_count"]` used to score that instance's candidates — never a second, separately-timed lookup (design spec §v2→v3 finding 3).
- Consumes: `_load` (unchanged), `_load_partial` (Task 2).

- [ ] **Step 1: Write the failing tests**

Add to `PartialIndexTest`:
```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_similarity.py::PartialIndexTest -v -k "serves_partial or not_yet_covered"
```
Expected: all three FAIL — `test_similar_functions_serves_partial_results_mid_build` because `out["partial"]`/`out["coverage"]` are absent and `out["results"]` is empty (today's `not_indexed` path fires instead); `test_similar_functions_query_not_yet_covered_does_not_crash` and `test_similar_functions_serves_partial_after_build_error` because `out` contains `"not_indexed": ["aaaa"]` and empty `results` instead of `partial: True`.

- [ ] **Step 3: Implement**

In `src/ida_multi_mcp/tools/similarity.py`, in `similar_functions()`, change the loop setup and the `entry is None` handling (`:525-536`):

Before:
```python
    results: list[dict] = []
    not_indexed: list[str] = []
    gallery_size = 0
    for giid in gallery_iids:
        gkey, _ = _instance_key(giid)
        if not gkey:
            not_indexed.append(giid)
            continue
        entry = _load(gkey, rp)
        if entry is None:
            not_indexed.append(giid)
            continue
```

After:
```python
    results: list[dict] = []
    not_indexed: list[str] = []
    partial_coverage: dict[str, int] = {}
    gallery_size = 0
    for giid in gallery_iids:
        gkey, _ = _instance_key(giid)
        if not gkey:
            not_indexed.append(giid)
            continue
        entry = _load(gkey, rp)
        partial = False
        if entry is None:
            entry = _load_partial(giid)
            partial = entry is not None
        if entry is None:
            not_indexed.append(giid)
            continue
        if partial:
            # Same `entry` used for scoring below -- never a second, separately
            # -timed lookup into `_jobs` (design spec §v2->v3 finding 3).
            partial_coverage[giid] = entry["index"]["function_count"]
```

Then, at the end of `similar_functions()` (`:583-592`), change:
```python
    results.sort(key=lambda r: r["score"], reverse=True)
    out: dict[str, Any] = {
        "query": {"instance_id": iid, "addr": q.get("addr"), "name": q.get("name", "")},
        "gallery_size": gallery_size,
        "results": results[:top_k],
    }
    if not_indexed:
        out["not_indexed"] = not_indexed
        out["hint"] = "Run index_functions on the listed instances first."
    return out
```
to:
```python
    results.sort(key=lambda r: r["score"], reverse=True)
    out: dict[str, Any] = {
        "query": {"instance_id": iid, "addr": q.get("addr"), "name": q.get("name", "")},
        "gallery_size": gallery_size,
        "results": results[:top_k],
    }
    if partial_coverage:
        out["partial"] = True
        out["coverage"] = {giid: {"done": n, "total": None} for giid, n in partial_coverage.items()}
    if not_indexed:
        out["not_indexed"] = not_indexed
        out["hint"] = "Run index_functions on the listed instances first."
    return out
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_similarity.py -v
```
Expected: all tests PASS, including both new ones and every pre-existing test (`entry = _load(gkey, rp)` still runs first and unchanged; `_load_partial` is only reached when `_load` returns `None`, so a fully-indexed instance's behavior is byte-for-byte unchanged).

- [ ] **Step 5: Commit**

```bash
git add src/ida_multi_mcp/tools/similarity.py tests/test_similarity.py
git commit -m "feat: serve partial similar_functions() results while a build is in progress

Falls back to _load_partial() when no persisted index exists yet, tagging
the response with partial:true and per-instance coverage counts (derived
from the same entry used for scoring, never a second lookup). A query
function not yet reached by the background build still resolves normally
via the existing direct-fetch path; it just won't itself be a candidate
until its page is processed."
```

---

## Task 6: Full regression run

**Files:** none (verification only).

- [ ] **Step 1: Run the complete test suite**

```bash
cd /Users/merozemory/projects/MeroZemory/ida-multi-mcp
python -m pytest tests/ -v
```
Expected: every test PASSES, including all pre-existing suites (`test_index_store.py`, `test_similarity.py`'s original classes, `test_similarity_neural.py`, and everything else under `tests/`) and every test added in Tasks 1–5. No skips introduced by this change.

- [ ] **Step 2: Confirm no stray debug output or leftover monkeypatches**

```bash
grep -rn "similarity\._assemble_index = " tests/test_similarity.py
```
Expected: every occurrence is inside a `try/finally` that restores `real_assemble` (Tasks 3 and 4) — confirm by reading the surrounding lines; there must be no test that monkeypatches `_assemble_index` without restoring it, since that would leak into other tests run in the same process.

- [ ] **Step 3: Commit (if step 2 required any fixup; otherwise this task produces no diff and can be skipped)**

If a fixup was needed:
```bash
git add tests/test_similarity.py
git commit -m "test: restore monkeypatched _assemble_index in all cases"
```

---

## Post-plan (not part of this plan's tasks, tracked separately)

Per the active `/goal`, after this plan's tasks are all green: independent (adversarial) code review of the resulting diff, then push `feature/similarity-partial-indexing` and open a PR. That work is tracked outside this plan.
