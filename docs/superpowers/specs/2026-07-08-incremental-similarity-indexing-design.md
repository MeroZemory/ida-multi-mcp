# Incremental / Partial Function-Similarity Indexing — Design v3 (converged after three rounds of adversarial review)

## Problem

`ida_multi_mcp/tools/similarity.py: index_functions()` builds the per-binary
similarity index as a background thread that pages through `func_features`
(500 functions/page) via `_build_records()`, accumulating everything in a
plain Python list, and only calls `_assemble_index()` +
`index_store.write_index()` **once, at the end**. Until that single atomic
write happens, `similar_functions()` returns `not_indexed` unconditionally
— even if 99% of a 130K-function binary has already been processed.

Goal: let `similar_functions()` serve results against whatever has been
processed so far, while the background build continues.

## v1 → v2: what changed after adversarial review

Three independent reviewers (architect-lens, adversarial bug-hunt, simplicity/
YAGNI) examined the first draft, which proposed incremental per-page merge
functions (`RunningStats`, `df_merge`, `lsh_merge`, `anchor_index_merge`) plus
an append-only `.features.partial.jsonl` resume sidecar mirroring
`vectors.jsonl`. Converging findings that changed the design:

1. **The O(n²)-per-query-recompute fear was never validated.** A from-scratch
   `df_of`/`zstats_of`/`build_lsh`/`build_anchor_index` pass over 130,717
   records is a few seconds total in pure Python (df/zstats: sub-second each;
   `build_lsh`'s ~2M blake2b calls across 16 bands: low seconds). Queries
   during a multi-minute build are rare, human-paced events — a **debounced
   recompute from the existing from-scratch functions** is cheap enough and
   needs zero new scoring code.
2. **Resume-on-restart didn't save the expensive part anyway.** The dominant
   build cost is IDA-side extraction (disasm/CFG/MinHash per function via
   `func_features`), which a resumed build still has to redo in full — the
   sidecar only would have saved the (already-cheap) Python-side merge work.
   Not worth the new persistence format, resume/skip logic, and orphan
   reconciliation it required. Cut entirely; matches this feature's own
   `01-v1-production-design.md` §7 precedent ("ship full-rebuild first").
3. **The proposed merge functions mutate arguments in place**
   (`df[item] = df.get(item,0)+1` re-assigns existing keys;
   `lsh`/`anchor_index` append into existing bucket lists) — this both
   contradicts `sim_score.py`'s existing convention (every function there is
   pure: builds and returns a fresh object, zero classes) and the user's
   global coding-style rule ("ALWAYS create new objects, NEVER mutate
   existing ones"). The debounced-recompute approach needs no merge
   functions, so this conflict disappears.
4. **A real bug survived simplification and must still be fixed**: nothing
   in v1 ever released the accumulated partial state after a build
   completed, so full per-instance record sets (up to 130K `FunctionFeature`
   dicts + derived structures) would stay memory-resident for the life of
   the process. v2 explicitly clears it on completion (§Memory below).
5. **A pre-existing bug is made materially worse and gets a minimal,
   in-scope mitigation**: if the analyzed binary changes mid-build (same
   `instance_id`, different content — the router's binary-change guard
   compares filename, not content, see `router.py`), today that would
   corrupt one *silent* final write. With partial-serving, the corrupted
   in-progress state would be **actively served to callers** for the whole
   build duration instead. v2 adds a cheap per-page fingerprint re-check to
   close this (§Binary-change guard below) since this change is what makes
   the exposure meaningfully worse.

## v2 → v3: round-2 review findings and fixes

A second round of two independent reviewers, given v2, converged on three
concrete implementation-detail bugs (not architectural — the core "reuse
from-scratch functions, debounce, GIL-safe list read" shape was confirmed
sound by both):

1. **`_load_partial`'s unlock→compute→relock pattern races with completion.**
   v2's helper reads `recs` under `_jobs_lock`, releases it to do the
   (multi-hundred-ms) `_assemble_index`/`build_anchor_index` work, then
   re-acquires the lock and unconditionally writes `_partial_cache` back.
   If the real build finishes and the completion handler (§4) pops
   `live_records`/`_partial_cache` during that window, this write silently
   re-attaches a full heavy entry to a now-`"ready"` job — never read again
   (the `status != "building"` guard prevents that), but never freed either.
   **Fix**: tag each build with a monotonic generation counter; only write
   the cache back if the generation and status still match what was read at
   the start (§2 below).
2. **Per-page fingerprint re-check was mis-located and its cost unvalidated.**
   v2 said "top of `_run()`'s per-page loop," but `_run()` has no loop — the
   page loop is inside `_build_records`, reachable only via the `on_page`
   callback, which fires **after** `records.extend(funcs)` — so a check
   there cannot prevent one page's worth of already-swapped data from being
   appended before detection (a real, but bounded, TOCTOU gap). Separately,
   `_instance_key` calls `binary_fingerprint` — a routed IDA round-trip —
   so checking on literally every page (up to ~262 for a 130K-function
   binary) adds that many extra round-trips competing with `func_features`
   calls for the same single-threaded IDA main-thread, an unvalidated and
   likely real cost regression. **Fix**: check every `N` pages (§5 below),
   accepting a bounded (not eliminated) exposure window in exchange for a
   bounded, small number of extra round-trips — documented as a known,
   deliberate trade-off, not silently swept under "cheap."
3. **`coverage.done` was read from `_jobs[giid]["live_records"]` directly,
   unlocked, after the gallery loop** — a `KeyError` if the build completed
   and popped that key in the meantime, and even when it doesn't error, a
   value that can disagree with the (possibly `_PARTIAL_TTL_S`-stale)
   `entry` actually used to compute `results`, since the two reads aren't
   from the same snapshot. **Fix**: derive `coverage` from the same `entry`
   already used for scoring (`entry["index"]["function_count"]`) instead of
   a second, separately-timed read of shared state (§3 below).

## Round 3: convergence check

A third independent reviewer verified all three round-2 fixes against the
actual code (confirmed `_build_records`'s `on_page -> bool` early-stop is
real at `similarity.py:242-243`; confirmed the `_load_partial` write-back
race is closed because the gen+status re-check and the write happen inside
one uninterrupted `with _jobs_lock:` block; confirmed the completion-path gen
guard doesn't break the normal case) and found only two LOW, non-blocking
documentation issues, both fixed inline: `_next_gen()` pinned to a concrete
module-level `itertools.count()`, and §4's rationale corrected to attribute
supersession-prevention to `_start_background`'s existing "already building"
guard rather than to `_on_page`'s early-stop (which is real but not the
mechanism actually load-bearing here). No new CRITICAL/HIGH findings. Design
considered converged.

## Post-review fix (found during implementation planning)

`_load_partial`'s guard (§2, as originally written) gated on
`job.get("status") != "building"`, returning `None` for any other status —
but §4 explicitly says the **error** path should keep serving the
last-known partial data (`live_records`/`_partial_cache` are deliberately
*not* cleared on error, specifically so `similar_functions` can keep
returning it labeled `partial: true`). §2's code as written could never
reach that data, since it always returned `None` once `status` left
`"building"`. This contradiction survived all three review rounds. §2 below
is corrected to check `status in ("building", "error")` in both the read
guard and the write-back guard — an errored job's `live_records` are frozen
(the build will not progress further under that `gen`), so caching a
computed snapshot of them is always safe, not just a "still fresh enough"
debounce.

## Approach (v3)

No new files, no new persisted formats, no mutation of shared state.
Everything reuses the existing from-scratch `sim_score.py` functions and the
existing `_load()`-shaped `entry = {"index": ..., "anchor_index": ...}`
structure that `similar_functions()` already consumes (`similarity.py:458-472`,
`:533-545`).

### 1. Expose the background job's growing record list, with a generation tag

`_build_records()` (`similarity.py:231-248`) already threads an `on_page`
callback that receives the **same, in-place-mutated** `records` list on every
page (`records.extend(funcs); on_page(records, total)`). `_start_background`
(`similarity.py:356+`, where `_jobs[iid] = {...}` is assigned fresh for every
new build — including retries after an error) gains one new field, and its
`_on_page` closure (`:371+`) stashes the list reference (not a copy) plus a
page counter, once per page, under the existing `_jobs_lock`:
```python
_gen_counter = itertools.count()   # module-level, next()'d only while holding _jobs_lock

def _start_background(...):
    with _jobs_lock:
        gen = next(_gen_counter)
        _jobs[iid] = {"status": "building", "progress": 0.0, "gen": gen, "pages_seen": 0, ...}
    ...
    def _on_page(recs, total):
        with _jobs_lock:
            job = _jobs.get(iid)
            if job is None or job.get("gen") != gen:
                return False   # a newer build superseded this one; stop
            job["progress"] = ...              # existing
            job.setdefault("live_records", recs)   # same list object every call; no-op after first page
            job["pages_seen"] = job.get("pages_seen", 0) + 1
        ...
```
`gen` (captured once per `_run()` invocation) is the fix for the v2→v3
finding-1 race: every later read/write that touches `_jobs[iid]` compares
against this captured `gen` before trusting or mutating shared state, so a
slow background write from a superseded or already-finished build can never
clobber a newer build's state or resurrect cleared state (§2, §4 below).

Because CPython list mutation (`.extend`) is safe to read concurrently from
another thread (no "changed size during iteration" error, unlike dict/set —
a reader just sees whatever length existed when it started iterating), no
further locking is needed to *read* `live_records` itself. This matches
reviewer feedback: the actual safety argument is "GIL + list, not dict,
semantics," not "pages only add" (true for the list, but previously stated
imprecisely against the dict-based merge functions that no longer exist).

### 2. Debounced partial-index assembly in `similar_functions`

New small helper in `tools/similarity.py`, sitting next to `_load`:
```python
_PARTIAL_TTL_S = 2.0

def _load_partial(iid: str) -> dict | None:
    """Ephemeral, debounced index+anchor_index entry from a build in progress.

    Reuses the exact from-scratch functions `_assemble_index`/`_load` already
    use for the final index, over whatever the background thread has
    accumulated so far. Returns None if no build is running for `iid`.
    """
    with _jobs_lock:
        job = _jobs.get(iid)
        if not job or job.get("status") not in ("building", "error"):
            return None
        gen = job["gen"]
        recs = job.get("live_records")
        cached = job.get("_partial_cache")
    if not recs:
        return None
    now = time.time()
    if cached and cached["gen"] == gen and now - cached["at"] < _PARTIAL_TTL_S:
        return cached["entry"]
    key, fp = _instance_key(iid)               # re-fingerprints; see §5
    if not key:
        return None
    info = (_registry.get_instance(iid) or {}) if _registry else {}
    idx = _assemble_index(list(recs), key, info.get("binary_name", ""), fp)
    funcs = list(idx["functions"].values())
    entry = {"index": idx, "anchor_index": sim_score.build_anchor_index(funcs)}
    with _jobs_lock:
        j = _jobs.get(iid)
        # Only cache back if this is STILL the same build (gen match) and
        # still in a state we're allowed to serve ("building" or "error" --
        # a build that finished or was superseded by a NEWER generation
        # while we were off the lock computing `entry` must not have its
        # (now-stale, and for a finished build, un-freed) result written
        # back — this is the v2→v3 fix for the completion race (finding 1).
        # The caller still gets the freshly-computed `entry` for THIS call
        # either way; only the cache write is conditional.
        if j is not None and j.get("gen") == gen and j.get("status") in ("building", "error"):
            j["_partial_cache"] = {"at": now, "gen": gen, "entry": entry}
    return entry
```
`_assemble_index` already runs `_valid_records` (drops `func_features` error
stubs before df/zstats/lsh see them — fixes a gap the v1 merge-function
draft would have hit), so no separate filtering is needed here.

### 3. Wire into `similar_functions`

At `similarity.py:533` (`entry = _load(gkey, rp)` → `not_indexed` on
`None`), fall back to the partial loader and tag the result. Coverage is
read from the **same `entry`** that scoring goes on to use — never a second,
separately-timed lookup into `_jobs` — so it can never disagree with
`results` or race a completing/popped job (v2→v3 finding 3):
```python
entry = _load(gkey, rp)
partial = False
if entry is None:
    entry = _load_partial(giid)
    partial = entry is not None
if entry is None:
    not_indexed.append(giid)
    continue
...
if partial:
    partial_coverage[giid] = entry["index"]["function_count"]  # same entry used below for scoring
```
After the loop, if `partial_coverage` is non-empty, add to `out`:
```python
out["partial"] = True
out["coverage"] = {giid: {"done": n, "total": None} for giid, n in partial_coverage.items()}
```
(`total` stays `None` — `func_features`'s paging cursor doesn't report an
upfront total function count cheaply; `index_status(instance_id)` already
reports `progress` as a 0..1 fraction computed the same way the build itself
tracks it, so coverage's absolute numerator is enough context and this
avoids a second, possibly-inconsistent, source of "total.")

A query whose own function address hasn't been reached by the background
loop yet still resolves normally — `q` is always fetched fresh via a direct
`func_features` call (`similarity.py:503`, unrelated to the gallery/index
build). It simply won't itself be *findable as a candidate in someone else's
search* until its page is processed — expected, not an error case.

### 4. Memory: clear partial state on completion

In `_run()`'s success path (`similarity.py:386-389`, where `status` flips to
`"ready"`), also drop the heavy partial-only state under the same lock —
guarded by the same `gen` check as everywhere else. In practice a `_run()`
never reaches this point with a stale `gen` at all: `_start_background`'s
existing "already building" short-circuit (`similarity.py:358-362`) refuses
to start a second build for the same `iid` while one is in progress, so
nothing can supersede a running `_run()`'s `gen` mid-flight — the guard here
is a belt-and-suspenders correctness check (matching the same pattern used
everywhere else `_jobs[iid]` is touched), not a load-bearing recovery from a
reachable race. If that upstream guard is ever relaxed in the future (e.g.
to support concurrent rebuilds), this check is what keeps completion
handling correct without relying on `_on_page`'s early-stop path, which
`_build_records` does honor (`similarity.py:242-243`, `on_page -> bool`)
but which is not the mechanism actually preventing supersession today:
```python
with _jobs_lock:
    job = _jobs.get(iid)
    if job is not None and job.get("gen") == gen:
        job.pop("live_records", None)
        job.pop("_partial_cache", None)
        job.update(status="ready", ...)   # existing
```
`similar_functions` always tries `_load(gkey, rp)` (the real, persisted,
`_loaded`-cached index) first and only calls `_load_partial` when that
returns `None` — once the real index exists, `_load_partial` is never
reached again for that key, so the pop above is the only cleanup needed (no
risk of a stale partial cache being served after completion).

On the **error** path (`similarity.py:406-409`), `live_records` and
`_partial_cache` are deliberately left in place — the partial data is "as
good as it'll get" until `index_functions` is invoked again, and
`similar_functions` should keep serving it (labeled `partial: true`).
`index_status`'s existing `job_status: "error"` field already tells the
caller the build has stalled.

### 5. Binary-change guard (bounded, not eliminated — explicit trade-off)

`_instance_key(iid)` calls the IDA-side `binary_fingerprint` tool — a routed
round-trip (`similarity.py:212-224`). Checking it on every page (~262 for a
130K-function binary) would add that many extra round-trips contending with
`func_features` for the same single-threaded IDA main thread — an
unacceptable, unvalidated cost regression against the very goal of this
change. Instead, the `_on_page` closure (§1) — which already runs after
`_build_records` has appended that page's records
(`records.extend(funcs); on_page(records, total)`, `similarity.py:240-243`
— confirmed there is no earlier hook available) — re-checks the fingerprint
every `_FP_CHECK_EVERY_N_PAGES` pages (default 20, so at most ~13 extra
round-trips for a 262-page build) using the `pages_seen` counter from §1:
```python
def _on_page(recs, total):
    with _jobs_lock:
        job = _jobs.get(iid)
        if job is None or job.get("gen") != gen:
            return False
        job["progress"] = ...
        job.setdefault("live_records", recs)
        job["pages_seen"] = n = job.get("pages_seen", 0) + 1
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
```
**Explicit, documented trade-off** (not silently swept under "cheap," per
round-2 feedback): this closes most of the exposure window a mid-build
binary swap opens, but not all of it — up to `_FP_CHECK_EVERY_N_PAGES - 1`
pages' worth of already-swapped-binary functions can land in `live_records`
(and be served as `partial: true` results, and end up in the final index if
the swap is never caught within the whole build) before detection fires.
This is strictly better than today (zero checks, unbounded exposure, only
ever surfaces via the router's *filename*-based guard on the *next* tool
call against the wrong binary) without adding a cost the goal can't afford.
A tighter guarantee (check every page, or make `_build_records` itself
fingerprint-aware) is left as a follow-up if this bounded window proves
insufficient in practice — this design does not claim to fully close it.

## Non-goals

- Skipping already-covered functions on the **IDA side** — out of scope;
  there is no resume to save work for anymore (§v1→v2 point 2).
- ~~Persisted resume across a server restart~~ — **dropped**. A restart
  mid-build loses progress and requires re-invoking `index_functions`,
  identical to today's behavior. No regression; explicitly deferred, per
  reviewer 3 and this feature's own `01-v1-production-design.md` §7
  precedent.
- Auto-resuming/auto-starting a background build from a bare
  `similar_functions()` call with no `index_functions()` ever invoked —
  unchanged from v1's reasoning (never silently start unbounded IDA-side
  work as a side effect of what looks like a read).
- Multi-process / multi-server-instance coordination — dropped from explicit
  discussion (reviewer 3: not asked for, existing final-index write path
  doesn't handle it either, mentioning it only invited unnecessary scope
  questions). Two *different `instance_id`s* (e.g. two IDA GUI windows) each
  running `index_functions()` on the *same* binary each get their own
  independent `_jobs[iid]` and `live_records` — no shared mutable state
  between them until each writes its own final index to the same
  content-hash key at the end, which is pre-existing, unchanged behavior.

## Testing

- `test_similarity.py` (extended):
  - Background build (fake IDA/router stub yielding controlled pages) +
    a `similar_functions` call mid-build asserts `partial: true`,
    `coverage[iid].done` equal to `entry["index"]["function_count"]` (i.e.
    read from the same object that produced `results`, not a second lookup),
    and results drawn only from already-seen addrs.
  - Debounce: two `similar_functions` calls within `_PARTIAL_TTL_S` of each
    other while no new pages have landed reuse the cached entry (assert via
    a call-counter on a monkeypatched `_assemble_index`/`build_anchor_index`
    or by timing).
  - Query function not yet reached by the build: `similar_functions` still
    returns (query resolves via the direct fetch), just with a smaller/empty
    candidate set from the partial gallery — no exception.
  - On completion, `partial` is absent (or `False`) and results match a
    normal from-scratch index; `_jobs[iid]` no longer holds `live_records`/
    `_partial_cache` (assert via `similarity._jobs`).
  - **Completion race (v2→v3 finding 1)**: start a build, call
    `_load_partial` and, via a monkeypatch/hook, pause it after it releases
    `_jobs_lock` the first time (having read `recs`/`gen`) but before it
    re-acquires the lock to write the cache; let the real build finish in
    that window (pops `live_records`/`_partial_cache`, flips `status`);
    resume `_load_partial`; assert it does NOT re-insert `_partial_cache`
    into the now-`"ready"` job (i.e. `_jobs[iid]` still has no
    `live_records`/`_partial_cache` after `_load_partial` returns).
  - **Retry/generation (v2→v3 finding 1, retry variant)**: start a build,
    force it to error, call `index_functions()` again for the same `iid`
    (new `_jobs[iid]`, new `gen`); assert a `_load_partial` call whose
    in-flight computation started against the OLD `gen` does not write its
    stale result into the new job's `_partial_cache`.
  - On a build error mid-way, `similar_functions` still returns the last
    partial results (`partial: true`) rather than `not_indexed`.
  - **Binary-change guard, bounded window (v2→v3 finding 2)**: monkeypatch
    `_instance_key` to flip to a different key partway through a fake
    multi-page build; assert the job transitions to `status: "error"` within
    `_FP_CHECK_EVERY_N_PAGES` pages of the flip (not immediately — assert
    the bound, not zero-tolerance), and that no further pages are appended
    after detection.
- Full existing test suite must stay green — the final-index code path
  (`_assemble_index`, `write_index`) is completely untouched.
