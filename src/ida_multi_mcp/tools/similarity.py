"""Function-similarity tools for ida-multi-mcp (server-side, zero-dependency).

Feature extraction runs IDA-side (``func_features`` / ``binary_fingerprint``);
this module builds and searches per-binary indexes and routes cross-instance.

Design: docs/plans/function-similarity/01-v1-production-design.md
Wiring mirrors tools/management.py (module-level registry/router injection).
"""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import threading
import time
from typing import Any, Callable

from . import index_store, sim_score

# Injected by server.py at startup.
_registry = None
_router = None

# Background index jobs: instance_id -> {status, progress, cancel, error, key, function_count}
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()

# In-memory loaded-index cache: key -> {"index": dict, "anchor_index": dict}
_loaded: dict[str, dict] = {}
_loaded_lock = threading.Lock()

PAGE = int(os.environ.get("IDA_MCP_SIM_PAGE", "500"))

# Monotonic build-generation counter: next()'d only while holding _jobs_lock,
# in _start_background. Lets in-flight work (e.g. _load_partial) tell whether
# the job it read from is still the one it started with, so a slow write-back
# from a superseded/finished build can never clobber newer state.
_gen_counter = itertools.count()

# How often (in pages) a background build re-verifies the instance's binary
# fingerprint still matches the one it started with. Every page would add a
# routed IDA round-trip per page (~262 for a 130K-function binary) contending
# with func_features calls on the same single-threaded IDA main thread; this
# bounds (does not eliminate) the window during which a mid-build binary swap
# can produce results attributed to the wrong binary.
_FP_CHECK_EVERY_N_PAGES = int(os.environ.get("IDA_MCP_SIM_FP_CHECK_EVERY_N_PAGES", "20"))
_PARTIAL_TTL_S = float(os.environ.get("IDA_MCP_SIM_PARTIAL_TTL_S", "2.0"))

# Neural recall (opt-in): set IDA_MCP_SIM_NEURAL=1 and point JTRANS_MODEL /
# JTRANS_TOKENIZER at a jTrans-finetune checkpoint. This adds a jTrans embedding
# recall stage (surfacing anchor-less cross-compiler twins that LSH/anchor
# candidate-gen misses) and blends its cosine into the final grouped score. Off by
# default -> behaviour is exactly the zero-dependency pipeline.
_NEURAL = os.environ.get("IDA_MCP_SIM_NEURAL") == "1"
# 0.7 gave the best cross-compiler Recall@3 (8/10) on the simbench gcc/clang set
# while keeping 30% grouped weight for same-toolchain confidence; env-tunable
# (small sample -- do not over-fit). 0 -> pure grouped, 1 -> pure neural cosine.
NEURAL_LAMBDA = float(os.environ.get("IDA_MCP_SIM_NEURAL_LAMBDA", "0.7"))
NEURAL_RECALL_K = int(os.environ.get("IDA_MCP_SIM_NEURAL_K", "50"))
# Functions embedded per forward pass during background indexing (non-blocking,
# progress-reported, resumable). Vectors persist to an append-only sidecar so the
# index is usable (non-neural immediately; neural recall over whatever is embedded).
EMBED_BATCH = int(os.environ.get("IDA_MCP_SIM_EMBED_BATCH", "64"))

TOOL_NAMES = frozenset(
    {"index_functions", "index_status", "similar_functions", "compare_functions"}
)


def _neural_enabled() -> bool:
    """True when neural recall is switched on and the [neural] extra is importable."""
    if not _NEURAL:
        return False
    try:
        from . import neural_backend
        return neural_backend.is_available()
    except Exception:
        return False


def _embed_incremental(iid: str, key: str, rp: str | None, valid_addrs: list[str]) -> None:
    """Embed valid functions in batches (the non-blocking background phase-2).

    Pages func_tokens, embeds ``EMBED_BATCH`` at a time, appends each batch to the
    vectors sidecar (durable + resumable), updates the in-memory index cache so
    live queries see new vectors without a reload, and reports progress via the
    job. Honors the job's cancel flag; already-embedded addrs are skipped (resume).
    """
    from . import neural_backend
    valid_set = set(valid_addrs)
    done = set(index_store.read_vectors(key, rp))  # resume from any prior run
    with _jobs_lock:
        if iid in _jobs:
            _jobs[iid]["embed_done"] = len(done & valid_set)
    be = neural_backend.get_backend()
    pending_a: list[str] = []
    pending_t: list[list] = []

    def _flush() -> None:
        if not pending_a:
            return
        vecs = be.embed_batch(pending_t)
        batch = {a: v for a, v in zip(pending_a, vecs)}
        index_store.append_vectors(key, batch, rp)
        done.update(batch)
        with _loaded_lock:                      # live queries see new vectors now
            entry = _loaded.get(key)
            if entry is not None:
                entry["index"].setdefault("vectors", {}).update(batch)
        with _jobs_lock:
            if iid in _jobs:
                _jobs[iid]["embed_done"] = len(done & valid_set)
        pending_a.clear()
        pending_t.clear()

    offset = 0
    while True:
        with _jobs_lock:
            if _jobs.get(iid, {}).get("cancel"):
                return
        page = _call_ida(iid, "func_tokens", {"addrs": "*", "offset": offset, "count": PAGE})
        if not page or "tokens" not in page:
            break
        for a, t in page["tokens"].items():
            if a in valid_set and a not in done:
                pending_a.append(a)
                pending_t.append(t)
                if len(pending_a) >= EMBED_BATCH:
                    _flush()
        cursor = page.get("cursor", {}) or {}
        if cursor.get("done"):
            break
        offset = int(cursor.get("next", offset + PAGE))
    _flush()


def _query_vector(iid: str, addr: str) -> list | None:
    """Embed a single query function (by addr) with the neural backend."""
    if not _neural_enabled():
        return None
    try:
        page = _call_ida(iid, "func_tokens", {"addrs": str(addr), "count": 1})
        toks = (page or {}).get("tokens", {})
        if not toks:
            return None
        from . import neural_backend
        vecs = neural_backend.get_backend().embed_batch(list(toks.values()))
        return vecs[0] if vecs else None
    except Exception:
        return None


def _cosine(a, b) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(x * x for x in b) ** 0.5
    return dot / (na * nb) if na and nb else 0.0


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------

def set_registry(registry) -> None:
    """Set the shared instance registry (called by server at startup)."""
    global _registry
    _registry = registry


def set_router(router) -> None:
    """Set the request router used to reach IDA instances."""
    global _router
    _router = router


def _registry_path() -> str | None:
    return getattr(_registry, "registry_path", None)


# ---------------------------------------------------------------------------
# IDA calls (routed) + instance resolution
# ---------------------------------------------------------------------------

def _resolve_instance(arguments: dict) -> tuple[str | None, dict | None]:
    """Resolve instance_id, auto-selecting when exactly one instance exists."""
    iid = arguments.get("instance_id")
    if iid:
        return iid, None
    if _registry is None:
        return None, {"error": "Registry not initialized"}
    insts = _registry.list_instances()
    if len(insts) == 1:
        return next(iter(insts)), None
    return None, {
        "error": "Missing required parameter 'instance_id'.",
        "hint": "Call list_instances() and pass instance_id explicitly.",
        "available_instances": [
            {"id": i, "binary_name": v.get("binary_name", "unknown")}
            for i, v in insts.items()
        ],
    }


def _call_ida(instance_id: str, tool: str, args: dict) -> dict | None:
    """Route a tool call to an IDA instance and parse its structured result."""
    if _router is None:
        return None
    payload = dict(args)
    payload["instance_id"] = instance_id
    resp = _router.route_request("tools/call", {"name": tool, "arguments": payload})
    if not isinstance(resp, dict) or "error" in resp:
        return None
    content = resp.get("content", [])
    if content:
        try:
            parsed = json.loads(content[0].get("text", "null"))
            if parsed is not None:
                return parsed
        except Exception:
            pass
    return resp.get("structuredContent")


def _instance_key(instance_id: str) -> tuple[str | None, dict | None]:
    """Resolve the content-hash index key (+fingerprint) for an instance."""
    fp = _call_ida(instance_id, "binary_fingerprint", {})
    if not fp:
        return None, None
    key = fp.get("sha256") or fp.get("md5")
    if not key:
        # Fallback (design §12): derive a stable key from path + size.
        info = (_registry.get_instance(instance_id) or {}) if _registry else {}
        seed = f"{info.get('binary_path', '')}:{fp.get('function_count', 0)}"
        key = "fb-" + hashlib.sha256(seed.encode()).hexdigest()[:24]
        fp["key_fallback"] = True
    return key, fp


# ---------------------------------------------------------------------------
# Index build
# ---------------------------------------------------------------------------

def _build_records(instance_id: str, on_page: Callable[[list, int], bool] | None = None) -> list[dict]:
    """Page through func_features. on_page(records_so_far, total) -> keep_going."""
    records: list[dict] = []
    offset = 0
    while True:
        page = _call_ida(instance_id, "func_features", {"addrs": "*", "offset": offset, "count": PAGE})
        if page is None:
            raise RuntimeError("func_features call failed")
        funcs = page.get("functions", [])
        records.extend(funcs)
        total = int(page.get("total") or 0)
        if on_page is not None and not on_page(records, total):
            break
        cursor = page.get("cursor", {}) or {}
        if cursor.get("done") or not funcs:
            break
        offset = int(cursor.get("next", offset + len(funcs)))
    return records


def _valid_records(records: list[dict]) -> list[dict]:
    """Keep only complete feature records; drop per-function extraction errors.

    ``func_features`` emits ``{"addr", "error"}`` stubs for functions it cannot
    analyze, mixed into the page with good records. Those stubs lack
    ``minhash``/``cfg``/``apis``/... and would ``KeyError`` the pure
    df/zstats/lsh builders, so a single un-analyzable function must not sink the
    whole index. Filtered here at the boundary; ``sim_score`` stays strict on
    full records.
    """
    return [
        r for r in records
        if isinstance(r, dict) and "error" not in r
        and "minhash" in r and "cfg" in r and "addr" in r
    ]


def _assemble_index(records: list[dict], key: str, binary_name: str, fp: dict) -> dict:
    valid = _valid_records(records)
    return {
        "schema_version": 1,
        "binary_sha256": key,
        "binary_name": binary_name,
        "arch": fp.get("arch", ""),
        "built_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "function_count": len(valid),
        "skipped_count": len(records) - len(valid),
        "params": {"M": sim_score.M, "K": sim_score.K, "bands": sim_score.BANDS, "rows": sim_score.ROWS},
        "df": {
            "apis": sim_score.df_of(valid, "apis"),
            "strings": sim_score.df_of(valid, "strings"),
            "consts": sim_score.df_of(valid, "consts"),
        },
        "zstats": sim_score.zstats_of(valid),
        "functions": {r["addr"]: r for r in valid},
        "lsh": sim_score.build_lsh(valid),
    }


def _invalidate_cache(key: str) -> None:
    with _loaded_lock:
        _loaded.pop(key, None)


def _embedding_incomplete(key: str, rp: str | None) -> bool:
    """True when neural is on and fewer vectors are stored than functions indexed."""
    if not _neural_enabled():
        return False
    idx = index_store.read_index(key, rp) or {}
    return len(index_store.read_vectors(key, rp)) < idx.get("function_count", 0)


def index_functions(arguments: dict) -> dict:
    """Build or refresh the per-binary similarity index for an instance.

    Non-blocking by default: features build first (the index is immediately usable
    for non-neural search), then neural vectors (when ``IDA_MCP_SIM_NEURAL=1``)
    accrue in the background -- batched, resumable, with progress via
    ``index_status``. A cached index whose embedding is incomplete is resumed.
    """
    iid, err = _resolve_instance(arguments)
    if err:
        return err
    rebuild = bool(arguments.get("rebuild", False))
    background = bool(arguments.get("background", True))
    key, fp = _instance_key(iid)
    if not key:
        return {"error": f"Could not fingerprint instance '{iid}'"}
    rp = _registry_path()

    features_ready = index_store.has_index(key, rp) and not rebuild
    if features_ready and not _embedding_incomplete(key, rp):
        idx = index_store.read_index(key, rp) or {}
        return {"index_id": key, "function_count": idx.get("function_count", 0),
                "status": "ready", "elapsed_s": 0.0, "pages": 0, "cached": True}

    info = (_registry.get_instance(iid) or {}) if _registry else {}
    binary_name = info.get("binary_name", "")

    if background:
        return _start_background(iid, key, fp, binary_name, rp, features_ready)

    t0 = time.time()
    if not features_ready:
        if rebuild:
            index_store.clear_vectors(key, rp)
        records = _build_records(iid)
        index = _assemble_index(records, key, binary_name, fp)
        index_store.write_index(index, rp)
        _invalidate_cache(key)
        valid_addrs = [r["addr"] for r in _valid_records(records)]
        fc, sk = len(valid_addrs), index["skipped_count"]
    else:
        idx = index_store.read_index(key, rp) or {}
        valid_addrs = list(idx.get("functions", {}).keys())
        fc, sk = idx.get("function_count", len(valid_addrs)), 0
    neural = False
    if _neural_enabled() and valid_addrs:
        _embed_incremental(iid, key, rp, valid_addrs)
        neural = bool(index_store.read_vectors(key, rp))
    return {"index_id": key, "function_count": fc, "skipped_count": sk,
            "status": "ready", "neural": neural,
            "elapsed_s": round(time.time() - t0, 2), "pages": -1}


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
                      "cancel": False, "error": None, "key": key, "fp": fp,
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
            # cur_key is None on a transient routing/IDA failure (_instance_key
            # returns (None, None) whenever _call_ida fails), not just on a
            # real binary swap -- treat that as inconclusive and skip this
            # check rather than aborting the build on a flaky round-trip.
            if cur_key is not None and cur_key != key:
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
                        job is None or job.get("gen") != gen
                        or job.get("status") == "error" or job.get("cancel")
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
                if valid_addrs:
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


def index_status(arguments: dict) -> dict:
    """Report index readiness / build progress for an instance."""
    iid, err = _resolve_instance(arguments)
    if err:
        return err
    key, _ = _instance_key(iid)
    rp = _registry_path()
    job = _jobs.get(iid, {})
    indexed = bool(key) and index_store.has_index(key, rp)
    out: dict[str, Any] = {
        "indexed": indexed,
        "index_id": key,
        "stale": False,  # content-hash keying: current binary always maps to its own key
        "job_status": job.get("status"),
        "progress": job.get("progress") if job.get("status") == "building"
        else (1.0 if indexed else None),
    }
    if indexed:
        idx = index_store.read_index(key, rp) or {}
        out["function_count"] = idx.get("function_count", 0)
        out["built_at"] = idx.get("built_at")
        out["path"] = index_store.index_path(key, rp)
        # Neural embedding progress (read from the durable sidecar, so it is
        # accurate even across a server restart when the in-memory job is gone).
        if _neural_enabled():
            fc = out["function_count"]
            nvec = len(index_store.read_vectors(key, rp))
            out["embed_done"] = nvec
            out["embed_total"] = fc
            out["embed_progress"] = (nvec / fc) if fc else None
            out["embed_status"] = job.get("embed_status") or (
                "done" if fc and nvec >= fc else "partial" if nvec else "pending")
    if job.get("status") == "error":
        out["error"] = job.get("error")
    return out


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

def _load(key: str, rp: str | None) -> dict | None:
    with _loaded_lock:
        if key in _loaded:
            return _loaded[key]
    idx = index_store.read_index(key, rp)
    if idx is None:
        return None
    vectors = index_store.read_vectors(key, rp)     # partial embedding is usable
    if vectors:
        idx["vectors"] = {**idx.get("vectors", {}), **vectors}
    funcs = list(idx.get("functions", {}).values())
    entry = {"index": idx, "anchor_index": sim_score.build_anchor_index(funcs)}
    with _loaded_lock:
        _loaded[key] = entry
    return entry


def _load_partial(iid: str) -> dict | None:
    """Ephemeral, debounced index+anchor_index entry from a build in progress
    (or one that errored, serving its last-known-good state).

    Reuses the exact from-scratch functions `_assemble_index`/`build_anchor_index`
    already used for the final index, over whatever the background thread has
    accumulated so far (`_jobs[iid]["live_records"]`). Returns None if no build
    is running/errored for `iid`, or none of its pages have landed yet.
    """
    with _jobs_lock:
        job = _jobs.get(iid)
        if not job or job.get("status") not in ("building", "error"):
            return None
        gen = job.get("gen")
        key = job.get("key")
        fp = job.get("fp") or {}
        recs = job.get("live_records")
        cached = job.get("_partial_cache")
    if not recs or not key:
        return None
    now = time.time()
    if cached and cached.get("gen") == gen and now - cached["at"] < _PARTIAL_TTL_S:
        return cached["entry"]
    # Use the build's own recorded key/fp (fixed at _start_background time),
    # not a live re-fingerprint: the live fingerprint may have already moved
    # on (e.g. after a detected binary-change error), and tagging these
    # STALE records with a fresh key would misattribute them. Live-swap
    # detection is _on_page's job (periodic recheck), not this loader's.
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
        # write is conditional.
        if j is not None and j.get("gen") == gen and j.get("status") in ("building", "error"):
            j["_partial_cache"] = {"at": now, "gen": gen, "entry": entry}
    return entry


def _cap_candidates(cand: set, q: dict, entry: dict) -> set:
    funcs = entry["index"]["functions"]
    qa = set(q.get("apis", [])) | set(q.get("strings", [])) | set(q.get("consts", []))

    def _hits(addr: str) -> int:
        b = funcs.get(addr, {})
        ba = set(b.get("apis", [])) | set(b.get("strings", [])) | set(b.get("consts", []))
        return len(qa & ba)

    return set(sorted(cand, key=lambda a: (_hits(a), a), reverse=True)[: sim_score.CAND_CAP])


def similar_functions(arguments: dict) -> dict:
    """Rank functions similar to a query function, within a binary or across instances."""
    iid, err = _resolve_instance(arguments)
    if err:
        return err
    func = arguments.get("func")
    if func in (None, ""):
        return {"error": "Missing 'func' (address or name)"}
    top_k = int(arguments.get("top_k", 20))
    min_score = float(arguments.get("min_score", 0.0))
    scope = arguments.get("scope", "binary")
    instances = arguments.get("instances") or []
    include_self = bool(arguments.get("include_self", False))
    weights = arguments.get("weights")   # None -> grouped (production) scoring
    rp = _registry_path()

    qpage = _call_ida(iid, "func_features", {"addrs": str(func), "count": 1})
    qfuncs = (qpage or {}).get("functions", [])
    q = qfuncs[0] if qfuncs else None
    # func_features returns an {"addr","error"} stub (not an empty list) for an
    # unresolvable target; guard on the required field so scoring never KeyErrors.
    if not q or "minhash" not in q:
        out = {"error": f"Could not extract features for '{func}' in instance '{iid}'"}
        if isinstance(q, dict) and q.get("error"):
            out["detail"] = q["error"]
        return out

    if scope == "binary":
        gallery_iids = [iid]
    elif scope == "instances":
        gallery_iids = list(instances) or [iid]
    elif scope == "all":
        gallery_iids = list((_registry.list_instances() or {}).keys()) if _registry else [iid]
    else:
        return {"error": f"Unknown scope '{scope}' (use binary|instances|all)"}

    qvec = _query_vector(iid, q.get("addr")) if _neural_enabled() else None

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
                # The build may have finished (and been persisted) in the
                # window between the _load() miss above and this point --
                # _load_partial returns None once status leaves
                # "building"/"error". Re-check the real index once more
                # before reporting a false not_indexed.
                entry = _load(gkey, rp)
        if entry is None:
            not_indexed.append(giid)
            continue
        if partial:
            # Same `entry` used for scoring below -- never a second, separately
            # -timed lookup into `_jobs`.
            partial_coverage[giid] = entry["index"]["function_count"]
        idx = entry["index"]
        funcs = idx.get("functions", {})
        gallery_size += len(funcs)
        n = idx.get("function_count", len(funcs)) or 1
        df = idx.get("df", {})
        zstats = idx.get("zstats", {})
        rare_df = max(2, int(0.01 * n))
        cand = sim_score.lsh_candidates(q.get("minhash", []), idx.get("lsh", {})) | \
            sim_score.anchor_candidates(q, entry["anchor_index"], df, rare_df)
        if giid == iid and not include_self:
            cand.discard(q.get("addr"))
        if len(cand) > sim_score.CAND_CAP:
            cand = _cap_candidates(cand, q, entry)
        # Neural recall: cosine top-K over the index's jTrans vectors, added AFTER
        # the anchor cap so anchor-less twins (which the cap would drop) survive.
        gvectors = idx.get("vectors", {}) if qvec else {}
        if gvectors:
            ranked = sorted(((_cosine(qvec, v), a) for a, v in gvectors.items()), reverse=True)
            cand.update(a for _, a in ranked[:NEURAL_RECALL_K])
            if giid == iid and not include_self:
                cand.discard(q.get("addr"))
        for addr in cand:
            b = funcs.get(addr)
            if b is None:
                continue
            if weights:
                final, signals = sim_score.score(q, b, df, zstats, n, weights)
            else:
                final, signals = sim_score.score_grouped(q, b, df, zstats, n)
            # Blend the neural cosine so anchor-less cross-compiler twins (grouped
            # ~0, neural high) surface. NEURAL_LAMBDA=0 reduces to grouped exactly.
            if gvectors.get(addr):
                ncos = _cosine(qvec, gvectors[addr])
                signals = {**signals, "neural": ncos}
                final = (1 - NEURAL_LAMBDA) * final + NEURAL_LAMBDA * ncos
            if final < min_score:
                continue
            results.append({
                "instance_id": giid,
                "addr": addr,
                "name": b.get("name", ""),
                "score": round(final, 4),
                "signals": {k: round(v, 4) for k, v in signals.items()},
                "confidence": sim_score.confidence(final, signals),
            })

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


def compare_functions(arguments: dict) -> dict:
    """Pairwise similarity between two functions with a per-signal breakdown."""
    a = arguments.get("a") or {}
    b = arguments.get("b") or {}
    ia, err_a = _resolve_instance({"instance_id": a.get("instance_id")})
    if err_a:
        return err_a
    ib, err_b = _resolve_instance({"instance_id": b.get("instance_id")})
    if err_b:
        return err_b
    fa, fb = a.get("func"), b.get("func")
    if fa in (None, "") or fb in (None, ""):
        return {"error": "Both a.func and b.func are required"}
    weights = arguments.get("weights")   # None -> grouped (production) scoring

    pa = _call_ida(ia, "func_features", {"addrs": str(fa), "count": 1})
    pb = _call_ida(ib, "func_features", {"addrs": str(fb), "count": 1})
    la = (pa or {}).get("functions", [])
    lb = (pb or {}).get("functions", [])
    feat_a = la[0] if la else None
    feat_b = lb[0] if lb else None
    if not feat_a or "minhash" not in feat_a:
        out = {"error": f"Could not extract features for '{fa}' in '{ia}'"}
        if isinstance(feat_a, dict) and feat_a.get("error"):
            out["detail"] = feat_a["error"]
        return out
    if not feat_b or "minhash" not in feat_b:
        out = {"error": f"Could not extract features for '{fb}' in '{ib}'"}
        if isinstance(feat_b, dict) and feat_b.get("error"):
            out["detail"] = feat_b["error"]
        return out

    rp = _registry_path()
    key_a, _ = _instance_key(ia)
    if key_a and index_store.has_index(key_a, rp):
        idx = index_store.read_index(key_a, rp) or {}
        df = idx.get("df", {})
        zstats = idx.get("zstats", {})
        n = idx.get("function_count", 1000) or 1000
    else:
        # No index context: neutral df (all zero) + large n makes widf_jaccard
        # reduce to plain Jaccard (equal weights); zstats over the two functions.
        df = {"apis": {}, "strings": {}, "consts": {}}
        n = 1000
        zstats = sim_score.zstats_of([feat_a, feat_b])

    if weights:
        final, signals = sim_score.score(feat_a, feat_b, df, zstats, n, weights)
    else:
        final, signals = sim_score.score_grouped(feat_a, feat_b, df, zstats, n)
    return {
        "score": round(final, 4),
        "signals": {k: round(v, 4) for k, v in signals.items()},
        "confidence": sim_score.confidence(final, signals),
        "a": {"instance_id": ia, "addr": feat_a.get("addr"), "name": feat_a.get("name", "")},
        "b": {"instance_id": ib, "addr": feat_b.get("addr"), "name": feat_b.get("name", "")},
    }


# ---------------------------------------------------------------------------
# Dispatch + schemas (consumed by server.py)
# ---------------------------------------------------------------------------

def dispatch(name: str, arguments: dict) -> dict:
    """Route a similarity tool call by name; never raises."""
    fn = {
        "index_functions": index_functions,
        "index_status": index_status,
        "similar_functions": similar_functions,
        "compare_functions": compare_functions,
    }.get(name)
    if fn is None:
        return {"error": f"Unknown similarity tool '{name}'"}
    try:
        return fn(arguments)
    except Exception as exc:  # noqa: BLE001 - surface as structured error
        return {"error": f"{type(exc).__name__}: {exc}"}


def _obj_schema(props: dict, required: list[str]) -> dict:
    return {"type": "object", "properties": props, "required": required}


SIMILARITY_TOOL_SCHEMAS = [
    {
        "name": "index_functions",
        "description": "Build or refresh the per-binary function-similarity index for an instance "
                       "(background, content-hash keyed). Required before similar_functions.",
        "inputSchema": _obj_schema({
            "instance_id": {"type": "string", "description": "Target IDA instance"},
            "rebuild": {"type": "boolean", "description": "Force rebuild (default false)"},
            "background": {"type": "boolean", "description": "Build in background (default true)"},
        }, []),
        "outputSchema": _obj_schema({
            "index_id": {"type": "string"}, "function_count": {"type": "integer"},
            "status": {"type": "string"}, "progress": {"type": "number"},
        }, []),
    },
    {
        "name": "index_status",
        "description": "Report similarity-index readiness and background build progress for an instance.",
        "inputSchema": _obj_schema({
            "instance_id": {"type": "string", "description": "Target IDA instance"},
        }, []),
        "outputSchema": _obj_schema({
            "indexed": {"type": "boolean"}, "index_id": {"type": "string"},
            "function_count": {"type": "integer"}, "progress": {"type": "number"},
        }, []),
    },
    {
        "name": "similar_functions",
        "description": "Rank functions similar to a query function using instruction-shingle MinHash, "
                       "imported-API/string/constant anchors, and CFG structure. Scope: binary | "
                       "instances | all (cross-binary). Returns per-signal score breakdown + confidence.",
        "inputSchema": _obj_schema({
            "instance_id": {"type": "string", "description": "Instance holding the query function"},
            "func": {"type": "string", "description": "Query function address or name"},
            "top_k": {"type": "integer", "description": "Max results (default 20)"},
            "scope": {"type": "string", "description": "binary | instances | all (default binary)"},
            "instances": {"type": "array", "items": {"type": "string"},
                          "description": "Gallery instances when scope=instances"},
            "min_score": {"type": "number", "description": "Minimum score filter (default 0)"},
            "include_self": {"type": "boolean", "description": "Include the query itself (default false)"},
        }, ["func"]),
        "outputSchema": _obj_schema({
            "query": {"type": "object"}, "gallery_size": {"type": "integer"},
            "results": {"type": "array", "items": {"type": "object"}},
        }, []),
    },
    {
        "name": "compare_functions",
        "description": "Pairwise similarity between two functions (optionally across instances) with a "
                       "per-signal breakdown and confidence.",
        "inputSchema": _obj_schema({
            "a": {"type": "object", "description": "{instance_id, func}"},
            "b": {"type": "object", "description": "{instance_id, func}"},
        }, ["a", "b"]),
        "outputSchema": _obj_schema({
            "score": {"type": "number"}, "signals": {"type": "object"},
            "confidence": {"type": "string"},
        }, []),
    },
]
