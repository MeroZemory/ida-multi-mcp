# Neural Embedding Scalability — Design v3 (two rounds of adversarial review)

## Problem

The optional neural-recall extra (`IDA_MCP_SIM_NEURAL=1`, jTrans embeddings)
has two real performance problems on large binaries (observed: a
130,717-function binary):

1. **`JTransBackend.embed_batch()` (`tools/neural_backend.py:111-123`) is not
   actually batched** despite its name — it loops per-function, doing one
   tokenizer call + one `model()` forward pass each. `_embed_incremental`
   (`tools/similarity.py:67-120`) already chunks work into `EMBED_BATCH`
   (default 64) groups before calling it, so the batching machinery exists
   one level up but is thrown away inside `embed_batch` itself.
2. **Device selection only checks CUDA** (`tools/neural_backend.py:95`:
   `dev = "cuda" if torch.cuda.is_available() else "cpu"`), so Apple Silicon
   Macs never use MPS (Metal) acceleration and fall back to CPU-only
   inference unconditionally — the concrete complaint that started this
   investigation.

## v1 → v2: what changed after adversarial review

v1 additionally proposed restricting embedding to "anchor-less" functions by
default (skip embedding any function that has at least one import/string/
constant anchor), on the premise that neural recall's whole purpose is
rescuing anchor-less functions per
`docs/plans/function-similarity/04-neural-semantic-track.md` §1. Three
independent reviewers found this premise doesn't survive contact with the
actual scoring code:

1. **CRITICAL — real recall regressions, not just missed optimization.**
   Neural recall in `similar_functions()` does cosine top-K over the
   **gallery** side's vectors (`gvectors = idx.get("vectors", {})`,
   `similarity.py:552-557`) — it is symmetric, not query-centric. The design
   only guaranteed the *query* gets a vector; it assumed an anchor-less
   query's true cross-compiler twin would *also* be anchor-less. That's not
   guaranteed: two twins can each have anchors that simply don't overlap
   (inlined vs. imported `memcpy`, differently-pooled strings), or only one
   side has any anchor at all. `anchor_candidates()`'s rare-anchor
   requirement (`sim_score.py:397-410`) already fails to surface such pairs
   lexically; restricting gallery-side embedding to anchor-less functions
   means neural recall *also* fails to surface them, because the twin never
   gets a vector. **Today's embed-everything behavior catches cases this
   design would have silently stopped catching** — a regression dressed up
   as an optimization.
2. **HIGH — ranking silently shifts for candidates that keep their vector.**
   The neural blend (`final = (1-λ)·grouped + λ·ncos`, `λ=0.7` default) only
   applies `if gvectors.get(addr)`. Anchor-rich candidates that lose their
   vector under the restricted scope silently revert to 100% grouped
   scoring, changing rankings for pairs that have nothing to do with the
   "anchor-less rescue" goal. The v1 design's "doesn't change how scoring
   works" non-goal claim was false.
3. **HIGH — the proposed "fix embedding completeness tracking" sub-change
   compared vector *counts* against a target count, not set membership.**
   `index_store.read_vectors()` returns every address ever appended to the
   sidecar, including ones outside whatever the *current* scope setting
   targets (e.g., left over from a prior `scope=all` run, or a cancelled
   job). Comparing `len(done) >= len(target)` instead of `target_set ⊆
   done_set` can report "embedding complete" while the specific functions
   that matter were never embedded — silently, with no error, exactly the
   shape of bug that's hardest to notice in production.
4. **Independent finding — even the selection predicate was wrong on its
   own terms.** `anchor_candidates()` only blocks on *rare* anchors
   (`df <= rare_df`); common anchors don't help candidate-gen find a
   function. The v1 predicate ("has zero anchors of any kind") would still
   exclude a function whose only anchors are common ones — exactly a
   function that's just as invisible to lexical/anchor matching as a truly
   anchor-less one, and exactly the kind neural recall exists to rescue.
   Getting this right would require wiring the `df`/`rare_df` machinery
   into the embedding-selection path — real additional complexity, not the
   one-line predicate v1 proposed.
5. **Independent argument — the performance case for restricting scope at
   all is weak once batching + MPS ship.** 130,717 functions /
   `EMBED_BATCH=64` ≈ 2,043 forward passes. A padded BERT-base batch of 64
   short sequences on GPU or MPS runs in roughly 100–400ms once tokenizer/
   kernel-launch-per-call overhead is gone — call it 5–15 minutes total,
   "minutes not days" for any CUDA or Apple Silicon machine. The scenario
   that's still slow is CPU-only hardware (no CUDA, no MPS) — a hardware-
   tier limitation, not evidence the *embedding target* was wrong.

**v2 drops the anchor-gated scope entirely.** Ship the two changes that are
unambiguously correct and address the concrete complaint (Apple Silicon /
GPU users watching a CPU-only, unbatched embedding phase crawl). If
CPU-only-hardware throughput still proves insufficient in practice after
these ship, a properly `df`/`rare_df`-gated scope-narrowing (fixing finding
4) is a well-scoped follow-up — not bundled into this change, and not
shipped with the correctness gaps findings 1–3 identified.

## v2 → v3: round-2 review findings and fixes

Two independent reviewers verified v2 against the real code. Both confirmed
fixes 1–2 (batching, MPS) are sound as specified. One found two real gaps:

1. **The §3 guard's placement at the `_run()` call site was
   under-specified and, applied literally, breaks status reporting for the
   zero-valid-functions edge case.** The real block at `similarity.py:397-404`
   (not `:397-401` — corrected) is `if _neural_enabled():` wrapping FOUR
   statements: pre-call bookkeeping (`embed_status="embedding",
   embed_total=len(valid_addrs), embed_done=0`), the `_embed_incremental`
   call, and post-call bookkeeping (`embed_status="done"`). Wrapping the
   whole header in `and valid_addrs` (as v2's snippet ambiguously suggested)
   skips the bookkeeping too, leaving `_jobs[iid]` without `embed_status`
   for a zero-valid-function build — `index_status()` then falls into its
   `"pending"` branch permanently (`fc=0` makes `fc and nvec>=fc` false)
   instead of correctly reporting `"done"` (nothing to embed). **Fix**: the
   `and valid_addrs` guard applies ONLY to the `_embed_incremental(...)`
   call itself, not the surrounding bookkeeping — see §3 below for the
   corrected snippet.
2. **The proposed `embed_batch([])` test is vacuous** — the empty-list guard
   returns before `import torch`/`_load()`, so the test would pass even
   under a badly broken batching implementation, and no *other* test
   (existing or proposed) exercises the real tokenizer/padding/CLS-indexing
   code path at all (`test_similarity_neural.py` replaces
   `neural_backend.get_backend()` wholesale with a mock, never touching
   `JTransBackend.embed_batch`'s real body). **Fix**: add a test that
   monkeypatches `neural_backend._load` (not `get_backend`) with a fake
   `(tok, model, dev)` triple whose fake `model()` call encodes each row's
   identity into its output, then calls the REAL `embed_batch()` with
   several differently-sized token lists and asserts output order/count
   matches input — catches a transposed or misindexed batch without
   needing `transformers`/real weights (still gated on `torch` being
   importable, since it constructs real tensors). Also noted: every
   existing test in this file uses `index_functions(...,
   background=False)`, so a regression test for finding 1 (which is
   specifically in the `_run()` **background** path) must explicitly use
   `background=True`, or it won't exercise the code it's meant to guard.

## Approach (v3)

### 1. Real batching in `JTransBackend.embed_batch`

Replace the per-item loop with a single padded-batch tokenizer call + one
forward pass per `embed_batch` invocation (still externally chunked to
`EMBED_BATCH` items by `_embed_incremental`, unchanged). Guards against an
empty input list, which the old per-item loop tolerated for free
(`for toks in []` is a no-op) but a batched `tok([], ...)` call is not
guaranteed to (tokenizer padding logic computing `max()` over an empty
batch is a known crash shape in some versions) — not reachable today (both
current callers already guard against calling with `[]`), but the batched
rewrite must not introduce a new crash mode a future caller could hit:
```python
def embed_batch(self, token_lists: list[list[str]]) -> list[list[float]]:
    """token_lists -> unit-normalized [CLS] vectors (list[list[float]])."""
    if not token_lists:
        return []
    import torch
    tok, model, dev = _load(self.model_id, self.tokenizer_id)
    texts = [" ".join(toks) if toks else "" for toks in token_lists]
    with torch.no_grad():
        enc = tok(texts, return_tensors="pt", truncation=True,
                   max_length=self.max_len, padding=True)
        enc = {k: v.to(dev) for k, v in enc.items()}
        cls = model(**enc).last_hidden_state[:, 0]          # [CLS] per row
        vecs = torch.nn.functional.normalize(cls, dim=1).cpu().tolist()
    return vecs
```
Verified safe against the actual bundled tokenizer config
(`tools/jtrans_tokenizer/`): declares `tokenizer_class: BertTokenizer` with
no `padding_side` override, so HF's default `padding_side="right"` holds —
`[CLS]` stays at index 0 for every row regardless of padding. `tok(...,
padding=True)` returns `attention_mask`, and `model(**enc)` consumes it, so
padded positions are masked out of the CLS token's contextualization — no
silent quality regression for short sequences batched with longer ones.
`unk_rate` (diagnostic-only, not in the hot path) is left as-is.

### 2. MPS device support

Extract device selection into its own function so it's unit-testable
without instantiating a model:
```python
def _select_device() -> str:
    import torch
    if torch.cuda.is_available():
        return "cuda"
    if torch.backends.mps.is_available():
        return "mps"
    return "cpu"
```
`_load()` calls `dev = _select_device()` instead of the inline ternary.
`torch.backends.mps` has existed since torch 1.12; `pyproject.toml` already
pins `torch>=2.0` for the `[neural]` extra, so no version guard needed.

### 3. Defensive empty-input guard in `_embed_incremental` (independent small fix)

Not scope-related — this closes a real gap reviewer feedback found
independent of the (now-dropped) scope change: `_embed_incremental` with an
empty `valid_addrs` today still unconditionally calls
`neural_backend.get_backend()` (`similarity.py:81`), which can trigger
`ensure_model()` — a ~1.2GB on-demand download — and pages through the
*entire* binary's `func_tokens` via the network/IDA round-trip, just to
filter everything out, for a binary with zero valid functions to embed
(a real, if rare, degenerate case — e.g. an index build where every function
was skipped as an extraction error). Guard at the call sites instead of
inside `_embed_incremental` itself (keeps the function's contract simple).
`valid_addrs` is unchanged from today (still every valid function; no scope
filtering in v3).

**Sync branch** (`similarity.py:347-350`) — the whole `if _neural_enabled():`
body is just the call + a status read, so it's safe to guard as a unit:
```python
if _neural_enabled() and valid_addrs:
    _embed_incremental(iid, key, rp, valid_addrs)
    neural = bool(index_store.read_vectors(key, rp))
```

**`_run()`'s phase-2 block** (`similarity.py:397-404`) — this `if
_neural_enabled():` body does bookkeeping *and* the call; per round-2
review, the `valid_addrs` guard must apply ONLY to the call, not the
bookkeeping either side of it, so `embed_status` still correctly resolves
to `"done"` (with `embed_total=0`) instead of getting stuck `"pending"` for
a zero-valid-function build:
```python
if _neural_enabled():
    with _jobs_lock:
        _jobs[iid].update(embed_status="embedding",
                          embed_total=len(valid_addrs), embed_done=0)
    if valid_addrs:
        _embed_incremental(iid, key, rp, valid_addrs)
    with _jobs_lock:
        if not _jobs[iid].get("cancel"):
            _jobs[iid].update(embed_status="done")
```
(Only the `if valid_addrs:` line is new; the rest of this block is existing
code shown for placement context.)

## Non-goals

- Anchor-gated / scope-restricted embedding — dropped, see §v1→v2. A
  future, correctly `df`/`rare_df`-gated version is a separate follow-up if
  CPU-only throughput proves insufficient after batching+MPS ship, not part
  of this change.
- Any change to `sim_score.py`'s scoring/blending logic, the
  `IDA_MCP_SIM_NEURAL_LAMBDA`/`IDA_MCP_SIM_NEURAL_K` tuning knobs, or the
  vectors-sidecar format/resumability (`index_store.py`'s
  `append_vectors`/`read_vectors`) — all unchanged, all already working as
  designed per `04-neural-semantic-track.md` §9b.
- A "tiny synthetic `BertConfig`" real-model test tier — considered and
  dropped; no test in this repo instantiates a real `transformers` model
  (grep-verified), and this codebase's established pattern is testing
  entirely at a mock-backend boundary (`tests/test_similarity_neural.py`'s
  `_MockBackend`). Introducing real-model test infrastructure for this one
  change would be new machinery inconsistent with that pattern. The batched
  rewrite is instead smoke-tested manually against the real jTrans
  checkpoint once during review (documented in the PR description), and
  covered automatically only at the `_select_device()` pure-function
  boundary (no model needed).

## Testing

- `tests/test_neural_backend.py` (new — pure-Python, no torch required to
  collect the file; individual tests skip if torch isn't importable):
  - `_select_device()`: monkeypatch `torch.cuda.is_available`/
    `torch.backends.mps.is_available` through all three priority
    combinations (cuda>mps>cpu), assert the right string returned.
    `@unittest.skipUnless(neural_backend.is_available(), "torch/transformers not installed")`.
  - `embed_batch([])` returns `[]` without ever reaching the `import torch`
    line (the `if not token_lists: return []` guard runs first). Gated with
    the same `skipUnless` as the other tests for consistency, even though
    `JTransBackend(...)` construction itself requires nothing torch-specific
    — keeps this test file's skip behavior uniform rather than having one
    test collect in environments where its siblings don't.
  - **Batching-equivalence (round-2 fix — the previous plan's only
    non-empty-input coverage was vacuous)**: monkeypatch `neural_backend._load`
    to return a fake `(tok, model, dev)` triple — `tok` a callable that
    records the input list and returns a minimal dict of real small tensors
    (`input_ids`, `attention_mask`) shaped from token-list lengths; `model`
    a callable returning an object whose `.last_hidden_state` is a real
    tensor where row `i`'s `[CLS]` position encodes `i` (e.g. a one-hot or
    index-scaled vector) so misordering/mis-indexing is detectable. Call the
    REAL (unmocked) `embed_batch()` with 3 token lists of different lengths
    (including one empty list mixed into a non-empty batch) and assert the
    output count matches input count and each output vector decodes back to
    its own row's index — catches a transposed batch dimension or wrong
    `[CLS]` index without needing `transformers`/real weights (still
    requires `torch` to construct the fake tensors, so still gated).
- `tests/test_similarity_neural.py` (extended, existing `_MockBackend`/mock
  router — no torch needed, unchanged from today for anything not listed):
  - New: `index_functions()` on a corpus where `_valid_records` returns an
    empty list (all records are `{"addr","error"}` stubs), called with
    `background=False` (the sync branch), does not call `get_backend()`
    (assert via monkeypatching `neural_backend.get_backend` to raise if
    called) — regression test for §3's sync-branch guard.
  - **New (round-2 fix — every existing test in this file uses
    `background=False`, which would never exercise the bug that motivated
    this fix)**: `index_functions(..., background=True)` on the same
    zero-valid-functions corpus, polled via `index_status()` **specifically
    until `embed_status == "done"`** (bounded timeout, e.g. ~5s) — NOT until
    `job_status != "building"`, which is a distinct field the background
    thread sets *before* reaching the phase-2 embed bookkeeping
    (`similarity.py:387`/`:394` set `status="ready"` strictly before
    `:397-404`'s `embed_status` bookkeeping runs); polling the wrong field
    would read `embed_status` while it's still unset and flake on `None`
    (round-3 review finding). Once the poll condition is met, additionally
    assert `embed_total == 0` — regression test for §3's `_run()`-branch
    guard placement specifically (the round-2 bug: guarding the bookkeeping
    instead of only the call).
  - No existing test changes needed — `NEURAL_SCOPE`/selective embedding
    was dropped, so `test_index_status_reports_full_embed_progress` and
    `test_partial_vectors_usable_then_resume`'s `embed_total == 3`
    assertions stay valid unchanged.
- Full existing suite must stay green — `similar_functions()`'s scoring
  path, `_embedding_incomplete()`, and `index_status()` are all untouched
  in v3.
- **Pre-existing, out-of-scope note**: `index_status()`'s embed-status
  fallback formula (`"done" if fc and nvec>=fc else "partial" if nvec else
  "pending"`, `similarity.py:447-448`) would report `"pending"` forever for
  a zero-valid-functions build queried *without* ever having gone through
  `_start_background`'s bookkeeping (e.g. only ever called with
  `background=False`, which never writes `_jobs[iid]["embed_status"]` at
  all). This is unrelated to and unchanged by this design — `_jobs` state
  for the sync branch has never been populated, before or after this
  change — noted for completeness, not fixed here.
