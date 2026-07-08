# Neural Embedding Scalability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **Note for this run**: tasks are executed sequentially in the main session (not fresh subagents per task) — Task 3 depends on Task 2's file existing and mirrors its patterns; sequential execution matches how this codebase's sibling feature (partial-index serving) was implemented in this same session.

**Goal:** Fix the two real performance problems in the optional neural (jTrans) embedding backend — a `embed_batch()` that isn't actually batched, and CUDA-only device selection that leaves Apple Silicon on CPU — without changing what gets embedded or how results are scored.

**Architecture:** Rewrite `JTransBackend.embed_batch()` to do one padded-tensor tokenizer call + one forward pass per invocation instead of a per-item Python loop; extract device selection into a standalone, unit-testable `_select_device()` function that adds an MPS branch; add a defensive empty-input guard around the two `_embed_incremental()` call sites in `similarity.py` (placed precisely so it doesn't break status bookkeeping for a zero-valid-function build).

**Tech Stack:** Python 3.11+. `torch`/`transformers` are an optional `[neural]` extra — code in `neural_backend.py` imports them lazily inside functions, never at module level. Tests: `unittest`, matching `tests/test_similarity_neural.py`'s existing style; new tests requiring real tensor construction are gated `@unittest.skipUnless(neural_backend.is_available(), ...)`.

## Global Constraints

- `torch`/`transformers` stay optional — no module-level `import torch` anywhere in `src/ida_multi_mcp/`; every existing and new use is inside a function body — spec §Approach, `neural_backend.py`'s existing pattern.
- No change to what gets embedded (still every valid function — the "anchor-gated selective embedding" idea was evaluated and dropped; see spec §v1→v2) and no change to `sim_score.py`'s scoring/blending — spec §Non-goals.
- No new persisted formats or schema changes to the vectors sidecar (`index_store.py`'s `append_vectors`/`read_vectors`) — untouched, spec §Non-goals.
- No "tiny real `BertConfig`" model-instantiation test tier — this repo's existing tests never instantiate a real `transformers` model; new tests either need zero torch (pure logic) or use a hand-mocked `_load()` returning fake-but-real small tensors, never a real HF model load — spec §Non-goals, §Testing.
- Full existing test suite (`pytest tests/`) must stay green throughout — spec §Testing.
- Design spec of record: `docs/superpowers/specs/2026-07-08-neural-embedding-scalability-design.md` (§Approach (v3) is authoritative for exact code shape; this plan mirrors it 1:1).

---

## File Structure

- **Modify**: `src/ida_multi_mcp/tools/neural_backend.py` — `_load()`'s device selection extracted to `_select_device()`; `JTransBackend.embed_batch()` rewritten for real batching.
- **Modify**: `src/ida_multi_mcp/tools/similarity.py` — two call sites (`index_functions()`'s sync branch, `_start_background`'s `_run()`) gain an empty-`valid_addrs` guard around the `_embed_incremental()` call only.
- **Create**: `tests/test_neural_backend.py` — new file, `_select_device()` unit tests + batching-equivalence test (both torch-gated).
- **Modify**: `tests/test_similarity_neural.py` — two new regression tests (sync-branch skip-on-empty, background-branch bookkeeping-stays-correct-on-empty).

---

## Task 1: Extract `_select_device()` and add MPS support

**Files:**
- Modify: `src/ida_multi_mcp/tools/neural_backend.py:78-97` (`_load`)
- Create: `tests/test_neural_backend.py`

**Interfaces:**
- Produces: `_select_device() -> str` — module-level function in `neural_backend.py`, returns `"cuda"`, `"mps"`, or `"cpu"` in that priority order, based on `torch.cuda.is_available()` / `torch.backends.mps.is_available()`. `_load()` calls it instead of its inline ternary; no change to `_load()`'s signature or its `@functools.lru_cache` decorator.
- Consumes: nothing from other tasks (first task).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_neural_backend.py`:
```python
"""Unit tests for tools/neural_backend.py's device selection and batched
embedding. torch/transformers are an optional [neural] extra; every test
here is gated on their availability and skips cleanly when absent.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ida_multi_mcp.tools import neural_backend  # noqa: E402

_SKIP_REASON = "torch/transformers not installed (optional [neural] extra)"


@unittest.skipUnless(neural_backend.is_available(), _SKIP_REASON)
class SelectDeviceTest(unittest.TestCase):
    def setUp(self):
        import torch
        self._orig_cuda = torch.cuda.is_available
        self._orig_mps = torch.backends.mps.is_available

    def tearDown(self):
        import torch
        torch.cuda.is_available = self._orig_cuda
        torch.backends.mps.is_available = self._orig_mps

    def test_prefers_cuda_when_available(self):
        import torch
        torch.cuda.is_available = lambda: True
        torch.backends.mps.is_available = lambda: True
        self.assertEqual(neural_backend._select_device(), "cuda")

    def test_prefers_mps_over_cpu_when_cuda_unavailable(self):
        import torch
        torch.cuda.is_available = lambda: False
        torch.backends.mps.is_available = lambda: True
        self.assertEqual(neural_backend._select_device(), "mps")

    def test_falls_back_to_cpu(self):
        import torch
        torch.cuda.is_available = lambda: False
        torch.backends.mps.is_available = lambda: False
        self.assertEqual(neural_backend._select_device(), "cpu")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/merozemory/projects/MeroZemory/ida-multi-mcp
python3 -m pytest tests/test_neural_backend.py -v
```
Expected: if `torch`/`transformers` are NOT installed in your environment, all three tests report `SKIPPED` (not a failure — this confirms the skip gate itself works; proceed to Step 3 regardless, since the code must be correct whether or not this particular environment can execute it). If they ARE installed, all three FAIL with `AttributeError: module 'ida_multi_mcp.tools.neural_backend' has no attribute '_select_device'`.

- [ ] **Step 3: Implement**

In `src/ida_multi_mcp/tools/neural_backend.py`, add `_select_device` immediately before `_load` (before line 78's `@functools.lru_cache(maxsize=2)`):
```python
def _select_device() -> str:
    import torch
    if torch.cuda.is_available():
        return "cuda"
    if torch.backends.mps.is_available():
        return "mps"
    return "cpu"


@functools.lru_cache(maxsize=2)
def _load(model_id: str, tokenizer_id: str):
    import torch
    from transformers import AutoTokenizer, BertModel

    class BinBertModel(BertModel):
        """jTrans's model: BERT with position embeddings tied to word embeddings,
        so a JUMP_ADDR_k token resonates with the target instruction's position
        (its jump-aware mechanism). Exactly jTrans eval_save.py:105."""

        def __init__(self, config, add_pooling_layer=False):
            super().__init__(config, add_pooling_layer=add_pooling_layer)
            self.embeddings.position_embeddings = self.embeddings.word_embeddings

    tok = AutoTokenizer.from_pretrained(tokenizer_id)
    model = BinBertModel.from_pretrained(
        model_id, add_pooling_layer=False, ignore_mismatched_sizes=True)
    dev = _select_device()
    model.to(dev).eval()
    return tok, model, dev
```
This changes exactly one line inside `_load` (`dev = "cuda" if torch.cuda.is_available() else "cpu"` → `dev = _select_device()`) and adds the new function above it; everything else in `_load` is unchanged.

- [ ] **Step 4: Run test to verify it passes**

```bash
python3 -m pytest tests/test_neural_backend.py -v
```
Expected: PASS (or SKIPPED, consistently with Step 2's result — if your environment doesn't have `torch` installed, install it temporarily to verify locally: `pip install torch transformers`, rerun, then it's fine to leave it uninstalled again — the test suite must pass either way).

- [ ] **Step 5: Commit**

```bash
git add src/ida_multi_mcp/tools/neural_backend.py tests/test_neural_backend.py
git commit -m "feat: add MPS device support to the neural embedding backend

Extracts device selection out of _load() into a standalone _select_device()
function (cuda > mps > cpu priority) so Apple Silicon Macs use Metal
acceleration instead of falling back to CPU-only inference. Also makes
device selection unit-testable without instantiating a model."
```

---

## Task 2: Real batched inference in `JTransBackend.embed_batch`

**Files:**
- Modify: `src/ida_multi_mcp/tools/neural_backend.py:111-123` (`JTransBackend.embed_batch`)
- Test: `tests/test_neural_backend.py` (extend)

**Interfaces:**
- Produces: `JTransBackend.embed_batch(token_lists: list[list[str]]) -> list[list[float]]` — same signature and return shape as today (unit-normalized `[CLS]` vectors, one per input, in input order), but implemented as one batched tokenizer call + one forward pass instead of a per-item loop. Returns `[]` immediately for an empty `token_lists`, without importing `torch`.
- Consumes: `_select_device()` (Task 1, indirectly via `_load()` — `embed_batch` itself doesn't call it directly, `_load()` does).

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_neural_backend.py`, after `SelectDeviceTest`:
```python
class EmbedBatchTest(unittest.TestCase):
    def test_empty_list_returns_empty_without_torch(self):
        # Must not require torch/transformers to be installed: verifies the
        # guard runs before `import torch`.
        backend = neural_backend.JTransBackend("unused-model-id", "unused-tok-id")
        self.assertEqual(backend.embed_batch([]), [])


@unittest.skipUnless(neural_backend.is_available(), _SKIP_REASON)
class EmbedBatchBatchingTest(unittest.TestCase):
    """Verifies embed_batch's real tensor batching logic (padding, attention
    mask, [CLS] indexing, output ordering) via a hand-mocked _load() --
    fake-but-real small torch tensors, no real transformers model needed.
    """

    def setUp(self):
        import torch

        class _FakeTokenizer:
            def __call__(self, texts, return_tensors, truncation, max_length, padding):
                # One token per character (deterministic, easy to reason about);
                # pad to the longest text in the batch (mirrors a real tokenizer).
                lengths = [max(len(t), 1) for t in texts]
                width = max(lengths)
                input_ids = torch.zeros((len(texts), width), dtype=torch.long)
                attention_mask = torch.zeros((len(texts), width), dtype=torch.long)
                for i, n in enumerate(lengths):
                    attention_mask[i, :n] = 1
                return {"input_ids": input_ids, "attention_mask": attention_mask}

        class _FakeOutput:
            def __init__(self, last_hidden_state):
                self.last_hidden_state = last_hidden_state

        class _FakeModel:
            def __call__(self, input_ids, attention_mask):
                batch, width = input_ids.shape
                # 4-dim hidden state; row i's [CLS] (position 0) is a one-hot
                # encoding of i, so a transposed/misindexed batch is detectable
                # by decoding argmax back to the row index.
                hidden = torch.zeros((batch, width, 4))
                for i in range(batch):
                    hidden[i, 0, i % 4] = 1.0
                return _FakeOutput(hidden)

        self._tok, self._model, self._dev = _FakeTokenizer(), _FakeModel(), "cpu"
        self._orig_load = neural_backend._load
        neural_backend._load = lambda model_id, tokenizer_id: (
            self._tok, self._model, self._dev)

    def tearDown(self):
        neural_backend._load = self._orig_load

    def test_batched_output_preserves_order_and_count(self):
        backend = neural_backend.JTransBackend("fake-model", "fake-tok")
        token_lists = [["a", "b", "c"], ["d"], ["e", "f"]]
        vecs = backend.embed_batch(token_lists)
        self.assertEqual(len(vecs), 3)
        for i, v in enumerate(vecs):
            self.assertEqual(len(v), 4)
            decoded = max(range(4), key=lambda j: v[j])
            self.assertEqual(decoded, i % 4,
                              f"row {i}'s decoded index doesn't match -- "
                              "batch dimension may be transposed or misindexed")

    def test_empty_token_list_entry_within_a_nonempty_batch(self):
        backend = neural_backend.JTransBackend("fake-model", "fake-tok")
        vecs = backend.embed_batch([["a", "b"], [], ["c"]])
        self.assertEqual(len(vecs), 3)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python3 -m pytest tests/test_neural_backend.py -v
```
Expected: `test_empty_list_returns_empty_without_torch` PASSES already (the empty-input behavior happens to already hold for the OLD per-item-loop implementation too — `for toks in []` is a no-op, returning `[]` — this test is here to lock in that behavior across the rewrite, not to prove a bug). `EmbedBatchBatchingTest`'s two tests FAIL (or SKIP if torch isn't installed) — the fake `_load` returns a 4-dim hidden state and the OLD implementation does `last_hidden_state[0, 0]` (indexing into the wrong axis for a batched multi-row tensor) rather than `[:, 0]`, so decoded values won't line up correctly, or the old per-item loop calls `model(**enc)` per single item so the fake `_FakeModel.__call__`'s multi-row batch logic wouldn't even receive a real batch — confirms the equivalence test actually exercises different code than today's implementation.

- [ ] **Step 3: Implement**

In `src/ida_multi_mcp/tools/neural_backend.py`, replace `embed_batch` (current lines 111-123):
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
(`unk_rate`, immediately below `embed_batch` in the same class, is unchanged — it's diagnostic-only, not in the hot path.)

- [ ] **Step 4: Run tests to verify they pass**

```bash
python3 -m pytest tests/test_neural_backend.py -v
```
Expected: all PASS (or SKIP consistently, if torch isn't installed in this environment — the empty-list test still PASSES either way since it doesn't need torch).

- [ ] **Step 5: Commit**

```bash
git add src/ida_multi_mcp/tools/neural_backend.py tests/test_neural_backend.py
git commit -m "feat: make JTransBackend.embed_batch actually batched

Was a per-item Python loop (one tokenizer call + one forward pass per
function) despite the name. Now does one padded-tensor tokenizer call +
one forward pass per invocation, with attention-mask-aware [CLS]
extraction per row. _embed_incremental already chunks work into
EMBED_BATCH-sized groups before calling this -- that batching survives
unchanged; this fixes what happens to each chunk once it gets here."
```

---

## Task 3: Defensive empty-input guard around `_embed_incremental`

**Files:**
- Modify: `src/ida_multi_mcp/tools/similarity.py:337-353` (`index_functions()`'s sync branch), `:396-404` (`_start_background`'s `_run()`, phase-2 block)
- Test: `tests/test_similarity_neural.py` (extend)

**Interfaces:**
- Consumes: nothing from Tasks 1-2 directly (this task only touches `similarity.py`, not `neural_backend.py`) — independent of them, but grouped in this plan because it's part of the same design spec.
- Produces: no new functions. Behavior change only: `_embed_incremental()` is no longer called at all when `valid_addrs` is empty, at either of its two call sites. At the `_run()` site specifically, the surrounding `embed_status`/`embed_total`/`embed_done` bookkeeping still runs unconditionally (this is the precise placement round-2 design review required — guarding the whole block, not just the call, was found to leave `embed_status` stuck at a stale/unset value for a zero-valid-function build).

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_similarity_neural.py`, after the existing `NeuralRecallTest` class's last test method (`test_partial_vectors_usable_then_resume`) and before `class NeuralBackendPathsTest`:
```python
    def test_sync_branch_skips_embedding_for_zero_valid_functions(self):
        # Reuse this test class's corpus/mocks but swap in a router that
        # reports zero valid functions (every func_features record is an
        # error stub) -- mirrors the real shape func_features returns for
        # an unextractable function (see test_similarity.py's _ErrRouter).
        class _EmptyValidRouter:
            def route_request(self, method, params):
                import json
                name = params.get("name")
                if name == "binary_fingerprint":
                    payload = {"sha256": "sha-empty", "md5": None,
                              "function_count": 1, "arch": "x86_64"}
                elif name == "func_features":
                    payload = {"functions": [{"addr": "0x1", "error": "no func"}],
                              "total": 1, "cursor": {"done": True}}
                else:
                    return {"error": f"unknown tool {name}"}
                return {"content": [{"type": "text", "text": json.dumps(payload)}],
                        "structuredContent": payload}

        similarity.set_router(_EmptyValidRouter())
        called = {"n": 0}

        def _raise_if_called(*a, **k):
            called["n"] += 1
            raise AssertionError("get_backend() must not be called for zero valid functions")

        orig_get_backend = neural_backend.get_backend
        neural_backend.get_backend = _raise_if_called
        try:
            res = similarity.index_functions({"instance_id": "nn", "background": False})
        finally:
            neural_backend.get_backend = orig_get_backend

        self.assertEqual(res["function_count"], 0)
        self.assertEqual(called["n"], 0)

    def test_background_branch_reports_done_for_zero_valid_functions(self):
        import time

        class _EmptyValidRouter:
            def route_request(self, method, params):
                import json
                name = params.get("name")
                if name == "binary_fingerprint":
                    payload = {"sha256": "sha-empty-bg", "md5": None,
                              "function_count": 1, "arch": "x86_64"}
                elif name == "func_features":
                    payload = {"functions": [{"addr": "0x1", "error": "no func"}],
                              "total": 1, "cursor": {"done": True}}
                else:
                    return {"error": f"unknown tool {name}"}
                return {"content": [{"type": "text", "text": json.dumps(payload)}],
                        "structuredContent": payload}

        similarity.set_router(_EmptyValidRouter())
        similarity.index_functions({"instance_id": "nn", "background": True})

        deadline = time.time() + 5.0
        st = {}
        while time.time() < deadline:
            st = similarity.index_status({"instance_id": "nn"})
            if st.get("embed_status") == "done":
                break
            time.sleep(0.01)
        else:
            self.fail("embed_status never reached 'done' within 5s "
                      f"(last status: {st})")

        self.assertEqual(st["embed_total"], 0)
```

Add `from ida_multi_mcp.tools import neural_backend` is already imported at the top of this file (line 19) — no new import needed for these two tests.

- [ ] **Step 2: Run tests to verify they fail**

```bash
python3 -m pytest tests/test_similarity_neural.py -v -k "zero_valid"
```
Expected: `test_sync_branch_skips_embedding_for_zero_valid_functions` FAILS with the `AssertionError("get_backend() must not be called...")` raised from inside `_raise_if_called` (today's code calls `_embed_incremental` unconditionally, which calls `get_backend()` even for zero valid functions). `test_background_branch_reports_done_for_zero_valid_functions` currently PASSES already (bookkeeping already runs unconditionally today, before this task's change) — that's expected and fine: it's here as a **regression guard** for Task 3's own upcoming edit, to prove the fix doesn't reintroduce the round-2-identified stuck-`"pending"` bug. Keep it in the suite; it should stay green through Step 4.

- [ ] **Step 3: Implement**

In `src/ida_multi_mcp/tools/similarity.py`, in `index_functions()`'s sync branch, change:
```python
    neural = False
    if _neural_enabled():
        _embed_incremental(iid, key, rp, valid_addrs)
        neural = bool(index_store.read_vectors(key, rp))
```
to:
```python
    neural = False
    if _neural_enabled() and valid_addrs:
        _embed_incremental(iid, key, rp, valid_addrs)
        neural = bool(index_store.read_vectors(key, rp))
```

In `_start_background`'s `_run()`, change:
```python
            # Phase 2: neural vectors accrue in the background (non-blocking).
            if _neural_enabled():
                with _jobs_lock:
                    _jobs[iid].update(embed_status="embedding",
                                      embed_total=len(valid_addrs), embed_done=0)
                _embed_incremental(iid, key, rp, valid_addrs)
                with _jobs_lock:
                    if not _jobs[iid].get("cancel"):
                        _jobs[iid].update(embed_status="done")
```
to (only the added `if valid_addrs:` line and its indentation of the existing call — the bookkeeping lines before and after are unchanged and stay unconditional):
```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python3 -m pytest tests/test_similarity_neural.py -v
python3 -m pytest tests/ -v
```
Expected: both new tests PASS; every pre-existing test in `test_similarity_neural.py` (and the whole suite) still PASSES — `test_index_stores_vectors`, `test_neural_recall_surfaces_anchorless_twin`, `test_disabled_neural_misses_twin`, `test_index_status_reports_full_embed_progress`, and `test_partial_vectors_usable_then_resume` all use corpora with valid (non-error) functions, so `valid_addrs` is always non-empty for them — the new `and valid_addrs` / `if valid_addrs:` guards are no-ops on those paths.

- [ ] **Step 5: Commit**

```bash
git add src/ida_multi_mcp/tools/similarity.py tests/test_similarity_neural.py
git commit -m "fix: skip neural embedding entirely for zero valid functions

_embed_incremental() unconditionally called neural_backend.get_backend()
(which can trigger a ~1.2GB model download) and paged the whole binary's
func_tokens, even when there was nothing to embed. Guarded at both call
sites. The background-thread call site's guard applies ONLY to the
_embed_incremental() call, not the embed_status/embed_total/embed_done
bookkeeping around it -- guarding the whole block would leave a
zero-valid-function build's embed_status stuck unset instead of
resolving to \"done\"."
```

---

## Task 4: Full regression run

**Files:** none (verification only).

- [ ] **Step 1: Run the complete test suite**

```bash
cd /Users/merozemory/projects/MeroZemory/ida-multi-mcp
python3 -m pytest tests/ -v
```
Expected: every test PASSES or SKIPS cleanly (torch-gated tests skip if `[neural]` isn't installed in this environment) — no FAILs, no ERRORs.

- [ ] **Step 2: If `torch`/`transformers` are available in this environment, additionally smoke-test the real batched path once**

This is a one-time manual check (per the design spec's Non-goals — no permanent real-model test infrastructure), not an automated test:
```bash
python3 -c "
from ida_multi_mcp.tools import neural_backend
if neural_backend.is_available():
    backend = neural_backend.get_backend()
    vecs = backend.embed_batch([['mov.rr', 'add.ri', 'ret.'], ['push.r', 'pop.r']])
    print('embedded', len(vecs), 'vectors, dim', len(vecs[0]) if vecs else 0)
else:
    print('torch/transformers not installed -- skipping manual smoke test')
"
```
Expected: either the skip message, or `embedded 2 vectors, dim 768` (jTrans's embedding dimension) — confirms the real tokenizer/model path works end-to-end with the batched rewrite, not just the mocked test. Note the result in the PR description (downloads the ~1.2GB jTrans checkpoint on first run if not already cached at `~/.ida-mcp/models/`).

- [ ] **Step 3: Commit (only if Step 1 or 2 required a fixup; otherwise this task produces no diff)**

```bash
git add -A
git commit -m "test: fix regression found during full-suite verification"
```
