# Function Similarity — Usage Examples

All examples below are **real tool calls and outputs** against two stripped benchmark binaries opened in IDA:

| Instance | Binary | Notes |
|---|---|---|
| `koeu` | `simbench_v2_clang_stripped.exe` | clang build, **symbols stripped** |
| `83oy` | `simbench_v3_stripped.exe` | a different build, **symbols stripped** |

Both are stripped (functions are `sub_*`), i.e. the realistic reverse-engineering condition. Every match below is **name-independent**.

Each example shows the natural-language prompt you'd give your LLM, the underlying tool call, and the real result.

---

## 0. Build the index (once per binary)

> Index the functions in koeu and 83oy

```jsonc
// index_functions(instance_id="koeu")
{ "index_id": "694060…", "function_count": 114, "status": "ready", "progress": 1 }

// index_status(instance_id="koeu")
{ "indexed": true, "function_count": 114, "stale": false, "progress": 1,
  "path": "C:\\Users\\…\\.ida-mcp\\index\\694060….json" }
```

The index is **content-hash keyed** and persisted under `~/.ida-mcp/index/`, so it is reused across sessions (GUI or headless) until the binary changes.

---

## 1. Find a function's twin in another binary (the headline use case)

> Find the function in 83oy most similar to sub_140002110 in koeu

```jsonc
// similar_functions(instance_id="koeu", func="0x140002110",
//                    scope="instances", instances=["83oy"], top_k=3)
{
  "query": { "instance_id": "koeu", "addr": "0x140002110", "name": "sub_140002110" },
  "gallery_size": 116,
  "results": [
    { "instance_id": "83oy", "addr": "0x140001DB0", "score": 1.0, "confidence": "high",
      "signals": { "ngram": 1, "api": 0, "str": 1, "const": 1, "cfg": 1, "shape": 1 } },
    { "instance_id": "83oy", "addr": "0x140001450", "score": 0.18, "confidence": "low",
      "signals": { "ngram": 0, "api": 0, "str": 0, "const": 0.04, "cfg": 0.004, "shape": 0.58 } },
    { "instance_id": "83oy", "addr": "0x140002BF0", "score": 0.11, "confidence": "low", "signals": { … } }
  ]
}
```

**Reading it:** the #1 hit scores **1.0 / high** with every signal maxed — the same function, recovered across two stripped binaries with no symbols. The large gap to #2 (**0.18 / low**) makes the match unambiguous. `api: 0` just means this function calls no imported APIs, so that one signal doesn't contribute.

---

## 2. A match where imported-API anchors contribute

Functions that call Windows/CRT APIs gain an extra stripping-resistant signal.

> Find the twin of sub_140001FA0 (koeu) in 83oy

```jsonc
// similar_functions(instance_id="koeu", func="0x140001fa0",
//                    scope="instances", instances=["83oy"], top_k=3)
{
  "query": { "addr": "0x140001FA0", "name": "sub_140001FA0" },
  "gallery_size": 116,
  "results": [
    { "instance_id": "83oy", "addr": "0x140001C40", "score": 1.0, "confidence": "high",
      "signals": { "ngram": 1, "api": 1, "str": 1, "const": 1, "cfg": 1, "shape": 1 } },
    { "addr": "0x140002EA0", "score": 0.28, "confidence": "low",
      "signals": { "ngram": 0, "api": 0, "str": 0, "const": 0.14, "cfg": 0.16, "shape": 0.79 } },
    { "name": "___w64_mingwthr_add_key_dtor", "score": 0.25, "confidence": "low", "signals": { … } }
  ]
}
```

Here **`api: 1`** — the twin shares the same imported-API call set (a strong fingerprint that survives stripping). Note the #3 candidate is a CRT function IDA recognized by name (`___w64_mingwthr_add_key_dtor`); it scores only **0.25 / low** and is correctly rejected.

---

## 3. Search within one binary (`scope="binary"`)

Use `scope="binary"` to find clones/siblings inside a single binary.

> Find functions in koeu similar to sub_140002110

```jsonc
// similar_functions(instance_id="koeu", func="0x140002110", scope="binary", top_k=3)
{
  "query": { "addr": "0x140002110", "name": "sub_140002110" },
  "gallery_size": 114,
  "results": [
    { "instance_id": "koeu", "addr": "0x140002840", "score": 0.11, "confidence": "low",
      "signals": { "ngram": 0, "api": 0, "str": 0, "const": 0.07, "cfg": 0.004, "shape": 0.33 } }
  ]
}
```

The best in-binary match is only **0.11 / low** — this function is **unique within its own binary** (no near-duplicate). Yet Example 1 found its exact twin in *another* binary. That contrast is exactly why cross-instance search is valuable.

---

## 4. Compare two specific functions (pairwise)

When you already suspect two functions correspond, `compare_functions` scores them directly.

> Compare sub_140002110 (koeu) with sub_140001DB0 (83oy)

```jsonc
// compare_functions(a={instance_id:"koeu", func:"0x140002110"},
//                    b={instance_id:"83oy", func:"0x140001DB0"})
{ "score": 1.0, "confidence": "high",
  "signals": { "ngram": 1, "api": 0, "str": 1, "const": 1, "cfg": 1, "shape": 1 } }
```

> Now compare it with sub_140001450 (83oy) instead

```jsonc
// compare_functions(a={…"0x140002110"}, b={…"0x140001450"})
{ "score": 0.18, "confidence": "low",
  "signals": { "ngram": 0, "api": 0, "str": 0, "const": 0.05, "cfg": 0.004, "shape": 0.58 } }
```

A confident **1.0 / high** for the true pair versus **0.18 / low** for an unrelated one — a direct "are these the same function?" check.

---

## Reading the output

| Field | Meaning |
|---|---|
| `score` | 0–1 blended similarity (weighted over the signals below) |
| `signals.ngram` | instruction-shingle MinHash (opcode-level similarity) |
| `signals.api` | shared imported-API set, IDF-weighted (`0` if the function calls no imports) |
| `signals.str` / `signals.const` | shared string / constant literals |
| `signals.cfg` | control-flow feature similarity (blocks, edges, complexity, loops) |
| `signals.shape` | CFG out-degree shape |
| `confidence` | `high` (≥0.75 and ≥2 strong signals) · `medium` (≥0.5) · `low` |
| `gallery_size` | number of candidate functions searched (production scale) |

**Practical notes**
- v1 is strongest for same-/similar-toolchain matches (the `1.0` hits above). The `confidence` label and per-signal breakdown surface uncertainty honestly rather than overclaiming.
- If the query binary has no index yet, run `index_functions` first (or the tool returns a hint to do so — it never silently full-scans).
- For harder cross-compiler cases where lexical/structural signals fade, enable the optional neural recall: `pip install ida-multi-mcp[neural]` + `IDA_MCP_SIM_NEURAL=1` (jTrans embeddings, model auto-downloads to `~/.ida-mcp/models/`).
