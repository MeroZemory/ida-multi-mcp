# Performance

[← back to README](../README.md)

## Performance

Benchmarked against a large game client (736K functions, x86-64, IDA 9.3):

| Metric | Value |
|---|---:|
| Total tool latency (28 tools) | **32.0 s** |
| Total response payload | 373 KB |
| Estimated token cost | ~93K tokens |

| Category | Latency | Tokens |
|---|---:|---:|
| Triage (`survey_binary`) | 17.0 s | ~77K |
| Query (`func_query`, `imports_query`) | 7.5 s | ~2.4K |
| Navigation (`list_funcs`, `find_*`, `xrefs_*`) | 5.5 s | ~8.5K |
| Analysis (`decompile`, `analyze_function`) | 41 ms | ~3.7K |
| Modification (`set_comments`, `append_comments`) | 4 ms | ~125 |

Infrastructure overhead:
- Registry operations: <1ms (JSON file, file-locked)
- Tool discovery: ~50ms per IDA instance (one-time cache)
- Tool call routing: <5ms (local HTTP JSON-RPC)
- Heartbeat interval: 60 seconds (negligible overhead)

**Cross-instance dispatch.** Measured against two live GUI instances, issuing a call to
instance B while instance A was busy for ~3.7 s:

| | Before ([#27](https://github.com/MeroZemory/ida-multi-mcp/pull/27)) | After |
|---|---:|---:|
| Response time for the call to instance B | 3.41 s | **0.01 s** |

[Full benchmark report with per-tool detail &rarr;](benchmark-report.md)
