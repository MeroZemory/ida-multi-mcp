# 11. Performance and Scalability

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## Bottlenecks
- The dominant bottleneck is IDA's single main thread
- `decompile(all)` scales linearly with the number of functions
- JSON serialization and large-response transfers are expensive

## Mitigations
- Large-output truncation + cache pagination
- `decompile_to_file` paginates via `list_funcs` (batches of 500)
- Stale cleanup reduces unnecessary routing

## Scaling Limits
- Increasing instance count is possible, but each instance is internally single-threaded
- Splitting by `instance_id` minimizes cross-conflict between multiple clients

## Operational Recommendations
- For large binaries, explore via `list_funcs` count/offset first
- Split bulk operations into batches

