# 13. Plugin Bootstrap Architecture

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## Loader Role
`plugin/ida_multi_mcp_loader.py` is a bootstrapper placed in the IDA plugins folder.

## Loading Strategy
1. Try a direct import of `ida_multi_mcp.plugin.ida_multi_mcp`
2. On failure, collect various candidate site-packages paths and retry
3. If failures persist, return a `PLUGIN_SKIP` dummy plugin

## Runtime Plugin Role
- Auto-start the server on DB open
- Stop the server and unregister on DB close
- Maintain heartbeat

## Benefits
- Absorbs installation diversity (pip/pipx/homebrew, etc.)
- Provides diagnostic messages on IDA-Python version mismatch

