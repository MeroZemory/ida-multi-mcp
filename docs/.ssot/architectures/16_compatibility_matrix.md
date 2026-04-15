# 16. Compatibility Matrix

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## Runtime Versions
- Python: >=3.11 (`pyproject.toml`)
- IDA: 8.3+ per README, 9.0+ recommended

## OS Compatibility
- Path-handling branches implemented for macOS / Windows / Linux
- File lock: Unix `fcntl`, Windows `msvcrt`
- Process scan: `lsof`/`ss`/`netstat+tasklist`

## MCP Clients
- Auto-configuration supported for multiple clients (see the README table)
- Handles per-client config file schema differences (VS Code, Codex TOML, etc.)

## Compatibility Risks
- IDA-Python vs system-Python mismatch
- User-environment variations in config file permissions/encoding

