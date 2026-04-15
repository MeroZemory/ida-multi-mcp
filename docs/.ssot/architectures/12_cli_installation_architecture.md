# 12. CLI and Installation Architecture

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## CLI Surface
- Default: run the MCP server
- `--install`: deploy the IDA plugin loader + automate MCP client configuration
- `--uninstall`: remove plugin/registry/client configuration
- `--list`: list registered instances
- `--config`: print MCP configuration JSON

## Installation Architecture
- Install the plugin loader into the IDA plugins directory, preferring a symlink
- Fall back to copy on failure
- Automatically update multiple MCP client config files (JSON/TOML)

## Platform Handling
- Windows rename failure (WinError 5) handled via overwrite fallback
- Built-in per-OS config-path table

## Operational Risks
- If a client process has a config file locked, part of installation may be skipped
- A restart notice is mandatory

