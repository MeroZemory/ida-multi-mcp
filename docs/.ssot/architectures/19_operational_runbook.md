# 19. Operational Runbook

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## Day-0 Install
1. Install the package (including IDA Python).
2. Run `ida-multi-mcp --install`.
3. Restart the MCP client.

## Day-1 Verification
1. Open a binary in IDA.
2. Verify plugin listening/registered logs in the console.
3. Check `ida-multi-mcp --list` from the terminal.

## Day-2 Operations
- On tool mismatch, run `refresh_tools`
- For large responses, paginate via `get_cached_output(cache_id, offset, size)`
- On instance-mismatch errors, refresh the ID via `list_instances`

## Incident Response
- `No IDA instances`:
  - Verify IDA plugin load
  - Verify registry file existence/permissions
- `instance not found/expired`:
  - Re-look up the latest instance ID
- Connection failure:
  - Verify process liveness and port listening

