# 05. Data Model and Persistence

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## Registry File
Path: `~/.ida-mcp/instances.json`

Structure:
- `instances`: `{instance_id -> instance_info}`
- `active_instance`: string|null
- `expired`: `{instance_id -> expired_info}`

Key fields of `instance_info`:
- `pid`, `host`, `port`
- `binary_name`, `binary_path`, `idb_path`, `arch`
- `registered_at`, `last_heartbeat`

## Atomicity/Concurrency
- File lock: `instances.json.lock` (`fcntl`/`msvcrt`)
- Save: write `*.tmp` then `os.replace`

## Cache Model
- In-memory LRU: `cache.py`
- Default max output: 10,000 chars
- Entry TTL: 600s
- Max entries: 200

## Data Invariants
- `instance_id` is unique within the `instances` keys
- `active_instance` is either absent or present in the current `instances`
- Default expired cleanup: 1 hour

