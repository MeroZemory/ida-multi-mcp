# AGENTS

Last updated: 2026-02-17

## 1) Entry Rules
- Read order: `docs/PROJECT_GOVERNANCE.md` -> `docs/.ssot/PRD.md` -> `docs/.ssot/contracts/*` -> target domain docs.
- Conflict resolution: Contracts are the source of truth.

## 2) Documentation Rules
- Do not redefine contract semantics outside `docs/.ssot/contracts/*`.
- Use links + versions when referencing contracts.
- Update absolute dates in modified docs.
- Record significant SSOT changes in `docs/.ssot/HISTORY.md`.

## 3) Code/Docs Traceability
- When changing architecture or behavior docs, include references to affected code paths.
- Keep roadmap and PRD synchronized with repository reality.

## 4) Project Profile
- CLI-centric project
- No external HTTP API spec
- No DB-backed schema docs
- Uses AI agents
- Does not use RAG KB currently
