# 17. Extensibility and Evolution

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## 확장 지점
- 새 management tool: `server._register_handlers()`에 추가
- 새 IDA tool: `ida_mcp/api_*.py`에 `@tool` 추가
- 새 리소스: `@resource("ida://...")`
- extension 그룹: `@ext("group")`

## 진화 전략
- static schema 기반 선행 호환 + dynamic discovery 기반 후행 호환
- `instance_id` 강제 계약은 멀티에이전트 충돌 방지의 핵심 불변조건

## 리팩터링 우선순위
- registry backend 추상화(JSON -> sqlite 가능)
- structured logging 도입
- decompile orchestration의 병렬 제어 정책 추가

