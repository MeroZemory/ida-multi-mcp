# 06. Tool Discovery and Schema Federation

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## 소스
- 정적 스키마: `src/ida_multi_mcp/ida_tool_schemas.json` (34개)
- 관리 도구: 서버 내장 4개
- 동적 스키마: 연결된 IDA 인스턴스 `tools/list`

## 연합 규칙
- 모든 IDA tool inputSchema에 `instance_id`를 required로 주입
- `py_eval`, `list_funcs` 설명에 싱글스레드 경고 추가
- outputSchema가 object가 아니면 `{result: T}` wrapper로 강제

## 가시성 전략
- IDA가 없어도 static schema로 도구가 보이게 함
- IDA 연결 시 첫 responsive 인스턴스 기준으로 최신 schema 반영

## 확장 툴
- `api_debug`는 `@ext("dbg")`로 extension gated
- 기본 사용 흐름에서 디버그 툴은 숨김 가능

