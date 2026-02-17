# 08. Concurrency and Synchronization

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## 중앙 서버 동시성
- registry 접근은 파일락으로 직렬화
- MCP 요청은 I/O 경계에서 병렬 가능

## IDA 내부 동시성
- 모든 IDA SDK 호출은 `@idasync` -> `idaapi.execute_sync(..., MFF_WRITE)`
- IDA 메인 스레드 단일 실행 모델
- long-running 호출은 다른 요청을 블로킹할 수 있음

## 취소/타임아웃
- 기본 timeout: 15초 (`IDA_MCP_TOOL_TIMEOUT_SEC`)
- `@tool_timeout`으로 개별 재정의 (`decompile` 90초)
- `notifications/cancelled` 이벤트와 profile hook 기반 취소

## 재진입 보호
- `call_stack` 검사로 동기화 경로 재진입 오류 감지

