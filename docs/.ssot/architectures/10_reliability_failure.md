# 10. Reliability and Failure Handling

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## 주요 실패 시나리오
- IDA 미연결 상태에서 tool call
- 없는/만료된 instance_id 사용
- IDA 프로세스 종료 후 stale registry
- HTTP 연결 실패/timeout

## 대응 전략
- 사전 오류 메시지 + 복구 힌트 제공
- `list_instances`로 현재 상태 유도
- startup cleanup으로 dead process 정리
- rediscovery로 재등록 자동 복원

## degraded 동작
- metadata 조회 실패 시 binary 검증은 fail-open(True)
- tools discovery 실패 시 static schema만 제공

## 운영 포인트
- 오류 응답이 사람이 읽을 수 있는 힌트를 포함하도록 설계됨

