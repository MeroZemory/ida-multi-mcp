# 11. Performance and Scalability

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## 병목
- 가장 큰 병목은 IDA 단일 메인 스레드
- `decompile(all)`은 함수 수에 선형 비례
- JSON 직렬화/대형 응답 전송 비용 큼

## 완화 기법
- large output truncation + cache pagination
- `decompile_to_file`에서 `list_funcs` 페이지네이션(500 단위)
- stale cleanup으로 불필요 라우팅 감소

## 스케일 한계
- 인스턴스 수 증가는 가능하나 각 인스턴스 내부는 single-thread
- 다중 클라이언트 경쟁시 `instance_id` 분리로 교차 충돌 최소화

## 권장 운영
- 대형 바이너리는 먼저 `list_funcs` count/offset으로 탐색
- bulk 작업은 분할(batch) 실행

