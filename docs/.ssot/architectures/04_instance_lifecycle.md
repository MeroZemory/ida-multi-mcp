# 04. Instance Lifecycle Model

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## 상태
- `registered` (active set)
- `expired` (history set)
- `removed` (cleanup 대상)

## 생성
- 입력: `pid`, `port`, `idb_path`
- ID 생성: `sha256(pid:port:idb_path)` 기반 base36 4자리
- 충돌 시: 5자리 확장 또는 suffix

## 유지
- heartbeat 갱신: `last_heartbeat`
- health 정리: 프로세스 생존 여부 기반

## 만료
- 사유: `process_dead`, `stale_heartbeat`, 기타 지정 reason
- 기록: `expired_at`, `binary_name`, `binary_path`, `reason`

## 재발견
- 빈 레지스트리 시 OS 레벨 포트 스캔(`lsof`/`ss`/`netstat`)
- `ping` 성공 + `ida://idb/metadata` 조회 성공시 등록

## 라우팅 안전장치
- 없는 instance: available_instances 제시
- expired instance: replacement 후보 제시
- binary mismatch: stale 경고

