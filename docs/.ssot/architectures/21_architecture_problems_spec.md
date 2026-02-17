# 21. Architecture Problems Specification

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## 범위
- 분석 대상: `ida-multi-mcp` 현재 아키텍처(2026-02-17)
- 근거 소스: 기존 SSOT 문서 + 실제 코드(`src/ida_multi_mcp/**`) + 테스트(`tests/**`)
- 목표: 현재 구조/기능의 문제점을 식별하고, 영향과 보완 명세를 확정

## 심각도 기준
- `P0`: 기능/신뢰성/안전성에 즉시 치명적 영향
- `P1`: 운영 장애/데이터 불일치/강한 품질 저하 위험
- `P2`: 중기적 유지보수/정합성/확장성 저해
- `P3`: 경미한 결함 또는 문서/진단 품질 문제

## 문제 명세

### P0

#### AP-P0-01 만료 사유 필드 키 불일치로 원인 추적 실패
- 근거:
  - `src/ida_multi_mcp/registry.py:244`는 `expired.reason` 저장
  - `src/ida_multi_mcp/router.py:189`, `src/ida_multi_mcp/router.py:199`는 `expire_reason` 조회
- 문제:
  - 만료 원인이 항상 `unknown`으로 표기되어 복구 가이드가 오염됨.
- 영향:
  - 사고 대응 시 root-cause 추적 실패, 자동 복구 힌트 품질 저하.
- 명세(수정 요구):
  - 라우터는 `reason`을 1순위로 읽고, 하위 호환으로 `expire_reason` fallback 허용.

#### AP-P0-02 사용자 지정 레지스트리 경로와 플러그인 등록 경로 분리
- 근거:
  - 서버/CLI는 `--registry` 지원: `src/ida_multi_mcp/__main__.py:909`, `src/ida_multi_mcp/__main__.py:925`
  - 플러그인 등록은 고정 경로만 사용: `src/ida_multi_mcp/plugin/registration.py:28`, `src/ida_multi_mcp/plugin/registration.py:50`, `src/ida_multi_mcp/plugin/registration.py:73`
- 문제:
  - 서버를 커스텀 레지스트리로 띄우면 IDA 플러그인이 다른 파일에 등록하여 인스턴스가 안 보임.
- 영향:
  - “인스턴스 없음” 오탐, 실제 운영 불능.
- 명세(수정 요구):
  - 플러그인 등록 경로를 환경변수/설정으로 주입 가능하게 통일.

### P1

#### AP-P1-01 레지스트리 JSON 손상 시 전체 기능 중단
- 근거: `src/ida_multi_mcp/registry.py:65-66`
- 문제:
  - `json.load` 예외를 복구하지 않아 한 번의 파일 손상으로 전체 명령이 실패할 수 있음.
- 영향:
  - 서버 시작 실패, list/route 전면 중단.
- 명세(수정 요구):
  - 손상 감지 시 백업 격리(`instances.json.bak`) + 기본 구조 자동 복구.

#### AP-P1-02 decompile_to_file 단일 모드 파일명 충돌로 결과 유실
- 근거: `src/ida_multi_mcp/server.py:433-437`
- 문제:
  - 동일 이름 함수(네임스페이스/오버로드/demangle 충돌) 시 앞선 파일이 덮어써짐.
- 영향:
  - 결과 누락/왜곡, 분석 재현성 저하.
- 명세(수정 요구):
  - 파일명에 주소를 포함(`{safe_name}_{addr}.c`)하거나 충돌 시 suffix 증가.

#### AP-P1-03 binary 변경 검증이 파일명 기반이라 오탐/미탐 가능
- 근거:
  - 이름 비교: `src/ida_multi_mcp/router.py:122-123`
  - 설명상 path 대신 name 사용: `src/ida_multi_mcp/router.py:88-89`
- 문제:
  - 서로 다른 경로의 동일 파일명 샘플에서 잘못된 instance를 정상으로 판단 가능.
- 영향:
  - 교차 바이너리 오염 분석 위험.
- 명세(수정 요구):
  - `module` + `input_file` + `idb_path` 복합 검증으로 강화.

#### AP-P1-04 binary 검증 실패 시 fail-open 정책으로 stale 라우팅 허용
- 근거: `src/ida_multi_mcp/router.py:118-120`
- 문제:
  - 메타데이터 조회 실패 시 요청을 계속 통과시켜 stale instance 오배달 가능.
- 영향:
  - 잘못된 대상에서 tool 실행.
- 명세(수정 요구):
  - 최소 `warning` 메타 반환 또는 configurable strict mode(default strict 권장).

#### AP-P1-05 설치 전제 실패(ImportError) 이후에도 설치 성공 흐름 지속
- 근거: `src/ida_multi_mcp/__main__.py:811-814` 이후 설치 계속(`:815+`)
- 문제:
  - 의존 패키지 미설치 상태에서도 plugin 배치/성공 메시지가 진행됨.
- 영향:
  - 사용자에게 성공 오인 제공, 실제 로드 실패.
- 명세(수정 요구):
  - prerequisite 실패 시 non-zero exit 및 설치 중단.

#### AP-P1-06 uninstall이 전체 `~/.ida-mcp` 디렉터리를 재귀 삭제
- 근거: `src/ida_multi_mcp/__main__.py:866-869`
- 문제:
  - 향후 다른 상태파일/운영 메타 포함 시 과삭제 위험.
- 영향:
  - 운영 상태/포렌식 히스토리 유실.
- 명세(수정 요구):
  - 소유 파일만 선택 삭제(allowlist) 또는 백업 후 삭제.

### P2

#### AP-P2-01 IDA tool 실행 전 `active_instance` 선검증이 라우팅 계약과 충돌
- 근거: `src/ida_multi_mcp/server.py:223-230`
- 문제:
  - 실제 라우팅은 명시적 `instance_id` 기반인데, 사전 `active` 체크 실패 시 전체 거부 가능.
- 영향:
  - 경계 상태에서 false negative 오류.
- 명세(수정 요구):
  - 사전 체크 제거하고 라우터에 위임.

#### AP-P2-02 정적 툴 스키마가 실제 기능 표면보다 축소되어 계약 변동성 존재
- 근거:
  - 정적 스키마 34개(`ida_tool_schemas.json`)
  - 실제 API는 더 많은 도구/리소스(`api_debug`, `api_resources`)
- 문제:
  - IDA 미연결 시 툴 목록과 연결 후 목록이 크게 달라짐.
- 영향:
  - 클라이언트 tool planning 불안정.
- 명세(수정 요구):
  - 빌드 시 전체 스키마 자동 생성/동기화 파이프라인 도입.

#### AP-P2-03 decompile_to_file의 대규모 실행 보호장치 부재
- 근거:
  - `all=true` 경로: `src/ida_multi_mcp/server.py:340-379`
  - IDA 단일 스레드 제약: `src/ida_multi_mcp/ida_mcp/sync.py:129-136`
- 문제:
  - 함수 수가 큰 바이너리에서 장시간 블로킹/실질적 서비스 정지.
- 영향:
  - 장기 작업 중 다른 요청 불능.
- 명세(수정 요구):
  - 함수 수 상한 확인/확인 프롬프트/진행률+취소 강제 지원.

#### AP-P2-04 라우터 오류 응답의 instance_id가 실제 ID를 잃어버림
- 근거: `src/ida_multi_mcp/router.py:163` (`instance_info.get("id", "unknown")`)
- 문제:
  - `instance_info`에는 `id` 필드가 없어 대부분 `unknown` 기록.
- 영향:
  - 장애 진단 난이도 상승.
- 명세(수정 요구):
  - 호출 컨텍스트의 `instance_id`를 명시적으로 전달/포함.

#### AP-P2-05 health cleanup 함수의 timeout 파라미터가 실질적으로 미사용
- 근거:
  - 시그니처: `src/ida_multi_mcp/health.py:96`
  - 로직은 process alive만 사용: `src/ida_multi_mcp/health.py:116-121`
- 문제:
  - API 계약과 동작 불일치.
- 영향:
  - 유지보수자 오해 및 잘못된 운영 튜닝.
- 명세(수정 요구):
  - 파라미터 제거 또는 heartbeat 기반 cleanup 실제 반영.

#### AP-P2-06 설치 문구/명령 표기가 실제 CLI 플래그와 불일치
- 근거:
  - 로더 문구: `src/ida_multi_mcp/plugin/ida_multi_mcp_loader.py:13` (`ida-multi-mcp install`)
  - 실제 CLI는 `--install`: `src/ida_multi_mcp/__main__.py:889`
- 문제:
  - 현장 설치 시 오조작 가능.
- 영향:
  - 온보딩 실패율 상승.
- 명세(수정 요구):
  - 문구를 실제 명령으로 정정.

### P3

#### AP-P3-01 레지스트리/캐시 접근 권한 하드닝 미명세
- 근거:
  - 레지스트리 생성 시 권한 정책 없음: `src/ida_multi_mcp/registry.py:37`
  - 캐시는 평문 in-memory, 보호 경계 문서화 미흡: `src/ida_multi_mcp/cache.py`
- 문제:
  - 로컬 멀티유저 환경에서 최소권한 정책 불명확.
- 영향:
  - 보안 감사 시 지적 가능.
- 명세(수정 요구):
  - 파일 생성 권한(예: 600) 명시/강제, 운영 가이드 추가.

#### AP-P3-02 테스트 커버리지가 핵심 아키텍처 경로 대비 제한적
- 근거:
  - 현재 테스트 4건 중심: `tests/test_router_requires_instance_id.py`, `tests/test_install_factory_droid.py`, `tests/test_install_windows_settings_fallback.py`, `tests/test_list_instances_schema.py`
- 문제:
  - registry 복구/rediscovery/decompile_to_file/plugin lifecycle 경로가 비검증.
- 영향:
  - 회귀 위험 상시 존재.
- 명세(수정 요구):
  - 고위험 경로 우선 테스트 셋 추가.

## 우선순위 실행 계획
1. P0 즉시 수정: `AP-P0-01`, `AP-P0-02`
2. P1 안정화: `AP-P1-01`~`AP-P1-06`
3. P2 계약 정합성 개선: `AP-P2-*`
4. P3 운영/품질 강화

## 태스크포스 결론
- 현재 아키텍처는 "멀티 인스턴스 MCP 라우팅" 핵심 목적은 달성했으나,
  - 만료 사유/레지스트리 경로/복구 내구성 영역에서 즉시 개선 필요,
  - 대용량 실행 제어 및 테스트 체계 보강 없이는 운영 확장 시 장애 확률이 높다.
