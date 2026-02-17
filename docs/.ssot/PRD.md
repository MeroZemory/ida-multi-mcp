# Product Requirements Document (PRD)

Last updated: 2026-02-17
Status: Active
Change class: B (scope/architecture)

## 1. Product Goal
`ida-multi-mcp`는 단일 MCP 엔드포인트를 통해 다중 IDA 인스턴스에 안전하게 라우팅되는 분석 환경을 제공한다.

## 2. Core Requirements
- 인스턴스별 명시 라우팅: 모든 IDA tool call은 `instance_id`를 요구한다.
- 멀티 인스턴스 운영: 동시 다중 바이너리 분석을 지원한다.
- 도구 표면 안정성: static + dynamic schema federation으로 툴 가시성을 유지한다.
- 설치/운영 실용성: cross-platform plugin 설치와 MCP client 구성 자동화를 지원한다.

## 3. In Scope
- Registry 기반 인스턴스 lifecycle 관리
- Router 기반 `instance_id` 강제 디스패치
- 대형 응답 캐시/분할 조회
- IDA plugin auto-load/auto-register

## 4. Out of Scope
- 외부 공개 HTTP API 플랫폼
- DB 기반 영속 스토리지
- 운영 온콜 서비스(runbook 필요 서비스)

## 5. Project Profile
```yaml
project_profile:
  interfaces:
    http_api: false
    external_api: false
    cli: true
  persistence:
    has_db_or_persistent_store: false
  ai_tooling:
    uses_ai_agents: true
    uses_rag_kb: false
```

## 6. N/A Document Types
- API Spec: `N/A`
- Data Model/Schema (DB): `N/A`
- Runbook: `N/A`
- KB Config: `N/A`

## 7. Authority Links
- Contracts (SSOT): `docs/.ssot/contracts/INDEX.md`
- Decisions: `docs/.ssot/decisions/INDEX.md`
- Architecture: `docs/.ssot/architectures/00_INDEX.md`
- Roadmap: `docs/ops/ROADMAP.md`
