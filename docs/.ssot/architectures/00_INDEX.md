# ida-multi-mcp Architecture SSOT Index

Last updated: 2026-02-17
Status: Active
Change class: B (scope/architecture)

## Governance Alignment
- Authority order:
1. `docs/.ssot/contracts/*`
2. `docs/.ssot/PRD.md`
3. `docs/.ssot/decisions/*`
4. `docs/.ssot/architectures/*`
5. `docs/phases/_completed/*`
6. `docs/ops/*`
- 이 디렉터리는 아키텍처 설명 문서이며 Contracts 의미론을 재정의하지 않는다.

## Required Cross-links
- Governance: `docs/PROJECT_GOVERNANCE.md`
- PRD: `docs/.ssot/PRD.md`
- Contracts: `docs/.ssot/contracts/INDEX.md`
- Decisions: `docs/.ssot/decisions/INDEX.md`
- SSOT TODO: `docs/.ssot/TODO.md`
- SSOT History: `docs/.ssot/HISTORY.md`
- Roadmap: `docs/ops/ROADMAP.md`

## Architecture Set
1. `01_system_context.md` - 시스템 컨텍스트
2. `02_component_decomposition.md` - 컴포넌트 분해
3. `03_runtime_sequences.md` - 런타임 시퀀스
4. `04_instance_lifecycle.md` - 인스턴스 생명주기
5. `05_data_model_persistence.md` - 데이터 모델/영속성
6. `06_tool_discovery_schema_federation.md` - 툴 발견/스키마 연합
7. `07_transport_protocol.md` - 전송/프로토콜
8. `08_concurrency_sync.md` - 동시성/동기화
9. `09_security_architecture.md` - 보안
10. `10_reliability_failure.md` - 신뢰성/장애 대응
11. `11_performance_scalability.md` - 성능/확장성
12. `12_cli_installation_architecture.md` - CLI/설치 아키텍처
13. `13_plugin_bootstrap.md` - 플러그인 부트스트랩
14. `14_observability_diagnostics.md` - 관측성/진단
15. `15_testing_architecture.md` - 테스트 아키텍처
16. `16_compatibility_matrix.md` - 호환성 매트릭스
17. `17_extensibility_evolution.md` - 확장성/진화
18. `18_module_ownership.md` - 모듈 책임 분리
19. `19_operational_runbook.md` - 운영 런북(현재 N/A 맥락 문서 포함)
20. `20_adr_summary.md` - ADR 요약
21. `21_architecture_problems_spec.md` - 아키텍처 문제점 리서치/명세
