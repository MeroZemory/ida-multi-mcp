# 20. Architecture Decision Record Summary

## ADR-001 단일 MCP 집계 서버
- 결정: 중앙 서버 + 멀티 IDA 라우팅
- 이유: 클라이언트 설정 단순화, 다중 바이너리 동시 분석

## ADR-002 동적 포트 사용
- 결정: IDA 플러그인은 port 0 바인딩
- 이유: 포트 충돌 제거

## ADR-003 파일 기반 레지스트리
- 결정: `~/.ida-mcp/instances.json`
- 이유: 단순성, 디버그 용이성, 프로세스 간 공유

## ADR-004 explicit instance_id 강제
- 결정: 모든 IDA tool 호출에 `instance_id` required
- 이유: 멀티 에이전트 환경의 교차 오염 방지

## ADR-005 static + dynamic schema 혼합
- 결정: 오프라인 가시성(static) + 런타임 정확성(dynamic)
- 이유: IDA 미연결 상태 UX 개선과 버전 호환 동시 확보

## ADR-006 출력 절단 및 캐싱
- 결정: 대형 응답 preview + cache pagination
- 이유: MCP 채널 안정성 및 사용자 응답성 확보

## ADR-007 IDA 메인 스레드 동기화
- 결정: `execute_sync(MFF_WRITE)` 강제
- 이유: IDA API thread-safety 보장

