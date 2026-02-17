# Tool Federation Contract

Last updated: 2026-02-17
Version: v1

## Authority
이 계약은 중앙 MCP 서버의 도구 스키마 연합과 대형 응답 처리 규칙을 정의한다.

## Schema Rules
- IDA tools는 `instance_id`를 required input으로 노출한다.
- 클라이언트 호환성을 위해 output schema는 object-compatible이어야 한다.

## Output Rules
- 큰 출력은 preview + cache pagination으로 제공할 수 있다.
- cache retrieval은 `get_cached_output`을 통해 offset/size 기반으로 조회한다.

## Traceability
- Tool cache/federation: `src/ida_multi_mcp/server.py`
- Cache model: `src/ida_multi_mcp/cache.py`
