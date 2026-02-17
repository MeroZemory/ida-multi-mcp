# Routing Contract

Last updated: 2026-02-17
Version: v1

## Authority
이 계약은 IDA tool 라우팅 요청의 필수 입력/오류 형태를 정의한다.

## Rules
- 모든 IDA tool call은 `instance_id`를 포함해야 한다.
- 누락/유효하지 않은 경우 응답은 다음 필드를 포함해야 한다:
  - `error`
  - `hint`
  - `available_instances` (해당 시)

## Traceability
- Implementation: `src/ida_multi_mcp/router.py`
- Error envelope shaping: `src/ida_multi_mcp/server.py`
