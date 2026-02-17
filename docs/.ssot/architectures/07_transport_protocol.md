# 07. Transport and Protocol Architecture

## 전송 계층
- Client <-> Aggregator: MCP stdio
- Aggregator <-> IDA instance: HTTP JSON-RPC (`POST /mcp`)

## 프로토콜 호출
중앙 서버 기준 핵심 메서드:
- `tools/list`: 로컬 tool cache 반환
- `tools/call`: local 관리도구 또는 원격 IDA 호출

IDA 쪽(zeromcp) 제공:
- `initialize`, `ping`, `tools/*`, `resources/*`, `prompts/*`, `notifications/cancelled`

## 라우팅 계약
- `instance_id` 누락 시 즉시 오류
- forwarding 전에 `arguments.instance_id` 제거
- IDA 응답 envelope 그대로 존중, 필요 시 structured 보정

