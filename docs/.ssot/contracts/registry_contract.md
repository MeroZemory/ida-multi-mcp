# Registry Contract

Last updated: 2026-02-17
Version: v1

## Authority
이 계약은 instance registry 파일 경로/스키마/복구 동작을 정의한다.

## Path Resolution
- `IDA_MULTI_MCP_REGISTRY_PATH` 환경변수가 있으면 해당 경로를 사용한다.
- 없으면 `~/.ida-mcp/instances.json`을 사용한다.

## Required Top-level Keys
- `instances`
- `active_instance`
- `expired`

## Lifecycle Invariants
- register -> heartbeat update -> expire/unregister
- 손상 JSON 감지 시 `*.corrupt-<ts>`로 격리 후 빈 기본 구조로 복구

## Traceability
- Implementation: `src/ida_multi_mcp/registry.py`
- Plugin bridge: `src/ida_multi_mcp/plugin/registration.py`
