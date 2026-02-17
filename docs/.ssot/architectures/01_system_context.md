# 01. System Context Architecture

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## 목적
`ida-multi-mcp`는 여러 IDA Pro 인스턴스를 단일 MCP 엔드포인트로 통합한다.

## 외부 액터
- MCP 클라이언트: Claude/Cursor/Codex 등
- IDA Pro 프로세스: 각 인스턴스가 로컬 HTTP MCP 서버 구동
- 운영자: `ida-multi-mcp --install/--list/--uninstall`
- 로컬 파일 시스템: `~/.ida-mcp/instances.json`, 클라이언트 설정 파일

## 시스템 경계
- 중앙 서버 프로세스: `src/ida_multi_mcp/server.py`
- IDA 내부 플러그인: `src/ida_multi_mcp/plugin/ida_multi_mcp.py`
- IDA 도구 제공 계층: `src/ida_multi_mcp/ida_mcp/*`

## 컨텍스트 흐름
1. IDA 플러그인이 동적 포트(0)로 HTTP MCP 서버 시작.
2. 플러그인이 중앙 레지스트리에 인스턴스 등록.
3. MCP 클라이언트는 중앙 서버 stdio로 접속.
4. 중앙 서버가 `instance_id`를 기준으로 해당 IDA에 요청 라우팅.

## 핵심 비기능 목표
- 다중 인스턴스 동시 지원
- 포트 충돌 회피
- 안전한 라우팅(명시적 `instance_id` 강제)
- 플러그인 재시작/프로세스 종료 복원력

