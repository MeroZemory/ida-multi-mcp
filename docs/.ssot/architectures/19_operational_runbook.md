# 19. Operational Runbook

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## Day-0 설치
1. 패키지 설치(IDA Python 포함).
2. `ida-multi-mcp --install` 실행.
3. MCP 클라이언트 재시작.

## Day-1 검증
1. IDA에서 바이너리 열기.
2. 콘솔에서 plugin listening/registered 로그 확인.
3. 터미널에서 `ida-multi-mcp --list` 확인.

## Day-2 운영
- 도구 불일치 시 `refresh_tools` 실행
- 대형 응답은 `get_cached_output(cache_id, offset, size)`로 페이지 조회
- 인스턴스 불일치 오류 시 `list_instances`로 최신 ID 교체

## 장애 대응
- `No IDA instances`:
  - IDA plugin load 확인
  - registry 파일 존재/권한 확인
- `instance not found/expired`:
  - 최신 인스턴스 ID 재조회
- 연결 실패:
  - 프로세스 생존/포트 청취 여부 확인

