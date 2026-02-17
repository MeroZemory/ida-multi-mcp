# 12. CLI and Installation Architecture

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## CLI 표면
- 기본: MCP 서버 실행
- `--install`: IDA plugin loader 배치 + MCP client 설정 자동화
- `--uninstall`: plugin/registry/client 설정 제거
- `--list`: 등록 인스턴스 조회
- `--config`: MCP 설정 JSON 출력

## 설치 아키텍처
- plugin loader를 IDA plugins 디렉토리에 symlink 우선 설치
- 실패시 copy fallback
- 다수 MCP 클라이언트 설정 파일(JSON/TOML) 자동 반영

## 플랫폼 처리
- Windows rename 실패(WinError 5) 대비 overwrite fallback
- 각 OS별 config path 테이블 내장

## 운영 리스크
- 클라이언트 프로세스가 설정 파일 잠금 중이면 설치 일부 스킵 가능
- 재시작 필요 안내가 필수

