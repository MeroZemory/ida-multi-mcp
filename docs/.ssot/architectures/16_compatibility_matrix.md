# 16. Compatibility Matrix

## 런타임 버전
- Python: >=3.11 (`pyproject.toml`)
- IDA: README 기준 8.3+, 권장 9.0+

## OS 호환
- macOS / Windows / Linux 경로 분기 구현
- 파일락: Unix `fcntl`, Windows `msvcrt`
- 프로세스 스캔: `lsof`/`ss`/`netstat+tasklist`

## MCP 클라이언트
- 다수 클라이언트 자동 설정 지원(README 표 참조)
- 클라이언트별 설정 파일 스키마 차이(VS Code, Codex TOML 등) 처리

## 호환성 위험
- IDA Python과 시스템 Python 불일치
- 사용자 환경의 설정 파일 권한/인코딩 차이

