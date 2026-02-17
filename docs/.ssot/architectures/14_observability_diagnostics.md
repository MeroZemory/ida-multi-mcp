# 14. Observability and Diagnostics

## 로그 채널
- 중앙 서버: stderr/print 기반 상태 로그
- 플러그인: IDA 콘솔 로그

## 관찰 가능한 상태
- instance 등록/해제/정리
- auto-discovery 성공/실패
- tool discovery 실패 원인
- heartbeat 오류

## 운영 진단 루틴
1. `ida-multi-mcp --list` 확인
2. IDA 콘솔에서 plugin startup 로그 확인
3. registry 파일(`~/.ida-mcp/instances.json`) 직접 점검
4. 필요 시 `refresh_tools` 수행

## 개선 여지
- 구조화 로그(JSON) 부재
- 메트릭(exporter) 부재
- trace ID 기반 request 추적 미구현

