# 13. Plugin Bootstrap Architecture

## 로더 역할
`plugin/ida_multi_mcp_loader.py`는 IDA 플러그인 폴더에 위치하는 bootstrapper다.

## 로딩 전략
1. `ida_multi_mcp.plugin.ida_multi_mcp` 직접 import 시도
2. 실패 시 다양한 site-packages 후보 경로 수집 후 재시도
3. 실패 지속 시 `PLUGIN_SKIP` 더미 플러그인 반환

## 런타임 플러그인 역할
- DB 열림 시 서버 자동 기동
- DB 닫힘 시 서버 중지 및 unregister
- heartbeat 유지

## 이점
- pip/pipx/homebrew 등 설치 방식 다양성을 흡수
- IDA Python 버전 불일치 시 진단 메시지 제공

