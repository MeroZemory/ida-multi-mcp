# 03. Runtime Sequences

## A. 초기 기동 시퀀스
1. 운영자가 `ida-multi-mcp` 실행.
2. `server.run()`이 stale process 정리 및 auto-rediscovery 수행.
3. `_refresh_tools()`가 management + static tool schema 준비.
4. stdio MCP 서버 대기 시작.

## B. IDA 인스턴스 시작 시퀀스
1. IDA 로드시 PLUGIN_FIX 플러그인 자동 로드.
2. `start_server()`가 IDA 내부 MCP HTTP 서버를 `127.0.0.1:0`으로 시작.
3. 실제 바인딩 포트를 읽어 registry 등록.
4. 60초 heartbeat 스레드 시작.

## C. Tool call 시퀀스
1. 클라이언트가 `tools/call(name,args)` 요청.
2. 중앙 서버가 management/local인지 IDA/proxy인지 분기.
3. proxy면 `instance_id` 검증.
4. IDA로 JSON-RPC POST `/mcp` 전달.
5. 결과를 `content + structuredContent`로 정규화.
6. 출력이 크면 cache 저장 후 preview 반환.

## D. 종료 시퀀스
1. DB close 또는 plugin term 이벤트 발생.
2. heartbeat 중지.
3. registry unregister.
4. HTTP 서버 stop.

