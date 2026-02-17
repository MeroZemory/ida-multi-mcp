# 02. Component Decomposition

## 최상위 컴포넌트
- MCP Aggregator Server: `server.py`
- Router: `router.py`
- Registry: `registry.py`
- Health: `health.py`
- Cache: `cache.py`
- CLI/Installer: `__main__.py`
- Plugin Runtime: `plugin/ida_multi_mcp.py`
- IDA Tool Provider: `ida_mcp/*`

## 서버 내부 분해
- Management tools(local): `list_instances`, `refresh_tools`, `get_cached_output`, `decompile_to_file`
- IDA tools(proxy): 정적 스키마(`ida_tool_schemas.json`) + 동적 툴 목록 통합
- MCP override: `tools/list`, `tools/call` 커스터마이즈

## 플러그인 내부 분해
- Loader: `plugin/ida_multi_mcp_loader.py`
- Runtime plugin: HTTP 서버 시작/정지 + registry 등록
- Registration adapter: `plugin/registration.py`
- Lifecycle hooks: `IDB_Hooks.closebase`, `UI_Hooks.database_inited`

## 도구 계층
- Base 분석 도구: `api_core`, `api_analysis`, `api_memory`, `api_types`, `api_modify`, `api_stack`, `api_python`
- 확장 디버그 도구: `api_debug` (`@ext("dbg")`)
- 리소스: `api_resources` (`ida://...`)

