# ida-multi-mcp 설계 문서

## 1. 프로젝트 개요

**ida-multi-mcp**는 여러 IDA Pro 인스턴스를 **단일 MCP 서버**로 통합하여, LLM 클라이언트(Claude, Cursor 등)가 하나의 MCP 엔드포인트를 통해 복수의 바이너리를 동시에 리버스 엔지니어링할 수 있게 하는 도구입니다.

### 1.1 문제 정의

현재 ida-pro-mcp의 한계:
- **단일 인스턴스**: 하나의 IDA Pro에 하나의 MCP 서버가 연결됨
- **고정 포트**: `127.0.0.1:13337`에 하드코딩 (TODO 주석만 있음)
- **다중 바이너리 불가**: 멀웨어 분석 시 여러 바이너리(dropper, payload, C2 등)를 동시에 분석할 수 없음
- **클라이언트 설정 복잡**: 여러 IDA 인스턴스를 사용하려면 각각의 MCP 서버를 클라이언트에 등록해야 함

### 1.2 해결 방안

```
┌──────────────────────────────────────────────┐
│              MCP Client (LLM)                │
│        (Claude, Cursor, VS Code 등)          │
│                                              │
│  tool call: decompile(instance_id="a3f",...) │
└───────────────────┬──────────────────────────┘
                    │  stdio / HTTP (MCP Protocol)
                    ▼
┌──────────────────────────────────────────────┐
│        ida-multi-mcp Server (Router)         │
│                                              │
│  ┌────────────┐  ┌────────────────────────┐  │
│  │  Instance   │  │  Dynamic Tool          │  │
│  │  Registry   │  │  Discovery             │  │
│  │  (JSON)     │  │  (from IDA instances)  │  │
│  └──────┬─────┘  └───────────┬────────────┘  │
│         │                    │               │
│  ┌──────▼────────────────────▼────────────┐  │
│  │         Request Router                  │  │
│  │    instance_id → host:port dispatch     │  │
│  └────┬──────────┬──────────┬─────────────┘  │
└───────┼──────────┼──────────┼────────────────┘
        │          │          │  HTTP JSON-RPC
        ▼          ▼          ▼
   ┌────────┐ ┌────────┐ ┌────────┐
   │ IDA #1 │ │ IDA #2 │ │ IDA #3 │
   │ :auto  │ │ :auto  │ │ :auto  │
   │ Plugin │ │ Plugin │ │ Plugin │
   │(HTTP)  │ │(HTTP)  │ │(HTTP)  │
   └────────┘ └────────┘ └────────┘
```

---

## 2. 레퍼런스 프로젝트 분석 (ida-pro-mcp)

### 2.1 아키텍처 개요

ida-pro-mcp는 **듀얼 프로세스** 아키텍처:

| 컴포넌트 | 프로세스 | 역할 |
|----------|---------|------|
| `server.py` | 외부 Python 프로세스 | MCP 클라이언트와 stdio/HTTP 통신, IDA에 HTTP 프록시 |
| `ida_mcp.py` + `ida_mcp/` | IDA Pro 내부 프로세스 | IDA SDK 접근, HTTP JSON-RPC 서버 제공 |
| `zeromcp/` | 벤더 라이브러리 | MCP 프로토콜 구현 (JSON-RPC, HTTP, SSE, stdio) |

**통신 흐름**:
```
LLM Client ──stdio──> server.py ──HTTP POST /mcp──> ida_mcp plugin ──execute_sync──> IDA SDK
                      (proxy)                       (ThreadingHTTPServer)             (main thread)
```

### 2.2 핵심 컴포넌트 상세

#### 2.2.1 MCP Proxy Server (`server.py`)

**역할**: MCP 클라이언트와 IDA 플러그인 사이의 브릿지

**핵심 함수 - `dispatch_proxy()`**:
```python
def dispatch_proxy(request):
    if request_obj["method"] == "initialize":
        return dispatch_original(request)        # 로컬 처리: MCP 핸드셰이크
    elif request_obj["method"].startswith("notifications/"):
        return dispatch_original(request)        # 로컬 처리: 알림
    # 그 외 모든 요청 → IDA에 HTTP 전달
    conn = http.client.HTTPConnection(IDA_HOST, IDA_PORT, timeout=30)
    conn.request("POST", "/mcp", request)
    return json.loads(conn.getresponse().read())
```

- `initialize`와 `notifications/*`는 프로토콜 레벨이므로 로컬 처리
- 모든 tool call, resource read 등은 IDA의 HTTP 엔드포인트로 전달
- `mcp.registry.dispatch`를 monkey-patch하여 프록시 구현

**설치 시스템**:
- `install_ida_plugin()`: IDA 플러그인 디렉토리에 symlink (우선) 또는 copy
  - Windows: `%APPDATA%/Hex-Rays/IDA Pro/plugins/`
  - Unix: `~/.idapro/plugins/`
- `install_mcp_servers()`: 20+ MCP 클라이언트 설정 파일에 자동 등록
  - Claude Desktop, Cursor, VS Code, Cline, Roo Code, Windsurf, Zed, LM Studio 등
  - JSON/TOML 파일 atomic write (temp file + `os.replace()`)

#### 2.2.2 IDA Plugin (`ida_mcp.py`)

```python
class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"
    HOST = "127.0.0.1"
    PORT = 13337              # ← 하드코딩된 포트 (TODO: configurable)

    def init(self):           # 플러그인 로드 시
        return idaapi.PLUGIN_KEEP

    def run(self, arg):       # 사용자 활성화 시 (Ctrl+Alt+M)
        unload_package("ida_mcp")  # 핫리로드 핵
        from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches
        init_caches()
        MCP_SERVER.serve(self.HOST, self.PORT, request_handler=IdaMcpHttpRequestHandler)

    def term(self):           # IDA 종료 시
        self.mcp.stop()
```

**핵심 특징**:
- `PLUGIN_KEEP`: IDA가 플러그인을 메모리에 유지 (수동 활성화 필요)
- `unload_package()`: 매번 실행 시 모듈 강제 리로드 (개발 편의)
- `ThreadingHTTPServer`: 백그라운드 데몬 스레드에서 HTTP 서빙

**포트 바인딩 한계**:
- 포트 13337 하드코딩, 스캐닝/리트라이 로직 없음
- 두 번째 IDA 인스턴스는 `EADDRINUSE` 에러 발생
- `CLAUDE.md`에 "13337-13346" 언급하지만 실제 구현 없음

#### 2.2.3 zeromcp 벤더 라이브러리

**`JsonRpcRegistry`** - JSON-RPC 2.0 디스패치 엔진:
- `dispatch(request)`: JSON 파싱 → 메서드 조회 → 파라미터 타입 체크 → 함수 호출 → 응답 생성
- Python `inspect.signature()` + `get_type_hints()`로 런타임 리플렉션 기반 파라미터 검증
- 리플렉션 결과 캐싱 (함수별 1회)
- 에러 코드: -32700(파싱), -32600(잘못된 요청), -32601(메서드 없음), -32602(잘못된 파라미터), -32603(내부 에러), -32800(취소됨)

**`McpServer`** - MCP 프로토콜 서버:
- 3개 레지스트리: `tools` (McpRpcRegistry), `resources` (McpRpcRegistry), `prompts` (McpRpcRegistry)
- 1개 프로토콜 레지스트리: `registry` (JsonRpcRegistry) - `initialize`, `tools/list`, `tools/call` 등

**프로토콜 메서드**:

| JSON-RPC 메서드 | 핸들러 | 용도 |
|-----------------|--------|------|
| `ping` | `_mcp_ping` | 연결 확인 |
| `initialize` | `_mcp_initialize` | MCP 핸드셰이크 (capabilities, serverInfo 반환) |
| `tools/list` | `_mcp_tools_list` | 등록된 모든 tool 스키마 반환 (extension gating 적용) |
| `tools/call` | `_mcp_tools_call` | tool 실행 (extension 체크 → 취소 추적 → tools.dispatch) |
| `resources/list` | `_mcp_resources_list` | 정적 리소스 목록 |
| `resources/templates/list` | `_mcp_resource_templates_list` | 파라미터화된 리소스 템플릿 목록 |
| `resources/read` | `_mcp_resources_read` | URI 매칭으로 리소스 읽기 |
| `prompts/list` | `_mcp_prompts_list` | 프롬프트 목록 |
| `prompts/get` | `_mcp_prompts_get` | 프롬프트 실행 |
| `notifications/cancelled` | `_mcp_notifications_cancelled` | 진행 중 요청 취소 |

**스키마 자동 생성**: Python 타입 힌트 → JSON Schema 변환
```python
Annotated[str, "desc"]  → {"type": "string", "description": "desc"}
list[T]                 → {"type": "array", "items": schema_of_T}
dict[str, T]            → {"type": "object", "additionalProperties": schema_of_T}
TypedDict               → {"type": "object", "properties": {...}, "required": [...]}
Union[A, B]             → {"anyOf": [schema_A, schema_B]}
```

**HTTP 엔드포인트**:

| Method | Path | Transport | Protocol Version |
|--------|------|-----------|-----------------|
| POST | `/mcp` | Streamable HTTP | 2025-06-18 |
| GET | `/sse` | SSE 연결 설정 | 2024-11-05 |
| POST | `/sse?session=X` | SSE 요청 전송 | 2024-11-05 |
| GET | `/config.html` | 설정 UI (IdaMcpHttpRequestHandler) | - |
| POST | `/config` | 설정 저장 | - |
| GET | `/output/{id}.json` | 캐시된 대용량 출력 다운로드 | - |

#### 2.2.4 IDA Thread Synchronization (`sync.py`)

**`@idasync` 데코레이터**: 모든 IDA SDK 호출을 메인 스레드에서 실행

```python
@tool             # 1. MCP tool로 등록
@idasync          # 2. IDA 메인 스레드에서 실행
def my_api(param: Annotated[str, "description"]) -> ReturnType:
    """MCP tool description"""
    # IDA SDK 사용
```

**동작 메커니즘**:
1. HTTP 스레드에서 tool 호출 수신
2. `sync_wrapper()`: 취소 이벤트 캡처, batch 모드 활성화, 타임아웃/취소 프로파일 훅 설정
3. `_sync_wrapper()`: `idaapi.execute_sync(runned, MFF_WRITE)` - IDA 메인 스레드에 스케줄
4. 메인 스레드에서 `runned()` 실행, `queue.Queue`로 결과 반환
5. `sys.setprofile()` 훅이 매 Python 문(statement)마다 체크:
   - `cancel_event.is_set()` → `CancelledError` 발생
   - `deadline` 초과 → `IDASyncError` 발생

**예외 계층**:
```
Exception
├── McpToolError          → JSON-RPC -32000
│   └── IDAError          → "Invalid address", "Function not found" 등
├── IDASyncError          → JSON-RPC -32603 (타임아웃, 재진입)
└── RequestCancelledError → JSON-RPC -32800
    └── CancelledError    → 클라이언트 취소 요청
```

**설정**:
- `IDA_MCP_TOOL_TIMEOUT_SEC` 환경변수 (기본 15초)
- `@tool_timeout(seconds)` 데코레이터 (per-tool 오버라이드, e.g. `decompile`은 90초)

#### 2.2.5 RPC 레이어 (`rpc.py`)

**데코레이터**:

| 데코레이터 | 용도 | 등록 대상 |
|-----------|------|---------|
| `@tool` | MCP tool 등록 | `MCP_SERVER.tools.methods[func.__name__]` |
| `@resource(uri)` | MCP resource 등록 | `MCP_SERVER.resources.methods[func.__name__]`, `__resource_uri__` 속성 설정 |
| `@unsafe` | unsafe 마킹 | `MCP_UNSAFE` set에 추가 (--unsafe 플래그 필요) |
| `@ext(group)` | extension 그룹 마킹 | `MCP_EXTENSIONS[group]` set에 추가 (?ext=group 필요) |

**출력 크기 제한**:
- `OUTPUT_LIMIT_MAX_CHARS = 50000` (50KB)
- `_install_tools_call_patch()`: `tools/call` 메서드를 monkey-patch하여 응답 크기 체크
- 초과 시: UUID 키로 캐시 → 미리보기(truncated) + 다운로드 URL 반환

**싱글톤**:
- `MCP_SERVER = McpServer("ida-pro-mcp")` (모듈 레벨 전역)
- `MCP_UNSAFE: set[str]` - unsafe 함수 이름 집합
- `MCP_EXTENSIONS: dict[str, set[str]]` - extension 그룹별 함수 이름 집합

#### 2.2.6 HTTP 확장 (`http.py`)

`IdaMcpHttpRequestHandler(McpHttpRequestHandler)`:
- `/config.html`: 웹 기반 설정 UI (CORS 정책, tool 활성화/비활성화)
- `/config`: POST로 설정 저장 (IDA netnode에 영구 저장)
- `/output/{id}.{ext}`: 캐시된 대용량 출력 다운로드
- CORS 정책: `unrestricted` | `local` | `direct`
- 보안: Origin 체크 (CSRF 방지), Host 체크 (DNS rebinding 방지), CSP 헤더, X-Frame-Options

#### 2.2.7 API 모듈 상세

| 모듈 | @tool | @resource | @unsafe | @ext("dbg") | 주요 기능 |
|------|-------|-----------|---------|-------------|----------|
| `api_core.py` | 6 | 0 | 0 | 0 | 함수 조회, 숫자 변환, 함수/글로벌 목록, import 목록, 문자열 정규식 검색 |
| `api_analysis.py` | 10 | 0 | 0 | 0 | 디컴파일, 디스어셈블리, xref, 바이트/패턴 검색, 기본 블록, 콜그래프, 함수 내보내기 |
| `api_memory.py` | 6 | 0 | 0 | 0 | 메모리 읽기(바이트/정수/문자열/글로벌), 패치, 정수 쓰기 |
| `api_types.py` | 5 | 0 | 0 | 0 | 타입 선언, 구조체 읽기/검색, 타입 적용, 타입 추론 |
| `api_modify.py` | 3 | 0 | 0 | 0 | 코멘트 설정, 어셈블리 패치, 일괄 이름 변경 |
| `api_stack.py` | 3 | 0 | 0 | 0 | 스택 프레임 조회, 스택 변수 선언/삭제 |
| `api_debug.py` | 20 | 0 | 20 | 20 | 디버거 제어/중단점/레지스터/스택트레이스/디버그 메모리 |
| `api_python.py` | 1 | 0 | 1 | 0 | IDA 컨텍스트에서 Python 코드 실행 |
| `api_resources.py` | 0 | 11 | 0 | 0 | IDB 메타데이터, 세그먼트, 엔트리포인트, 커서, 타입, 구조체, import/export, xref |
| **합계** | **54** | **11** | **21** | **20** | |

**주요 Tool 목록**:

**Core** (6): `lookup_funcs`, `int_convert`, `list_funcs`, `list_globals`, `imports`, `find_regex`

**Analysis** (10): `decompile`, `disasm`, `xrefs_to`, `xrefs_to_field`, `callees`, `find_bytes`, `find`, `basic_blocks`, `export_funcs`, `callgraph`

**Memory** (6): `get_bytes`, `get_int`, `get_string`, `get_global_value`, `patch`, `put_int`

**Types** (5): `declare_type`, `read_struct`, `search_structs`, `set_type`, `infer_types`

**Modify** (3): `set_comments`, `patch_asm`, `rename`

**Stack** (3): `stack_frame`, `declare_stack`, `delete_stack`

**Debug** (20): `dbg_start`, `dbg_exit`, `dbg_continue`, `dbg_run_to`, `dbg_step_into`, `dbg_step_over`, `dbg_bps`, `dbg_add_bp`, `dbg_delete_bp`, `dbg_toggle_bp`, `dbg_regs_all`, `dbg_regs_remote`, `dbg_regs`, `dbg_gpregs_remote`, `dbg_gpregs`, `dbg_regs_named_remote`, `dbg_regs_named`, `dbg_stacktrace`, `dbg_read`, `dbg_write`

**Python** (1): `py_eval`

**Resources** (11): `ida://idb/metadata`, `ida://idb/segments`, `ida://idb/entrypoints`, `ida://cursor`, `ida://selection`, `ida://types`, `ida://structs`, `ida://struct/{name}`, `ida://import/{name}`, `ida://export/{name}`, `ida://xrefs/from/{addr}`

---

## 3. ida-multi-mcp 설계

### 3.1 설계 결정

| 결정 사항 | 선택 | 근거 |
|----------|------|------|
| 라우팅 방식 | 단일 MCP 서버 + Router | 클라이언트 설정 간소화, 중앙 관리 |
| 포트 할당 | OS auto-assign (port 0) | 포트 충돌 없음, 자동화 |
| 인스턴스 발견 | 파일 기반 JSON Registry | 단순, 디버깅 용이, 크로스 프로세스 |
| 코드베이스 | 새 프로젝트 (기존 참조) | 깔끔한 아키텍처, 레거시 없음 |
| 언어 | Python 3.11+ | IDA 플러그인과 동일, zeromcp 재활용 |
| 인스턴스 지정 | Tool 파라미터 (`instance_id`) | 모든 tool에 optional 파라미터 주입 |
| Instance ID | 4자리 base36 (e.g., `k7m2`) | 짧고 읽기 쉬우면서 167만 조합으로 충돌 거의 없음 |
| ID 생성 입력 | `hash(pid:port:idb_path)` | 바이너리 교체 시 ID 자동 변경 (세대 관리) |
| 바이너리 교체 감지 | Dual: IDA Hooks (primary) + 요청 시 검증 (fallback) | 훅 실패에도 안전 |
| 만료 인스턴스 처리 | expired 섹션에 이력 보관 | LLM에 교체 안내, 자동 active 전환 |
| Tool 발견 | IDA 인스턴스에서 동적 발견 | 미래 호환, 플러그인 버전 독립 |
| 파일 락킹 | 플랫폼 추상화 (fcntl/msvcrt) | Windows + Unix 지원 |

### 3.2 프로젝트 구조

```
ida-multi-mcp/
├── pyproject.toml                    # 패키지 설정, 의존성, 엔트리포인트
├── README.md                         # 사용 가이드
├── DESIGN.md                         # 이 문서
├── src/
│   └── ida_multi_mcp/
│       ├── __init__.py               # 패키지 초기화
│       ├── __main__.py               # CLI 엔트리포인트 (serve, list, install)
│       ├── server.py                 # MCP Server (stdio/HTTP) + Router 통합
│       ├── registry.py               # Instance Registry (JSON 파일 R/W + 파일 락킹)
│       ├── router.py                 # Request Router (instance_id → HTTP dispatch)
│       ├── instance_id.py            # Short ID 생성, 충돌 처리
│       ├── health.py                 # 헬스체크, stale 인스턴스 정리
│       ├── filelock.py               # 크로스 플랫폼 파일 락킹 (fcntl/msvcrt)
│       ├── tools/
│       │   ├── __init__.py
│       │   └── management.py         # list_instances, get/set_active, refresh
│       └── plugin/
│           ├── __init__.py
│           ├── ida_multi_mcp.py      # IDA 플러그인 엔트리 (PLUGIN_ENTRY)
│           ├── registration.py       # 자동 등록/해제, 하트비트
│           └── http_server.py        # HTTP 서버 (port 0 = auto)
└── vendor/
    └── zeromcp/                      # ida-pro-mcp에서 벤더링
        ├── __init__.py
        ├── mcp.py
        └── jsonrpc.py
```

### 3.3 Instance Registry 설계

**파일 위치**: `~/.ida-mcp/instances.json`

```json
{
  "instances": {
    "a3f": {
      "pid": 12345,
      "host": "127.0.0.1",
      "port": 49152,
      "binary_name": "malware.exe",
      "binary_path": "C:/samples/malware.exe",
      "arch": "x86_64",
      "registered_at": "2025-01-15T10:30:00Z",
      "last_heartbeat": "2025-01-15T10:35:00Z"
    },
    "b12": {
      "pid": 12346,
      "host": "127.0.0.1",
      "port": 49153,
      "binary_name": "driver.sys",
      "binary_path": "C:/samples/driver.sys",
      "arch": "arm64",
      "registered_at": "2025-01-15T10:31:00Z",
      "last_heartbeat": "2025-01-15T10:35:00Z"
    }
  },
  "active_instance": "a3f",
  "expired": {
    "c90": {
      "binary_name": "old_sample.exe",
      "binary_path": "C:/samples/old_sample.exe",
      "expired_at": "2025-01-15T10:29:00Z",
      "replaced_by": "a3f",
      "reason": "binary_changed"
    }
  }
}
```

**Instance ID 생성 (Generation 기반, 4자리 base36)**:

바이너리가 교체되면 ID도 자동 변경되어, 이전 분석 컨텍스트의 만료를 보장합니다.

```python
import hashlib

def generate_instance_id(pid: int, port: int, idb_path: str) -> str:
    """4자리 base36 ID 생성 (a-z, 0-9)"""
    raw = hashlib.sha256(f"{pid}:{port}:{idb_path}".encode()).digest()
    # 첫 4바이트를 정수로 변환 후 base36 인코딩
    n = int.from_bytes(raw[:4], "big") % (36 ** 4)  # 0 ~ 1,679,615
    chars = "0123456789abcdefghijklmnopqrstuvwxyz"
    result = ""
    for _ in range(4):
        result = chars[n % 36] + result
        n //= 36
    return result
    # 예: "k7m2", "px3a", "9bf1"
```

**ID 형식 비교**:

| 방식 | 길이 | 조합 수 | 충돌 확률 (10개) | 예시 |
|------|------|---------|-----------------|------|
| 3자리 hex | 3 | 4,096 | ~1.1% | `a3f` |
| **4자리 base36** | **4** | **1,679,616** | **~0.003%** | **`k7m2`** |
| 6자리 hex | 6 | 16,777,216 | ~0.0003% | `a3f1b2` |

4자리 base36을 채택: hex와 같은 길이에서 **400배 많은 조합**, 사람이 읽고 말하기 쉬움.
충돌 시: 5자리로 확장 (`k7m2` → `k7m2a`, 6000만 조합).

**왜 `idb_path`를 포함하는가?**
- 같은 IDA 프로세스(PID)에서 분석 대상을 바꾸면 주소/함수/타입 등 모든 컨텍스트가 무효
- `timestamp` 대신 `idb_path`를 사용하면 **같은 바이너리 재오픈 시 같은 ID 유지** (결정적)
- 바이너리 변경 시 경로가 달라지므로 **자동으로 새 ID 생성** → 이전 ID는 만료 처리

```
시나리오:
  IDA PID=12345, port=49152, malware.exe 분석 중
  → ID = base36(hash("12345:49152:C:/samples/malware.exe")) = "k7m2"

  사용자가 driver.sys로 교체
  → 기존 "k7m2" unregister + expired 처리
  → HTTP 서버 재시작 (새 포트 49153)
  → ID = base36(hash("12345:49153:C:/samples/driver.sys")) = "px3a"
  → LLM이 "k7m2"로 요청 시: "Instance 'k7m2' expired, replaced by 'px3a' (driver.sys)"
```

**Registry API**:
```python
class InstanceRegistry:
    def __init__(self, registry_path: str | None = None)
    def register(self, info: InstanceInfo) -> str          # 새 인스턴스 등록, ID 반환
    def unregister(self, instance_id: str) -> None         # 인스턴스 제거
    def list_instances(self) -> dict[str, InstanceInfo]    # 모든 인스턴스 조회
    def get_instance(self, instance_id: str) -> InstanceInfo | None
    def update_heartbeat(self, instance_id: str) -> None   # 하트비트 갱신
    def get_active(self) -> str | None                     # 활성 인스턴스 ID
    def set_active(self, instance_id: str) -> None         # 활성 인스턴스 변경
    def cleanup_stale(self, timeout_seconds: int = 120) -> list[str]  # 죽은 인스턴스 정리
    def expire_instance(self, instance_id: str, reason: str, replaced_by: str | None = None) -> None  # 인스턴스 만료 처리
    def get_expired(self, instance_id: str) -> ExpiredInfo | None    # 만료된 인스턴스 조회
    def cleanup_expired(self, max_age_seconds: int = 3600) -> int    # 오래된 만료 기록 정리
```

**만료(Expired) 처리 정책**:
- `expire_instance()`: 활성 인스턴스를 `expired` 섹션으로 이동, 사유와 교체 ID 기록
- `get_expired()`: 만료된 ID로 조회 시 교체 안내 정보 반환
- `cleanup_expired()`: 1시간 이상 된 만료 기록 자동 삭제 (무한 누적 방지)
- `active_instance`가 만료되면 자동으로 다음 활성 인스턴스로 전환 (없으면 `null`)

**파일 락킹**:
```python
class FileLock:
    """크로스 플랫폼 파일 락"""
    # Unix: fcntl.flock(fd, LOCK_EX)
    # Windows: msvcrt.locking(fd, LK_LOCK, size)
    def __enter__(self) -> Self
    def __exit__(self, ...) -> None
```

**Atomic Write**:
```python
def atomic_write(path: str, data: str):
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
    os.write(fd, data.encode())
    os.close(fd)
    os.replace(tmp, path)  # atomic on same filesystem
```

### 3.4 IDA Plugin 설계

**원본과의 차이점**:

| 항목 | ida-pro-mcp | ida-multi-mcp |
|------|-------------|---------------|
| 포트 | 13337 (하드코딩) | 0 (OS 자동 할당) |
| 활성화 | 수동 (Ctrl+Alt+M) | 자동 (`PLUGIN_FIX`) |
| 등록 | 없음 | Registry에 자동 등록/해제 |
| 하트비트 | 없음 | 60초마다 |
| API 모듈 | 자체 포함 (54 tools) | **기존 ida-pro-mcp 재사용** |

**핵심: API 모듈은 건드리지 않음**. 기존 ida-pro-mcp의 `ida_mcp/` 패키지를 그대로 사용하고, 플러그인 로더만 교체.

```python
# plugin/ida_multi_mcp.py
class MultiMCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX           # 자동 로드 (원본은 PLUGIN_KEEP)
    wanted_name = "Multi-MCP"
    wanted_hotkey = ""                   # 핫키 없음 (자동 시작)

    def init(self):
        self._start_server()             # IDA 시작 시 자동으로 서버 시작
        return idaapi.PLUGIN_KEEP

    def _start_server(self):
        # 1. ida_mcp 패키지 로드 (기존 API 모듈 전체)
        from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches
        init_caches()

        # 2. Port 0으로 HTTP 서버 시작 (OS가 포트 할당)
        MCP_SERVER.serve("127.0.0.1", 0, request_handler=IdaMcpHttpRequestHandler)
        actual_port = MCP_SERVER._http_server.server_address[1]

        # 3. Registry에 등록
        from ida_multi_mcp.plugin.registration import register_instance
        self.instance_id = register_instance(
            pid=os.getpid(),
            host="127.0.0.1",
            port=actual_port,
            binary_name=idaapi.get_input_file_path(),
            arch=self._get_arch()
        )

        # 4. 하트비트 스레드 시작
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._heartbeat_thread.start()

    def term(self):
        # Registry에서 해제
        unregister_instance(self.instance_id)
        self.mcp.stop()
```

**바이너리 교체 감지 (Dual Strategy)**:

두 가지 전략을 병행하여 안정성을 확보합니다:

| 전략 | 방식 | 장점 | 한계 |
|------|------|------|------|
| **Primary**: IDA Hooks | `IDB_Hooks.closebase()` + `UI_Hooks.database_inited()` 콜백 | 즉시 감지, 지연 없음 | IDA 버전/환경에 따라 훅 미작동 가능 |
| **Fallback**: 요청 시 검증 | 매 tool call 라우팅 전 바이너리 경로 조회 비교 | 훅 실패해도 안전 | 요청당 1회 경량 API 호출 오버헤드 |

**전략 1 (Primary) — IDA Event Hooks**:

```python
# plugin/registration.py

class IDBChangeHandler(idaapi.IDB_Hooks):
    """IDB 이벤트 감지: 바이너리 닫힘/교체"""

    def closebase(self):
        """IDB가 닫힐 때 (바이너리 교체 또는 IDA 종료 전)"""
        registry.expire_instance(
            instance_id=current_instance_id,
            reason="binary_changed"
        )
        MCP_SERVER.stop()
        return 0


class UIChangeHandler(idaapi.UI_Hooks):
    """UI 이벤트 감지: 새 바이너리 로드 완료"""

    def database_inited(self, is_new_database, idc_script):
        """새 IDB가 열린 후 (새 바이너리 분석 준비 완료)"""
        MCP_SERVER.serve("127.0.0.1", 0, request_handler=IdaMcpHttpRequestHandler)
        new_port = MCP_SERVER._http_server.server_address[1]

        new_id = register_instance(
            pid=os.getpid(), host="127.0.0.1", port=new_port,
            binary_name=idaapi.get_input_file_path(), arch=get_arch()
        )

        # 만료된 이전 ID에 교체 정보 기록
        if old_instance_id:
            expired = registry.get_expired(old_instance_id)
            if expired:
                expired["replaced_by"] = new_id

        registry.set_active(new_id)
        return 0
```

**전략 2 (Fallback) — 요청 시 검증**:

IDA Hook이 실패하더라도, Router가 매 요청마다 바이너리 경로를 검증합니다:

```python
# router.py

class InstanceRouter:
    def route_request(self, method, arguments):
        instance_id = arguments.pop("instance_id", None) or self.registry.get_active()
        instance = self.registry.get_instance(instance_id)
        if not instance:
            return self._handle_missing(instance_id)

        # Fallback 검증: IDA에 현재 바이너리 경로 조회
        current_path = self._query_binary_path(instance)
        if current_path and current_path != instance["binary_path"]:
            # 바이너리가 바뀌었으나 Hook이 미작동 → 수동 만료 처리
            self.registry.expire_instance(instance_id, reason="binary_changed_detected")
            new_id = self._re_register_instance(instance, current_path)
            return {
                "error": f"Instance '{instance_id}' binary changed: "
                         f"{instance['binary_name']} → {os.path.basename(current_path)}. "
                         f"New instance: '{new_id}'",
                "replacement": new_id
            }

        return self._forward(instance, method, arguments)

    def _query_binary_path(self, instance) -> str | None:
        """IDA 인스턴스에 현재 분석 중인 바이너리 경로를 조회 (경량 API)"""
        try:
            conn = http.client.HTTPConnection(instance["host"], instance["port"], timeout=5)
            # resources/read로 idb metadata 조회 (기존 ida-pro-mcp의 ida://idb/metadata)
            request = {
                "jsonrpc": "2.0", "id": 1,
                "method": "resources/read",
                "params": {"uri": "ida://idb/metadata"}
            }
            conn.request("POST", "/mcp", json.dumps(request))
            response = json.loads(conn.getresponse().read())
            # metadata에서 path 추출
            contents = response.get("result", {}).get("contents", [{}])
            if contents:
                metadata = json.loads(contents[0].get("text", "{}"))
                return metadata.get("path")
        except Exception:
            return None  # 연결 실패 시 검증 스킵 (health check가 처리)
```

**Fallback 최적화**:
- `_query_binary_path()`는 `ida://idb/metadata` 리소스를 조회 — 기존 API 재사용, 추가 구현 불필요
- 캐시: 마지막 검증 시간을 기록하여 **5초 이내 재요청은 스킵** (과도한 오버헤드 방지)
- 검증 실패(연결 불가)는 무시 — health check 모듈이 별도 처리

**라이프사이클 전체 흐름**:
```
IDA 시작
  → PLUGIN_FIX로 자동 로드
  → init(): IDB_Hooks, UI_Hooks 등록
  → database_inited(): port 0 서버 시작, Registry 등록, ID="k7m2"

사용자가 다른 바이너리 열기 (File → Open)
  [Hook 작동 시 - Primary]
    → closebase(): "k7m2" 만료 처리, 서버 정지
    → database_inited(): 새 서버 시작, Registry 등록, ID="px3a"

  [Hook 미작동 시 - Fallback]
    → LLM이 tool 호출 → Router가 ida://idb/metadata 조회
    → binary_path 불일치 감지 → "k7m2" 만료 + 재등록 → ID="px3a"
    → LLM에 교체 안내 반환

IDA 종료
  → closebase(): 현재 ID 만료 처리 (reason="ida_closed")
  → term(): 서버 정지, 정리
```

### 3.5 MCP Server + Router 설계

**동적 Tool Discovery**:

```
1. MCP 서버 시작
2. Registry에서 활성 IDA 인스턴스 확인
3. 활성 인스턴스에 HTTP 요청: POST /mcp {"method": "tools/list"}
4. 응답에서 tool schema 목록 수신
5. 각 tool schema에 instance_id 파라미터 주입:
   {
     "name": "instance_id",
     "type": "string",
     "description": "Target IDA instance ID (default: active instance)"
   }
6. Management tools 추가 (list_instances, get_active, set_active, refresh_tools)
7. 수정된 tool 목록을 MCP 클라이언트에 제공
```

**장점**:
- IDA 플러그인의 tool이 추가/변경되어도 MCP 서버 코드 수정 불필요
- 기존 ida-pro-mcp 플러그인과도 호환
- Tool schema가 항상 최신 상태

**Request 라우팅**:

```python
class InstanceRouter:
    def route_request(self, method: str, arguments: dict) -> dict:
        # 1. instance_id 추출 (없으면 active_instance 사용)
        instance_id = arguments.pop("instance_id", None)
        if instance_id is None:
            instance_id = self.registry.get_active()

        # 2. 대상 인스턴스의 host:port 조회
        instance = self.registry.get_instance(instance_id)

        if instance:
            # 3. HTTP POST로 전달
            conn = http.client.HTTPConnection(instance["host"], instance["port"], timeout=30)
            request = {"jsonrpc": "2.0", "method": "tools/call",
                       "params": {"name": method, "arguments": arguments}, "id": 1}
            conn.request("POST", "/mcp", json.dumps(request))
            return json.loads(conn.getresponse().read())

        # 4. 만료된 인스턴스인지 확인 → 교체 안내
        expired = self.registry.get_expired(instance_id)
        if expired:
            msg = (f"Instance '{instance_id}' has expired. "
                   f"Previous binary: {expired['binary_name']}. "
                   f"Reason: {expired['reason']}.")
            if expired.get("replaced_by"):
                replacement = self.registry.get_instance(expired["replaced_by"])
                if replacement:
                    msg += (f" Replaced by '{expired['replaced_by']}' "
                            f"({replacement['binary_name']}).")
            return {"error": msg, "expired": True,
                    "replacement": expired.get("replaced_by")}

        # 5. 완전히 알 수 없는 ID
        available = self.registry.list_instances()
        names = [f"{id} ({info['binary_name']})" for id, info in available.items()]
        return {"error": f"Instance '{instance_id}' not found. "
                         f"Available: {', '.join(names) or 'none'}"}
```

**Management Tools** (MCP 서버 자체 구현):

```python
@tool
def list_instances() -> list[dict]:
    """List all registered IDA Pro instances with their metadata"""
    return [{"id": id, **info} for id, info in registry.list_instances().items()]

@tool
def get_active_instance() -> dict:
    """Get the currently active IDA Pro instance"""
    active_id = registry.get_active()
    return {"id": active_id, **registry.get_instance(active_id)}

@tool
def set_active_instance(instance_id: Annotated[str, "Instance ID to activate"]) -> dict:
    """Set the active IDA Pro instance for subsequent tool calls"""
    registry.set_active(instance_id)
    return {"active": instance_id}

@tool
def refresh_tools() -> dict:
    """Re-discover tools from the active IDA Pro instance"""
    # tools/list를 다시 가져와서 캐시 갱신
    return {"tools_count": len(refreshed_tools)}
```

### 3.6 Health & Robustness

**헬스체크 전략**:
```python
def check_instance_health(instance: InstanceInfo) -> bool:
    # 1. 프로세스 생존 확인
    if not is_process_alive(instance["pid"]):
        return False

    # 2. HTTP 핑
    try:
        conn = http.client.HTTPConnection(instance["host"], instance["port"], timeout=5)
        conn.request("POST", "/mcp", json.dumps({
            "jsonrpc": "2.0", "method": "ping", "id": 1
        }))
        response = conn.getresponse()
        return response.status == 200
    except:
        return False

def is_process_alive(pid: int) -> bool:
    """크로스 플랫폼 프로세스 생존 확인"""
    # Unix: os.kill(pid, 0)
    # Windows: ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
```

**Stale Cleanup**:
- 하트비트 타임아웃: 120초 (2분)
- MCP 서버 시작 시 전체 Registry 스캔
- 죽은 인스턴스 자동 제거
- 로그 기록

**에러 처리**:
| 상황 | 에러 메시지 |
|------|-----------|
| instance_id 없는 인스턴스 | `"Instance '{id}' not found. Available: a3f (malware.exe), b12 (driver.sys)"` |
| **만료된 인스턴스 (바이너리 교체)** | `"Instance 'a3f' expired. Previous: malware.exe. Replaced by 'd7e' (driver.sys)."` |
| **만료된 인스턴스 (IDA 종료)** | `"Instance 'a3f' expired. Previous: malware.exe. Reason: ida_closed."` |
| 인스턴스 연결 실패 | `"Failed to connect to instance '{id}' at {host}:{port}. Instance may have crashed."` |
| 모든 인스턴스 죽음 | `"No active IDA Pro instances. Please open IDA Pro with the multi-MCP plugin installed."` |
| Registry 손상 | 자동 재빌드 (running 프로세스 스캔) |

### 3.7 CLI 인터페이스

```bash
# MCP 서버 시작 (stdio - 기본, MCP 클라이언트가 사용)
ida-multi-mcp

# MCP 서버 시작 (HTTP)
ida-multi-mcp --transport http://127.0.0.1:8744

# 등록된 인스턴스 목록
ida-multi-mcp --list

# IDA 플러그인 + MCP 클라이언트 설치
ida-multi-mcp --install

# 제거
ida-multi-mcp --uninstall

# MCP 클라이언트 설정 JSON 출력
ida-multi-mcp --config
```

---

## 4. 구현 단계

### Phase 1: Foundation — 프로젝트 기초 + IDA Plugin

| Task | 설명 | 파일 |
|------|------|------|
| 1.1 | 프로젝트 스캐폴딩 (pyproject.toml, 패키지 구조, zeromcp 벤더링) | `pyproject.toml`, `src/`, `vendor/` |
| 1.2 | Instance ID 모듈 (4자리 base36, Generation 기반: `hash(pid:port:idb_path)`, 충돌 처리) | `instance_id.py` |
| 1.3 | Registry 모듈 (JSON R/W, 파일 락킹, CRUD 오퍼레이션) | `registry.py`, `filelock.py` |
| 1.4 | Plugin HTTP 서버 (port 0 바인딩) | `plugin/http_server.py` |
| 1.5 | Plugin 엔트리 포인트 (PLUGIN_FIX, 자동 시작) | `plugin/ida_multi_mcp.py` |
| 1.6 | Registration 로직 (등록/해제/하트비트/IDB 변경 감지: Hook + Fallback 검증) | `plugin/registration.py` |

### Phase 2: MCP Router — 단일 MCP 서버 + 라우팅

| Task | 설명 | 파일 |
|------|------|------|
| 2.1 | Router 모듈 (instance_id → HTTP dispatch) | `router.py` |
| 2.2 | Dynamic Tool Discovery (tools/list 쿼리 + instance_id 주입) | `server.py` |
| 2.3 | MCP Server (stdio/HTTP, tools/call 라우팅) | `server.py` |
| 2.4 | Management Tools (list/get/set active, refresh) | `tools/management.py` |
| 2.5 | CLI 엔트리 포인트 (serve, list, install, config) | `__main__.py` |

### Phase 3: Health — 안정성 + 에러 처리

| Task | 설명 | 파일 |
|------|------|------|
| 3.1 | Health Check (프로세스 생존 + HTTP 핑) | `health.py` |
| 3.2 | Stale Cleanup (서버 시작 시 + 주기적) | `health.py` |
| 3.3 | Graceful Error Handling (명확한 에러 메시지) | `router.py`, `server.py` |
| 3.4 | Registry File Locking (크로스 플랫폼) | `filelock.py` |

### Phase 4: Integration — 설치 + 문서

| Task | 설명 | 파일 |
|------|------|------|
| 4.1 | MCP 클라이언트 자동 설치 (20+ 클라이언트) | `__main__.py` |
| 4.2 | IDA 플러그인 설치 (symlink/copy) | `__main__.py` |
| 4.3 | README.md (설치, 사용법, 아키텍처) | `README.md` |

---

## 5. 리스크 분석

| 리스크 | 영향도 | 확률 | 완화 방안 |
|--------|--------|------|----------|
| Registry 파일 손상 (동시 쓰기) | 높음 | 낮음 | 파일 락킹 + atomic write (temp→rename) |
| IDA 비정상 종료 (cleanup 없이) | 중간 | 중간 | 하트비트 타임아웃 + 프로세스 생존 체크 |
| Instance ID 충돌 | 낮음 | 매우 낮음 | 4자리 base36 = 167만 조합 / <10 인스턴스, 5자리 폴백 |
| 바이너리 교체 시 stale 컨텍스트 | 높음 | 중간 | Dual Strategy: IDA Hooks(primary) + 요청 시 metadata 검증(fallback) |
| IDA Hook 미작동 | 중간 | 낮음 | Fallback 검증이 매 요청 시 바이너리 경로 비교, 5초 캐시로 오버헤드 최소화 |
| Dynamic Tool Discovery 지연 | 낮음 | 낮음 | 스키마 캐싱, 요청 시 갱신 |
| Windows 파일 락킹 차이 | 중간 | 중간 | 플랫폼 추상화 모듈 |
| 기존 ida-pro-mcp와의 공존 | 중간 | 높음 | 문서화: 둘 중 하나만 사용 또는 공존 가이드 |
| IDA 플러그인 버전 간 tool schema 변경 | 낮음 | 낮음 | Dynamic Discovery가 자동 대응 |

---

## 6. 범위 외 (v1.0)

- 원격 IDA 인스턴스 (다른 머신)
- 인증/암호화
- IDA batch/headless (idalib) 모드 통합
- 플러그인 자동 업데이트
- 웹 UI 인스턴스 관리
- Resource 라우팅 (v1.0은 tools 중심, v1.1에서 resources 추가)

---

## 7. 사용 시나리오

### 7.1 멀웨어 분석 워크플로우

```
1. IDA Pro에서 dropper.exe 열기 → 자동 등록 (k7m2)
2. IDA Pro에서 payload.dll 열기 → 자동 등록 (px3a)
3. IDA Pro에서 c2_client.exe 열기 → 자동 등록 (9bf1)

4. LLM에게 요청:
   "k7m2(dropper.exe)의 main 함수를 디컴파일하고,
    px3a(payload.dll)의 export 함수 목록을 보여줘.
    dropper가 payload의 어떤 함수를 호출하는지 분석해줘."

5. LLM이 자동으로:
   - decompile(instance_id="k7m2", addr="main")
   - list_funcs(instance_id="px3a", filter="Dll*")
   - xrefs_to(instance_id="k7m2", addrs="LoadLibrary")
   → 크로스 바이너리 분석 수행
```

### 7.2 일반적인 사용

```bash
# 1. 설치 (1회)
pip install ida-multi-mcp
ida-multi-mcp --install

# 2. IDA Pro 실행 (플러그인 자동 로드)
#    → 콘솔: "[Multi-MCP] Registered as 'a3f' on port 49152"

# 3. MCP 클라이언트에서 사용 (설정 자동 완료)
#    Claude/Cursor에서 바로 IDA tool 사용 가능
```
