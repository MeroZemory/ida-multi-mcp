# 05. Data Model and Persistence

## Registry 파일
경로: `~/.ida-mcp/instances.json`

구조:
- `instances`: `{instance_id -> instance_info}`
- `active_instance`: string|null
- `expired`: `{instance_id -> expired_info}`

`instance_info` 주요 필드:
- `pid`, `host`, `port`
- `binary_name`, `binary_path`, `idb_path`, `arch`
- `registered_at`, `last_heartbeat`

## 원자성/동시성
- 파일락: `instances.json.lock` (`fcntl`/`msvcrt`)
- 저장: `*.tmp` 작성 후 `os.replace`

## 캐시 모델
- in-memory LRU: `cache.py`
- 기본 최대 출력: 10,000 chars
- 항목 TTL: 600s
- 엔트리 최대: 200

## 데이터 불변조건
- instance_id는 `instances` 키에서 유일
- active_instance는 없거나 현재 `instances`에 존재
- expired cleanup 기본 1시간

