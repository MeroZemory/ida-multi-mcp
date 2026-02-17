# 15. Testing Architecture

## 현재 테스트 커버리지
- router: `instance_id` 필수 검증 (`tests/test_router_requires_instance_id.py`)
- install: Windows settings overwrite fallback (`tests/test_install_windows_settings_fallback.py`)
- install: Factory Droid 설정 생성/삭제 (`tests/test_install_factory_droid.py`)
- management schema: `list_instances`가 object 반환 (`tests/test_list_instances_schema.py`)

## 강점
- 설치 경로의 회귀 위험 지점(권한/파일 포맷) 방어
- core routing safety contract(`instance_id`) 고정

## 갭
- registry expire/cleanup 경로 단위 테스트 부족
- rediscovery 실환경 모의 테스트 부족
- decompile_to_file 대규모 경로/오류 처리 테스트 부족
- plugin hook lifecycle 테스트 부족

## 권장 추가 테스트
- registry filelock 경쟁 상황
- router expired replacement 안내 로직
- cache TTL/eviction 경계값

