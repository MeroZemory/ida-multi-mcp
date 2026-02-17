# 09. Security Architecture

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## 신뢰 경계
- 기본 통신은 localhost(127.0.0.1)
- 중앙 서버는 `instance_id` 명시 강제로 오작동/혼선 완화

## IDA HTTP 보호
- `/config` POST는 Origin 검증
- `/config.html` GET는 Host 검증
- CSP + X-Frame-Options 적용
- CORS policy: `unrestricted | local | direct`

## 위험 명시
- unsafe 도구(`@unsafe`): 디버깅/메모리 쓰기/py_eval 등 고위험
- extension gating(`@ext`)으로 노출 통제 가능

## 남은 리스크
- 로컬 호스트 위협 모델(같은 사용자 세션 악성 코드)
- registry 파일 변조 시 라우팅 오염 가능
- mcp client 설정 파일 권한/무결성 의존

