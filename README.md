# data2flow-auth

아이디·비밀번호 로그인(자격 확인은 core에 위임), 토큰 발급·재발급·폐기, introspection, Redis 블랙리스트.

- 관련 스펙: IAM-02/03/07 (정본은 비공개 저장소 `data2flow-docs`)
- 패키지: `net.java21.data2flow.auth` · Spring Boot 4.1.1 · Java 21 · Maven Wrapper
- 포트: API 8080, actuator 8081(프로브·지표 전용)

## 빌드와 실행

```bash
./mvnw verify                 # 단위·통합 테스트 + 커버리지 80% 검사
./mvnw spring-boot:run        # 로컬 실행(프로필 local)
```

공통 라이브러리 `data2flow-contracts`는 GitHub Packages에 있어서 읽기에도 토큰이 필요합니다. `~/.m2/settings.xml`에 서버 `github`(사용자 이름 + `read:packages` 권한 토큰)를 넣거나, `data2flow-contracts`를 받아 `./mvnw install`로 로컬 저장소에 설치합니다.

## 작업 규칙

스펙 ID에서 시작하고(인수 테스트 → 테스트 케이스 → 구현), 브랜치·PR·테스트 이름에 스펙 ID를 남깁니다. 1.0 전에는 `main` + `feat/<스펙ID>-<요약>`, 1.0 뒤에는 버전 브랜치 `feature/vX.Y`를 씁니다(ADR-039).

## 설정(환경변수)

| 변수 | 내용 |
|---|---|
| `DATA2FLOW_AUTH_JWT_KEYS` | **필수.** JWT 서명 키 `kid:Base64(32바이트 이상)[@검증 종료 ISO-8601],…`. 없으면 기동하지 않습니다. 운영은 k8s Secret, 로컬은 루트 `.env` |
| `DATA2FLOW_AUTH_JWT_ACTIVE_KEY_ID` | 키가 여러 개일 때 서명에 쓰는 키(교체: 새 키 추가 → 활성 변경 → 이전 키에 `@종료 시각` → 제거) |
| `DATA2FLOW_REDIS_HOST`·`_PORT`·`_USERNAME`·`_PASSWORD` | 블랙리스트·호출 한도·MFA 티켓·폐기 이벤트용 Redis(키 접두사 `data2flow:`) |
| `DATA2FLOW_CORE_URI` | core-api 내부 API(기본 `http://data2flow-core-api`) |
