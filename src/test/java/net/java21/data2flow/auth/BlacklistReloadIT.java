package net.java21.data2flow.auth;

import net.java21.data2flow.auth.support.AuthIntegrationTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Redis 내용이 사라져도 폐기한 토큰이 다시 통과하지 않는다(ADR-022, design/auth.md §4.2, design/testing/backend.md §4.1
 * {@code BlacklistReloadIT}). 원천은 core의 폐기 기록(API-IAM-39a)이다.
 */
class BlacklistReloadIT extends AuthIntegrationTest {

    @Test
    @DisplayName("[IAM-07.05][ADR-022] 로그아웃 뒤 Redis가 비워져도 core 기록으로 다시 적재해 이전 Access를 거부한다")
    void reloadAfterRedisRestart() {
        CORE.addUser(11, 1, "kim.op", "correct-horse-battery");
        Tokens t = loginOk("kim.op", "correct-horse-battery");
        assertThat(logout(t.refresh()).status()).isEqualTo(204);
        CLOCK.advance(Duration.ofMinutes(5));

        wipeRedis();

        assertThat(introspection(t.access()).path("inactiveReason").asString()).isEqualTo("REVOKED");
        assertThat(CORE.calls()).anyMatch(c -> c.startsWith("GET /internal/core/revocations?since="));
        assertThat(redis.opsForValue().get("data2flow:boot")).isNotNull();
        assertThat(redis.hasKey("data2flow:bl:sid:" + t.sid())).isTrue();
    }

    @Test
    @DisplayName("[IAM-07.10][ADR-022] Redis가 비었는데 core도 응답하지 않으면 introspection은 503 SERVICE_UNAVAILABLE(fail-closed)")
    void reloadFailureIsFailClosed() {
        CORE.addUser(11, 1, "kim.op", "correct-horse-battery");
        Tokens t = loginOk("kim.op", "correct-horse-battery");
        wipeRedis();
        CORE.setDown(true);

        Response res = introspect(t.access());

        assertThat(res.status()).isEqualTo(503);
        assertThat(res.resultCode()).isEqualTo("SERVICE_UNAVAILABLE");

        CORE.setDown(false);
        assertThat(introspection(t.access()).path("active").asBoolean()).isTrue();
    }

    @Test
    @DisplayName("[IAM-07.05] Redis 재시작 직후에는 활동 기록이 없어도 유휴 만료로 끊지 않는다(로그인이 한꺼번에 끊기지 않게)")
    void wipeDoesNotExpireActiveSessions() {
        CORE.addUser(11, 1, "kim.op", "correct-horse-battery");
        Tokens t = loginOk("kim.op", "correct-horse-battery");
        CLOCK.advance(Duration.ofMinutes(20));

        wipeRedis();

        assertThat(introspection(t.access()).path("active").asBoolean()).isTrue();
        CLOCK.advance(Duration.ofMinutes(20));
        assertThat(introspection(t.access()).path("active").asBoolean()).isTrue();
    }

    @Test
    @DisplayName("[IAM-07.05] API-IAM-38 운영자 재적재 → 다시 등록한 개수")
    void manualReload() {
        CORE.addUser(11, 1, "kim.op", "correct-horse-battery");
        Tokens t = loginOk("kim.op", "correct-horse-battery");
        logout(t.refresh());

        Response res = postJson("/internal/auth/revocations/reload", null);

        assertThat(res.status()).isEqualTo(200);
        assertThat(res.response().path("sids").asInt()).isEqualTo(1);
        assertThat(res.response().path("jtis").asInt()).isZero();
    }
}
