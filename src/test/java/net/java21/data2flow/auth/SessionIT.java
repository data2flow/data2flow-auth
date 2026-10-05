package net.java21.data2flow.auth;

import net.java21.data2flow.auth.support.AuthIntegrationTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * 세션: 재발급·회전·유휴/절대 만료·로그아웃·강제 종료(IAM-03.01·03.03·07.03·07.05·07.08, API-IAM-02·03·37b).
 */
class SessionIT extends AuthIntegrationTest {

    @BeforeEach
    void user() {
        CORE.addUser(11, 1, "kim.op", "correct-horse-battery");
    }

    @Test
    @DisplayName("[IAM-07.03][AT-IAM-03.1] Access 만료 후 Refresh로 재발급 → 새 Access·새 Refresh(회전), 감사 TOKEN_REFRESHED")
    void refreshRotates() {
        Tokens t = loginOk("kim.op", "correct-horse-battery");
        CLOCK.advance(Duration.ofMinutes(25));
        introspection(t.access()); // 활동
        CLOCK.advance(Duration.ofMinutes(25));
        introspection(t.access());
        CLOCK.advance(Duration.ofMinutes(11));
        assertThat(introspection(t.access()).path("inactiveReason").asString()).isEqualTo("EXPIRED");

        Response res = refresh(t.refresh());

        assertThat(res.status()).isEqualTo(200);
        String newRefresh = res.response().path("refreshToken").asString();
        assertThat(newRefresh).isNotEqualTo(t.refresh());
        assertThat(res.header("Set-Cookie")).startsWith("data2flow_refresh=" + newRefresh);
        assertThat(res.response().path("sid").asString()).isEqualTo(t.sid());
        assertThat(res.response().path("expiresIn").asLong()).isEqualTo(3600);
        assertThat(introspection(res.response().path("accessToken").asString()).path("active").asBoolean()).isTrue();
        assertThat(CORE.activeRefreshRows(t.sid())).hasSize(1);
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertThat(CORE.audits())
                .anyMatch(a -> a.path("action").asString().equals("TOKEN_REFRESHED")
                        && a.path("detail").path("decision").asString().equals("ROTATED")));
    }

    @Test
    @DisplayName("[IAM-07.04][AT-IAM-03.2] 두 탭이 같은 Refresh로 동시에 재발급(30초 유예) → 둘 다 성공, 로그아웃되지 않음")
    void multiTabGrace() {
        Tokens t = loginOk("kim.op", "correct-horse-battery");

        Response tab1 = refresh(t.refresh());
        CLOCK.advance(Duration.ofSeconds(5));
        Response tab2 = refresh(t.refresh());

        assertThat(tab1.status()).isEqualTo(200);
        assertThat(tab2.status()).isEqualTo(200);
        assertThat(introspection(tab2.response().path("accessToken").asString()).path("active").asBoolean()).isTrue();
        // GRACE 재발급 토큰도 계보의 최신 jti를 이어 받아 다음 회전이 된다
        CLOCK.advance(Duration.ofSeconds(40));
        assertThat(refresh(tab2.response().path("refreshToken").asString()).status()).isEqualTo(200);
    }

    @Test
    @DisplayName("[IAM-07.03][TC-IAM-116][AT-IAM-03.5] 회전 후 31초 지난 이전 Refresh → 401 AUTH_SESSION_REVOKED, 그 sid의 Access도 즉시 거부, 감사 REFRESH_REUSED")
    void reuseRevokesSession() {
        List<JsonNode> events = listenRevocations();
        Tokens t = loginOk("kim.op", "correct-horse-battery");
        Response rotated = refresh(t.refresh());
        String latestAccess = rotated.response().path("accessToken").asString();
        CLOCK.advance(Duration.ofSeconds(31));

        Response reuse = refresh(t.refresh());

        assertThat(reuse.status()).isEqualTo(401);
        assertThat(reuse.resultCode()).isEqualTo("AUTH_SESSION_REVOKED");
        assertThat(introspection(latestAccess).path("inactiveReason").asString()).isEqualTo("REVOKED");
        assertThat(introspection(t.access()).path("inactiveReason").asString()).isEqualTo("REVOKED");
        assertThat(refresh(rotated.response().path("refreshToken").asString()).resultCode()).isEqualTo("AUTH_SESSION_REVOKED");
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> {
            assertThat(CORE.audits()).anyMatch(a -> a.path("action").asString().equals("REFRESH_REUSED")
                    && a.path("result").asString().equals("FAILURE"));
            assertThat(events).anyMatch(e -> e.path("type").asString().equals("SID") && e.path("value").asString().equals(t.sid())
                    && e.path("reason").asString().equals("REUSE_DETECTED"));
        });
    }

    @Test
    @DisplayName("[IAM-03.01][TC-IAM-114][AT-IAM-03.4] 12시간 동안 계속 활동해도 12시간 1분째 요청 → 401 AUTH_SESSION_EXPIRED")
    void absoluteLifetime() {
        Tokens t = loginOk("kim.op", "correct-horse-battery");
        String refreshToken = t.refresh();
        String access = t.access();
        for (int i = 0; i < 35; i++) { // 20분마다 재발급(활동) — 11시간 40분까지
            CLOCK.advance(Duration.ofMinutes(20));
            Response res = refresh(refreshToken);
            assertThat(res.status()).as("재발급 %d", i).isEqualTo(200);
            refreshToken = res.response().path("refreshToken").asString();
            access = res.response().path("accessToken").asString();
        }
        // 11:40에 받은 Access는 60분이 아니라 세션 절대 만료(12:00)까지만 유효
        CLOCK.advance(Duration.ofMinutes(10));
        assertThat(introspection(access).path("exp").asLong())
                .isEqualTo(MutableClockStart.PLUS_12H.getEpochSecond());

        CLOCK.advance(Duration.ofMinutes(11)); // 12:01
        Response expired = refresh(refreshToken);
        assertThat(expired.status()).isEqualTo(401);
        assertThat(expired.resultCode()).isEqualTo("AUTH_SESSION_EXPIRED");
        assertThat(introspection(access).path("inactiveReason").asString()).isEqualTo("EXPIRED");
    }

    @Test
    @DisplayName("[IAM-03.01][AT-IAM-03.3] 마지막 활동 후 31분 → Access는 EXPIRED, 재발급은 401 AUTH_SESSION_EXPIRED")
    void idleTimeout() {
        Tokens t = loginOk("kim.op", "correct-horse-battery");
        CLOCK.advance(Duration.ofMinutes(29));
        assertThat(introspection(t.access()).path("active").asBoolean()).isTrue();
        CLOCK.advance(Duration.ofMinutes(29)); // 마지막 활동 후 29분 — 아직 유효
        assertThat(introspection(t.access()).path("active").asBoolean()).isTrue();

        CLOCK.advance(Duration.ofMinutes(31));

        assertThat(introspection(t.access()).path("inactiveReason").asString()).isEqualTo("EXPIRED");
        Response res = refresh(t.refresh());
        assertThat(res.status()).isEqualTo(401);
        assertThat(res.resultCode()).isEqualTo("AUTH_SESSION_EXPIRED");
    }

    @Test
    @DisplayName("[IAM-07.05][TC-IAM-119][AT-IAM-04.1] 로그아웃 후 이전 Access → REVOKED(gateway가 401 AUTH_SESSION_REVOKED), 폐기 이벤트 발행")
    void logoutRevokesImmediately() {
        List<JsonNode> events = listenRevocations();
        Tokens t = loginOk("kim.op", "correct-horse-battery");
        assertThat(introspection(t.access()).path("active").asBoolean()).isTrue();

        Response res = logout(t.refresh());

        assertThat(res.status()).isEqualTo(204);
        assertThat(res.header("Set-Cookie")).startsWith("data2flow_refresh=").contains("Max-Age=0");
        assertThat(introspection(t.access()).path("inactiveReason").asString()).isEqualTo("REVOKED");
        assertThat(refresh(t.refresh()).resultCode()).isEqualTo("AUTH_SESSION_REVOKED");
        assertThat(CORE.sessionRevoked(t.sid())).isTrue();
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> {
            assertThat(events).anyMatch(e -> e.path("type").asString().equals("SID") && e.path("value").asString().equals(t.sid())
                    && e.path("sid").asString().equals(t.sid()) && e.path("reason").asString().equals("LOGOUT"));
            assertThat(CORE.audits()).anyMatch(a -> a.path("action").asString().equals("USER_LOGGED_OUT"));
        });
    }

    @Test
    @DisplayName("[IAM-07.05][AT-IAM-04.1] 로그아웃은 멱등: 두 번 호출해도, 쿠키가 없거나 틀려도 204")
    void logoutIsIdempotent() {
        Tokens t = loginOk("kim.op", "correct-horse-battery");

        assertThat(logout(t.refresh()).status()).isEqualTo(204);
        assertThat(logout(t.refresh()).status()).isEqualTo(204);
        assertThat(postJson("/auth/logout", null).status()).isEqualTo(204);
        assertThat(logout("garbage").status()).isEqualTo(204);
    }

    @Test
    @DisplayName("[IAM-03.03][AT-IAM-04.2] 관리자가 사용자 A의 모든 세션 종료(core → POST /internal/auth/blacklists) → 두 기기 모두 즉시 거부")
    void forceLogoutAllSessions() {
        List<JsonNode> events = listenRevocations();
        Tokens deviceA = loginOk("kim.op", "correct-horse-battery");
        Tokens deviceB = loginOk("kim.op", "correct-horse-battery");
        CORE.revokeSessionDirectly(deviceA.sid());
        CORE.revokeSessionDirectly(deviceB.sid());

        Response res = postJson("/internal/auth/blacklists",
                Map.of("sids", List.of(deviceA.sid(), deviceB.sid()), "jtis", List.of(), "reason", "FORCED"),
                Map.of("X-CALLER-SERVICE", "data2flow-core-api"));

        assertThat(res.status()).isEqualTo(204);
        assertThat(introspection(deviceA.access()).path("inactiveReason").asString()).isEqualTo("REVOKED");
        assertThat(introspection(deviceB.access()).path("inactiveReason").asString()).isEqualTo("REVOKED");
        assertThat(refresh(deviceB.refresh()).resultCode()).isEqualTo("AUTH_SESSION_REVOKED");
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertThat(events)
                .filteredOn(e -> e.path("reason").asString().equals("FORCED")).hasSize(2));
    }

    @Test
    @DisplayName("[IAM-05.03][AT-IAM-12.4] 장기 토큰 폐기(core → POST /internal/auth/blacklists tokenIds) → EVT-IAM-03 TOKEN_ID 발행, 블랙리스트에는 넣지 않음 — TC-IAM-150")
    void revokeLongLivedTokens() {
        List<JsonNode> events = listenRevocations();

        Response res = postJson("/internal/auth/blacklists",
                Map.of("sids", List.of(), "jtis", List.of(), "tokenIds", List.of("41", "42"), "reason", "API_TOKEN_REVOKED"),
                Map.of("X-CALLER-SERVICE", "data2flow-core-api"));

        assertThat(res.status()).isEqualTo(204);
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertThat(events)
                .filteredOn(e -> e.path("reason").asString().equals("API_TOKEN_REVOKED"))
                .extracting(e -> e.path("type").asString() + ":" + e.path("value").asString())
                .containsExactlyInAnyOrder("TOKEN_ID:41", "TOKEN_ID:42"));
    }

    @Test
    @DisplayName("[IAM-07.08][AT-IAM-08.4] 활성 로그인 한 줄(sid)만 종료 → 그 기기만 거부되고 다른 기기는 유지")
    void revokeSingleSession() {
        Tokens deviceA = loginOk("kim.op", "correct-horse-battery");
        Tokens deviceB = loginOk("kim.op", "correct-horse-battery");

        Response res = postJson("/internal/auth/blacklists", Map.of("sids", List.of(deviceB.sid()), "reason", "LOGOUT"),
                Map.of("X-CALLER-SERVICE", "data2flow-core-api"));

        assertThat(res.status()).isEqualTo(204);
        assertThat(introspection(deviceB.access()).path("inactiveReason").asString()).isEqualTo("REVOKED");
        assertThat(introspection(deviceA.access()).path("active").asBoolean()).isTrue();
    }

    @Test
    @DisplayName("[IAM-07.05] 블랙리스트 등록 요청 검증: reason 없음 → 400 INVALID_REQUEST")
    void blacklistValidation() {
        Response res = postJson("/internal/auth/blacklists", Map.of("sids", List.of("x")));

        assertThat(res.status()).isEqualTo(400);
        assertThat(res.resultCode()).isEqualTo("INVALID_REQUEST");
    }

    @Test
    @DisplayName("[IAM-07.07] 재발급은 sid당 분당 10회 → 11번째 429 AUTH_RATE_LIMITED")
    void refreshRateLimit() {
        Tokens t = loginOk("kim.op", "correct-horse-battery");
        String token = t.refresh();
        for (int i = 0; i < 10; i++) {
            Response res = refresh(token);
            assertThat(res.status()).isEqualTo(200);
            token = res.response().path("refreshToken").asString();
        }

        Response limited = refresh(token);

        assertThat(limited.status()).isEqualTo(429);
        assertThat(limited.resultCode()).isEqualTo("AUTH_RATE_LIMITED");
    }

    @Test
    @DisplayName("[IAM-07.03] Refresh 없이 재발급 → 401 AUTH_TOKEN_INVALID, Access를 Refresh 자리에 → 401 AUTH_TOKEN_INVALID")
    void refreshWithoutValidToken() {
        Tokens t = loginOk("kim.op", "correct-horse-battery");

        assertThat(postJson("/auth/refresh-token", null).resultCode()).isEqualTo("AUTH_TOKEN_INVALID");
        assertThat(refresh(t.access()).resultCode()).isEqualTo("AUTH_TOKEN_INVALID");
        // 본문으로 보낸 Refresh도 받는다(쿠키가 우선)
        assertThat(postJson("/auth/refresh-token", Map.of("refreshToken", t.refresh())).status()).isEqualTo(200);
    }

    /** 기본 시작 시각 + 12시간 */
    private static final class MutableClockStart {
        static final java.time.Instant PLUS_12H = net.java21.data2flow.auth.support.MutableClock.DEFAULT_START.plus(Duration.ofHours(12));
    }
}
