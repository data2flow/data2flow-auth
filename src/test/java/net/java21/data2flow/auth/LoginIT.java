package net.java21.data2flow.auth;

import net.java21.data2flow.auth.common.Hashes;
import net.java21.data2flow.auth.support.AuthIntegrationTest;
import net.java21.data2flow.auth.support.FakeCore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * 로그인(API-IAM-01·62) 주 흐름과 예외 흐름. 스펙 IAM-02.01·02.03·02.05·07.01·07.07·01.02.
 * core-api는 {@link FakeCore}(계약 그대로), Redis는 Testcontainers Valkey.
 */
class LoginIT extends AuthIntegrationTest {

    @Test
    @DisplayName("[IAM-02.01][AT-IAM-02.1] 올바른 아이디·비밀번호 → Access·Refresh 발급, Refresh 계보 등록(해시만), 감사 USER_LOGGED_IN")
    void loginIssuesTokens() {
        // given
        CORE.addUser(11, 1, "kim.op", "correct-horse-battery");

        // when
        Response res = login("kim.op", "correct-horse-battery");

        // then
        assertThat(res.status()).isEqualTo(200);
        assertThat(res.resultCode()).isEqualTo("SUCCESS");
        JsonNode body = res.response();
        assertThat(body.path("tokenType").asString()).isEqualTo("Bearer");
        assertThat(body.path("expiresIn").asLong()).isEqualTo(3600);
        assertThat(body.path("mustChangePassword").asBoolean()).isFalse();
        assertThat(body.path("mfaRequired").asBoolean()).isFalse();
        assertThat(body.path("userId").asString()).isEqualTo("11");
        assertThat(body.path("orgId").asString()).isEqualTo("1");
        String refresh = body.path("refreshToken").asString();
        assertThat(res.header("Set-Cookie")).startsWith("data2flow_refresh=" + refresh)
                .contains("HttpOnly").contains("Secure").contains("SameSite=Strict").contains("Max-Age=21600");

        FakeCore.RefreshRow row = CORE.activeRefreshRows(body.path("sid").asString()).getFirst();
        assertThat(row.tokenHash).isEqualTo(Hashes.sha256Hex(refresh));
        assertThat(row.expiresAt).isEqualTo(CLOCK.instant().plus(Duration.ofHours(6)));
        assertThat(row.absoluteExpiresAt).isEqualTo(CLOCK.instant().plus(Duration.ofHours(12)));
        assertThat(row.ip).isEqualTo("203.0.113.7");
        assertThat(row.userAgent).isEqualTo("IT-Browser");

        assertThat(introspection(body.path("accessToken").asString()).path("active").asBoolean()).isTrue();
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertThat(CORE.audits())
                .anySatisfy(a -> {
                    assertThat(a.path("action").asString()).isEqualTo("USER_LOGGED_IN");
                    assertThat(a.path("organizationId").asLong()).isEqualTo(1);
                    assertThat(a.path("actorId").asString()).isEqualTo("11");
                    assertThat(a.path("ip").asString()).isEqualTo("203.0.113.7");
                    assertThat(a.path("result").asString()).isEqualTo("SUCCESS");
                }));
    }

    @Test
    @DisplayName("[IAM-02.01][AT-IAM-02.2] 아이디를 대문자로 입력해도 소문자로 맞춰 로그인된다")
    void loginIdIsCaseInsensitive() {
        CORE.addUser(11, 1, "kim.op", "correct-horse-battery");

        assertThat(login("KIM.OP", "correct-horse-battery").status()).isEqualTo(200);
    }

    @Test
    @DisplayName("[IAM-02.03][TC-IAM-090][AT-IAM-02.3] 없는 아이디·틀린 비밀번호·비활성 사용자는 모두 같은 401 AUTH_INVALID_CREDENTIALS")
    void failuresAreIndistinguishable() {
        CORE.addUser(11, 1, "kim.op", "correct-horse-battery");
        CORE.addUser(12, 1, "lee.off", "correct-horse-battery").status = "DISABLED";

        Response unknown = login("nobody", "whatever-password");
        Response wrong = login("kim.op", "wrong-password-1");
        Response disabled = login("lee.off", "correct-horse-battery");

        assertThat(unknown.status()).isEqualTo(401);
        assertThat(unknown.resultCode()).isEqualTo("AUTH_INVALID_CREDENTIALS");
        assertThat(wrong.body()).isEqualTo(unknown.body());
        assertThat(disabled.body()).isEqualTo(unknown.body());
        assertThat(wrong.status()).isEqualTo(401);
        assertThat(disabled.status()).isEqualTo(401);
    }

    @Test
    @DisplayName("[IAM-02.03][TC-IAM-090][AT-IAM-02.4] 5회 연속 실패 → 잠금(올바른 비밀번호도 실패), 15분 뒤 다시 로그인")
    void lockoutAfterFiveFailures() {
        CORE.addUser(11, 1, "kim.op", "correct-horse-battery");
        for (int i = 0; i < 5; i++) {
            assertThat(login("kim.op", "wrong-password-" + i).resultCode()).isEqualTo("AUTH_INVALID_CREDENTIALS");
        }

        // 같은 1분 안의 6번째: 아이디당 분당 5회 한도(BR-IAM-23)
        Response limited = login("kim.op", "correct-horse-battery");
        assertThat(limited.status()).isEqualTo(429);
        assertThat(limited.resultCode()).isEqualTo("AUTH_RATE_LIMITED");
        assertThat(limited.header("Retry-After")).isNotNull();

        // 1분 뒤: 한도는 풀렸지만 계정이 잠겨 올바른 비밀번호도 실패, 응답은 다른 실패와 같다
        CLOCK.advance(Duration.ofMinutes(1));
        Response locked = login("kim.op", "correct-horse-battery");
        assertThat(locked.status()).isEqualTo(401);
        assertThat(locked.resultCode()).isEqualTo("AUTH_INVALID_CREDENTIALS");

        // [AT-IAM-02.5] 15분 뒤 올바른 비밀번호 → 성공
        CLOCK.advance(Duration.ofMinutes(15));
        assertThat(login("kim.op", "correct-horse-battery").status()).isEqualTo(200);
    }

    @Test
    @DisplayName("[IAM-07.07][AT-IAM-02.6] 같은 IP에서 1분에 21번째 로그인 시도 → 429 AUTH_RATE_LIMITED + Retry-After·X-RateLimit-*")
    void loginRateLimitPerIp() {
        for (int i = 0; i < 20; i++) {
            assertThat(login("user" + i + "x", "wrong-password").status()).isEqualTo(401);
        }

        Response res = login("user99x", "wrong-password");

        assertThat(res.status()).isEqualTo(429);
        assertThat(res.resultCode()).isEqualTo("AUTH_RATE_LIMITED");
        assertThat(res.body().path("header").path("resultMessage").asString()).contains("60");
        assertThat(res.header("Retry-After")).isEqualTo("60");
        assertThat(res.header("X-RateLimit-Limit")).isEqualTo("20");
        assertThat(res.header("X-RateLimit-Remaining")).isEqualTo("0");
        // 한도 초과 요청은 core까지 가지 않는다
        assertThat(CORE.calls()).filteredOn(c -> c.contains("verify-credentials")).hasSize(20);
    }

    @Test
    @DisplayName("[IAM-02.05][AT-IAM-14.2] TOTP 사용자: 비밀번호만 맞으면 401 MFA_REQUIRED + 티켓, 토큰 미발급 → 코드 확인 후 발급, 티켓은 1회용")
    void mfaStep() {
        CORE.addUser(21, 1, "admin", "correct-horse-battery").mfaCode = "123456";

        Response first = login("admin", "correct-horse-battery");
        assertThat(first.status()).isEqualTo(401);
        assertThat(first.resultCode()).isEqualTo("MFA_REQUIRED");
        assertThat(first.body().path("header").path("isSuccessful").asBoolean()).isFalse();
        String ticket = first.response().path("mfaTicket").asString();
        assertThat(ticket).isNotBlank();
        assertThat(first.response().path("expiresIn").asLong()).isEqualTo(300);
        assertThat(first.header("Set-Cookie")).isNull();
        assertThat(CORE.calls()).noneMatch(c -> c.contains("/internal/core/refresh-tokens"));

        Response wrong = postJson("/auth/login/mfa", Map.of("mfaTicket", ticket, "code", "000000"));
        assertThat(wrong.status()).isEqualTo(401);
        assertThat(wrong.resultCode()).isEqualTo("MFA_CODE_INVALID");

        Response ok = postJson("/auth/login/mfa", Map.of("mfaTicket", ticket, "code", "123456"));
        assertThat(ok.status()).isEqualTo(200);
        assertThat(introspection(ok.response().path("accessToken").asString()).path("sub").asString()).isEqualTo("21");

        Response reused = postJson("/auth/login/mfa", Map.of("mfaTicket", ticket, "code", "123456"));
        assertThat(reused.status()).isEqualTo(401);
        assertThat(reused.resultCode()).isEqualTo("AUTH_TOKEN_INVALID");
    }

    @Test
    @DisplayName("[IAM-02.05][AT-IAM-14.2] MFA 티켓은 5분 뒤 만료되고, 시도 한도(5회)를 넘으면 버려진다")
    void mfaTicketExpiryAndAttempts() {
        CORE.addUser(21, 1, "admin", "correct-horse-battery").mfaCode = "123456";
        String ticket = login("admin", "correct-horse-battery").response().path("mfaTicket").asString();
        for (int i = 0; i < 5; i++) {
            assertThat(postJson("/auth/login/mfa", Map.of("mfaTicket", ticket, "code", "99999" + i)).resultCode())
                    .isEqualTo("MFA_CODE_INVALID");
        }
        Response limited = postJson("/auth/login/mfa", Map.of("mfaTicket", ticket, "code", "123456"));
        assertThat(limited.status()).isEqualTo(429);
        assertThat(postJson("/auth/login/mfa", Map.of("mfaTicket", ticket, "code", "123456")).resultCode())
                .isEqualTo("AUTH_TOKEN_INVALID");

        String second = login("admin", "correct-horse-battery").response().path("mfaTicket").asString();
        CLOCK.advance(Duration.ofMinutes(5));
        assertThat(postJson("/auth/login/mfa", Map.of("mfaTicket", second, "code", "123456")).resultCode())
                .isEqualTo("AUTH_TOKEN_INVALID");
    }

    @Test
    @DisplayName("[IAM-01.02][AT-IAM-01.1] 임시 비밀번호 사용자 로그인 → mustChangePassword=true로 발급(변경 강제는 core·BFF)")
    void mustChangePasswordIsForwarded() {
        CORE.addUser(1, 1, "admin", "initial-password-1").mustChangePassword = true;

        Response res = login("admin", "initial-password-1");

        assertThat(res.status()).isEqualTo(200);
        assertThat(res.response().path("mustChangePassword").asBoolean()).isTrue();
    }

    @Test
    @DisplayName("[IAM-07.10][AT-IAM-02.9] core 장애 → 503 AUTH_UNAVAILABLE(fail-closed), 토큰 미발급")
    void coreDownIsFailClosed() {
        CORE.addUser(11, 1, "kim.op", "correct-horse-battery");
        CORE.setDown(true);

        Response res = login("kim.op", "correct-horse-battery");

        assertThat(res.status()).isEqualTo(503);
        assertThat(res.resultCode()).isEqualTo("AUTH_UNAVAILABLE");
        assertThat(res.header("Set-Cookie")).isNull();
    }

    @Test
    @DisplayName("[IAM-07.01] 형식이 틀린 요청 → 400 INVALID_REQUEST + errors")
    void invalidRequest() {
        Response res = postJson("/auth/login", Map.of("loginId", "ab", "password", "x"));

        assertThat(res.status()).isEqualTo(400);
        assertThat(res.resultCode()).isEqualTo("INVALID_REQUEST");
        assertThat(res.body().path("errors").get(0).path("field").asString()).isEqualTo("loginId");
    }
}
