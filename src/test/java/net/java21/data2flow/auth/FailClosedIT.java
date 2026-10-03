package net.java21.data2flow.auth;

import net.java21.data2flow.auth.support.AuthIntegrationTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** 블랙리스트 저장소 장애 시 통과시키지 않는다(IAM-07.10, BR-IAM-24). Redis 컨테이너를 멈춰서 확인한다 */
class FailClosedIT extends AuthIntegrationTest {

    @Test
    @DisplayName("[IAM-07.10][AT-IAM-02.9] Redis 장애 → introspection 503 SERVICE_UNAVAILABLE, 로그인 503 AUTH_UNAVAILABLE, 복구 후 정상")
    void redisDownIsFailClosed() {
        CORE.addUser(11, 1, "kim.op", "correct-horse-battery");
        Tokens t = loginOk("kim.op", "correct-horse-battery");

        pauseRedis();
        Response introspect;
        Response login;
        try {
            introspect = introspect(t.access());
            login = login("kim.op", "correct-horse-battery");
        } finally {
            resumeRedis();
        }

        assertThat(introspect.status()).isEqualTo(503);
        assertThat(introspect.resultCode()).isEqualTo("SERVICE_UNAVAILABLE");
        assertThat(login.status()).isEqualTo(503);
        assertThat(login.resultCode()).isEqualTo("AUTH_UNAVAILABLE");
        assertThat(introspection(t.access()).path("active").asBoolean()).isTrue();
    }
}
