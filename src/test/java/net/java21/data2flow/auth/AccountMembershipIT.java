package net.java21.data2flow.auth;

import net.java21.data2flow.auth.support.AuthIntegrationTest;
import net.java21.data2flow.auth.support.FakeCore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** 계정 상태에 따른 로그인(auth 쪽 확인). 상태 원천과 감사는 core가 맡는다 */
class AccountMembershipIT extends AuthIntegrationTest {

    @Test
    @DisplayName("[IAM-01.04][TC-IAM-040][AT-IAM-10.3] 잠긴 사용자를 관리자가 풀면 auth에 남은 잠금 상태 없이 즉시 로그인된다")
    void unlockAllowsImmediateLogin() {
        FakeCore.User user = CORE.addUser(11, 1, "kim.op", "correct-horse-battery");
        user.status = "LOCKED";
        user.lockedUntil = CLOCK.instant().plusSeconds(900);
        assertThat(login("kim.op", "correct-horse-battery").resultCode()).isEqualTo("AUTH_INVALID_CREDENTIALS");

        user.unlock(); // core API-IAM-27 (감사 USER_UNLOCKED는 core가 남긴다)

        assertThat(login("kim.op", "correct-horse-battery").status()).isEqualTo(200);
    }

    @Test
    @DisplayName("[IAM-01.08][TC-IAM-066][AT-IAM-16.4] 승인 대기 계정: 맞는 비밀번호 → 403 AUTH_PENDING_APPROVAL, 틀린 비밀번호 → 401 AUTH_INVALID_CREDENTIALS")
    void pendingApproval() {
        CORE.addUser(31, 1, "new.user", "correct-horse-battery").status = "PENDING_APPROVAL";

        Response right = login("new.user", "correct-horse-battery");
        Response wrong = login("new.user", "wrong-password");

        assertThat(right.status()).isEqualTo(403);
        assertThat(right.resultCode()).isEqualTo("AUTH_PENDING_APPROVAL");
        assertThat(right.body().path("header").path("resultMessage").asString()).contains("승인 대기");
        assertThat(wrong.status()).isEqualTo(401);
        assertThat(wrong.resultCode()).isEqualTo("AUTH_INVALID_CREDENTIALS");
    }

    @Test
    @DisplayName("[IAM-01.08][AT-IAM-16.4] 오류 문구는 Accept-Language로 현지화된다(ADR-037)")
    void localizedMessage() {
        CORE.addUser(31, 1, "new.user", "correct-horse-battery").status = "PENDING_APPROVAL";

        Response res = postJson("/auth/login", java.util.Map.of("loginId", "new.user", "password", "correct-horse-battery"),
                java.util.Map.of("Accept-Language", "en"));

        assertThat(res.body().path("header").path("resultMessage").asString()).contains("approval");
    }
}
