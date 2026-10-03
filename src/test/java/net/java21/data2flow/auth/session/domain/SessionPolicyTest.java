package net.java21.data2flow.auth.session.domain;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/** BR-IAM-15 세션 유휴·절대 만료 */
class SessionPolicyTest {

    private final Instant login = Instant.parse("2026-10-03T00:00:00Z");
    private final SessionPolicy policy = new SessionPolicy(Duration.ofMinutes(30), Duration.ofHours(12));

    @Test
    @DisplayName("[IAM-03.01][BR-IAM-15] 토큰 만료는 세션 절대 만료(12시간)를 넘지 않는다")
    void tokenExpiryIsCapped() {
        Instant absolute = policy.absoluteExpiry(login);
        assertThat(absolute).isEqualTo(login.plus(Duration.ofHours(12)));
        assertThat(policy.tokenExpiry(login, Duration.ofHours(1), absolute)).isEqualTo(login.plus(Duration.ofHours(1)));
        assertThat(policy.tokenExpiry(login.plus(Duration.ofHours(11).plusMinutes(30)), Duration.ofHours(1), absolute)).isEqualTo(absolute);
        assertThat(policy.absolutelyExpired(absolute.minusSeconds(1), absolute)).isFalse();
        assertThat(policy.absolutelyExpired(absolute, absolute)).isTrue();
    }

    @Test
    @DisplayName("[IAM-03.01][BR-IAM-15] 마지막 활동 후 30분이 지나면 유휴 만료, Redis가 비워진 직후에는 끊지 않는다")
    void idle() {
        Instant now = login.plus(Duration.ofHours(1));
        assertThat(policy.idleExpired(now.minus(Duration.ofMinutes(29)), null, now)).isFalse();
        assertThat(policy.idleExpired(now.minus(Duration.ofMinutes(31)), null, now)).isTrue();
        assertThat(policy.idleExpired(null, null, now)).isTrue();
        assertThat(policy.idleExpired(null, now.minus(Duration.ofMinutes(10)), now)).isFalse();
        assertThat(policy.idleExpired(null, now.minus(Duration.ofMinutes(40)), now)).isTrue();
        SessionPolicy disabled = new SessionPolicy(Duration.ZERO, Duration.ofHours(12));
        assertThat(disabled.idleCheckEnabled()).isFalse();
        assertThat(disabled.idleExpired(null, null, now)).isFalse();
    }
}
