package net.java21.data2flow.auth.session.domain;

import java.time.Duration;
import java.time.Instant;

/**
 * 세션 만료 규칙(BR-IAM-15, IAM-03.01): 마지막 활동 후 유휴 시간(기본 30분)이 지나면 끝나고, 최초 로그인 후 절대 수명(기본 12시간)이
 * 지나면 활동과 관계없이 끝난다. 토큰 만료는 절대 만료를 넘지 않게 자른다.
 *
 * @param idleTimeout 유휴 만료. 0이면 유휴 검사를 하지 않는다
 * @param absoluteTtl 절대 수명
 */
public record SessionPolicy(Duration idleTimeout, Duration absoluteTtl) {

    public Instant absoluteExpiry(Instant loginAt) {
        return loginAt.plus(absoluteTtl);
    }

    /** {@code min(now + ttl, 절대 만료)} */
    public Instant tokenExpiry(Instant now, Duration ttl, Instant absoluteExpiresAt) {
        Instant candidate = now.plus(ttl);
        return candidate.isAfter(absoluteExpiresAt) ? absoluteExpiresAt : candidate;
    }

    public boolean absolutelyExpired(Instant now, Instant absoluteExpiresAt) {
        return !now.isBefore(absoluteExpiresAt);
    }

    public boolean idleCheckEnabled() {
        return !idleTimeout.isZero() && !idleTimeout.isNegative();
    }

    /**
     * 유휴 만료인가. 마지막 활동이 유휴 시간보다 오래됐으면 만료다. 활동 기록(Redis)이 없으면 만료로 보되, Redis가 비워진 뒤
     * (재적재 표식이 유휴 시간 안에 새로 생김)에는 기록이 사라진 것일 수 있으므로 활동 중으로 본다
     * (ADR-022: Redis 내용이 사라져도 로그인이 한꺼번에 끊기지 않게).
     */
    public boolean idleExpired(Instant lastActivity, Instant bootMarker, Instant now) {
        if (!idleCheckEnabled()) {
            return false;
        }
        Instant threshold = now.minus(idleTimeout);
        if (lastActivity != null) {
            return lastActivity.isBefore(threshold);
        }
        return bootMarker == null || !bootMarker.isAfter(threshold);
    }
}
