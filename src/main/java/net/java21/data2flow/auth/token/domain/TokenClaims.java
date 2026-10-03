package net.java21.data2flow.auth.token.domain;

import java.time.Instant;

/**
 * 검증을 통과한 토큰의 클레임. Access 클레임은 {@code sub, org, sid, jti, typ, iss, aud, iat, nbf, exp}로 고정이다(BR-IAM-36).
 * Refresh에만 세션 절대 만료 {@code aexp}가 더 있다(IAM-03.01 최대 수명 12시간).
 *
 * @param userId            {@code sub}
 * @param organizationId    {@code org}
 * @param sid               로그인 계열
 * @param jti               토큰 ID
 * @param type              ACCESS / REFRESH
 * @param expiresAt         {@code exp}
 * @param absoluteExpiresAt Refresh의 {@code aexp}. Access는 null
 */
public record TokenClaims(long userId, long organizationId, String sid, String jti, TokenType type, Instant expiresAt,
                          Instant absoluteExpiresAt) {
}
