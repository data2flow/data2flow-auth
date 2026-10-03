package net.java21.data2flow.auth.token.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import net.java21.data2flow.auth.token.service.SessionTokens;

import java.time.Duration;
import java.time.Instant;

/**
 * 로그인 응답(API-IAM-01·62) {@code {accessToken, tokenType, expiresIn, mustChangePassword, mfaRequired:false}}.
 * 이 응답은 클러스터 안에서 BFF만 받는다(브라우저로 가지 않음, ADR-024). BFF가 세션 쿠키({@code data2flow_session})에 넣을
 * {@code sid}·{@code refreshToken}·{@code userId}·{@code orgId}도 함께 준다(design/auth.md §3.2·§9.1 — BFF는 JWT를 해석하지 않으므로).
 * Refresh는 {@code Set-Cookie: data2flow_refresh}로도 준다.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record TokenResponse(String accessToken, String tokenType, long expiresIn, boolean mustChangePassword,
                            boolean mfaRequired, String sid, String refreshToken, String userId, String orgId) {

    public static final String BEARER = "Bearer";

    public static TokenResponse of(SessionTokens tokens, Instant now) {
        return new TokenResponse(tokens.access().value(), BEARER, secondsUntil(now, tokens.access().expiresAt()),
                tokens.mustChangePassword(), false, tokens.sid(), tokens.refresh().value(),
                Long.toString(tokens.userId()), Long.toString(tokens.organizationId()));
    }

    static long secondsUntil(Instant now, Instant expiresAt) {
        return Math.max(0, Duration.between(now, expiresAt).toSeconds());
    }
}
