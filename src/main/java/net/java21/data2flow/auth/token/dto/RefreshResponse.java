package net.java21.data2flow.auth.token.dto;

import net.java21.data2flow.auth.token.service.SessionTokens;

import java.time.Instant;

/**
 * 재발급 응답(API-IAM-02) {@code {accessToken, expiresIn}} + BFF용 {@code tokenType}, {@code sid}, 새 {@code refreshToken}
 * (Set-Cookie {@code data2flow_refresh}와 같은 값 — BFF가 세션 쿠키를 다시 쓴다).
 */
public record RefreshResponse(String accessToken, String tokenType, long expiresIn, String sid, String refreshToken) {

    public static RefreshResponse of(SessionTokens tokens, Instant now) {
        return new RefreshResponse(tokens.access().value(), TokenResponse.BEARER,
                TokenResponse.secondsUntil(now, tokens.access().expiresAt()), tokens.sid(), tokens.refresh().value());
    }
}
