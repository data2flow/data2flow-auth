package net.java21.data2flow.auth.token.domain;

import java.time.Instant;

/**
 * 발급한 토큰 한 개.
 *
 * @param value     JWT 원문
 * @param jti       토큰 ID(UUID)
 * @param sid       로그인 계열(세션) ID(UUID)
 * @param expiresAt 만료 시각
 */
public record IssuedToken(String value, String jti, String sid, Instant expiresAt) {

    @Override
    public String toString() {
        return "IssuedToken[jti=" + jti + ", sid=" + sid + ", expiresAt=" + expiresAt + ", value=***]";
    }
}
