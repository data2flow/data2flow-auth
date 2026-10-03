package net.java21.data2flow.auth.client.dto;

import java.time.Instant;

/** API-IAM-36 요청 본문. 원문 토큰은 보내지 않고 SHA-256 해시만 보낸다(design/auth.md §10 [보강]) */
public record RegisterRefreshTokenRequest(String jti, String sid, String userId, String orgId, String tokenHash,
                                          Instant expiresAt, Instant absoluteExpiresAt, String ip, String userAgent) {
}
