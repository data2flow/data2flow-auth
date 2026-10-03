package net.java21.data2flow.auth.client.dto;

import java.time.Instant;

/** API-IAM-35 요청 본문 */
public record RotateRefreshTokenRequest(String presentedJti, String nextJti, String nextTokenHash, Instant nextExpiresAt) {
}
