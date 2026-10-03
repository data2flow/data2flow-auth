package net.java21.data2flow.auth.client.dto;

/** API-IAM-30 성공 응답 {@code {userId, orgId, mustChangePassword, mfaEnabled}} */
public record VerifiedCredentials(long userId, long organizationId, boolean mustChangePassword, boolean mfaEnabled) {
}
