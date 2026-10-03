package net.java21.data2flow.auth.client.dto;

import java.util.List;

/**
 * API-IAM-46 응답 {@code {active, ownerType, ownerId, userId, org, scopes, spaceScope, kind, tokenId, rateLimitPerMin}}.
 * 장기 토큰(MCP·API 키)은 IAM-05(M6) 범위지만 introspection 계약(API-IAM-34)에 들어 있어 그대로 중계한다.
 */
public record ApiTokenVerification(boolean active, String ownerType, String ownerId, String userId, String org,
                                   List<String> scopes, List<String> spaceScope, String kind, String tokenId,
                                   Long rateLimitPerMin) {
}
