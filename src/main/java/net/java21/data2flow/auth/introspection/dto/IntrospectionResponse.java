package net.java21.data2flow.auth.introspection.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

/**
 * API-IAM-34 응답 {@code {active, sub, org, jti, sid, typ(ACCESS|API_KEY|MCP), tokenId, scopes, spaceScope, exp, inactiveReason}}.
 * active=false여도 200이다(계약 응답). gateway는 inactiveReason으로 401 코드를 고른다:
 * EXPIRED → {@code AUTH_TOKEN_EXPIRED}, REVOKED → {@code AUTH_SESSION_REVOKED}, INVALID → {@code AUTH_TOKEN_INVALID}.
 * ID는 JSON 문자열, {@code exp}는 epoch 초다. 장기 토큰이면 gateway 키별 한도용 {@code rateLimitPerMin}을 더 준다(IAM-05.04).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record IntrospectionResponse(boolean active, String sub, String org, String jti, String sid, String typ, String tokenId,
                                    List<String> scopes, List<String> spaceScope, Long exp, String inactiveReason,
                                    Long rateLimitPerMin) {

    public enum InactiveReason {
        EXPIRED,
        REVOKED,
        INVALID
    }

    public static IntrospectionResponse inactive(InactiveReason reason) {
        return new IntrospectionResponse(false, null, null, null, null, null, null, null, null, null, reason.name(), null);
    }
}
