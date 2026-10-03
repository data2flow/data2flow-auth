package net.java21.data2flow.auth.revocation.event;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/**
 * EVT-IAM-03 토큰 폐기 알림. Redis Pub/Sub 채널 {@code data2flow:auth.revocations}(RabbitMQ 아님, 지연 최소화).
 * 소비: 모든 gateway 인스턴스(검증 캐시 삭제), BFF(Access 캐시 삭제). 페이로드 {@code {type: SID|JTI|TOKEN_ID, value, reason, occurredAt}}.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record RevocationEvent(Type type, String value, String reason, Instant occurredAt) {

    public static final String CHANNEL = "data2flow:auth.revocations";

    /** 소비자 편의: type=SID면 {@code sid}에도 같은 값(gateway는 type·value를 읽는다) */
    @JsonProperty("sid")
    public String sid() {
        return type == Type.SID ? value : null;
    }

    /** type=JTI면 {@code jti}에도 같은 값 */
    @JsonProperty("jti")
    public String jti() {
        return type == Type.JTI ? value : null;
    }

    public enum Type {
        SID,
        JTI,
        TOKEN_ID
    }
}
