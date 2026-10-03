package net.java21.data2flow.auth.client.dto;

/**
 * API-IAM-35 응답 {@code {decision: ROTATED|GRACE, effectiveJti}}.
 * ROTATED면 auth가 보낸 다음 후보가 새 Refresh이고, GRACE(회전 후 30초 안의 재사용, 여러 탭)면 계보의 최신 jti로 다시 발급한다.
 */
public record RotationDecision(Decision decision, String effectiveJti) {

    public enum Decision {
        ROTATED,
        GRACE
    }
}
