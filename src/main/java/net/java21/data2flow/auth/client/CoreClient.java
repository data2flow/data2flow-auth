package net.java21.data2flow.auth.client;

import net.java21.data2flow.auth.client.dto.ApiTokenVerification;
import net.java21.data2flow.auth.client.dto.RegisterRefreshTokenRequest;
import net.java21.data2flow.auth.client.dto.Revocations;
import net.java21.data2flow.auth.client.dto.RotateRefreshTokenRequest;
import net.java21.data2flow.auth.client.dto.RotationDecision;
import net.java21.data2flow.auth.client.dto.VerifiedCredentials;
import net.java21.data2flow.contracts.audit.AuditEvent;

import java.time.Instant;

/**
 * core-api 내부 API(design/api/IAM-api.md §7). 회원·Refresh 계보·폐기 기록·감사의 원천은 core에 있다.
 * core가 응답하지 않거나 5xx면 {@link net.java21.data2flow.auth.common.DependencyUnavailableException}을 던진다(fail-closed).
 */
public interface CoreClient {

    /** API-IAM-30. 실패: 401 AUTH_INVALID_CREDENTIALS(원인 구분 없음), 403 AUTH_PENDING_APPROVAL */
    VerifiedCredentials verifyCredentials(String loginId, String password, String ip, String userAgent);

    /** API-IAM-36. 실패하면 로그인 전체가 실패한다(fail-closed) */
    void registerRefreshToken(RegisterRefreshTokenRequest request);

    /** API-IAM-35. 재사용이면 {@link RefreshReuseDetectedException} */
    RotationDecision rotateRefreshToken(RotateRefreshTokenRequest request);

    /** API-IAM-37 {@code DELETE /internal/core/sessions/{sid}}. 이미 없으면(404) 성공으로 본다(멱등) */
    void revokeSession(String sid, String reason);

    /** API-IAM-39a */
    Revocations findRevocationsSince(Instant since);

    /** API-IAM-61b. 코드가 맞으면 true */
    boolean verifyMfa(long userId, String code);

    /** API-IAM-46 */
    ApiTokenVerification verifyApiToken(String tokenHash);

    /** API-IAM-39(202). 호출한 쪽은 결과를 기다리지 않는다 */
    void recordAudit(AuditEvent event);
}
