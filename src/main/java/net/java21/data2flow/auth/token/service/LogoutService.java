package net.java21.data2flow.auth.token.service;

import net.java21.data2flow.auth.audit.service.AuthAuditActions;
import net.java21.data2flow.auth.client.CoreClient;
import net.java21.data2flow.auth.common.ClientInfo;
import net.java21.data2flow.auth.revocation.service.RevocationService;
import net.java21.data2flow.auth.token.domain.JwtCodec;
import net.java21.data2flow.auth.token.domain.TokenClaims;
import net.java21.data2flow.auth.token.domain.TokenType;
import net.java21.data2flow.auth.token.domain.TokenVerification;
import net.java21.data2flow.contracts.audit.AuditActorType;
import net.java21.data2flow.contracts.audit.AuditEvent;
import net.java21.data2flow.contracts.audit.AuditRecorder;
import org.springframework.stereotype.Service;

/**
 * 로그아웃(API-IAM-03, IAM-07.05). 멱등: Refresh가 없거나 틀려도 204다.
 * core에서 세션 계보 폐기(원천) → {@code data2flow:bl:sid:{sid}} 등록 + EVT-IAM-03 → 감사 {@code USER_LOGGED_OUT}.
 * 그 로그인으로 받은 모든 Access가 바로 막힌다(crowfoot은 jti 하나만 막았음 — design/auth.md §11 #5).
 */
@Service
public class LogoutService {

    public static final String REASON_LOGOUT = "LOGOUT";

    private final JwtCodec jwt;
    private final CoreClient core;
    private final RevocationService revocations;
    private final AuditRecorder audit;

    public LogoutService(JwtCodec jwt, CoreClient core, RevocationService revocations, AuditRecorder audit) {
        this.jwt = jwt;
        this.core = core;
        this.revocations = revocations;
        this.audit = audit;
    }

    public void logout(String refreshToken, ClientInfo client) {
        TokenVerification verification = jwt.verifyIgnoringExpiry(refreshToken, TokenType.REFRESH);
        if (!verification.valid()) {
            return;
        }
        TokenClaims claims = verification.claims();
        core.revokeSession(claims.sid(), REASON_LOGOUT);
        revocations.revokeSession(claims.sid(), REASON_LOGOUT);
        audit.record(AuditEvent.builder(claims.organizationId(), AuthAuditActions.USER_LOGGED_OUT)
                .occurredAt(jwt.now())
                .actor(AuditActorType.USER, Long.toString(claims.userId()), null)
                .target("SESSION", claims.sid())
                .ip(client.ip())
                .userAgent(client.userAgent())
                .build());
    }
}
