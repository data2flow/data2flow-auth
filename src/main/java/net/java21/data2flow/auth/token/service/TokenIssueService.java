package net.java21.data2flow.auth.token.service;

import net.java21.data2flow.auth.audit.service.AuthAuditActions;
import net.java21.data2flow.auth.client.CoreClient;
import net.java21.data2flow.auth.client.dto.RegisterRefreshTokenRequest;
import net.java21.data2flow.auth.common.ClientInfo;
import net.java21.data2flow.auth.common.Hashes;
import net.java21.data2flow.auth.config.AuthProperties;
import net.java21.data2flow.auth.revocation.repository.BlacklistRepository;
import net.java21.data2flow.auth.session.domain.SessionPolicy;
import net.java21.data2flow.auth.token.domain.IssuedToken;
import net.java21.data2flow.auth.token.domain.JwtCodec;
import net.java21.data2flow.contracts.audit.AuditActorType;
import net.java21.data2flow.contracts.audit.AuditEvent;
import net.java21.data2flow.contracts.audit.AuditRecorder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

/**
 * 로그인을 마친 사용자에게 토큰을 발급한다(IAM-07.01, crowfoot TokenIssueService 준용).
 * sid 생성 → Access(60분)·Refresh(6시간) 발급 → 세션 활동 기록 → core에 Refresh 계보 등록(실패하면 로그인 실패, fail-closed)
 * → 감사 {@code USER_LOGGED_IN}. 두 토큰 모두 세션 절대 만료(12시간)를 넘지 않는다.
 */
@Service
public class TokenIssueService {

    private final JwtCodec jwt;
    private final CoreClient core;
    private final BlacklistRepository sessionStore;
    private final AuditRecorder audit;
    private final AuthProperties properties;
    private final SessionPolicy sessionPolicy;

    public TokenIssueService(JwtCodec jwt, CoreClient core, BlacklistRepository sessionStore, AuditRecorder audit,
                             AuthProperties properties, SessionPolicy sessionPolicy) {
        this.jwt = jwt;
        this.core = core;
        this.sessionStore = sessionStore;
        this.audit = audit;
        this.properties = properties;
        this.sessionPolicy = sessionPolicy;
    }

    public SessionTokens issueForLogin(long userId, long organizationId, boolean mustChangePassword, boolean viaMfa,
                                       ClientInfo client) {
        Instant now = jwt.now();
        String sid = UUID.randomUUID().toString();
        Instant absolute = sessionPolicy.absoluteExpiry(now);
        IssuedToken access = jwt.issueAccess(userId, organizationId, sid, UUID.randomUUID().toString(),
                sessionPolicy.tokenExpiry(now, properties.token().accessTtl(), absolute));
        IssuedToken refresh = jwt.issueRefresh(userId, organizationId, sid, UUID.randomUUID().toString(),
                sessionPolicy.tokenExpiry(now, properties.token().refreshTtl(), absolute), absolute);
        if (sessionPolicy.idleCheckEnabled()) {
            sessionStore.touchActivity(sid, now, sessionPolicy.idleTimeout());
        }
        core.registerRefreshToken(new RegisterRefreshTokenRequest(refresh.jti(), sid, Long.toString(userId),
                Long.toString(organizationId), Hashes.sha256Hex(refresh.value()), refresh.expiresAt(), absolute,
                client.ip(), client.userAgent()));
        audit.record(AuditEvent.builder(organizationId, AuthAuditActions.USER_LOGGED_IN)
                .occurredAt(now)
                .actor(AuditActorType.USER, Long.toString(userId), null)
                .target("USER", Long.toString(userId))
                .detail("sid", sid)
                .detail("mfa", viaMfa)
                .ip(client.ip())
                .userAgent(client.userAgent())
                .build());
        return new SessionTokens(userId, organizationId, sid, access, refresh, mustChangePassword);
    }
}
