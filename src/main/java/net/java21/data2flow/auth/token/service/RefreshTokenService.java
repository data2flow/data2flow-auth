package net.java21.data2flow.auth.token.service;

import net.java21.data2flow.auth.audit.service.AuthAuditActions;
import net.java21.data2flow.auth.client.CoreClient;
import net.java21.data2flow.auth.client.RefreshReuseDetectedException;
import net.java21.data2flow.auth.client.dto.RotateRefreshTokenRequest;
import net.java21.data2flow.auth.client.dto.RotationDecision;
import net.java21.data2flow.auth.common.ClientInfo;
import net.java21.data2flow.auth.common.Hashes;
import net.java21.data2flow.auth.config.AuthProperties;
import net.java21.data2flow.auth.ratelimit.service.AuthRateLimiter;
import net.java21.data2flow.auth.revocation.repository.BlacklistRepository;
import net.java21.data2flow.auth.revocation.service.RevocationService;
import net.java21.data2flow.auth.session.domain.SessionPolicy;
import net.java21.data2flow.auth.token.domain.IssuedToken;
import net.java21.data2flow.auth.token.domain.JwtCodec;
import net.java21.data2flow.auth.token.domain.TokenClaims;
import net.java21.data2flow.auth.token.domain.TokenType;
import net.java21.data2flow.auth.token.domain.TokenVerification;
import net.java21.data2flow.contracts.audit.AuditActorType;
import net.java21.data2flow.contracts.audit.AuditEvent;
import net.java21.data2flow.contracts.audit.AuditRecorder;
import net.java21.data2flow.contracts.audit.AuditResult;
import net.java21.data2flow.contracts.error.BusinessException;
import net.java21.data2flow.contracts.error.CommonErrorCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

/**
 * 토큰 재발급과 Refresh 회전(API-IAM-02, IAM-07.03, crowfoot RefreshTokenService 준용).
 *
 * <ol>
 *   <li>Refresh 서명·typ 확인. 만료(6시간 슬라이딩)면 {@code AUTH_SESSION_EXPIRED}, 그 밖은 {@code AUTH_TOKEN_INVALID}</li>
 *   <li>sid당 분당 10회 한도, 절대 만료(12시간)·폐기 목록·유휴 만료(30분) 확인(BR-IAM-15)</li>
 *   <li>다음 Refresh 후보를 만들어 core 판정(ROTATED/GRACE). 재사용이면 sid를 블랙리스트에 올려 그 로그인의 Access도 바로 막는다
 *       (design/auth.md §4.1 [보강]) → 401 {@code AUTH_SESSION_REVOKED} + 감사 {@code REFRESH_REUSED}</li>
 *   <li>Access 발급, 세션 활동 기록, 감사 {@code TOKEN_REFRESHED}</li>
 * </ol>
 */
@Service
public class RefreshTokenService {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenService.class);
    public static final String REASON_REUSE_DETECTED = "REUSE_DETECTED";

    private final JwtCodec jwt;
    private final CoreClient core;
    private final BlacklistRepository sessionStore;
    private final RevocationService revocations;
    private final AuthRateLimiter rateLimiter;
    private final AuditRecorder audit;
    private final AuthProperties properties;
    private final SessionPolicy sessionPolicy;

    public RefreshTokenService(JwtCodec jwt, CoreClient core, BlacklistRepository sessionStore, RevocationService revocations,
                               AuthRateLimiter rateLimiter, AuditRecorder audit, AuthProperties properties,
                               SessionPolicy sessionPolicy) {
        this.jwt = jwt;
        this.core = core;
        this.sessionStore = sessionStore;
        this.revocations = revocations;
        this.rateLimiter = rateLimiter;
        this.audit = audit;
        this.properties = properties;
        this.sessionPolicy = sessionPolicy;
    }

    public SessionTokens refresh(String refreshToken, ClientInfo client) {
        TokenVerification verification = jwt.verify(refreshToken, TokenType.REFRESH);
        if (!verification.valid()) {
            throw new BusinessException(verification.failure() == TokenVerification.Failure.EXPIRED
                    ? CommonErrorCode.AUTH_SESSION_EXPIRED : CommonErrorCode.AUTH_TOKEN_INVALID);
        }
        TokenClaims claims = verification.claims();
        rateLimiter.refreshBySid(claims.sid());
        Instant now = jwt.now();
        if (sessionPolicy.absolutelyExpired(now, claims.absoluteExpiresAt())) {
            throw new BusinessException(CommonErrorCode.AUTH_SESSION_EXPIRED);
        }
        // 폐기 목록·유휴 만료 확인(표식이 없으면 먼저 다시 적재 — 폐기한 세션이 Redis 재시작으로 살아나지 않게)
        revocations.reloadIfMarkerMissing();
        BlacklistRepository.Snapshot snapshot = sessionStore.snapshot(claims.jti(), claims.sid());
        if (snapshot.sidRevoked()) {
            throw new BusinessException(CommonErrorCode.AUTH_SESSION_REVOKED);
        }
        if (sessionPolicy.idleExpired(snapshot.lastActivity(), snapshot.bootMarker(), now)) {
            throw new BusinessException(CommonErrorCode.AUTH_SESSION_EXPIRED);
        }

        Instant absolute = claims.absoluteExpiresAt();
        Instant refreshExpiry = sessionPolicy.tokenExpiry(now, properties.token().refreshTtl(), absolute);
        IssuedToken candidate = jwt.issueRefresh(claims.userId(), claims.organizationId(), claims.sid(),
                UUID.randomUUID().toString(), refreshExpiry, absolute);
        RotationDecision decision;
        try {
            decision = core.rotateRefreshToken(new RotateRefreshTokenRequest(claims.jti(), candidate.jti(),
                    Hashes.sha256Hex(candidate.value()), candidate.expiresAt()));
        } catch (RefreshReuseDetectedException ex) {
            onReuse(claims, client, now);
            throw new BusinessException(CommonErrorCode.AUTH_SESSION_REVOKED);
        }
        IssuedToken nextRefresh = candidate;
        if (decision.decision() == RotationDecision.Decision.GRACE) {
            // 유예(30초) 안의 재사용(여러 탭): 계보의 최신 jti로 다시 발급한다. core는 GRACE에서 새 행을 만들지 않는다
            if (decision.effectiveJti() == null) {
                throw new BusinessException(CommonErrorCode.AUTH_TOKEN_INVALID);
            }
            nextRefresh = jwt.issueRefresh(claims.userId(), claims.organizationId(), claims.sid(), decision.effectiveJti(),
                    refreshExpiry, absolute);
        }
        IssuedToken access = jwt.issueAccess(claims.userId(), claims.organizationId(), claims.sid(),
                UUID.randomUUID().toString(), sessionPolicy.tokenExpiry(now, properties.token().accessTtl(), absolute));
        if (sessionPolicy.idleCheckEnabled()) {
            sessionStore.touchActivity(claims.sid(), now, sessionPolicy.idleTimeout());
        }
        audit.record(AuditEvent.builder(claims.organizationId(), AuthAuditActions.TOKEN_REFRESHED)
                .occurredAt(now)
                .actor(AuditActorType.USER, Long.toString(claims.userId()), null)
                .target("SESSION", claims.sid())
                .detail("decision", decision.decision().name())
                .ip(client.ip())
                .userAgent(client.userAgent())
                .build());
        return new SessionTokens(claims.userId(), claims.organizationId(), claims.sid(), access, nextRefresh, false);
    }

    /** 재사용 탐지(BR-IAM-14): core가 계보를 폐기했고, auth는 그 sid의 Access를 바로 막고 기록한다 */
    private void onReuse(TokenClaims claims, ClientInfo client, Instant now) {
        log.atWarn().addKeyValue("sid", claims.sid()).addKeyValue("userId", claims.userId())
                .log("Refresh 재사용 탐지 — 로그인 계열 전체 폐기(BR-IAM-14)");
        revocations.revokeSession(claims.sid(), REASON_REUSE_DETECTED);
        audit.record(AuditEvent.builder(claims.organizationId(), AuthAuditActions.REFRESH_REUSED)
                .occurredAt(now)
                .actor(AuditActorType.USER, Long.toString(claims.userId()), null)
                .target("SESSION", claims.sid())
                .result(AuditResult.FAILURE)
                .detail("presentedJti", claims.jti())
                .ip(client.ip())
                .userAgent(client.userAgent())
                .build());
    }
}
