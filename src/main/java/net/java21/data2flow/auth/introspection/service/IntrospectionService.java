package net.java21.data2flow.auth.introspection.service;

import net.java21.data2flow.auth.client.CoreClient;
import net.java21.data2flow.auth.client.dto.ApiTokenVerification;
import net.java21.data2flow.auth.common.Hashes;
import net.java21.data2flow.auth.introspection.dto.IntrospectionResponse;
import net.java21.data2flow.auth.introspection.dto.IntrospectionResponse.InactiveReason;
import net.java21.data2flow.auth.revocation.repository.BlacklistRepository;
import net.java21.data2flow.auth.revocation.service.RevocationService;
import net.java21.data2flow.auth.session.domain.SessionPolicy;
import net.java21.data2flow.auth.token.domain.JwtCodec;
import net.java21.data2flow.auth.token.domain.TokenClaims;
import net.java21.data2flow.auth.token.domain.TokenType;
import net.java21.data2flow.auth.token.domain.TokenVerification;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.regex.Pattern;

/**
 * 토큰 조회(introspection, API-IAM-34, IAM-07.02·07.10). gateway만 부른다.
 *
 * <ul>
 *   <li>JWT: 서명·kid·exp·iss·aud·typ=ACCESS 확인 → 블랙리스트(jti·sid)·재적재 표식·세션 활동을 MGET 한 번 →
 *       폐기면 REVOKED, 유휴 만료(30분)면 EXPIRED, 아니면 활동을 기록하고 active</li>
 *   <li>장기 토큰({@code data2flow_} 접두): 원문의 SHA-256으로 core API-IAM-46에 묻는다</li>
 *   <li>Redis·core 장애: 예외 → 503 {@code SERVICE_UNAVAILABLE}(fail-closed, BR-IAM-24). 표식이 없으면(Redis 비워짐)
 *       core에서 다시 적재한 뒤에만 판정한다</li>
 * </ul>
 */
@Service
public class IntrospectionService {

    public static final String LONG_LIVED_PREFIX = "data2flow_";
    private static final Pattern LONG_LIVED = Pattern.compile("data2flow_[A-Za-z0-9_-]{20,200}");
    private static final Pattern NUMERIC = Pattern.compile("[1-9][0-9]{0,18}");

    private final JwtCodec jwt;
    private final BlacklistRepository blacklist;
    private final RevocationService revocations;
    private final CoreClient core;
    private final SessionPolicy sessionPolicy;

    public IntrospectionService(JwtCodec jwt, BlacklistRepository blacklist, RevocationService revocations, CoreClient core,
                                SessionPolicy sessionPolicy) {
        this.jwt = jwt;
        this.blacklist = blacklist;
        this.revocations = revocations;
        this.core = core;
        this.sessionPolicy = sessionPolicy;
    }

    public IntrospectionResponse introspect(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return IntrospectionResponse.inactive(InactiveReason.INVALID);
        }
        String token = rawToken.trim();
        if (token.startsWith(LONG_LIVED_PREFIX)) {
            return introspectLongLived(token);
        }
        TokenVerification verification = jwt.verify(token, TokenType.ACCESS);
        if (!verification.valid()) {
            return IntrospectionResponse.inactive(verification.failure() == TokenVerification.Failure.EXPIRED
                    ? InactiveReason.EXPIRED : InactiveReason.INVALID);
        }
        TokenClaims claims = verification.claims();
        BlacklistRepository.Snapshot snapshot = blacklist.snapshot(claims.jti(), claims.sid());
        if (snapshot.bootMarker() == null) {
            revocations.reloadIfMarkerMissing();
            snapshot = blacklist.snapshot(claims.jti(), claims.sid());
        }
        if (snapshot.revoked()) {
            return IntrospectionResponse.inactive(InactiveReason.REVOKED);
        }
        Instant now = jwt.now();
        if (sessionPolicy.idleExpired(snapshot.lastActivity(), snapshot.bootMarker(), now)) {
            return IntrospectionResponse.inactive(InactiveReason.EXPIRED);
        }
        if (sessionPolicy.idleCheckEnabled()) {
            blacklist.touchActivity(claims.sid(), now, sessionPolicy.idleTimeout());
        }
        return new IntrospectionResponse(true, Long.toString(claims.userId()), Long.toString(claims.organizationId()),
                claims.jti(), claims.sid(), TokenType.ACCESS.name(), null, null, null, claims.expiresAt().getEpochSecond(),
                null, null);
    }

    /** 장기 토큰(MCP·API 키, IAM-05). 폐기는 core 조회로 바로 반영되므로 블랙리스트를 보지 않는다 */
    private IntrospectionResponse introspectLongLived(String token) {
        if (!LONG_LIVED.matcher(token).matches()) {
            return IntrospectionResponse.inactive(InactiveReason.INVALID);
        }
        ApiTokenVerification verified = core.verifyApiToken(Hashes.sha256Hex(token));
        String sub = verified.userId() != null ? verified.userId() : verified.ownerId();
        if (!verified.active() || sub == null || !NUMERIC.matcher(sub).matches() || verified.org() == null
                || !NUMERIC.matcher(verified.org()).matches() || verified.tokenId() == null) {
            return IntrospectionResponse.inactive(InactiveReason.INVALID);
        }
        String typ = "MCP".equals(verified.kind()) ? "MCP" : "API_KEY";
        return new IntrospectionResponse(true, sub, verified.org(), null, null, typ, verified.tokenId(), verified.scopes(),
                verified.spaceScope(), null, null, verified.rateLimitPerMin());
    }
}
