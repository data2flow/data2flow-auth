package net.java21.data2flow.auth.token.domain;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * JWT 발급과 검증(IAM-07.02, BR-IAM-36). <b>JWT를 해석하는 곳은 이 클래스뿐</b>이다(ArchUnit으로 강제, TC-IAM-187).
 * HS256 + kid. 역할·공간·개인정보는 넣지 않는다. 시각은 주입한 {@link Clock}으로만 계산한다.
 */
public final class JwtCodec {

    public static final String CLAIM_ORG = "org";
    public static final String CLAIM_SID = "sid";
    public static final String CLAIM_TYP = "typ";
    /** Refresh 전용: 세션 절대 만료(최초 로그인 + 12시간, IAM-03.01) */
    public static final String CLAIM_ABSOLUTE_EXP = "aexp";

    private static final Pattern NUMERIC = Pattern.compile("[1-9][0-9]{0,18}");
    private static final Pattern UUID_LIKE = Pattern.compile("[0-9a-fA-F-]{32,36}");

    private final SigningKeyRing keyRing;
    private final String issuer;
    private final String audience;
    private final Duration clockSkew;
    private final Clock clock;

    public JwtCodec(SigningKeyRing keyRing, String issuer, String audience, Duration clockSkew, Clock clock) {
        this.keyRing = Objects.requireNonNull(keyRing);
        this.issuer = Objects.requireNonNull(issuer);
        this.audience = Objects.requireNonNull(audience);
        this.clockSkew = Objects.requireNonNull(clockSkew);
        this.clock = Objects.requireNonNull(clock);
    }

    /** 지금 시각(초 단위로 자름 — JWT 시각이 초 단위이므로 발급 결과와 클레임이 같아지게) */
    public Instant now() {
        return clock.instant().truncatedTo(ChronoUnit.SECONDS);
    }

    /**
     * Access 발급. 만료는 {@code min(now + ttl, 세션 절대 만료)}로, 12시간이 지난 세션의 Access가 남지 않게 한다.
     */
    public IssuedToken issueAccess(long userId, long organizationId, String sid, String jti, Instant expiresAt) {
        return issue(TokenType.ACCESS, userId, organizationId, sid, jti, expiresAt, null);
    }

    /** Refresh 발급. {@code aexp}(세션 절대 만료)를 함께 싣는다 */
    public IssuedToken issueRefresh(long userId, long organizationId, String sid, String jti, Instant expiresAt,
                                    Instant absoluteExpiresAt) {
        return issue(TokenType.REFRESH, userId, organizationId, sid, jti, expiresAt,
                Objects.requireNonNull(absoluteExpiresAt, "absoluteExpiresAt"));
    }

    private IssuedToken issue(TokenType type, long userId, long organizationId, String sid, String jti, Instant expiresAt,
                              Instant absoluteExpiresAt) {
        Instant now = now();
        Instant exp = expiresAt.truncatedTo(ChronoUnit.SECONDS);
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .subject(Long.toString(userId))
                .claim(CLAIM_ORG, Long.toString(organizationId))
                .claim(CLAIM_SID, sid)
                .jwtID(jti)
                .claim(CLAIM_TYP, type.name())
                .issuer(issuer)
                .audience(audience)
                .issueTime(Date.from(now))
                .notBeforeTime(Date.from(now))
                .expirationTime(Date.from(exp));
        if (absoluteExpiresAt != null) {
            claims.claim(CLAIM_ABSOLUTE_EXP, absoluteExpiresAt.getEpochSecond());
        }
        SigningKey key = keyRing.active();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID(key.keyId()).type(JOSEObjectType.JWT).build(),
                claims.build());
        try {
            jwt.sign(new MACSigner(key.secret()));
        } catch (JOSEException ex) {
            throw new IllegalStateException("JWT 서명 실패", ex);
        }
        return new IssuedToken(jwt.serialize(), jti, sid, exp);
    }

    /** 서명·kid·iss·aud·typ·nbf·exp를 확인한다. 만료만 따로 EXPIRED로 알리고, 나머지 실패는 INVALID다 */
    public TokenVerification verify(String token, TokenType expectedType) {
        return verify(token, expectedType, false);
    }

    /** 만료를 허용하고 검증한다(로그아웃에서 만료 직후 Refresh로도 세션을 끊을 수 있게) */
    public TokenVerification verifyIgnoringExpiry(String token, TokenType expectedType) {
        return verify(token, expectedType, true);
    }

    private TokenVerification verify(String token, TokenType expectedType, boolean ignoreExpiry) {
        if (token == null || token.isBlank() || token.length() > 4096) {
            return TokenVerification.fail(TokenVerification.Failure.INVALID);
        }
        try {
            SignedJWT jwt = SignedJWT.parse(token.trim());
            if (!JWSAlgorithm.HS256.equals(jwt.getHeader().getAlgorithm())) {
                return TokenVerification.fail(TokenVerification.Failure.INVALID);
            }
            Instant now = clock.instant();
            SigningKey key = keyRing.find(jwt.getHeader().getKeyID()).orElse(null);
            if (key == null || !key.verifiableAt(now) || !jwt.verify(new MACVerifier(key.secret()))) {
                return TokenVerification.fail(TokenVerification.Failure.INVALID);
            }
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            TokenClaims parsed = parseClaims(claims, expectedType);
            if (parsed == null) {
                return TokenVerification.fail(TokenVerification.Failure.INVALID);
            }
            Date nbf = claims.getNotBeforeTime();
            if (nbf != null && nbf.toInstant().isAfter(now.plus(clockSkew))) {
                return TokenVerification.fail(TokenVerification.Failure.INVALID);
            }
            if (!ignoreExpiry && !parsed.expiresAt().plus(clockSkew).isAfter(now)) {
                return TokenVerification.fail(TokenVerification.Failure.EXPIRED);
            }
            return TokenVerification.ok(parsed);
        } catch (ParseException | JOSEException | RuntimeException ex) {
            return TokenVerification.fail(TokenVerification.Failure.INVALID);
        }
    }

    private TokenClaims parseClaims(JWTClaimsSet claims, TokenType expectedType) throws ParseException {
        String typ = claims.getStringClaim(CLAIM_TYP);
        String sub = claims.getSubject();
        String org = claims.getStringClaim(CLAIM_ORG);
        String sid = claims.getStringClaim(CLAIM_SID);
        String jti = claims.getJWTID();
        List<String> aud = claims.getAudience();
        Date exp = claims.getExpirationTime();
        if (!expectedType.name().equals(typ) || !issuer.equals(claims.getIssuer()) || aud == null || !aud.contains(audience)
                || exp == null || claims.getIssueTime() == null || sub == null || !NUMERIC.matcher(sub).matches()
                || org == null || !NUMERIC.matcher(org).matches() || sid == null || !UUID_LIKE.matcher(sid).matches()
                || jti == null || !UUID_LIKE.matcher(jti).matches()) {
            return null;
        }
        Instant absolute = null;
        if (expectedType == TokenType.REFRESH) {
            Long aexp = claims.getLongClaim(CLAIM_ABSOLUTE_EXP);
            if (aexp == null) {
                return null;
            }
            absolute = Instant.ofEpochSecond(aexp);
        }
        return new TokenClaims(Long.parseLong(sub), Long.parseLong(org), sid, jti, expectedType, exp.toInstant(), absolute);
    }
}
