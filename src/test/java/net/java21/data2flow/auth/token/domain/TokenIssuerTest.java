package net.java21.data2flow.auth.token.domain;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.java21.data2flow.auth.support.MutableClock;
import net.java21.data2flow.auth.support.TestKeys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 운영 서명기로 실제 JWT를 발급·검증한다(design/testing/backend.md §4.1 TokenIssuerTest).
 * 위조 키, 만료, nbf, kid 교체 기간에 이전 키와 새 키 모두 검증되는지.
 */
class TokenIssuerTest {

    private final MutableClock clock = MutableClock.atDefault();
    private final JwtCodec codec = TestKeys.codec(clock);
    private final String sid = UUID.randomUUID().toString();

    private IssuedToken access(JwtCodec c) {
        return c.issueAccess(11, 1, sid, UUID.randomUUID().toString(), clock.instant().plus(Duration.ofHours(1)));
    }

    @Test
    @DisplayName("[IAM-07.02] 발급한 Access를 검증하면 클레임이 그대로 나온다")
    void roundTrip() {
        IssuedToken token = access(codec);

        TokenVerification v = codec.verify(token.value(), TokenType.ACCESS);

        assertThat(v.valid()).isTrue();
        assertThat(v.claims().userId()).isEqualTo(11);
        assertThat(v.claims().organizationId()).isEqualTo(1);
        assertThat(v.claims().sid()).isEqualTo(sid);
        assertThat(v.claims().jti()).isEqualTo(token.jti());
        assertThat(v.claims().expiresAt()).isEqualTo(token.expiresAt());
        assertThat(v.claims().absoluteExpiresAt()).isNull();
        assertThat(token.toString()).doesNotContain(token.value());
    }

    @Test
    @DisplayName("[IAM-07.02] 다른 키로 서명한 토큰(위조) → INVALID")
    void forgedKey() {
        JwtCodec forger = TestKeys.codec("t1:" + TestKeys.KEY2, "t1", clock);

        assertThat(codec.verify(access(forger).value(), TokenType.ACCESS).failure()).isEqualTo(TokenVerification.Failure.INVALID);
    }

    @Test
    @DisplayName("[IAM-07.02] 만료(허용 오차 30초 뒤) → EXPIRED, 허용 오차 안 → 유효")
    void expiry() {
        IssuedToken token = access(codec);
        clock.advance(Duration.ofHours(1).plusSeconds(20));
        assertThat(codec.verify(token.value(), TokenType.ACCESS).valid()).isTrue();

        clock.advance(Duration.ofSeconds(10));
        assertThat(codec.verify(token.value(), TokenType.ACCESS).failure()).isEqualTo(TokenVerification.Failure.EXPIRED);
        assertThat(codec.verifyIgnoringExpiry(token.value(), TokenType.ACCESS).valid()).isTrue();
    }

    @Test
    @DisplayName("[IAM-07.02] nbf가 허용 오차보다 미래 → INVALID")
    void notBefore() {
        IssuedToken token = access(codec);
        clock.advance(Duration.ofMinutes(-5));

        assertThat(codec.verify(token.value(), TokenType.ACCESS).failure()).isEqualTo(TokenVerification.Failure.INVALID);
    }

    @Test
    @DisplayName("[IAM-07.02][TC-IAM-185][AT-IAM-21.5] 키 교체: 이전 kid 토큰은 유예 동안 유효, 유예 종료 후 INVALID. 새 토큰은 새 kid")
    void keyRotation() {
        IssuedToken old = access(codec);
        Instant graceEnd = clock.instant().plus(Duration.ofHours(1));
        JwtCodec rotated = TestKeys.codec("t2:" + TestKeys.KEY2 + ",t1:" + TestKeys.KEY1 + "@" + graceEnd, "t2", clock);

        IssuedToken fresh = access(rotated);
        assertThat(rotated.verify(old.value(), TokenType.ACCESS).valid()).isTrue();
        assertThat(rotated.verify(fresh.value(), TokenType.ACCESS).valid()).isTrue();
        assertThat(new String(Base64.getUrlDecoder().decode(fresh.value().split("\\.")[0]))).contains("\"kid\":\"t2\"");

        clock.set(graceEnd);
        assertThat(rotated.verify(old.value(), TokenType.ACCESS).failure()).isEqualTo(TokenVerification.Failure.INVALID);
        assertThat(rotated.verify(fresh.value(), TokenType.ACCESS).valid()).isTrue();
    }

    @Test
    @DisplayName("[IAM-07.02] 종류가 다르면(Refresh를 Access로) INVALID, Refresh는 aexp가 있어야 한다")
    void typeMismatch() {
        Instant absolute = clock.instant().plus(Duration.ofHours(12));
        IssuedToken refresh = codec.issueRefresh(11, 1, sid, UUID.randomUUID().toString(), clock.instant().plus(Duration.ofHours(6)), absolute);

        assertThat(codec.verify(refresh.value(), TokenType.ACCESS).valid()).isFalse();
        TokenVerification v = codec.verify(refresh.value(), TokenType.REFRESH);
        assertThat(v.claims().absoluteExpiresAt()).isEqualTo(absolute);
        assertThat(codec.verify(access(codec).value(), TokenType.REFRESH).valid()).isFalse();
    }

    @Test
    @DisplayName("[IAM-07.02] kid 없음·모르는 kid·다른 알고리즘·iss/aud 불일치·숫자가 아닌 sub → INVALID")
    void malformed() throws Exception {
        assertThat(codec.verify(sign("t1", JWSAlgorithm.HS256, claims().build()), TokenType.ACCESS).valid()).isTrue();
        assertThat(codec.verify(sign(null, JWSAlgorithm.HS256, claims().build()), TokenType.ACCESS).valid()).isFalse();
        assertThat(codec.verify(sign("zz", JWSAlgorithm.HS256, claims().build()), TokenType.ACCESS).valid()).isFalse();
        assertThat(codec.verify(sign("t1", JWSAlgorithm.HS512, claims().build()), TokenType.ACCESS).valid()).isFalse();
        assertThat(codec.verify(sign("t1", JWSAlgorithm.HS256, claims().issuer("evil").build()), TokenType.ACCESS).valid()).isFalse();
        assertThat(codec.verify(sign("t1", JWSAlgorithm.HS256, claims().audience("other").build()), TokenType.ACCESS).valid()).isFalse();
        assertThat(codec.verify(sign("t1", JWSAlgorithm.HS256, claims().subject("abc").build()), TokenType.ACCESS).valid()).isFalse();
        assertThat(codec.verify(sign("t1", JWSAlgorithm.HS256, claims().claim("sid", "x").build()), TokenType.ACCESS).valid()).isFalse();
        assertThat(codec.verify(null, TokenType.ACCESS).valid()).isFalse();
        assertThat(codec.verify("a.b.c", TokenType.ACCESS).valid()).isFalse();
        assertThat(codec.verify("x".repeat(5000), TokenType.ACCESS).valid()).isFalse();
    }

    private JWTClaimsSet.Builder claims() {
        Instant now = clock.instant();
        return new JWTClaimsSet.Builder().subject("11").claim("org", "1").claim("sid", sid).jwtID(UUID.randomUUID().toString())
                .claim("typ", "ACCESS").issuer(TestKeys.ISSUER).audience(TestKeys.AUDIENCE).issueTime(Date.from(now))
                .notBeforeTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(600)));
    }

    private String sign(String kid, JWSAlgorithm alg, JWTClaimsSet claims) throws Exception {
        byte[] secret = Base64.getDecoder().decode(TestKeys.KEY1);
        if (alg == JWSAlgorithm.HS512) {
            secret = (new String(secret) + new String(secret)).getBytes();
        }
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(alg).keyID(kid).build(), claims);
        jwt.sign(new MACSigner(secret));
        return jwt.serialize();
    }
}
