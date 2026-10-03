package net.java21.data2flow.auth.token.domain;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

/**
 * HS256 서명 키 하나(design/auth.md §4 [보강] 키 교체). 키 값은 로그·toString에 나오지 않는다.
 *
 * @param keyId       JWT 헤더 {@code kid}
 * @param secret      32바이트 이상
 * @param verifyUntil 이 시각 뒤에는 이 키로 서명된 토큰을 받지 않는다(교체 유예 종료). null이면 제한 없음
 */
public record SigningKey(String keyId, byte[] secret, Instant verifyUntil) {

    static final int MIN_SECRET_BYTES = 32;

    public SigningKey {
        Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(secret, "secret");
        if (keyId.isBlank() || !keyId.matches("[A-Za-z0-9._-]{1,64}")) {
            throw new IllegalArgumentException("JWT 키 ID 형식이 맞지 않습니다: " + keyId);
        }
        if (secret.length < MIN_SECRET_BYTES) {
            throw new IllegalArgumentException("JWT 키 " + keyId + "는 32바이트 이상이어야 합니다");
        }
        secret = secret.clone();
    }

    @Override
    public byte[] secret() {
        return secret.clone();
    }

    /** 지금 이 키로 서명된 토큰을 검증해도 되는가 */
    public boolean verifiableAt(Instant now) {
        return verifyUntil == null || now.isBefore(verifyUntil);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof SigningKey other && keyId.equals(other.keyId) && Arrays.equals(secret, other.secret)
                && Objects.equals(verifyUntil, other.verifyUntil);
    }

    @Override
    public int hashCode() {
        return Objects.hash(keyId, Arrays.hashCode(secret), verifyUntil);
    }

    @Override
    public String toString() {
        return "SigningKey[keyId=" + keyId + ", secret=***, verifyUntil=" + verifyUntil + "]";
    }
}
