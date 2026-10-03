package net.java21.data2flow.auth.support;

import net.java21.data2flow.auth.token.domain.JwtCodec;
import net.java21.data2flow.auth.token.domain.SigningKeyRing;

import java.time.Clock;
import java.time.Duration;

/** 테스트 전용 서명 키(운영 키 아님) */
public final class TestKeys {

    /** "test-only-signing-key-0000000001" */
    public static final String KEY1 = "dGVzdC1vbmx5LXNpZ25pbmcta2V5LTAwMDAwMDAwMDE=";
    /** "test-only-signing-key-0000000002" */
    public static final String KEY2 = "dGVzdC1vbmx5LXNpZ25pbmcta2V5LTAwMDAwMDAwMDI=";
    public static final String ISSUER = "data2flow-auth";
    public static final String AUDIENCE = "data2flow";

    private TestKeys() {
    }

    public static JwtCodec codec(String keySpec, String activeKeyId, Clock clock) {
        return new JwtCodec(SigningKeyRing.parse(keySpec, activeKeyId), ISSUER, AUDIENCE, Duration.ofSeconds(30), clock);
    }

    public static JwtCodec codec(Clock clock) {
        return codec("t1:" + KEY1, "t1", clock);
    }
}
