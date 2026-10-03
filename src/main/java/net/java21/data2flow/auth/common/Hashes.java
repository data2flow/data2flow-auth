package net.java21.data2flow.auth.common;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** SHA-256 16진수(64자). Refresh {@code token_hash}, 장기 토큰 해시, Redis 키의 개인정보 가림에 쓴다 */
public final class Hashes {

    private Hashes() {
    }

    public static String sha256Hex(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
