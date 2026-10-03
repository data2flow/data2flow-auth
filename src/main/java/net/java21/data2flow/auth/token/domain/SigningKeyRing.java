package net.java21.data2flow.auth.token.domain;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * 서명 키 묶음(IAM-07.02 "서명 키는 키 ID(kid)를 붙여 교체할 수 있다", design/auth.md §4).
 * 새 토큰은 활성 키로 서명하고, 검증은 kid로 고른 키로 한다. 교체 절차: 새 키 추가 → 활성 키 변경 → 이전 키에 검증 종료 시각을
 * 붙임(Access 수명 이상) → 종료 뒤 이전 키 제거.
 *
 * <p>설정 형식: {@code kid:Base64[@검증 종료 ISO-8601],kid2:Base64}. 값은 환경변수·k8s Secret에서만 받는다(코드·문서에 두지 않음).
 */
public final class SigningKeyRing {

    private final Map<String, SigningKey> keys;
    private final SigningKey active;

    public SigningKeyRing(Map<String, SigningKey> keys, String activeKeyId) {
        if (keys == null || keys.isEmpty()) {
            throw new IllegalStateException("JWT 서명 키가 없습니다. data2flow.auth.jwt.keys(DATA2FLOW_AUTH_JWT_KEYS)를 설정하세요");
        }
        this.keys = Map.copyOf(keys);
        String activeId = activeKeyId == null || activeKeyId.isBlank()
                ? (keys.size() == 1 ? keys.keySet().iterator().next() : null)
                : activeKeyId.trim();
        if (activeId == null) {
            throw new IllegalStateException("키가 여러 개면 data2flow.auth.jwt.active-key-id를 정해야 합니다");
        }
        SigningKey candidate = this.keys.get(activeId);
        if (candidate == null) {
            throw new IllegalStateException("활성 키 " + activeId + "가 키 목록에 없습니다");
        }
        if (candidate.verifyUntil() != null) {
            throw new IllegalStateException("활성 키에는 검증 종료 시각을 둘 수 없습니다: " + activeId);
        }
        this.active = candidate;
    }

    public static SigningKeyRing parse(String spec, String activeKeyId) {
        Map<String, SigningKey> keys = new LinkedHashMap<>();
        if (spec != null) {
            for (String raw : spec.split(",")) {
                String entry = raw.trim();
                if (entry.isEmpty()) {
                    continue;
                }
                int colon = entry.indexOf(':');
                if (colon <= 0) {
                    throw new IllegalStateException("JWT 키 형식은 kid:Base64[@ISO-8601]입니다");
                }
                String keyId = entry.substring(0, colon).trim();
                String rest = entry.substring(colon + 1).trim();
                Instant verifyUntil = null;
                int at = rest.indexOf('@');
                if (at >= 0) {
                    try {
                        verifyUntil = Instant.parse(rest.substring(at + 1).trim());
                    } catch (DateTimeParseException ex) {
                        throw new IllegalStateException("JWT 키 " + keyId + "의 검증 종료 시각 형식이 틀렸습니다", ex);
                    }
                    rest = rest.substring(0, at).trim();
                }
                byte[] secret;
                try {
                    secret = Base64.getDecoder().decode(rest);
                } catch (IllegalArgumentException ex) {
                    throw new IllegalStateException("JWT 키 " + keyId + "가 Base64가 아닙니다", ex);
                }
                if (keys.put(keyId, new SigningKey(keyId, secret, verifyUntil)) != null) {
                    throw new IllegalStateException("JWT 키 ID가 겹칩니다: " + keyId);
                }
            }
        }
        return new SigningKeyRing(keys, activeKeyId);
    }

    public SigningKey active() {
        return active;
    }

    public Optional<SigningKey> find(String keyId) {
        return keyId == null ? Optional.empty() : Optional.ofNullable(keys.get(keyId));
    }
}
