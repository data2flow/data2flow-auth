package net.java21.data2flow.auth.token.domain;

/**
 * 토큰 검증 결과. 실패 사유는 크게만 나눈다(EXPIRED / INVALID). 폐기(REVOKED)는 블랙리스트를 본 뒤에 정한다.
 *
 * @param claims  성공이면 클레임
 * @param failure 실패면 사유
 */
public record TokenVerification(TokenClaims claims, Failure failure) {

    public enum Failure {
        /** 서명·형식·iss·aud·typ·kid가 맞지만 exp가 지남 */
        EXPIRED,
        /** 그 밖의 모든 실패(서명 오류, 형식, 종류 불일치, 모르는 kid, 유예가 끝난 kid, nbf 전) */
        INVALID
    }

    static TokenVerification ok(TokenClaims claims) {
        return new TokenVerification(claims, null);
    }

    static TokenVerification fail(Failure failure) {
        return new TokenVerification(null, failure);
    }

    public boolean valid() {
        return failure == null;
    }
}
