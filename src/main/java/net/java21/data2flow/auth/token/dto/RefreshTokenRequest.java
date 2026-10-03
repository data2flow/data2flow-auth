package net.java21.data2flow.auth.token.dto;

/** 쿠키 대신 본문으로 Refresh를 보낼 때 {@code {refreshToken}}(선택). 쿠키가 우선이다 */
public record RefreshTokenRequest(String refreshToken) {

    @Override
    public String toString() {
        return "RefreshTokenRequest[refreshToken=***]";
    }
}
