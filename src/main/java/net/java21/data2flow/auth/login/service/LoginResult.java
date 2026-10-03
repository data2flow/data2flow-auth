package net.java21.data2flow.auth.login.service;

import net.java21.data2flow.auth.token.service.SessionTokens;

import java.time.Duration;

/** 로그인 결과: 토큰 발급, 또는 2단계 인증 필요(IAM-02.05) */
public sealed interface LoginResult {

    record Issued(SessionTokens tokens) implements LoginResult {
    }

    record MfaRequired(String mfaTicket, Duration ttl) implements LoginResult {
        @Override
        public String toString() {
            return "MfaRequired[mfaTicket=***, ttl=" + ttl + "]";
        }
    }
}
