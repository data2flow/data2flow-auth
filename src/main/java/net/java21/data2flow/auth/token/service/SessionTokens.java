package net.java21.data2flow.auth.token.service;

import net.java21.data2flow.auth.token.domain.IssuedToken;

/**
 * 로그인·재발급 한 번의 결과.
 *
 * @param userId             사용자
 * @param organizationId     조직
 * @param sid                로그인 계열(세션) ID
 * @param access             Access
 * @param refresh            Refresh
 * @param mustChangePassword 임시 비밀번호 상태(IAM-01.02). 재발급 결과에서는 false
 */
public record SessionTokens(long userId, long organizationId, String sid, IssuedToken access, IssuedToken refresh,
                            boolean mustChangePassword) {
}
