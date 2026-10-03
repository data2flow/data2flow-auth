package net.java21.data2flow.auth.audit.service;

/** auth가 남기는 감사 action 코드(spec/detail/IAM/domain-model.md §5). 로그인 실패·잠금은 core가 자격 확인 때 남긴다 */
public final class AuthAuditActions {

    public static final String USER_LOGGED_IN = "USER_LOGGED_IN";
    public static final String USER_LOGGED_OUT = "USER_LOGGED_OUT";
    public static final String TOKEN_REFRESHED = "TOKEN_REFRESHED";
    public static final String REFRESH_REUSED = "REFRESH_REUSED";

    private AuthAuditActions() {
    }
}
