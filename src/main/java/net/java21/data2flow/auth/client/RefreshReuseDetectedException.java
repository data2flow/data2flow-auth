package net.java21.data2flow.auth.client;

/** core가 Refresh 재사용을 탐지했다(API-IAM-35 409 AUTH_SESSION_REVOKED). 그 계보는 core가 폐기한다(BR-IAM-14) */
public class RefreshReuseDetectedException extends RuntimeException {

    public RefreshReuseDetectedException() {
        super("refresh token reuse detected");
    }
}
