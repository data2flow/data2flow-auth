package net.java21.data2flow.auth.common;

import net.java21.data2flow.contracts.error.ErrorCode;

/** IAM 도메인 오류 코드 중 auth가 응답하는 것(spec/detail/IAM/domain-model.md §6). 공통 코드는 CommonErrorCode를 쓴다 */
public enum AuthErrorCode implements ErrorCode {
    /** 비밀번호 확인 후 TOTP 입력 필요. 응답 response.mfaTicket */
    MFA_REQUIRED(401),
    /** TOTP·복구 코드 불일치 */
    MFA_CODE_INVALID(401),
    /** 가입 신청 계정이 관리자 승인 전(맞는 비밀번호일 때만, IAM-01.08) */
    AUTH_PENDING_APPROVAL(403);

    private final int httpStatus;

    AuthErrorCode(int httpStatus) {
        this.httpStatus = httpStatus;
    }

    @Override
    public String code() {
        return name();
    }

    @Override
    public int httpStatus() {
        return httpStatus;
    }
}
