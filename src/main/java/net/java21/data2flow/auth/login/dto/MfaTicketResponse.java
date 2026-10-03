package net.java21.data2flow.auth.login.dto;

/** 401 MFA_REQUIRED 응답의 {@code response}: 티켓(5분, 1회용)과 남은 초 */
public record MfaTicketResponse(String mfaTicket, long expiresIn) {
}
