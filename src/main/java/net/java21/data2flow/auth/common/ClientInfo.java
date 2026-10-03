package net.java21.data2flow.auth.common;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;

/**
 * 요청한 사용자의 IP와 User-Agent. BFF가 {@code X-Forwarded-For}를 사용자 IP 하나로 다시 쓰고 gateway가 그대로 넘기므로
 * 맨 앞 값을 쓴다(design/auth.md §5 사용자 IP 전달). 감사 로그와 로그인 시도 한도에 쓴다.
 */
public record ClientInfo(String ip, String userAgent) {

    private static final int MAX_USER_AGENT = 300;

    public static ClientInfo from(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        String ip = null;
        if (forwarded != null && !forwarded.isBlank()) {
            ip = forwarded.split(",")[0].trim();
        }
        if (ip == null || ip.isEmpty() || !ip.matches("[0-9A-Fa-f:.]{2,45}")) {
            ip = request.getRemoteAddr();
        }
        String ua = request.getHeader(HttpHeaders.USER_AGENT);
        if (ua != null && ua.length() > MAX_USER_AGENT) {
            ua = ua.substring(0, MAX_USER_AGENT);
        }
        return new ClientInfo(ip, ua);
    }
}
