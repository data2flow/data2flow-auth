package net.java21.data2flow.auth.token.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import net.java21.data2flow.auth.config.AuthProperties;
import net.java21.data2flow.auth.token.domain.IssuedToken;
import net.java21.data2flow.auth.token.dto.RefreshTokenRequest;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;

/**
 * Refresh 쿠키 {@code data2flow_refresh}(API-IAM-01·02·03). BFF가 받아 세션 쿠키 안에 암호화해 두고, 재발급·로그아웃 때 다시 보낸다.
 * 브라우저로는 가지 않는다(ADR-024). HttpOnly·Secure·SameSite=Strict, Path는 auth 경로만.
 */
@Component
public class RefreshCookies {

    private final AuthProperties.RefreshCookie settings;

    public RefreshCookies(AuthProperties properties) {
        this.settings = properties.refreshCookie();
    }

    public String issue(IssuedToken refresh, Instant now) {
        return base(refresh.value()).maxAge(Duration.between(now, refresh.expiresAt()).isNegative()
                ? Duration.ZERO : Duration.between(now, refresh.expiresAt())).build().toString();
    }

    public String clear() {
        return base("").maxAge(Duration.ZERO).build().toString();
    }

    /** 쿠키가 우선, 없으면 본문 {@code refreshToken} */
    public Optional<String> read(HttpServletRequest request, RefreshTokenRequest body) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            Optional<String> fromCookie = Arrays.stream(cookies)
                    .filter(c -> settings.name().equals(c.getName()) && c.getValue() != null && !c.getValue().isBlank())
                    .map(Cookie::getValue)
                    .findFirst();
            if (fromCookie.isPresent()) {
                return fromCookie;
            }
        }
        return Optional.ofNullable(body).map(RefreshTokenRequest::refreshToken).filter(t -> !t.isBlank());
    }

    private ResponseCookie.ResponseCookieBuilder base(String value) {
        return ResponseCookie.from(settings.name(), value)
                .httpOnly(true)
                .secure(settings.secure())
                .sameSite("Strict")
                .path(settings.path());
    }
}
