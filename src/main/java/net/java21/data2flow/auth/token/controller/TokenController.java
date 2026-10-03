package net.java21.data2flow.auth.token.controller;

import jakarta.servlet.http.HttpServletRequest;
import net.java21.data2flow.auth.common.ClientInfo;
import net.java21.data2flow.auth.token.domain.JwtCodec;
import net.java21.data2flow.auth.token.dto.RefreshResponse;
import net.java21.data2flow.auth.token.dto.RefreshTokenRequest;
import net.java21.data2flow.auth.token.service.LogoutService;
import net.java21.data2flow.auth.token.service.RefreshTokenService;
import net.java21.data2flow.auth.token.service.SessionTokens;
import net.java21.data2flow.contracts.error.BusinessException;
import net.java21.data2flow.contracts.error.CommonErrorCode;
import net.java21.data2flow.contracts.web.ApiResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 토큰 재발급(API-IAM-02)·로그아웃(API-IAM-03). 외부 경로 {@code /api/v1/auth/**} → gateway stripPrefix(2) → {@code /auth/**}.
 * 둘 다 gateway 공개 경로이고 Refresh가 자격증명이다.
 */
@RestController
@RequestMapping("/auth")
public class TokenController {

    private final RefreshTokenService refreshTokens;
    private final LogoutService logoutService;
    private final RefreshCookies cookies;
    private final JwtCodec jwt;

    public TokenController(RefreshTokenService refreshTokens, LogoutService logoutService, RefreshCookies cookies, JwtCodec jwt) {
        this.refreshTokens = refreshTokens;
        this.logoutService = logoutService;
        this.cookies = cookies;
        this.jwt = jwt;
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<ApiResponse<RefreshResponse>> refresh(HttpServletRequest request,
                                                               @RequestBody(required = false) RefreshTokenRequest body) {
        String token = cookies.read(request, body).orElseThrow(() -> new BusinessException(CommonErrorCode.AUTH_TOKEN_INVALID));
        SessionTokens tokens = refreshTokens.refresh(token, ClientInfo.from(request));
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookies.issue(tokens.refresh(), jwt.now()))
                .body(ApiResponse.success(RefreshResponse.of(tokens, jwt.now())));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, @RequestBody(required = false) RefreshTokenRequest body) {
        cookies.read(request, body).ifPresent(token -> logoutService.logout(token, ClientInfo.from(request)));
        return ResponseEntity.noContent().header(HttpHeaders.SET_COOKIE, cookies.clear()).build();
    }
}
