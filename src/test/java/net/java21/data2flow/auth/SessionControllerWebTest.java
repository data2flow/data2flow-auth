package net.java21.data2flow.auth;

import jakarta.servlet.http.Cookie;
import net.java21.data2flow.auth.common.ClientInfo;
import net.java21.data2flow.auth.common.DependencyUnavailableException;
import net.java21.data2flow.auth.support.WebSliceConfig;
import net.java21.data2flow.auth.token.controller.TokenController;
import net.java21.data2flow.auth.token.domain.IssuedToken;
import net.java21.data2flow.auth.token.service.LogoutService;
import net.java21.data2flow.auth.token.service.RefreshTokenService;
import net.java21.data2flow.auth.token.service.SessionTokens;
import net.java21.data2flow.contracts.error.BusinessException;
import net.java21.data2flow.contracts.error.CommonErrorCode;
import net.java21.data2flow.contracts.ratelimit.RateLimitInfo;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Duration;
import java.time.Instant;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.never;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** 재발급·로그아웃 슬라이스(API-IAM-02·03) */
@WebMvcTest(TokenController.class)
@ActiveProfiles("test")
@Import(WebSliceConfig.class)
class SessionControllerWebTest {

    @Autowired
    MockMvc mvc;
    @MockitoBean
    RefreshTokenService refreshTokens;
    @MockitoBean
    LogoutService logoutService;

    private final Cookie refreshCookie = new Cookie("data2flow_refresh", "old-refresh");

    @Test
    @DisplayName("[IAM-07.03][AT-IAM-03.1] 재발급 성공 → 200 {accessToken, expiresIn, sid, refreshToken} + 새 Set-Cookie")
    void refreshOk() throws Exception {
        Instant now = WebSliceConfig.CLOCK.instant();
        given(refreshTokens.refresh(eq("old-refresh"), any(ClientInfo.class))).willReturn(new SessionTokens(11, 1, "sid-1",
                new IssuedToken("new-access", "j1", "sid-1", now.plus(Duration.ofHours(1))),
                new IssuedToken("new-refresh", "j2", "sid-1", now.plus(Duration.ofHours(6))), false));

        mvc.perform(post("/auth/refresh-token").cookie(refreshCookie))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.accessToken").value("new-access"))
                .andExpect(jsonPath("$.response.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.response.expiresIn").value(3600))
                .andExpect(jsonPath("$.response.sid").value("sid-1"))
                .andExpect(jsonPath("$.response.refreshToken").value("new-refresh"))
                .andExpect(header().string("Set-Cookie", startsWith("data2flow_refresh=new-refresh")))
                .andExpect(header().string("Set-Cookie", containsString("Path=/api/v1/auth")));
    }

    @Test
    @DisplayName("[IAM-03.01][TC-IAM-115][AT-IAM-03.4] 12시간 1분째 재발급 → 401 AUTH_SESSION_EXPIRED")
    void sessionExpired() throws Exception {
        given(refreshTokens.refresh(any(), any())).willThrow(new BusinessException(CommonErrorCode.AUTH_SESSION_EXPIRED));

        mvc.perform(post("/auth/refresh-token").cookie(refreshCookie))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.header.isSuccessful").value(false))
                .andExpect(jsonPath("$.header.resultCode").value("AUTH_SESSION_EXPIRED"))
                .andExpect(jsonPath("$.header.resultMessage").value("오랫동안 사용하지 않아 로그아웃되었습니다"));
    }

    @Test
    @DisplayName("[IAM-07.03][TC-IAM-117][AT-IAM-03.5] 재사용된 Refresh → 401 AUTH_SESSION_REVOKED")
    void reuse() throws Exception {
        given(refreshTokens.refresh(any(), any())).willThrow(new BusinessException(CommonErrorCode.AUTH_SESSION_REVOKED));

        mvc.perform(post("/auth/refresh-token").cookie(refreshCookie))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.header.resultCode").value("AUTH_SESSION_REVOKED"));
    }

    @Test
    @DisplayName("[IAM-07.03] Refresh 쿠키·본문이 모두 없으면 401 AUTH_TOKEN_INVALID")
    void missingRefresh() throws Exception {
        mvc.perform(post("/auth/refresh-token"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.header.resultCode").value("AUTH_TOKEN_INVALID"));
        mvc.perform(post("/auth/refresh-token").contentType(MediaType.APPLICATION_JSON).content("{\"refreshToken\":\" \"}"))
                .andExpect(jsonPath("$.header.resultCode").value("AUTH_TOKEN_INVALID"));
    }

    @Test
    @DisplayName("[IAM-07.07] 재발급 한도 초과 → 429 AUTH_RATE_LIMITED + Retry-After·X-RateLimit-*")
    void rateLimited() throws Exception {
        given(refreshTokens.refresh(any(), any())).willThrow(new RateLimitInfo(10, 0, 42).exceeded(CommonErrorCode.AUTH_RATE_LIMITED));

        mvc.perform(post("/auth/refresh-token").cookie(refreshCookie))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "42"))
                .andExpect(header().string("X-RateLimit-Limit", "10"))
                .andExpect(jsonPath("$.header.resultMessage").value(containsString("42")));
    }

    @Test
    @DisplayName("[IAM-07.10] core·Redis 장애 → 503 AUTH_UNAVAILABLE(공개 경로)")
    void unavailable() throws Exception {
        given(refreshTokens.refresh(any(), any())).willThrow(new DependencyUnavailableException("down"));

        mvc.perform(post("/auth/refresh-token").cookie(refreshCookie))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.header.resultCode").value("AUTH_UNAVAILABLE"));
    }

    @Test
    @DisplayName("[IAM-07.05][TC-IAM-120][AT-IAM-04.1] 로그아웃 → 204 + 쿠키 삭제, 서비스가 sid를 폐기. 쿠키 없이도 204")
    void logout() throws Exception {
        mvc.perform(post("/auth/logout").cookie(refreshCookie))
                .andExpect(status().isNoContent())
                .andExpect(header().string("Set-Cookie", containsString("Max-Age=0")));
        then(logoutService).should().logout(eq("old-refresh"), any(ClientInfo.class));

        mvc.perform(post("/auth/logout")).andExpect(status().isNoContent());
        then(logoutService).should(never()).logout(eq(null), any());
    }
}
