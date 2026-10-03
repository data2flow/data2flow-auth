package net.java21.data2flow.auth;

import net.java21.data2flow.auth.common.AuthErrorCode;
import net.java21.data2flow.auth.common.ClientInfo;
import net.java21.data2flow.auth.login.controller.LoginController;
import net.java21.data2flow.auth.login.dto.ConfirmMfaRequest;
import net.java21.data2flow.auth.login.dto.LoginRequest;
import net.java21.data2flow.auth.login.service.LoginResult;
import net.java21.data2flow.auth.login.service.LoginService;
import net.java21.data2flow.auth.support.WebSliceConfig;
import net.java21.data2flow.auth.token.domain.IssuedToken;
import net.java21.data2flow.auth.token.service.SessionTokens;
import net.java21.data2flow.contracts.error.BusinessException;
import net.java21.data2flow.contracts.error.CommonErrorCode;
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

import static org.hamcrest.Matchers.startsWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** 로그인 슬라이스(API-IAM-01·62): 계정 상태별 응답 */
@WebMvcTest(LoginController.class)
@ActiveProfiles("test")
@Import(WebSliceConfig.class)
class AccountMembershipControllerWebTest {

    private static final String BODY = "{\"loginId\":\"kim.op\",\"password\":\"correct-horse-battery\"}";

    @Autowired
    MockMvc mvc;
    @MockitoBean
    LoginService loginService;

    private SessionTokens tokens() {
        Instant now = WebSliceConfig.CLOCK.instant();
        return new SessionTokens(11, 1, "sid-1", new IssuedToken("acc", "j1", "sid-1", now.plus(Duration.ofHours(1))),
                new IssuedToken("ref", "j2", "sid-1", now.plus(Duration.ofHours(6))), true);
    }

    @Test
    @DisplayName("[IAM-01.04][TC-IAM-041][AT-IAM-10.3] 잠금 해제된 사용자 로그인 → 200 토큰 + Set-Cookie data2flow_refresh")
    void loginOk() throws Exception {
        given(loginService.login(any(LoginRequest.class), any(ClientInfo.class))).willReturn(new LoginResult.Issued(tokens()));

        mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.header.resultCode").value("SUCCESS"))
                .andExpect(jsonPath("$.response.accessToken").value("acc"))
                .andExpect(jsonPath("$.response.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.response.expiresIn").value(3600))
                .andExpect(jsonPath("$.response.mustChangePassword").value(true))
                .andExpect(jsonPath("$.response.mfaRequired").value(false))
                .andExpect(jsonPath("$.response.sid").value("sid-1"))
                .andExpect(jsonPath("$.response.userId").value("11"))
                .andExpect(jsonPath("$.response.orgId").value("1"))
                .andExpect(header().string("Set-Cookie", startsWith("data2flow_refresh=ref")));
    }

    @Test
    @DisplayName("[IAM-01.08][TC-IAM-067][AT-IAM-16.4] 승인 대기 계정 → 403 AUTH_PENDING_APPROVAL, 틀린 비밀번호 → 401 AUTH_INVALID_CREDENTIALS")
    void pendingApproval() throws Exception {
        given(loginService.login(any(), any()))
                .willThrow(new BusinessException(AuthErrorCode.AUTH_PENDING_APPROVAL))
                .willThrow(new BusinessException(CommonErrorCode.AUTH_INVALID_CREDENTIALS));

        mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.header.resultCode").value("AUTH_PENDING_APPROVAL"))
                .andExpect(jsonPath("$.header.resultMessage").value("관리자 승인 대기 중입니다. 승인되면 메일로 알려 드립니다"));
        mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.header.resultCode").value("AUTH_INVALID_CREDENTIALS"));
    }

    @Test
    @DisplayName("[IAM-02.05][AT-IAM-14.2] TOTP 사용자 → 401 MFA_REQUIRED + response.mfaTicket, 쿠키 없음. 확인하면 200")
    void mfa() throws Exception {
        given(loginService.login(any(), any())).willReturn(new LoginResult.MfaRequired("ticket-1", Duration.ofMinutes(5)));
        given(loginService.confirmMfa(any(ConfirmMfaRequest.class), any())).willReturn(new LoginResult.Issued(tokens()));

        mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content(BODY).header("Accept-Language", "en"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().doesNotExist("Set-Cookie"))
                .andExpect(jsonPath("$.header.isSuccessful").value(false))
                .andExpect(jsonPath("$.header.resultCode").value("MFA_REQUIRED"))
                .andExpect(jsonPath("$.header.resultMessage").value("Enter the 6-digit code from your authenticator app"))
                .andExpect(jsonPath("$.response.mfaTicket").value("ticket-1"))
                .andExpect(jsonPath("$.response.expiresIn").value(300));
        mvc.perform(post("/auth/login/mfa").contentType(MediaType.APPLICATION_JSON).content("{\"mfaTicket\":\"ticket-1\",\"code\":\"123456\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.accessToken").value("acc"));
    }

    @Test
    @DisplayName("[IAM-02.01] 형식 오류 → 400 INVALID_REQUEST + errors[field]")
    void validation() throws Exception {
        mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content("{\"loginId\":\"ab\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.header.resultCode").value("INVALID_REQUEST"))
                .andExpect(jsonPath("$.errors.length()").value(2));
        mvc.perform(post("/auth/login/mfa").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());
    }
}
