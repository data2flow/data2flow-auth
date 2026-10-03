package net.java21.data2flow.auth.login.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import net.java21.data2flow.auth.common.AuthErrorCode;
import net.java21.data2flow.auth.common.ClientInfo;
import net.java21.data2flow.auth.login.dto.ConfirmMfaRequest;
import net.java21.data2flow.auth.login.dto.LoginRequest;
import net.java21.data2flow.auth.login.dto.MfaTicketResponse;
import net.java21.data2flow.auth.login.service.LoginResult;
import net.java21.data2flow.auth.login.service.LoginService;
import net.java21.data2flow.auth.token.controller.RefreshCookies;
import net.java21.data2flow.auth.token.domain.JwtCodec;
import net.java21.data2flow.auth.token.dto.TokenResponse;
import net.java21.data2flow.contracts.web.ApiHeader;
import net.java21.data2flow.contracts.web.ApiResponse;
import net.java21.data2flow.contracts.web.ErrorMessages;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 로그인(API-IAM-01)과 2단계 인증 확인(API-IAM-62). 로그인 방식은 아이디·비밀번호뿐이다(IAM-07.11, ADR-016) —
 * {@code /auth/oauth2/**} 같은 소셜 로그인 경로는 없고 404다.
 */
@RestController
@RequestMapping("/auth")
public class LoginController {

    private final LoginService loginService;
    private final RefreshCookies cookies;
    private final JwtCodec jwt;
    private final ErrorMessages messages;

    public LoginController(LoginService loginService, RefreshCookies cookies, JwtCodec jwt, ErrorMessages messages) {
        this.loginService = loginService;
        this.cookies = cookies;
        this.jwt = jwt;
        this.messages = messages;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest body, HttpServletRequest request) {
        LoginResult result = loginService.login(body, ClientInfo.from(request));
        if (result instanceof LoginResult.MfaRequired mfa) {
            return ResponseEntity.status(AuthErrorCode.MFA_REQUIRED.httpStatus())
                    .body(new MfaRequiredResponse(ApiHeader.failure(AuthErrorCode.MFA_REQUIRED.code(),
                            messages.resolve(AuthErrorCode.MFA_REQUIRED)),
                            new MfaTicketResponse(mfa.mfaTicket(), mfa.ttl().toSeconds())));
        }
        return issued((LoginResult.Issued) result);
    }

    @PostMapping("/login/mfa")
    public ResponseEntity<ApiResponse<TokenResponse>> confirmMfa(@Valid @RequestBody ConfirmMfaRequest body,
                                                                 HttpServletRequest request) {
        return issued(loginService.confirmMfa(body, ClientInfo.from(request)));
    }

    private ResponseEntity<ApiResponse<TokenResponse>> issued(LoginResult.Issued issued) {
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookies.issue(issued.tokens().refresh(), jwt.now()))
                .body(ApiResponse.success(TokenResponse.of(issued.tokens(), jwt.now())));
    }

    /** 401 MFA_REQUIRED: 실패 머리 + {@code response.mfaTicket} (design/openapi/auth.yaml) */
    public record MfaRequiredResponse(ApiHeader header, MfaTicketResponse response) {
    }
}
