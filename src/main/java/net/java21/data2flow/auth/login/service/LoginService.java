package net.java21.data2flow.auth.login.service;

import net.java21.data2flow.auth.client.CoreClient;
import net.java21.data2flow.auth.client.dto.VerifiedCredentials;
import net.java21.data2flow.auth.common.AuthErrorCode;
import net.java21.data2flow.auth.common.ClientInfo;
import net.java21.data2flow.auth.common.Hashes;
import net.java21.data2flow.auth.config.AuthProperties;
import net.java21.data2flow.auth.login.dto.ConfirmMfaRequest;
import net.java21.data2flow.auth.login.dto.LoginRequest;
import net.java21.data2flow.auth.login.repository.MfaTicketRepository;
import net.java21.data2flow.auth.ratelimit.service.AuthRateLimiter;
import net.java21.data2flow.auth.token.service.TokenIssueService;
import net.java21.data2flow.contracts.error.BusinessException;
import net.java21.data2flow.contracts.error.CommonErrorCode;
import net.java21.data2flow.contracts.error.FieldErrorDetail;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import java.util.List;

/**
 * 아이디·비밀번호 로그인(IAM-02.01, IAM-07.11, design/auth.md §3.2). 소셜 로그인은 없다(ADR-016).
 * 자격 확인(Argon2id, 실패 횟수, 잠금, 계정 존재 은닉)은 core가 하고(API-IAM-30), auth는 한도 확인과 토큰 발급만 한다.
 * TOTP를 켠 사용자는 비밀번호 확인 뒤 토큰 대신 MFA 티켓을 받고 API-IAM-62로 코드를 보낸다(BR-IAM-25).
 */
@Service
public class LoginService {

    static final int MAX_PASSWORD_LENGTH = 128;
    private static final int TICKET_BYTES = 32;

    private final CoreClient core;
    private final TokenIssueService tokenIssue;
    private final AuthRateLimiter rateLimiter;
    private final MfaTicketRepository mfaTickets;
    private final AuthProperties properties;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    public LoginService(CoreClient core, TokenIssueService tokenIssue, AuthRateLimiter rateLimiter,
                        MfaTicketRepository mfaTickets, AuthProperties properties, Clock clock) {
        this.core = core;
        this.tokenIssue = tokenIssue;
        this.rateLimiter = rateLimiter;
        this.mfaTickets = mfaTickets;
        this.properties = properties;
        this.clock = clock;
    }

    public LoginResult login(LoginRequest request, ClientInfo client) {
        String loginId = request.normalizedLoginId();
        String password = request.password().reveal();
        if (password.isEmpty() || password.length() > MAX_PASSWORD_LENGTH) {
            throw new BusinessException(CommonErrorCode.INVALID_REQUEST,
                    List.of(new FieldErrorDetail("password", "Size", "1~128자")));
        }
        rateLimiter.loginByIp(client.ip());
        rateLimiter.loginByLoginId(loginId);
        VerifiedCredentials verified = core.verifyCredentials(loginId, password, client.ip(), client.userAgent());
        if (verified.mfaEnabled()) {
            String ticket = newTicket();
            mfaTickets.save(Hashes.sha256Hex(ticket),
                    new MfaTicketRepository.PendingMfa(verified.userId(), verified.organizationId(), verified.mustChangePassword(),
                            clock.instant().plus(properties.mfa().ticketTtl())),
                    properties.mfa().ticketTtl());
            return new LoginResult.MfaRequired(ticket, properties.mfa().ticketTtl());
        }
        return new LoginResult.Issued(tokenIssue.issueForLogin(verified.userId(), verified.organizationId(),
                verified.mustChangePassword(), false, client));
    }

    /** API-IAM-62: 티켓 + TOTP·복구 코드. 실패 횟수는 core가 로그인 실패에 합산한다(BR-IAM-27) */
    public LoginResult.Issued confirmMfa(ConfirmMfaRequest request, ClientInfo client) {
        rateLimiter.mfaByIp(client.ip());
        String ticketHash = Hashes.sha256Hex(request.mfaTicket().trim());
        MfaTicketRepository.PendingMfa pending = mfaTickets.find(ticketHash)
                .filter(p -> clock.instant().isBefore(p.expiresAt()))
                .orElseThrow(() -> new BusinessException(CommonErrorCode.AUTH_TOKEN_INVALID));
        try {
            rateLimiter.mfaByTicket(ticketHash, properties.mfa().maxAttempts(), properties.mfa().ticketTtl());
        } catch (BusinessException ex) {
            mfaTickets.delete(ticketHash); // 시도 한도를 넘은 티켓은 버린다. 다시 로그인해야 한다
            throw ex;
        }
        String code = request.code().reveal().trim();
        if (code.isEmpty() || code.length() > 64 || !core.verifyMfa(pending.userId(), code)) {
            throw new BusinessException(AuthErrorCode.MFA_CODE_INVALID);
        }
        if (!mfaTickets.consume(ticketHash)) {
            throw new BusinessException(CommonErrorCode.AUTH_TOKEN_INVALID);
        }
        return new LoginResult.Issued(tokenIssue.issueForLogin(pending.userId(), pending.organizationId(),
                pending.mustChangePassword(), true, client));
    }

    private String newTicket() {
        byte[] bytes = new byte[TICKET_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
