package net.java21.data2flow.auth.login.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import net.java21.data2flow.contracts.secret.Secret;

/** API-IAM-62 요청: 로그인 때 받은 티켓 + 6자리 TOTP 또는 복구 코드 */
public record ConfirmMfaRequest(@NotBlank @Size(max = 200) String mfaTicket, @jakarta.validation.constraints.NotNull Secret code) {
}
