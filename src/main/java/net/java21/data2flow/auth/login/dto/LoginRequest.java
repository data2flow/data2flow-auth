package net.java21.data2flow.auth.login.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import net.java21.data2flow.contracts.secret.Secret;

/**
 * API-IAM-01 요청. 아이디는 대소문자를 구분하지 않고 소문자로 맞춘다(design/auth.md §3.1). 비밀번호는 로그·toString에 나오지 않는다.
 */
public record LoginRequest(@NotBlank @Size(min = 4, max = 30) String loginId,
                           @jakarta.validation.constraints.NotNull Secret password) {

    public String normalizedLoginId() {
        return loginId.trim().toLowerCase(java.util.Locale.ROOT);
    }
}
