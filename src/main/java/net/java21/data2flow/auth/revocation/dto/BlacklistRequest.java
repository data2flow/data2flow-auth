package net.java21.data2flow.auth.revocation.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.List;

/**
 * API-IAM-37b 요청 {@code {sids[], jtis[], reason}} (core → auth). 비밀번호 변경·비활성화·삭제·관리자 강제 종료·개별 세션 종료 때
 * core가 계보를 폐기한 뒤 부른다(BR-IAM-12, IAM-01.04·03.02·03.03).
 */
public record BlacklistRequest(@Size(max = 1000) List<@NotBlank @Size(max = 64) String> sids,
                               @Size(max = 1000) List<@NotBlank @Size(max = 64) String> jtis,
                               @NotBlank @Size(max = 30) String reason) {
}
