package net.java21.data2flow.auth.revocation.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.List;

/**
 * API-IAM-37b 요청 {@code {sids[], jtis[], tokenIds[]?, reason}} (core → auth). 비밀번호 변경·비활성화·삭제·관리자 강제 종료·개별 세션 종료 때
 * core가 계보를 폐기한 뒤 부른다(BR-IAM-12, IAM-01.04·03.02·03.03).
 *
 * <p>{@code tokenIds}는 장기 토큰(API 키·MCP) 폐기·교체 유예 끝·서비스 계정 비활성화 때 core가 넣는다(IAM-05.03·BR-IAM-35). 원천 판정은
 * core(API-IAM-46)이므로 Redis 블랙리스트에는 넣지 않고 EVT-IAM-03 {@code TOKEN_ID}만 내어 gateway 검증 캐시를 바로 지운다.
 */
public record BlacklistRequest(@Size(max = 1000) List<@NotBlank @Size(max = 64) String> sids,
                               @Size(max = 1000) List<@NotBlank @Size(max = 64) String> jtis,
                               @Size(max = 1000) List<@NotBlank @Size(max = 64) String> tokenIds,
                               @NotBlank @Size(max = 30) String reason) {
}
