package net.java21.data2flow.auth.revocation.dto;

/** API-IAM-38 응답: 다시 등록한 sid·jti 개수 */
public record ReloadResponse(int sids, int jtis) {
}
