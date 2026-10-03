package net.java21.data2flow.auth.client.dto;

import java.util.List;

/** API-IAM-39a 응답 {@code {sids[], jtis[]}}: 기준 시각 뒤에 폐기된 세션과 토큰 */
public record Revocations(List<String> sids, List<String> jtis) {

    public Revocations {
        sids = sids == null ? List.of() : List.copyOf(sids);
        jtis = jtis == null ? List.of() : List.copyOf(jtis);
    }
}
