package net.java21.data2flow.auth;

import net.java21.data2flow.auth.common.Hashes;
import net.java21.data2flow.auth.support.AuthIntegrationTest;
import net.java21.data2flow.auth.support.FakeCore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** 토큰 형식과 introspection(IAM-07.01·07.02·07.11, API-IAM-34) */
class TokenAuthIT extends AuthIntegrationTest {

    @Test
    @DisplayName("[IAM-07.02][TC-IAM-181][AT-IAM-21.1] Access 클레임은 sub, org, sid, jti, typ, iss, aud, iat, nbf, exp뿐이고 헤더에 kid가 있다")
    void accessTokenClaims() {
        CORE.addUser(11, 1, "kim.op", "correct-horse-battery");
        Tokens t = loginOk("kim.op", "correct-horse-battery");

        String[] parts = t.access().split("\\.");
        JsonNode header = json.readTree(new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8));
        JsonNode payload = json.readTree(new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));

        List<String> names = new ArrayList<>(payload.propertyNames());
        assertThat(names).containsExactlyInAnyOrder("sub", "org", "sid", "jti", "typ", "iss", "aud", "iat", "nbf", "exp");
        assertThat(header.path("kid").asString()).isEqualTo("t1");
        assertThat(header.path("alg").asString()).isEqualTo("HS256");
        assertThat(payload.path("typ").asString()).isEqualTo("ACCESS");
        assertThat(payload.path("sub").asString()).isEqualTo("11");
        assertThat(payload.path("org").asString()).isEqualTo("1");
        assertThat(payload.path("exp").asLong() - payload.path("iat").asLong()).isEqualTo(3600);
    }

    @Test
    @DisplayName("[IAM-07.02] introspection: 유효한 Access → active + sub·org·jti·sid·typ·exp (gateway 계약)")
    void introspectActive() {
        CORE.addUser(11, 1, "kim.op", "correct-horse-battery");
        Tokens t = loginOk("kim.op", "correct-horse-battery");

        JsonNode r = introspection(t.access());

        assertThat(r.path("active").asBoolean()).isTrue();
        assertThat(r.path("sub").asString()).isEqualTo("11");
        assertThat(r.path("org").asString()).isEqualTo("1");
        assertThat(r.path("sid").asString()).isEqualTo(t.sid());
        assertThat(r.path("jti").asString()).isNotBlank();
        assertThat(r.path("typ").asString()).isEqualTo("ACCESS");
        assertThat(r.path("exp").asLong()).isEqualTo(CLOCK.instant().plus(Duration.ofHours(1)).getEpochSecond());
        assertThat(r.has("inactiveReason")).isFalse();
    }

    @Test
    @DisplayName("[IAM-07.02][TC-IAM-180] Access 만료 → active=false, inactiveReason=EXPIRED(gateway가 401 AUTH_TOKEN_EXPIRED)")
    void introspectExpired() {
        CORE.addUser(11, 1, "kim.op", "correct-horse-battery");
        Tokens t = loginOk("kim.op", "correct-horse-battery");
        CLOCK.advance(Duration.ofMinutes(61));

        JsonNode r = introspection(t.access());

        assertThat(r.path("active").asBoolean()).isFalse();
        assertThat(r.path("inactiveReason").asString()).isEqualTo("EXPIRED");
        assertThat(r.has("sub")).isFalse();
    }

    @Test
    @DisplayName("[IAM-07.02] 위조·형식 오류·Refresh 토큰·빈 토큰 → active=false, INVALID")
    void introspectInvalid() {
        CORE.addUser(11, 1, "kim.op", "correct-horse-battery");
        Tokens t = loginOk("kim.op", "correct-horse-battery");
        String tampered = t.access().substring(0, t.access().length() - 2) + "xx";

        assertThat(introspection(tampered).path("inactiveReason").asString()).isEqualTo("INVALID");
        assertThat(introspection(t.refresh()).path("inactiveReason").asString()).isEqualTo("INVALID");
        assertThat(introspection("not-a-jwt").path("inactiveReason").asString()).isEqualTo("INVALID");
        assertThat(introspection("").path("inactiveReason").asString()).isEqualTo("INVALID");
    }

    @Test
    @DisplayName("[IAM-07.02] 장기 토큰(data2flow_) → core API-IAM-46에 해시로 확인, typ·tokenId·scopes 전달")
    void introspectLongLivedToken() {
        String raw = "data2flow_" + "A".repeat(43);
        CORE.addApiToken(Hashes.sha256Hex(raw), new FakeCore.ApiToken(true, "11", "1", "501", "MCP", List.of("read:telemetry")));

        JsonNode r = introspection(raw);

        assertThat(r.path("active").asBoolean()).isTrue();
        assertThat(r.path("typ").asString()).isEqualTo("MCP");
        assertThat(r.path("tokenId").asString()).isEqualTo("501");
        assertThat(r.path("sub").asString()).isEqualTo("11");
        assertThat(r.path("org").asString()).isEqualTo("1");
        assertThat(r.path("scopes").get(0).asString()).isEqualTo("read:telemetry");
        assertThat(r.path("rateLimitPerMin").asLong()).isEqualTo(60);
        assertThat(introspection("data2flow_" + "B".repeat(43)).path("inactiveReason").asString()).isEqualTo("INVALID");
    }

    @Test
    @DisplayName("[IAM-07.11][TC-IAM-204][AT-IAM-02.10] 소셜 로그인 경로 /auth/oauth2/github → 404 RESOURCE_NOT_FOUND")
    void noSocialLogin() {
        Response res = get("/auth/oauth2/github");

        assertThat(res.status()).isEqualTo(404);
        assertThat(res.resultCode()).isEqualTo("RESOURCE_NOT_FOUND");
        assertThat(postJson("/auth/oauth2/authorization/google", null).status()).isEqualTo(404);
    }
}
