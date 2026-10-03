package net.java21.data2flow.auth.client;

import net.java21.data2flow.auth.client.dto.ApiTokenVerification;
import net.java21.data2flow.auth.client.dto.RegisterRefreshTokenRequest;
import net.java21.data2flow.auth.client.dto.Revocations;
import net.java21.data2flow.auth.client.dto.RotateRefreshTokenRequest;
import net.java21.data2flow.auth.client.dto.RotationDecision;
import net.java21.data2flow.auth.client.dto.VerifiedCredentials;
import net.java21.data2flow.auth.common.DependencyUnavailableException;
import net.java21.data2flow.contracts.audit.AuditEvent;
import net.java21.data2flow.contracts.error.BusinessException;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import okhttp3.mockwebserver.SocketPolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.json.JsonMapper;

import java.net.http.HttpClient;
import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** core 내부 API 호출의 오류 매핑(design/testing/backend.md §3 *ClientTest, MockWebServer) */
class RestCoreClientTest {

    private MockWebServer server;
    private RestCoreClient client;

    @BeforeEach
    void setUp() throws Exception {
        server = new MockWebServer();
        server.start();
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(1)).build());
        factory.setReadTimeout(Duration.ofMillis(500));
        JsonMapper mapper = JsonMapper.builder().build();
        client = new RestCoreClient(RestClient.builder().baseUrl(server.url("/").toString()).requestFactory(factory).build(), mapper);
    }

    @AfterEach
    void tearDown() throws Exception {
        server.shutdown();
        MDC.clear();
    }

    private void reply(int status, String body) {
        server.enqueue(new MockResponse().setResponseCode(status).setHeader("Content-Type", "application/json").setBody(body));
    }

    private static String ok(String response) {
        return "{\"header\":{\"isSuccessful\":true,\"resultCode\":\"SUCCESS\",\"resultMessage\":\"SUCCESS\"},\"response\":" + response + "}";
    }

    private static String fail(String code) {
        return "{\"header\":{\"isSuccessful\":false,\"resultCode\":\"" + code + "\",\"resultMessage\":\"x\"}}";
    }

    @Test
    @DisplayName("[IAM-02.01] API-IAM-30 성공·실패 매핑과 호출자·요청 ID 헤더")
    void verifyCredentials() throws Exception {
        MDC.put("requestId", "req-1");
        reply(200, ok("{\"userId\":\"11\",\"orgId\":1,\"mustChangePassword\":true,\"mfaEnabled\":false}"));
        VerifiedCredentials v = client.verifyCredentials("kim.op", "pw", "1.2.3.4", "UA");
        assertThat(v).isEqualTo(new VerifiedCredentials(11, 1, true, false));
        RecordedRequest req = server.takeRequest();
        assertThat(req.getPath()).isEqualTo("/internal/core/users/verify-credentials");
        assertThat(req.getHeader("X-CALLER-SERVICE")).isEqualTo("data2flow-auth");
        assertThat(req.getHeader("X-REQUEST-ID")).isEqualTo("req-1");
        assertThat(req.getBody().readUtf8()).contains("\"loginId\":\"kim.op\"").contains("\"ip\":\"1.2.3.4\"");

        reply(401, fail("AUTH_INVALID_CREDENTIALS"));
        assertThatThrownBy(() -> client.verifyCredentials("a", "b", null, null)).isInstanceOf(BusinessException.class)
                .hasMessage("AUTH_INVALID_CREDENTIALS");
        reply(403, fail("AUTH_PENDING_APPROVAL"));
        assertThatThrownBy(() -> client.verifyCredentials("a", "b", null, null)).hasMessage("AUTH_PENDING_APPROVAL");
        reply(400, "not json");
        assertThatThrownBy(() -> client.verifyCredentials("a", "b", null, null)).hasMessage("AUTH_INVALID_CREDENTIALS");
        reply(500, fail("INTERNAL_ERROR"));
        assertThatThrownBy(() -> client.verifyCredentials("a", "b", null, null)).isInstanceOf(DependencyUnavailableException.class);
        reply(200, ok("{\"orgId\":\"1\"}"));
        assertThatThrownBy(() -> client.verifyCredentials("a", "b", null, null)).isInstanceOf(DependencyUnavailableException.class);
        reply(200, "{\"header\":{}}");
        assertThatThrownBy(() -> client.verifyCredentials("a", "b", null, null)).isInstanceOf(DependencyUnavailableException.class);
    }

    @Test
    @DisplayName("[IAM-07.10] 시간 초과·연결 끊김 → fail-closed")
    void timeouts() {
        server.enqueue(new MockResponse().setBodyDelay(2, java.util.concurrent.TimeUnit.SECONDS).setBody(ok("{}")));
        assertThatThrownBy(() -> client.verifyMfa(1, "123456")).isInstanceOf(DependencyUnavailableException.class);
        server.enqueue(new MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AT_START));
        assertThatThrownBy(() -> client.findRevocationsSince(Instant.EPOCH)).isInstanceOf(DependencyUnavailableException.class);
    }

    @Test
    @DisplayName("[IAM-07.03] API-IAM-36·35 계보 등록과 회전 판정 매핑")
    void refreshLineage() throws Exception {
        Instant t = Instant.parse("2026-10-03T00:00:00Z");
        reply(201, ok("{\"jti\":\"j\",\"sid\":\"s\",\"expiresAt\":\"2026-10-03T06:00:00Z\"}"));
        client.registerRefreshToken(new RegisterRefreshTokenRequest("j", "s", "11", "1", "h", t, t, "ip", "ua"));
        assertThat(server.takeRequest().getBody().readUtf8()).contains("\"expiresAt\":\"2026-10-03T00:00:00Z\"").contains("\"userId\":\"11\"");
        reply(409, fail("VERSION_CONFLICT"));
        assertThatThrownBy(() -> client.registerRefreshToken(new RegisterRefreshTokenRequest("j", "s", "11", "1", "h", t, t, null, null)))
                .isInstanceOf(DependencyUnavailableException.class);

        RotateRefreshTokenRequest rotate = new RotateRefreshTokenRequest("p", "n", "h", t);
        reply(200, ok("{\"decision\":\"GRACE\",\"effectiveJti\":\"latest\"}"));
        assertThat(client.rotateRefreshToken(rotate)).isEqualTo(new RotationDecision(RotationDecision.Decision.GRACE, "latest"));
        reply(200, ok("{\"decision\":\"WHAT\"}"));
        assertThatThrownBy(() -> client.rotateRefreshToken(rotate)).isInstanceOf(DependencyUnavailableException.class);
        reply(409, fail("AUTH_SESSION_REVOKED"));
        assertThatThrownBy(() -> client.rotateRefreshToken(rotate)).isInstanceOf(RefreshReuseDetectedException.class);
        reply(401, fail("AUTH_SESSION_REVOKED"));
        assertThatThrownBy(() -> client.rotateRefreshToken(rotate)).hasMessage("AUTH_SESSION_REVOKED");
        reply(401, fail("AUTH_SESSION_EXPIRED"));
        assertThatThrownBy(() -> client.rotateRefreshToken(rotate)).hasMessage("AUTH_SESSION_EXPIRED");
        reply(404, fail("RESOURCE_NOT_FOUND"));
        assertThatThrownBy(() -> client.rotateRefreshToken(rotate)).hasMessage("AUTH_TOKEN_INVALID");
    }

    @Test
    @DisplayName("[IAM-07.05] API-IAM-37 세션 폐기는 404도 성공(멱등), API-IAM-39a는 문자열·객체 배열을 모두 읽는다")
    void revocations() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(204));
        client.revokeSession("sid-1", "LOGOUT");
        RecordedRequest req = server.takeRequest();
        assertThat(req.getMethod()).isEqualTo("DELETE");
        assertThat(req.getPath()).isEqualTo("/internal/core/sessions/sid-1");
        assertThat(req.getBody().readUtf8()).isEqualTo("{\"reason\":\"LOGOUT\"}");
        reply(404, fail("RESOURCE_NOT_FOUND"));
        client.revokeSession("sid-2", "LOGOUT");
        reply(400, fail("INVALID_REQUEST"));
        assertThatThrownBy(() -> client.revokeSession("x", "LOGOUT")).isInstanceOf(DependencyUnavailableException.class);
        server.takeRequest();
        server.takeRequest();

        reply(200, ok("{\"sids\":[\"a\",{\"sid\":\"b\"},{\"value\":\"c\"},null,\"\"],\"jtis\":[{\"jti\":\"j1\"}]}"));
        Revocations r = client.findRevocationsSince(Instant.parse("2026-10-03T00:00:00Z"));
        assertThat(r.sids()).containsExactly("a", "b", "c");
        assertThat(r.jtis()).containsExactly("j1");
        assertThat(server.takeRequest().getPath()).isEqualTo("/internal/core/revocations?since=2026-10-03T00:00:00Z");
        reply(200, ok("{}"));
        assertThat(client.findRevocationsSince(Instant.EPOCH).sids()).isEmpty();
        reply(404, fail("RESOURCE_NOT_FOUND"));
        assertThatThrownBy(() -> client.findRevocationsSince(Instant.EPOCH)).isInstanceOf(DependencyUnavailableException.class);
    }

    @Test
    @DisplayName("[IAM-02.05] API-IAM-61b: ok·불일치·4xx는 결과, 5xx는 장애")
    void mfa() throws Exception {
        reply(200, ok("{\"ok\":true}"));
        assertThat(client.verifyMfa(21, "123456")).isTrue();
        assertThat(server.takeRequest().getPath()).isEqualTo("/internal/core/users/21/mfa/verify");
        reply(200, ok("{\"ok\":false}"));
        assertThat(client.verifyMfa(21, "1")).isFalse();
        reply(401, fail("MFA_CODE_INVALID"));
        assertThat(client.verifyMfa(21, "1")).isFalse();
        reply(429, fail("RATE_LIMITED"));
        assertThatThrownBy(() -> client.verifyMfa(21, "1")).isInstanceOf(DependencyUnavailableException.class);
    }

    @Test
    @DisplayName("[IAM-07.02] API-IAM-46 장기 토큰 확인과 API-IAM-39 감사 전송")
    void apiTokenAndAudit() throws Exception {
        reply(200, ok("{\"active\":true,\"ownerType\":\"USER\",\"ownerId\":\"11\",\"userId\":\"11\",\"org\":\"1\",\"scopes\":[\"read:devices\"],"
                + "\"spaceScope\":[\"5\"],\"kind\":\"API_KEY\",\"tokenId\":\"7\",\"rateLimitPerMin\":120}"));
        ApiTokenVerification v = client.verifyApiToken("hash");
        assertThat(v.active()).isTrue();
        assertThat(v.scopes()).containsExactly("read:devices");
        assertThat(v.spaceScope()).containsExactly("5");
        assertThat(v.rateLimitPerMin()).isEqualTo(120);
        reply(404, fail("RESOURCE_NOT_FOUND"));
        assertThat(client.verifyApiToken("hash").active()).isFalse();
        reply(503, fail("SERVICE_UNAVAILABLE"));
        assertThatThrownBy(() -> client.verifyApiToken("hash")).isInstanceOf(DependencyUnavailableException.class);

        reply(202, ok("{}"));
        server.takeRequest();
        server.takeRequest();
        server.takeRequest();
        AuditEvent event = AuditEvent.builder(1, "USER_LOGGED_IN").occurredAt(Instant.parse("2026-10-03T00:00:00Z")).build();
        client.recordAudit(event);
        assertThat(server.takeRequest().getBody().readUtf8()).contains("\"action\":\"USER_LOGGED_IN\"")
                .contains("\"occurredAt\":\"2026-10-03T00:00:00Z\"");
        reply(400, fail("INVALID_REQUEST"));
        assertThatThrownBy(() -> client.recordAudit(event)).isInstanceOf(DependencyUnavailableException.class);
    }
}
