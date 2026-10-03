package net.java21.data2flow.auth.support;

import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Map;

/**
 * 서비스 전체 통합 테스트 바탕(design/testing/backend.md §3 {@code *IT}). Redis는 Testcontainers Valkey(BSD),
 * core-api는 MockWebServer 위의 {@link FakeCore}. 컨테이너와 가짜 서버는 모든 IT가 함께 쓰고(스프링 컨텍스트도 하나),
 * 테스트마다 Redis를 비우고 가짜 core와 시계를 처음 상태로 돌린다.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "management.server.port=0")
@ActiveProfiles("test")
@Import(AuthIntegrationTest.ClockConfig.class)
public abstract class AuthIntegrationTest {

    protected static final MutableClock CLOCK = MutableClock.atDefault();
    protected static final FakeCore CORE = new FakeCore(CLOCK);
    protected static final GenericContainer<?> REDIS = new GenericContainer<>("valkey/valkey:8.1-alpine").withExposedPorts(6379);
    private static final MockWebServer CORE_SERVER = new MockWebServer();

    static {
        REDIS.start();
        CORE_SERVER.setDispatcher(CORE);
        try {
            CORE_SERVER.start();
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
        registry.add("data2flow.auth.core.base-url", () -> CORE_SERVER.url("/").toString().replaceAll("/$", ""));
    }

    @LocalServerPort
    protected int port;

    @Autowired
    protected StringRedisTemplate redis;

    protected final JsonMapper json = JsonMapper.builder().build();
    private final HttpClient http = HttpClient.newHttpClient();

    @BeforeEach
    void resetWorld() {
        CLOCK.set(MutableClock.DEFAULT_START);
        CORE.reset();
        redis.getRequiredConnectionFactory().getConnection().serverCommands().flushDb();
    }

    // ---- HTTP ----

    protected Response postJson(String path, Object body, Map<String, String> headers) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body == null ? "" : json.writeValueAsString(body)));
        headers.forEach(b::header);
        return send(b.build());
    }

    protected Response postJson(String path, Object body) {
        return postJson(path, body, Map.of());
    }

    protected Response get(String path) {
        return send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).GET().build());
    }

    protected Response introspect(String token) {
        String form = "token=" + URLEncoder.encode(token, StandardCharsets.UTF_8);
        return send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/internal/auth/introspect"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("X-CALLER-SERVICE", "data2flow-api-gateway")
                .POST(HttpRequest.BodyPublishers.ofString(form)).build());
    }

    protected Response login(String loginId, String password) {
        return postJson("/auth/login", Map.of("loginId", loginId, "password", password),
                Map.of("X-Forwarded-For", "203.0.113.7", "User-Agent", "IT-Browser"));
    }

    protected Response refresh(String refreshToken) {
        return postJson("/auth/refresh-token", null, Map.of("Cookie", "data2flow_refresh=" + refreshToken));
    }

    protected Response logout(String refreshToken) {
        return postJson("/auth/logout", null, Map.of("Cookie", "data2flow_refresh=" + refreshToken));
    }

    private Response send(HttpRequest request) {
        try {
            HttpResponse<String> res = http.send(request, HttpResponse.BodyHandlers.ofString());
            JsonNode body = res.body() == null || res.body().isBlank() ? null : json.readTree(res.body());
            return new Response(res.statusCode(), res.headers().map(), body);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(ex);
        }
    }

    /** HTTP 응답 */
    public record Response(int status, Map<String, java.util.List<String>> headers, JsonNode body) {

        public String resultCode() {
            return body == null ? null : body.path("header").path("resultCode").asString(null);
        }

        public JsonNode response() {
            return body.path("response");
        }

        public String header(String name) {
            return headers.entrySet().stream().filter(e -> e.getKey().equalsIgnoreCase(name))
                    .flatMap(e -> e.getValue().stream()).findFirst().orElse(null);
        }
    }

    // ---- 공통 동작 ----

    /** 로그인해서 토큰을 받는다 */
    protected Tokens loginOk(String loginId, String password) {
        Response res = login(loginId, password);
        if (res.status() != 200) {
            throw new AssertionError("로그인 실패: " + res.status() + " " + res.body());
        }
        return new Tokens(res.response().path("accessToken").asString(), res.response().path("refreshToken").asString(),
                res.response().path("sid").asString());
    }

    /** introspection 결과의 response */
    protected JsonNode introspection(String token) {
        Response res = introspect(token);
        if (res.status() != 200) {
            throw new AssertionError("introspection 실패: " + res.status() + " " + res.body());
        }
        return res.response();
    }

    /** Redis 재시작을 흉내 낸다(내용이 모두 사라짐, ADR-022) */
    protected void wipeRedis() {
        redis.getRequiredConnectionFactory().getConnection().serverCommands().flushDb();
    }

    /** Redis 응답을 멈춘다(장애 주입). 끝나면 {@link #resumeRedis()} */
    protected static void pauseRedis() {
        REDIS.getDockerClient().pauseContainerCmd(REDIS.getContainerId()).exec();
    }

    protected static void resumeRedis() {
        REDIS.getDockerClient().unpauseContainerCmd(REDIS.getContainerId()).exec();
    }

    /** 폐기 이벤트 채널(EVT-IAM-03)을 듣는다 */
    protected java.util.List<JsonNode> listenRevocations() {
        java.util.List<JsonNode> received = new java.util.concurrent.CopyOnWriteArrayList<>();
        org.springframework.data.redis.connection.RedisConnection connection =
                redis.getRequiredConnectionFactory().getConnection();
        connection.subscribe((message, pattern) -> received.add(json.readTree(new String(message.getBody(), StandardCharsets.UTF_8))),
                "data2flow:auth.revocations".getBytes(StandardCharsets.UTF_8));
        subscriptions.add(connection);
        return received;
    }

    private final java.util.List<org.springframework.data.redis.connection.RedisConnection> subscriptions =
            new java.util.concurrent.CopyOnWriteArrayList<>();

    @org.junit.jupiter.api.AfterEach
    void closeSubscriptions() {
        subscriptions.forEach(c -> {
            try {
                c.close();
            } catch (RuntimeException ignored) {
                // 테스트 정리
            }
        });
        subscriptions.clear();
    }

    /** 로그인 결과 토큰 */
    public record Tokens(String access, String refresh, String sid) {
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class ClockConfig {
        @Bean
        @Primary
        Clock testClock() {
            return CLOCK;
        }
    }
}
