package net.java21.data2flow.auth.support;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.RecordedRequest;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * core-api 내부 API의 가짜(MockWebServer Dispatcher). design/api/IAM-api.md §7과 design/openapi/internal/core-IAM.yaml의 계약을
 * 그대로 흉내 낸다. core-api는 병행 개발 중이라 auth는 이 계약으로만 검증한다.
 *
 * <ul>
 *   <li>API-IAM-30 verify-credentials: 원인 구분 없는 401, 5회 실패 시 LOCKED, PENDING_APPROVAL은 맞는 비밀번호일 때만 403</li>
 *   <li>API-IAM-36·35 Refresh 계보: ROTATED / GRACE(회전 후 30초 이내) / 재사용이면 계보 폐기 + 409 AUTH_SESSION_REVOKED</li>
 *   <li>API-IAM-37 세션 폐기, API-IAM-39a 폐기 기록, API-IAM-61b MFA, API-IAM-46 장기 토큰, API-IAM-39 감사</li>
 * </ul>
 */
public final class FakeCore extends Dispatcher {

    public static final Duration GRACE = Duration.ofSeconds(30);

    private final JsonMapper json = JsonMapper.builder().build();
    private final Clock clock;
    private final Map<String, User> users = new HashMap<>();
    private final Map<String, RefreshRow> refreshTokens = new LinkedHashMap<>();
    private final Map<String, Instant> revokedSessions = new LinkedHashMap<>();
    private final Map<String, ApiToken> apiTokens = new HashMap<>();
    private final List<JsonNode> audits = new CopyOnWriteArrayList<>();
    private final List<String> calls = new CopyOnWriteArrayList<>();
    private volatile boolean down;

    public FakeCore(Clock clock) {
        this.clock = clock;
    }

    // ---- 시나리오 준비 ----

    public synchronized void reset() {
        users.clear();
        refreshTokens.clear();
        revokedSessions.clear();
        apiTokens.clear();
        audits.clear();
        calls.clear();
        down = false;
    }

    public synchronized User addUser(long id, long orgId, String loginId, String password) {
        User user = new User(id, orgId, loginId, password);
        users.put(loginId, user);
        return user;
    }

    public synchronized void addApiToken(String tokenHash, ApiToken token) {
        apiTokens.put(tokenHash, token);
    }

    public void setDown(boolean down) {
        this.down = down;
    }

    /** 관리자 강제 종료(API-IAM-24)를 core가 처리한 것처럼 계보를 폐기한다 */
    public synchronized void revokeSessionDirectly(String sid) {
        revokeLineage(sid);
    }

    public synchronized User user(String loginId) {
        return users.get(loginId);
    }

    public List<JsonNode> audits() {
        return List.copyOf(audits);
    }

    public List<String> calls() {
        return List.copyOf(calls);
    }

    public synchronized RefreshRow refreshRow(String jti) {
        return refreshTokens.get(jti);
    }

    public synchronized List<RefreshRow> activeRefreshRows(String sid) {
        return refreshTokens.values().stream().filter(r -> r.sid.equals(sid) && r.revokedAt == null && r.rotatedAt == null).toList();
    }

    public synchronized long activeRefreshCount(String sid) {
        return refreshTokens.values().stream().filter(r -> r.sid.equals(sid) && r.revokedAt == null && r.rotatedAt == null).count();
    }

    public synchronized boolean sessionRevoked(String sid) {
        return revokedSessions.containsKey(sid);
    }

    // ---- 디스패치 ----

    @Override
    public synchronized MockResponse dispatch(RecordedRequest request) {
        String path = request.getPath() == null ? "" : request.getPath();
        String method = request.getMethod();
        calls.add(method + " " + path);
        if (down) {
            return error(503, "SERVICE_UNAVAILABLE");
        }
        if (!"data2flow-auth".equals(request.getHeader("X-CALLER-SERVICE"))) {
            return error(400, "INVALID_REQUEST");
        }
        JsonNode body = readBody(request);
        if ("POST".equals(method) && path.equals("/internal/core/users/verify-credentials")) {
            return verifyCredentials(body);
        }
        if ("POST".equals(method) && path.equals("/internal/core/refresh-tokens")) {
            return registerRefresh(body);
        }
        if ("POST".equals(method) && path.equals("/internal/core/refresh-tokens/rotate")) {
            return rotate(body);
        }
        if ("DELETE".equals(method) && path.startsWith("/internal/core/sessions/")) {
            String sid = path.substring("/internal/core/sessions/".length());
            boolean exists = refreshTokens.values().stream().anyMatch(r -> r.sid.equals(sid));
            if (!exists) {
                return error(404, "RESOURCE_NOT_FOUND");
            }
            revokeLineage(sid);
            return new MockResponse().setResponseCode(204);
        }
        if ("GET".equals(method) && path.startsWith("/internal/core/revocations")) {
            return revocations(path);
        }
        if ("POST".equals(method) && path.matches("/internal/core/users/\\d+/mfa/verify")) {
            long userId = Long.parseLong(path.split("/")[4]);
            String code = body.path("code").asString("");
            boolean ok = users.values().stream().anyMatch(u -> u.id == userId && code.equals(u.mfaCode));
            if (!ok) {
                users.values().stream().filter(u -> u.id == userId).forEach(u -> u.failures++);
            }
            return ok(200, Map.of("ok", ok));
        }
        if ("POST".equals(method) && path.equals("/internal/core/api-tokens/verify")) {
            ApiToken token = apiTokens.get(body.path("tokenHash").asString(""));
            if (token == null) {
                return ok(200, Map.of("active", false));
            }
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("active", token.active);
            r.put("ownerType", "USER");
            r.put("ownerId", token.userId);
            r.put("userId", token.userId);
            r.put("org", token.org);
            r.put("scopes", token.scopes);
            r.put("spaceScope", List.of());
            r.put("kind", token.kind);
            r.put("tokenId", token.tokenId);
            r.put("rateLimitPerMin", 60);
            return ok(200, r);
        }
        if ("POST".equals(method) && path.equals("/internal/core/audit-logs")) {
            audits.add(body);
            return ok(202, Map.of("accepted", true));
        }
        return error(404, "RESOURCE_NOT_FOUND");
    }

    private MockResponse verifyCredentials(JsonNode body) {
        String loginId = body.path("loginId").asString("");
        String password = body.path("password").asString("");
        User user = users.get(loginId);
        Instant now = clock.instant();
        if (user == null) {
            return error(401, "AUTH_INVALID_CREDENTIALS");
        }
        if ("LOCKED".equals(user.status) && user.lockedUntil != null && !now.isBefore(user.lockedUntil)) {
            user.status = "ACTIVE";
            user.failures = 0;
        }
        boolean passwordOk = password.equals(user.password);
        if ("PENDING_APPROVAL".equals(user.status)) {
            return passwordOk ? error(403, "AUTH_PENDING_APPROVAL") : error(401, "AUTH_INVALID_CREDENTIALS");
        }
        if (!"ACTIVE".equals(user.status)) {
            return error(401, "AUTH_INVALID_CREDENTIALS");
        }
        if (!passwordOk) {
            user.failures++;
            if (user.failures >= 5) {
                user.status = "LOCKED";
                user.lockedUntil = now.plus(Duration.ofMinutes(15));
            }
            return error(401, "AUTH_INVALID_CREDENTIALS");
        }
        user.failures = 0;
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("userId", Long.toString(user.id));
        r.put("orgId", Long.toString(user.orgId));
        r.put("mustChangePassword", user.mustChangePassword);
        r.put("mfaEnabled", user.mfaCode != null);
        return ok(200, r);
    }

    private MockResponse registerRefresh(JsonNode body) {
        RefreshRow row = new RefreshRow(body.path("jti").asString(), body.path("sid").asString(),
                Long.parseLong(body.path("userId").asString()), body.path("tokenHash").asString(),
                Instant.parse(body.path("expiresAt").asString()), Instant.parse(body.path("absoluteExpiresAt").asString()));
        row.ip = body.path("ip").asString(null);
        row.userAgent = body.path("userAgent").asString(null);
        refreshTokens.put(row.jti, row);
        return ok(201, Map.of("jti", row.jti, "sid", row.sid, "expiresAt", row.expiresAt.toString()));
    }

    private MockResponse rotate(JsonNode body) {
        RefreshRow presented = refreshTokens.get(body.path("presentedJti").asString(""));
        Instant now = clock.instant();
        if (presented == null) {
            return error(404, "RESOURCE_NOT_FOUND");
        }
        if (presented.revokedAt != null) {
            return error(409, "AUTH_SESSION_REVOKED");
        }
        if (presented.rotatedAt == null) {
            presented.rotatedAt = now;
            RefreshRow next = new RefreshRow(body.path("nextJti").asString(), presented.sid, presented.userId,
                    body.path("nextTokenHash").asString(), Instant.parse(body.path("nextExpiresAt").asString()),
                    presented.absoluteExpiresAt);
            refreshTokens.put(next.jti, next);
            return ok(200, Map.of("decision", "ROTATED", "effectiveJti", next.jti));
        }
        if (!now.isAfter(presented.rotatedAt.plus(GRACE))) {
            String latest = refreshTokens.values().stream()
                    .filter(r -> r.sid.equals(presented.sid) && r.rotatedAt == null && r.revokedAt == null)
                    .map(r -> r.jti).reduce((a, b) -> b).orElse(presented.jti);
            return ok(200, Map.of("decision", "GRACE", "effectiveJti", latest));
        }
        revokeLineage(presented.sid);
        return error(409, "AUTH_SESSION_REVOKED");
    }

    private MockResponse revocations(String path) {
        Instant since = Instant.EPOCH;
        int q = path.indexOf("since=");
        if (q >= 0) {
            since = Instant.parse(java.net.URLDecoder.decode(path.substring(q + 6), java.nio.charset.StandardCharsets.UTF_8));
        }
        Instant from = since;
        List<String> sids = new ArrayList<>();
        revokedSessions.forEach((sid, at) -> {
            if (!at.isBefore(from)) {
                sids.add(sid);
            }
        });
        return ok(200, Map.of("sids", sids, "jtis", List.of()));
    }

    private void revokeLineage(String sid) {
        Instant now = clock.instant();
        refreshTokens.values().stream().filter(r -> r.sid.equals(sid) && r.revokedAt == null).forEach(r -> r.revokedAt = now);
        revokedSessions.putIfAbsent(sid, now);
    }

    private JsonNode readBody(RecordedRequest request) {
        String text = request.getBody().readUtf8();
        if (text.isBlank()) {
            return json.createObjectNode();
        }
        return json.readTree(text);
    }

    private MockResponse ok(int status, Object response) {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("header", Map.of("isSuccessful", true, "resultCode", "SUCCESS", "resultMessage", "SUCCESS"));
        root.put("response", response);
        return new MockResponse().setResponseCode(status).setHeader("Content-Type", "application/json")
                .setBody(json.writeValueAsString(root));
    }

    private MockResponse error(int status, String code) {
        Map<String, Object> root = Map.of("header", Map.of("isSuccessful", false, "resultCode", code, "resultMessage", code));
        return new MockResponse().setResponseCode(status).setHeader("Content-Type", "application/json")
                .setBody(json.writeValueAsString(root));
    }

    /** 가짜 회원 */
    public static final class User {
        public final long id;
        public final long orgId;
        public final String loginId;
        public String password;
        public String status = "ACTIVE";
        public boolean mustChangePassword;
        public String mfaCode;
        public int failures;
        public Instant lockedUntil;

        User(long id, long orgId, String loginId, String password) {
            this.id = id;
            this.orgId = orgId;
            this.loginId = loginId;
            this.password = password;
        }

        /** 관리자 잠금 해제(API-IAM-27) */
        public void unlock() {
            status = "ACTIVE";
            failures = 0;
            lockedUntil = null;
        }
    }

    /** refresh_tokens 한 행 */
    public static final class RefreshRow {
        public final String jti;
        public final String sid;
        public final long userId;
        public final String tokenHash;
        public final Instant expiresAt;
        public final Instant absoluteExpiresAt;
        public Instant rotatedAt;
        public Instant revokedAt;
        public String ip;
        public String userAgent;

        RefreshRow(String jti, String sid, long userId, String tokenHash, Instant expiresAt, Instant absoluteExpiresAt) {
            this.jti = jti;
            this.sid = sid;
            this.userId = userId;
            this.tokenHash = tokenHash;
            this.expiresAt = expiresAt;
            this.absoluteExpiresAt = absoluteExpiresAt;
        }
    }

    /** 장기 토큰 */
    public record ApiToken(boolean active, String userId, String org, String tokenId, String kind, List<String> scopes) {
    }
}
