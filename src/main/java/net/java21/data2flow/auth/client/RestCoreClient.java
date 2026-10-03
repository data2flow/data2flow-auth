package net.java21.data2flow.auth.client;

import net.java21.data2flow.auth.client.dto.ApiTokenVerification;
import net.java21.data2flow.auth.client.dto.RegisterRefreshTokenRequest;
import net.java21.data2flow.auth.client.dto.Revocations;
import net.java21.data2flow.auth.client.dto.RotateRefreshTokenRequest;
import net.java21.data2flow.auth.client.dto.RotationDecision;
import net.java21.data2flow.auth.client.dto.VerifiedCredentials;
import net.java21.data2flow.auth.common.AuthErrorCode;
import net.java21.data2flow.auth.common.DependencyUnavailableException;
import net.java21.data2flow.contracts.audit.AuditEvent;
import net.java21.data2flow.contracts.error.BusinessException;
import net.java21.data2flow.contracts.error.CommonErrorCode;
import net.java21.data2flow.contracts.identity.DataflowHeaders;
import net.java21.data2flow.contracts.web.RequestIdFilter;
import org.slf4j.MDC;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.io.InputStream;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * core-api 내부 API를 RestClient로 부른다(HTTP 80, 토큰 없음 + {@code X-CALLER-SERVICE: data2flow-auth}, ADR-021).
 * 응답은 공통 형식 {@code {header:{isSuccessful,resultCode,resultMessage}, response}}이고 실패는 resultCode로 가른다.
 * 연결 실패·시간 초과·5xx는 {@link DependencyUnavailableException}(fail-closed)이다.
 */
public class RestCoreClient implements CoreClient {

    static final String CALLER = "data2flow-auth";
    private static final Pattern NUMERIC = Pattern.compile("[1-9][0-9]{0,18}");

    private final RestClient restClient;
    private final JsonMapper jsonMapper;

    public RestCoreClient(RestClient restClient, JsonMapper jsonMapper) {
        this.restClient = restClient;
        this.jsonMapper = jsonMapper;
    }

    @Override
    public VerifiedCredentials verifyCredentials(String loginId, String password, String ip, String userAgent) {
        Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("loginId", loginId);
        body.put("password", password);
        body.put("ip", ip);
        body.put("userAgent", userAgent);
        Reply reply = call(HttpMethod.POST, URI.create("/internal/core/users/verify-credentials"), body);
        if (reply.status() == 200) {
            JsonNode r = reply.response();
            return new VerifiedCredentials(requireId(r, "userId"), requireId(r, "orgId"),
                    r.path("mustChangePassword").asBoolean(false), r.path("mfaEnabled").asBoolean(false));
        }
        if (reply.status() == 403 && AuthErrorCode.AUTH_PENDING_APPROVAL.code().equals(reply.resultCode())) {
            throw new BusinessException(AuthErrorCode.AUTH_PENDING_APPROVAL);
        }
        // 401(아이디 없음·비밀번호 틀림·잠금·비활성), 그 밖의 4xx도 원인을 드러내지 않는다(IAM-02.03)
        throw new BusinessException(CommonErrorCode.AUTH_INVALID_CREDENTIALS);
    }

    @Override
    public void registerRefreshToken(RegisterRefreshTokenRequest request) {
        Reply reply = call(HttpMethod.POST, URI.create("/internal/core/refresh-tokens"), request);
        if (reply.status() != 201 && reply.status() != 200) {
            throw new DependencyUnavailableException("Refresh 계보 등록 실패: " + reply.status() + " " + reply.resultCode());
        }
    }

    @Override
    public RotationDecision rotateRefreshToken(RotateRefreshTokenRequest request) {
        Reply reply = call(HttpMethod.POST, URI.create("/internal/core/refresh-tokens/rotate"), request);
        if (reply.status() == 200) {
            String decision = reply.response().path("decision").asString("");
            String effectiveJti = text(reply.response(), "effectiveJti");
            try {
                return new RotationDecision(RotationDecision.Decision.valueOf(decision), effectiveJti);
            } catch (IllegalArgumentException ex) {
                throw new DependencyUnavailableException("알 수 없는 회전 판정: " + decision);
            }
        }
        if (reply.status() == 409 && CommonErrorCode.AUTH_SESSION_REVOKED.code().equals(reply.resultCode())) {
            throw new RefreshReuseDetectedException();
        }
        if (CommonErrorCode.AUTH_SESSION_REVOKED.code().equals(reply.resultCode())) {
            throw new BusinessException(CommonErrorCode.AUTH_SESSION_REVOKED);
        }
        if (CommonErrorCode.AUTH_SESSION_EXPIRED.code().equals(reply.resultCode())) {
            throw new BusinessException(CommonErrorCode.AUTH_SESSION_EXPIRED);
        }
        // 없는 jti(404), 그 밖의 4xx는 토큰을 믿을 수 없다
        throw new BusinessException(CommonErrorCode.AUTH_TOKEN_INVALID);
    }

    @Override
    public void revokeSession(String sid, String reason) {
        Reply reply = call(HttpMethod.DELETE, URI.create("/internal/core/sessions/" + sid), Map.of("reason", reason));
        if (reply.status() != 204 && reply.status() != 200 && reply.status() != 404) {
            throw new DependencyUnavailableException("세션 폐기 실패: " + reply.status() + " " + reply.resultCode());
        }
    }

    @Override
    public Revocations findRevocationsSince(Instant since) {
        Reply reply = call(HttpMethod.GET, URI.create("/internal/core/revocations?since=" + since), null);
        if (reply.status() != 200) {
            throw new DependencyUnavailableException("폐기 기록 조회 실패: " + reply.status() + " " + reply.resultCode());
        }
        return new Revocations(values(reply.response().get("sids"), "sid"), values(reply.response().get("jtis"), "jti"));
    }

    @Override
    public boolean verifyMfa(long userId, String code) {
        Reply reply = call(HttpMethod.POST, URI.create("/internal/core/users/" + userId + "/mfa/verify"), Map.of("code", code));
        if (reply.status() == 200) {
            return reply.response().path("ok").asBoolean(false);
        }
        if (reply.status() == 401 || reply.status() == 400 || reply.status() == 404 || reply.status() == 409) {
            return false;
        }
        throw new DependencyUnavailableException("2단계 인증 확인 실패: " + reply.status() + " " + reply.resultCode());
    }

    @Override
    public ApiTokenVerification verifyApiToken(String tokenHash) {
        Reply reply = call(HttpMethod.POST, URI.create("/internal/core/api-tokens/verify"), Map.of("tokenHash", tokenHash));
        if (reply.status() != 200) {
            if (reply.status() >= 400 && reply.status() < 500) {
                return new ApiTokenVerification(false, null, null, null, null, List.of(), List.of(), null, null, null);
            }
            throw new DependencyUnavailableException("장기 토큰 확인 실패: " + reply.status());
        }
        JsonNode r = reply.response();
        JsonNode rate = r.get("rateLimitPerMin");
        return new ApiTokenVerification(r.path("active").asBoolean(false), text(r, "ownerType"), text(r, "ownerId"),
                text(r, "userId"), text(r, "org"), values(r.get("scopes"), null), values(r.get("spaceScope"), null),
                text(r, "kind"), text(r, "tokenId"), rate != null && rate.isNumber() ? rate.asLong() : null);
    }

    @Override
    public void recordAudit(AuditEvent event) {
        Reply reply = call(HttpMethod.POST, URI.create("/internal/core/audit-logs"), event);
        if (reply.status() >= 300) {
            throw new DependencyUnavailableException("감사 기록 실패: " + reply.status() + " " + reply.resultCode());
        }
    }

    // --- 공통 ---

    private Reply call(HttpMethod method, URI uri, Object body) {
        try {
            RestClient.RequestBodySpec spec = restClient.method(method).uri(uri.toString())
                    .header(DataflowHeaders.CALLER_SERVICE, CALLER)
                    .accept(MediaType.APPLICATION_JSON);
            String requestId = MDC.get(RequestIdFilter.MDC_KEY);
            if (requestId != null) {
                spec.header(DataflowHeaders.REQUEST_ID, requestId);
            }
            if (body != null) {
                spec.contentType(MediaType.APPLICATION_JSON).body(body);
            }
            Reply reply = spec.exchange((req, res) -> {
                int status = res.getStatusCode().value();
                JsonNode root = null;
                try (InputStream in = res.getBody()) {
                    byte[] bytes = in.readAllBytes();
                    if (bytes.length > 0) {
                        root = jsonMapper.readTree(bytes);
                    }
                } catch (RuntimeException ex) {
                    root = null; // 형식이 다른 본문(예: 프록시 HTML)은 상태 코드로만 판정
                }
                return new Reply(status, root);
            });
            if (reply.status() >= 500) {
                throw new DependencyUnavailableException("core-api " + reply.status() + " " + uri.getPath());
            }
            return reply;
        } catch (RestClientException ex) {
            throw new DependencyUnavailableException("core-api 호출 실패 " + uri.getPath(), ex);
        }
    }

    private static long requireId(JsonNode node, String field) {
        String value = text(node, field);
        if (value == null || !NUMERIC.matcher(value).matches()) {
            throw new DependencyUnavailableException("core 응답에 " + field + "가 없습니다");
        }
        return Long.parseLong(value);
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node == null ? null : node.get(field);
        if (value == null || value.isNull()) {
            return null;
        }
        String text = value.asString();
        return text == null || text.isBlank() ? null : text;
    }

    /** 배열 항목이 문자열이든 {@code {sid|jti|value: …}} 객체든 값만 꺼낸다(core 응답 모양 차이에 견디기) */
    private static List<String> values(JsonNode array, String objectField) {
        List<String> values = new ArrayList<>();
        if (array == null || !array.isArray()) {
            return values;
        }
        for (JsonNode item : array) {
            String value = null;
            if (item.isObject()) {
                value = objectField == null ? null : text(item, objectField);
                if (value == null) {
                    value = text(item, "value");
                }
            } else if (!item.isNull()) {
                value = item.asString();
            }
            if (value != null && !value.isBlank()) {
                values.add(value);
            }
        }
        return values;
    }

    /** core 응답 한 건 */
    record Reply(int status, JsonNode root) {

        JsonNode response() {
            JsonNode response = root == null ? null : root.get("response");
            if (response == null || response.isNull()) {
                throw new DependencyUnavailableException("core 응답에 response가 없습니다");
            }
            return response;
        }

        String resultCode() {
            return root == null ? null : root.path("header").path("resultCode").asString(null);
        }
    }
}
