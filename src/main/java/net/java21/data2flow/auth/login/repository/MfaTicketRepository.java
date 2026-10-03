package net.java21.data2flow.auth.login.repository;

import net.java21.data2flow.auth.common.RedisCalls;
import org.springframework.data.redis.core.StringRedisTemplate;
import net.java21.data2flow.contracts.tenancy.OrganizationScopeExempt;
import org.springframework.stereotype.Repository;
import tools.jackson.databind.json.JsonMapper;

import java.time.Duration;
import java.util.Optional;

/**
 * 2단계 인증 대기 티켓(API-IAM-01 → API-IAM-62, 5분·1회용). 키는 티켓 원문이 아닌 SHA-256({@code data2flow:auth:mfa:{hash}}).
 * Redis가 비워지면 사용자는 다시 로그인하면 된다(ADR-022 캐시 용도).
 */
@Repository
@OrganizationScopeExempt("Redis 캐시: 토큰·세션·티켓 해시로 찾는 인증 조회라 조직 조건이 없다(조직은 토큰 클레임에 있음)")
public class MfaTicketRepository {

    public static final String PREFIX = "data2flow:auth:mfa:";

    private final StringRedisTemplate redis;
    private final JsonMapper jsonMapper;

    public MfaTicketRepository(StringRedisTemplate redis, JsonMapper jsonMapper) {
        this.redis = redis;
        this.jsonMapper = jsonMapper;
    }

    public void save(String ticketHash, PendingMfa pending, Duration ttl) {
        String json = jsonMapper.writeValueAsString(pending);
        RedisCalls.run("MFA 티켓 저장", () -> redis.opsForValue().set(PREFIX + ticketHash, json, ttl));
    }

    public Optional<PendingMfa> find(String ticketHash) {
        String json = RedisCalls.call("MFA 티켓 조회", () -> redis.opsForValue().get(PREFIX + ticketHash));
        return Optional.ofNullable(json).map(j -> jsonMapper.readValue(j, PendingMfa.class));
    }

    /** 원자적으로 꺼내며 지운다. 같은 티켓을 두 요청이 동시에 써도 하나만 성공한다 */
    public boolean consume(String ticketHash) {
        return RedisCalls.call("MFA 티켓 사용", () -> redis.opsForValue().getAndDelete(PREFIX + ticketHash)) != null;
    }

    public void delete(String ticketHash) {
        RedisCalls.run("MFA 티켓 삭제", () -> redis.delete(PREFIX + ticketHash));
    }

    /** 비밀번호까지 확인된 로그인 정보 */
    public record PendingMfa(long userId, long organizationId, boolean mustChangePassword, java.time.Instant expiresAt) {
    }
}
