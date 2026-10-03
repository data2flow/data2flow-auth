package net.java21.data2flow.auth.revocation.repository;

import net.java21.data2flow.auth.common.RedisCalls;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.SessionCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import net.java21.data2flow.contracts.tenancy.OrganizationScopeExempt;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * Redis에 둔 토큰 상태(design/auth.md §4.2). 모두 재시작하면 사라져도 되는 사본이고 원천은 core DB다(ADR-022).
 *
 * <ul>
 *   <li>{@code data2flow:bl:at:{jti}}, {@code data2flow:bl:sid:{sid}} — 폐기 목록. TTL은 Access 수명</li>
 *   <li>{@code data2flow:boot} — 재적재 표식. 없으면 Redis가 비었다고 보고 core에서 다시 적재한다</li>
 *   <li>{@code data2flow:auth:session:{sid}} — 세션 마지막 활동. TTL은 유휴 만료(IAM-03.01)</li>
 * </ul>
 * introspection 한 번에 네 키를 {@code MGET} 한 번으로 읽는다.
 */
@Repository
@OrganizationScopeExempt("Redis 캐시: 토큰·세션·티켓 해시로 찾는 인증 조회라 조직 조건이 없다(조직은 토큰 클레임에 있음)")
public class BlacklistRepository {

    public static final String JTI_PREFIX = "data2flow:bl:at:";
    public static final String SID_PREFIX = "data2flow:bl:sid:";
    public static final String BOOT_KEY = "data2flow:boot";
    public static final String ACTIVITY_PREFIX = "data2flow:auth:session:";

    private final StringRedisTemplate redis;

    public BlacklistRepository(StringRedisTemplate redis) {
        this.redis = redis;
    }

    /** 한 토큰의 폐기 여부, 재적재 표식, 세션 마지막 활동을 한 번에 읽는다 */
    public Snapshot snapshot(String jti, String sid) {
        List<String> values = RedisCalls.call("블랙리스트 조회",
                () -> redis.opsForValue().multiGet(List.of(JTI_PREFIX + jti, SID_PREFIX + sid, BOOT_KEY, ACTIVITY_PREFIX + sid)));
        if (values == null || values.size() < 4) {
            throw new IllegalStateException("MGET 결과가 모자랍니다");
        }
        return new Snapshot(values.get(0) != null, values.get(1) != null, parse(values.get(2)), parse(values.get(3)));
    }

    public boolean isSessionRevoked(String sid) {
        return Boolean.TRUE.equals(RedisCalls.call("블랙리스트 조회", () -> redis.hasKey(SID_PREFIX + sid)));
    }

    /** sid·jti를 폐기 목록에 올린다. 같은 값을 다시 올려도 TTL만 다시 정해진다(멱등) */
    public void revoke(Collection<String> sids, Collection<String> jtis, String reason, Duration ttl) {
        RedisCalls.run("블랙리스트 등록", () -> redis.executePipelined(new SessionCallback<Object>() {
            @Override
            @SuppressWarnings("unchecked")
            public <K, V> Object execute(RedisOperations<K, V> operations) {
                RedisOperations<String, String> ops = (RedisOperations<String, String>) operations;
                sids.forEach(sid -> ops.opsForValue().set(SID_PREFIX + sid, reason, ttl));
                jtis.forEach(jti -> ops.opsForValue().set(JTI_PREFIX + jti, reason, ttl));
                return null;
            }
        }));
    }

    public Optional<Instant> bootMarker() {
        return Optional.ofNullable(parse(RedisCalls.call("재적재 표식 조회", () -> redis.opsForValue().get(BOOT_KEY))));
    }

    public void markBoot(Instant reloadedAt) {
        RedisCalls.run("재적재 표식 기록", () -> redis.opsForValue().set(BOOT_KEY, reloadedAt.toString()));
    }

    /** 세션 활동 기록. TTL이 지나면 키가 사라져 유휴 만료로 본다 */
    public void touchActivity(String sid, Instant at, Duration idleTimeout) {
        RedisCalls.run("세션 활동 기록", () -> redis.opsForValue().set(ACTIVITY_PREFIX + sid, at.toString(), idleTimeout));
    }

    private static Instant parse(String value) {
        if (value == null) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException ex) {
            return Instant.EPOCH; // 표식은 있지만 형식이 다르면(다른 도구가 씀) 오래전에 적재된 것으로 본다
        }
    }

    /**
     * @param jtiRevoked     {@code bl:at:{jti}} 있음
     * @param sidRevoked     {@code bl:sid:{sid}} 있음
     * @param bootMarker     재적재 시각. null이면 Redis가 비었다고 본다
     * @param lastActivity   세션 마지막 활동 시각. null이면 기록 없음(유휴 만료로 TTL이 지났거나 Redis가 비워짐)
     */
    public record Snapshot(boolean jtiRevoked, boolean sidRevoked, Instant bootMarker, Instant lastActivity) {

        public boolean revoked() {
            return jtiRevoked || sidRevoked;
        }
    }
}
