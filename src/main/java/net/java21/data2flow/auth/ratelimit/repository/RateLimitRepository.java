package net.java21.data2flow.auth.ratelimit.repository;

import net.java21.data2flow.auth.common.RedisCalls;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import net.java21.data2flow.contracts.tenancy.OrganizationScopeExempt;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.util.List;

/**
 * 고정 창 카운터(Redis, 인스턴스가 여러 개여도 한도가 늘지 않음 — design/auth.md §11 #11). 키 접두사 {@code data2flow:auth:rl:}.
 * INCR과 만료 설정을 스크립트 하나로 묶어, 중간에 끊겨도 만료 없는 키가 남지 않게 한다.
 */
@Repository
@OrganizationScopeExempt("Redis 캐시: 토큰·세션·티켓 해시로 찾는 인증 조회라 조직 조건이 없다(조직은 토큰 클레임에 있음)")
public class RateLimitRepository {

    public static final String PREFIX = "data2flow:auth:rl:";

    private static final RedisScript<Long> INCREMENT = new DefaultRedisScript<>(
            "local c = redis.call('INCR', KEYS[1]) if c == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end return c",
            Long.class);

    private final StringRedisTemplate redis;

    public RateLimitRepository(StringRedisTemplate redis) {
        this.redis = redis;
    }

    /** 창 안 호출 수를 하나 올리고 올린 뒤의 값을 돌려준다 */
    public long increment(String key, Duration ttl) {
        Long count = RedisCalls.call("호출 한도", () -> redis.execute(INCREMENT, List.of(PREFIX + key), Long.toString(ttl.toMillis())));
        return count == null ? Long.MAX_VALUE : count;
    }
}
