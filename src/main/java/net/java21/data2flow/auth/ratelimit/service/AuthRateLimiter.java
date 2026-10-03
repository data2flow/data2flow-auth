package net.java21.data2flow.auth.ratelimit.service;

import io.micrometer.core.instrument.MeterRegistry;
import net.java21.data2flow.auth.common.Hashes;
import net.java21.data2flow.auth.config.AuthProperties;
import net.java21.data2flow.auth.ratelimit.repository.RateLimitRepository;
import net.java21.data2flow.contracts.error.CommonErrorCode;
import net.java21.data2flow.contracts.ratelimit.RateLimitInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;

/**
 * 로그인·재발급·2단계 인증 시도 한도(IAM-07.07, BR-IAM-23). 넘으면 429 {@code AUTH_RATE_LIMITED} + {@code Retry-After}·
 * {@code X-RateLimit-*}(data2flow-contracts {@link RateLimitInfo}), 로그와 지표({@code data2flow_auth_rate_limited_total})에 남긴다.
 * Redis를 못 쓰면 503(fail-closed, AT-IAM-02.9).
 *
 * <p>로그인 IP 한도는 gateway도 같은 값으로 센다(인증 전 필터). auth도 세는 이유는 클러스터 안에서 gateway를 거치지 않은 호출도
 * 같은 한도를 받게 하기 위해서다. 아이디·sid·티켓 한도는 본문을 읽어야 알 수 있어 auth만 센다.
 */
@Service
public class AuthRateLimiter {

    private static final Logger log = LoggerFactory.getLogger(AuthRateLimiter.class);

    private final RateLimitRepository repository;
    private final AuthProperties.RateLimit limits;
    private final Clock clock;
    private final MeterRegistry meterRegistry;

    public AuthRateLimiter(RateLimitRepository repository, AuthProperties properties, Clock clock, MeterRegistry meterRegistry) {
        this.repository = repository;
        this.limits = properties.rateLimit();
        this.clock = clock;
        this.meterRegistry = meterRegistry;
    }

    /** 로그인: IP당 분당 20회 */
    public void loginByIp(String ip) {
        hit("login-ip", ip, limits.loginPerIp(), limits.window());
    }

    /** 로그인: 아이디당 분당 5회(아이디는 해시로 키를 만든다) */
    public void loginByLoginId(String normalizedLoginId) {
        hit("login-id", Hashes.sha256Hex(normalizedLoginId), limits.loginPerLoginId(), limits.window());
    }

    /** 재발급: sid당 분당 10회 */
    public void refreshBySid(String sid) {
        hit("refresh-sid", sid, limits.refreshPerSid(), limits.window());
    }

    /** 2단계 인증 확인: IP당 분당 20회 */
    public void mfaByIp(String ip) {
        hit("mfa-ip", ip, limits.mfaPerIp(), limits.window());
    }

    /** 2단계 인증 확인: 티켓 하나당 시도 수(티켓 수명 동안) */
    public void mfaByTicket(String ticketHash, int maxAttempts, Duration ticketTtl) {
        hit("mfa-ticket", ticketHash, maxAttempts, ticketTtl);
    }

    RateLimitInfo hit(String bucket, String subject, int limit, Duration window) {
        long nowMillis = clock.millis();
        long windowMillis = Math.max(1000, window.toMillis());
        long index = nowMillis / windowMillis;
        long windowEnd = (index + 1) * windowMillis;
        long count = repository.increment(bucket + ":" + subject + ":" + index, Duration.ofMillis(windowEnd - nowMillis + 1000));
        long resetSeconds = Math.max(1, (windowEnd - nowMillis + 999) / 1000);
        RateLimitInfo info = new RateLimitInfo(limit, limit - count, resetSeconds);
        if (count > limit) {
            meterRegistry.counter("data2flow_auth_rate_limited", "limit", bucket).increment();
            log.atWarn().addKeyValue("limit", bucket).addKeyValue("count", count)
                    .log("호출 한도 초과로 거부(IAM-07.07): {}", bucket);
            throw info.exceeded(CommonErrorCode.AUTH_RATE_LIMITED);
        }
        return info;
    }
}
