package net.java21.data2flow.auth.support;

import net.java21.data2flow.auth.config.AuthProperties;
import net.java21.data2flow.auth.session.domain.SessionPolicy;
import net.java21.data2flow.auth.token.controller.RefreshCookies;
import net.java21.data2flow.auth.token.domain.JwtCodec;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

import java.time.Duration;

/** 컨트롤러 슬라이스 테스트 공통 빈: 설정, 실제 서명기(테스트 키), 시계, Refresh 쿠키 */
@TestConfiguration(proxyBeanMethods = false)
@EnableConfigurationProperties(AuthProperties.class)
@Import(RefreshCookies.class)
public class WebSliceConfig {

    public static final MutableClock CLOCK = MutableClock.atDefault();

    @Bean
    MutableClock clock() {
        return CLOCK;
    }

    @Bean
    JwtCodec jwtCodec() {
        return TestKeys.codec(CLOCK);
    }

    @Bean
    SessionPolicy sessionPolicy() {
        return new SessionPolicy(Duration.ofMinutes(30), Duration.ofHours(12));
    }
}
