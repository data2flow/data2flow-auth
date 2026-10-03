package net.java21.data2flow.auth.config;

import net.java21.data2flow.auth.client.CoreClient;
import net.java21.data2flow.auth.client.RestCoreClient;
import net.java21.data2flow.auth.session.domain.SessionPolicy;
import net.java21.data2flow.auth.token.domain.JwtCodec;
import net.java21.data2flow.auth.token.domain.SigningKeyRing;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.json.JsonMapper;

import java.net.http.HttpClient;
import java.time.Clock;

/** auth 빈 구성. 서명 키가 없거나 형식이 틀리면 기동하지 않는다(design/auth.md §11 #8 — 기본 시크릿 없음) */
@Configuration(proxyBeanMethods = false)
public class AuthConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    public SigningKeyRing signingKeyRing(AuthProperties properties) {
        return SigningKeyRing.parse(properties.jwt().keys(), properties.jwt().activeKeyId());
    }

    @Bean
    public JwtCodec jwtCodec(SigningKeyRing keyRing, AuthProperties properties, Clock clock) {
        return new JwtCodec(keyRing, properties.jwt().issuer(), properties.jwt().audience(), properties.jwt().clockSkew(), clock);
    }

    @Bean
    public SessionPolicy sessionPolicy(AuthProperties properties) {
        return new SessionPolicy(properties.session().idleTimeout(), properties.session().absoluteTtl());
    }

    @Bean
    public CoreClient coreClient(RestClient.Builder builder, AuthProperties properties, JsonMapper jsonMapper) {
        AuthProperties.Core core = properties.core();
        HttpClient http = HttpClient.newBuilder().connectTimeout(core.connectTimeout()).build();
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(http);
        factory.setReadTimeout(core.readTimeout());
        return new RestCoreClient(builder.clone().baseUrl(core.baseUrl().toString()).requestFactory(factory).build(), jsonMapper);
    }
}
