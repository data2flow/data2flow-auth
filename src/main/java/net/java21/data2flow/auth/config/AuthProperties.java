package net.java21.data2flow.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;
import java.time.Duration;

/**
 * data2flow-auth 설정(design/auth.md §3·§4, IAM-03.01, IAM-07.01·07.07). 비밀값(서명 키)은 환경변수·k8s Secret에서만 받는다.
 *
 * @param jwt          서명·검증
 * @param token        토큰 수명
 * @param session      세션 유휴·절대 만료(BR-IAM-15)
 * @param mfa          2단계 인증 티켓(API-IAM-62)
 * @param rateLimit    호출 한도(BR-IAM-23)
 * @param revocation   블랙리스트 재적재(ADR-022)
 * @param core         core-api 내부 API
 * @param refreshCookie Refresh 쿠키(API-IAM-01·02)
 */
@ConfigurationProperties(prefix = "data2flow.auth")
public record AuthProperties(Jwt jwt, Token token, Session session, Mfa mfa, RateLimit rateLimit, Revocation revocation,
                             Core core, RefreshCookie refreshCookie) {

    public AuthProperties {
        jwt = jwt == null ? new Jwt(null, null, null, null, null) : jwt;
        token = token == null ? new Token(null, null) : token;
        session = session == null ? new Session(null, null) : session;
        mfa = mfa == null ? new Mfa(null, 0) : mfa;
        rateLimit = rateLimit == null ? new RateLimit(null, 0, 0, 0, 0) : rateLimit;
        revocation = revocation == null ? new Revocation(null, null) : revocation;
        core = core == null ? new Core(null, null, null) : core;
        refreshCookie = refreshCookie == null ? new RefreshCookie(null, null, null) : refreshCookie;
    }

    /**
     * @param issuer      {@code iss}
     * @param audience    {@code aud}
     * @param keys        {@code kid:Base64(32바이트 이상)[@검증 종료 ISO-8601],…} — 키 교체 기간에는 이전 키에 종료 시각을 붙인다
     * @param activeKeyId 서명에 쓰는 키. 키가 하나면 생략
     * @param clockSkew   exp·nbf 허용 오차
     */
    public record Jwt(String issuer, String audience, String keys, String activeKeyId, Duration clockSkew) {
        public Jwt {
            issuer = blank(issuer) ? "data2flow-auth" : issuer;
            audience = blank(audience) ? "data2flow" : audience;
            clockSkew = clockSkew == null ? Duration.ofSeconds(30) : clockSkew;
        }
    }

    /** @param accessTtl 기본 60분, @param refreshTtl 기본 6시간(슬라이딩) — IAM-07.01 */
    public record Token(Duration accessTtl, Duration refreshTtl) {
        public Token {
            accessTtl = accessTtl == null ? Duration.ofMinutes(60) : accessTtl;
            refreshTtl = refreshTtl == null ? Duration.ofHours(6) : refreshTtl;
        }
    }

    /** @param idleTimeout 마지막 활동 후 세션 종료(기본 30분, 0이면 끔), @param absoluteTtl 최초 로그인 후 최대 수명(기본 12시간) */
    public record Session(Duration idleTimeout, Duration absoluteTtl) {
        public Session {
            idleTimeout = idleTimeout == null ? Duration.ofMinutes(30) : idleTimeout;
            absoluteTtl = absoluteTtl == null ? Duration.ofHours(12) : absoluteTtl;
        }

        public boolean idleCheckEnabled() {
            return !idleTimeout.isZero() && !idleTimeout.isNegative();
        }
    }

    /** @param ticketTtl MFA 티켓 수명(5분, 1회용), @param maxAttempts 티켓 하나로 시도할 수 있는 횟수 */
    public record Mfa(Duration ticketTtl, int maxAttempts) {
        public Mfa {
            ticketTtl = ticketTtl == null ? Duration.ofMinutes(5) : ticketTtl;
            maxAttempts = maxAttempts <= 0 ? 5 : maxAttempts;
        }
    }

    /** BR-IAM-23: 로그인 IP당 분당 20회, 아이디당 분당 5회, 재발급 sid당 분당 10회 */
    public record RateLimit(Duration window, int loginPerIp, int loginPerLoginId, int refreshPerSid, int mfaPerIp) {
        public RateLimit {
            window = window == null ? Duration.ofMinutes(1) : window;
            loginPerIp = loginPerIp <= 0 ? 20 : loginPerIp;
            loginPerLoginId = loginPerLoginId <= 0 ? 5 : loginPerLoginId;
            refreshPerSid = refreshPerSid <= 0 ? 10 : refreshPerSid;
            mfaPerIp = mfaPerIp <= 0 ? 20 : mfaPerIp;
        }
    }

    /** @param watchInterval Redis 재시작 표식 확인 주기, @param reloadWindow 재적재할 폐기 기록 범위(기본 Access 수명) */
    public record Revocation(Duration watchInterval, Duration reloadWindow) {
        public Revocation {
            watchInterval = watchInterval == null ? Duration.ofSeconds(15) : watchInterval;
        }
    }

    /** core-api 내부 API(k8s Service, HTTP 80). 연결 1초·응답 2초 */
    public record Core(URI baseUrl, Duration connectTimeout, Duration readTimeout) {
        public Core {
            baseUrl = baseUrl == null ? URI.create("http://data2flow-core-api") : baseUrl;
            connectTimeout = connectTimeout == null ? Duration.ofSeconds(1) : connectTimeout;
            readTimeout = readTimeout == null ? Duration.ofSeconds(2) : readTimeout;
        }
    }

    /** BFF가 받아 세션 쿠키에 암호화해 넣는 Refresh 쿠키(API-IAM-01) */
    public record RefreshCookie(String name, String path, Boolean secure) {
        public RefreshCookie {
            name = blank(name) ? "data2flow_refresh" : name;
            path = blank(path) ? "/api/v1/auth" : path;
            secure = secure == null ? Boolean.TRUE : secure;
        }
    }

    private static boolean blank(String s) {
        return s == null || s.isBlank();
    }

    /** 재적재 범위: 따로 정하지 않으면 Access 수명 + 허용 오차(그 안에 발급된 Access가 아직 살아 있을 수 있음) */
    public Duration revocationReloadWindow() {
        return revocation.reloadWindow() != null ? revocation.reloadWindow() : token.accessTtl().plus(jwt.clockSkew());
    }

    /** 블랙리스트 TTL: 폐기 시점에 살아 있던 Access가 모두 만료될 때까지 */
    public Duration blacklistTtl() {
        return token.accessTtl().plus(jwt.clockSkew());
    }
}
