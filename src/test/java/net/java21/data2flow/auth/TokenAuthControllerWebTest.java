package net.java21.data2flow.auth;

import net.java21.data2flow.auth.client.CoreClient;
import net.java21.data2flow.auth.common.DependencyUnavailableException;
import net.java21.data2flow.auth.introspection.controller.InternalIntrospectionController;
import net.java21.data2flow.auth.introspection.service.IntrospectionService;
import net.java21.data2flow.auth.revocation.repository.BlacklistRepository;
import net.java21.data2flow.auth.revocation.service.RevocationService;
import net.java21.data2flow.auth.support.MutableClock;
import net.java21.data2flow.auth.support.TestKeys;
import net.java21.data2flow.auth.support.WebSliceConfig;
import net.java21.data2flow.auth.token.domain.IssuedToken;
import net.java21.data2flow.auth.token.domain.JwtCodec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** introspection 슬라이스(API-IAM-34): 실제 서명기 + 블랙리스트·core는 대역 */
@WebMvcTest(InternalIntrospectionController.class)
@ActiveProfiles("test")
@Import({WebSliceConfig.class, IntrospectionService.class})
class TokenAuthControllerWebTest {

    @Autowired
    MockMvc mvc;
    @Autowired
    JwtCodec jwt;
    @MockitoBean
    BlacklistRepository blacklist;
    @MockitoBean
    RevocationService revocations;
    @MockitoBean
    CoreClient core;

    private final MutableClock clock = WebSliceConfig.CLOCK;
    private final String sid = UUID.randomUUID().toString();

    @BeforeEach
    void setUp() {
        clock.set(MutableClock.DEFAULT_START);
        given(blacklist.snapshot(anyString(), anyString()))
                .willAnswer(inv -> new BlacklistRepository.Snapshot(false, false, MutableClock.DEFAULT_START, clock.instant()));
    }

    private IssuedToken access(JwtCodec codec) {
        return codec.issueAccess(11, 1, sid, UUID.randomUUID().toString(), clock.instant().plus(Duration.ofHours(1)));
    }

    private org.springframework.test.web.servlet.ResultActions introspect(String token) throws Exception {
        return mvc.perform(post("/internal/auth/introspect").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header("X-CALLER-SERVICE", "data2flow-api-gateway").param("token", token));
    }

    @Test
    @DisplayName("[IAM-07.02] 유효한 Access → 200 {header, response:{active, sub, org, sid, typ, exp}} (gateway 계약, ID는 문자열)")
    void active() throws Exception {
        IssuedToken token = access(jwt);

        introspect(token.value())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.header.isSuccessful").value(true))
                .andExpect(jsonPath("$.response.active").value(true))
                .andExpect(jsonPath("$.response.sub").value("11"))
                .andExpect(jsonPath("$.response.org").value("1"))
                .andExpect(jsonPath("$.response.sid").value(sid))
                .andExpect(jsonPath("$.response.jti").value(token.jti()))
                .andExpect(jsonPath("$.response.typ").value("ACCESS"))
                .andExpect(jsonPath("$.response.exp").value(token.expiresAt().getEpochSecond()))
                .andExpect(jsonPath("$.response.inactiveReason").doesNotExist());
        verify(blacklist).touchActivity(sid, clock.instant(), Duration.ofMinutes(30));
    }

    @Test
    @DisplayName("[IAM-07.02][TC-IAM-180] Access 만료 → 200 active=false, inactiveReason=EXPIRED(gateway가 401 AUTH_TOKEN_EXPIRED로 바꿈)")
    void expired() throws Exception {
        IssuedToken token = access(jwt);
        clock.advance(Duration.ofMinutes(61));

        introspect(token.value())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.active").value(false))
                .andExpect(jsonPath("$.response.inactiveReason").value("EXPIRED"));
    }

    @Test
    @DisplayName("[IAM-07.02][TC-IAM-185][AT-IAM-21.5] 키 교체: 이전 kid 토큰 → 유예 중 active, 유예 종료 후 INVALID")
    void previousKeyDuringGrace() throws Exception {
        Instant graceEnd = clock.instant().plus(Duration.ofHours(1));
        JwtCodec previous = TestKeys.codec("t0:" + TestKeys.KEY2 + ",t1:" + TestKeys.KEY1, "t0", clock);
        IssuedToken old = access(previous);
        // 운영 서명기는 t1이 활성이고 t0은 graceEnd까지만 검증 — 같은 키 링을 쓰는 서명기를 만들어 확인한다
        JwtCodec current = TestKeys.codec("t1:" + TestKeys.KEY1 + ",t0:" + TestKeys.KEY2 + "@" + graceEnd, "t1", clock);
        IntrospectionService service = new IntrospectionService(current, blacklist, revocations, core,
                new net.java21.data2flow.auth.session.domain.SessionPolicy(Duration.ofMinutes(30), Duration.ofHours(12)));

        org.assertj.core.api.Assertions.assertThat(service.introspect(old.value()).active()).isTrue();
        clock.set(graceEnd.plusSeconds(1));
        org.assertj.core.api.Assertions.assertThat(service.introspect(old.value()).inactiveReason()).isEqualTo("INVALID");
        // 컨트롤러 경로: 모르는 kid(t0, 테스트 서명기에는 없음) → INVALID
        introspect(old.value()).andExpect(jsonPath("$.response.inactiveReason").value("INVALID"));
    }

    @Test
    @DisplayName("[IAM-07.05] 폐기된 sid → REVOKED, Redis가 비었으면 다시 적재한 뒤 판정")
    void revoked() throws Exception {
        IssuedToken token = access(jwt);
        given(blacklist.snapshot(anyString(), anyString()))
                .willReturn(new BlacklistRepository.Snapshot(false, false, null, null))
                .willReturn(new BlacklistRepository.Snapshot(false, true, clock.instant(), null));

        introspect(token.value()).andExpect(jsonPath("$.response.inactiveReason").value("REVOKED"));
        verify(revocations).reloadIfMarkerMissing();
    }

    @Test
    @DisplayName("[IAM-07.10] 블랙리스트 저장소 장애 → 503 SERVICE_UNAVAILABLE(fail-closed)")
    void storeDown() throws Exception {
        given(blacklist.snapshot(anyString(), anyString())).willThrow(new DependencyUnavailableException("redis down"));

        introspect(access(jwt).value())
                .andExpect(status().isServiceUnavailable())
                .andExpect(header().string("Retry-After", "1"))
                .andExpect(jsonPath("$.header.resultCode").value("SERVICE_UNAVAILABLE"));
    }

    @Test
    @DisplayName("[IAM-07.02] 장기 토큰: core가 비활성·형식 오류면 INVALID")
    void longLivedInactive() throws Exception {
        given(core.verifyApiToken(anyString())).willReturn(new net.java21.data2flow.auth.client.dto.ApiTokenVerification(
                false, null, null, null, null, java.util.List.of(), java.util.List.of(), null, null, null));

        introspect("data2flow_" + "C".repeat(43)).andExpect(jsonPath("$.response.inactiveReason").value("INVALID"));
        introspect("data2flow_short").andExpect(jsonPath("$.response.inactiveReason").value("INVALID"));
    }

    @Test
    @DisplayName("[IAM-07.11][TC-IAM-205][AT-IAM-02.10] GET /auth/oauth2/github → 404 RESOURCE_NOT_FOUND")
    void noSocialLogin() throws Exception {
        mvc.perform(get("/auth/oauth2/github"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.header.resultCode").value("RESOURCE_NOT_FOUND"));
    }
}
