package net.java21.data2flow.auth.token.domain;

import net.java21.data2flow.auth.support.TestKeys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** 서명 키 설정(IAM-07.02 kid 교체, design/auth.md §11 #8 기본 시크릿 없음) */
class SigningKeyRingTest {

    @Test
    @DisplayName("[IAM-07.02] 키 하나면 활성 키를 생략할 수 있고, 여러 개면 활성 키와 이전 키의 검증 종료 시각을 둔다")
    void parse() {
        assertThat(SigningKeyRing.parse("a:" + TestKeys.KEY1, null).active().keyId()).isEqualTo("a");

        SigningKeyRing ring = SigningKeyRing.parse(" b:" + TestKeys.KEY2 + " , a:" + TestKeys.KEY1 + "@2026-10-04T00:00:00Z ,", "b");
        assertThat(ring.active().keyId()).isEqualTo("b");
        SigningKey old = ring.find("a").orElseThrow();
        assertThat(old.verifyUntil()).isEqualTo(Instant.parse("2026-10-04T00:00:00Z"));
        assertThat(old.verifiableAt(Instant.parse("2026-10-03T23:59:59Z"))).isTrue();
        assertThat(old.verifiableAt(Instant.parse("2026-10-04T00:00:00Z"))).isFalse();
        assertThat(ring.find(null)).isEmpty();
        assertThat(old.toString()).contains("***").doesNotContain(TestKeys.KEY1);
        assertThat(old).isEqualTo(new SigningKey("a", Base64.getDecoder().decode(TestKeys.KEY1), old.verifyUntil()));
        assertThat(old.hashCode()).isEqualTo(new SigningKey("a", Base64.getDecoder().decode(TestKeys.KEY1), old.verifyUntil()).hashCode());
    }

    @Test
    @DisplayName("[IAM-07.02] 키가 없거나 형식이 틀리면 기동하지 않는다")
    void invalid() {
        assertThatThrownBy(() -> SigningKeyRing.parse(null, null)).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> SigningKeyRing.parse("", null)).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> SigningKeyRing.parse("nokid", null)).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> SigningKeyRing.parse("a:@@@", null)).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> SigningKeyRing.parse("a:" + Base64.getEncoder().encodeToString("short".getBytes()), null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SigningKeyRing.parse("a:" + TestKeys.KEY1 + ",a:" + TestKeys.KEY2, "a"))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> SigningKeyRing.parse("a:" + TestKeys.KEY1 + ",b:" + TestKeys.KEY2, null))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> SigningKeyRing.parse("a:" + TestKeys.KEY1, "c")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> SigningKeyRing.parse("a:" + TestKeys.KEY1 + "@2026-10-04T00:00:00Z", "a"))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> SigningKeyRing.parse("a:" + TestKeys.KEY1 + "@tomorrow", null)).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> SigningKeyRing.parse("a b:" + TestKeys.KEY1, null)).isInstanceOf(IllegalArgumentException.class);
    }
}
