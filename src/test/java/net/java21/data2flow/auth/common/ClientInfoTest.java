package net.java21.data2flow.auth.common;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

/** 사용자 IP·User-Agent(design/auth.md §5 사용자 IP 전달) */
class ClientInfoTest {

    @Test
    @DisplayName("[IAM-07.07] X-Forwarded-For 맨 앞 값을 쓰고, 이상한 값이면 접속 주소. User-Agent는 300자로 자른다")
    void extract() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("10.0.0.9");
        req.addHeader("X-Forwarded-For", "203.0.113.7, 10.0.0.5");
        req.addHeader("User-Agent", "u".repeat(400));
        ClientInfo info = ClientInfo.from(req);
        assertThat(info.ip()).isEqualTo("203.0.113.7");
        assertThat(info.userAgent()).hasSize(300);

        MockHttpServletRequest bad = new MockHttpServletRequest();
        bad.setRemoteAddr("10.0.0.9");
        bad.addHeader("X-Forwarded-For", "<script>");
        assertThat(ClientInfo.from(bad).ip()).isEqualTo("10.0.0.9");
        assertThat(ClientInfo.from(new MockHttpServletRequest()).userAgent()).isNull();
    }
}
