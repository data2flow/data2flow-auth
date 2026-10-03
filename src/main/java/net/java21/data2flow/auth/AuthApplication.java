package net.java21.data2flow.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableScheduling;

/** data2flow-auth: 아이디·비밀번호 로그인(자격 확인은 core에 위임), 토큰 발급·재발급·폐기, introspection, Redis 블랙리스트 */
@SpringBootApplication
@ConfigurationPropertiesScan
@EnableScheduling
public class AuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthApplication.class, args);
    }
}
