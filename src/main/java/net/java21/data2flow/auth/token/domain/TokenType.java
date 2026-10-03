package net.java21.data2flow.auth.token.domain;

/** JWT {@code typ} 클레임. Access로만 API를 부르고, Refresh는 재발급·로그아웃에만 쓴다 */
public enum TokenType {
    ACCESS,
    REFRESH
}
