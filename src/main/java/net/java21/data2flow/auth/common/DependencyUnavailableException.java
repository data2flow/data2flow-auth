package net.java21.data2flow.auth.common;

/**
 * 블랙리스트 저장소(Redis)나 core-api가 응답하지 않는다. 인증은 이때 통과시키지 않고 503으로 거부한다
 * (fail-closed, IAM-07.10, BR-IAM-24). 공개 경로(로그인·재발급)는 {@code AUTH_UNAVAILABLE}, 내부 경로(introspection 등)는
 * {@code SERVICE_UNAVAILABLE}로 응답한다({@link AuthExceptionHandler}).
 */
public class DependencyUnavailableException extends RuntimeException {

    public DependencyUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }

    public DependencyUnavailableException(String message) {
        super(message);
    }
}
