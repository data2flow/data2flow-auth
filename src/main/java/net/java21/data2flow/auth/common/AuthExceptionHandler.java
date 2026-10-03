package net.java21.data2flow.auth.common;

import jakarta.servlet.http.HttpServletRequest;
import net.java21.data2flow.contracts.error.CommonErrorCode;
import net.java21.data2flow.contracts.web.ErrorMessages;
import net.java21.data2flow.contracts.web.ErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 의존 서비스 장애를 503으로 바꾼다(fail-closed). 그 밖의 실패는 data2flow-contracts의 공통 처리기가 맡는다.
 * 공개 경로는 {@code AUTH_UNAVAILABLE}(spec/detail/00-error-codes.md: 로그인·재발급 경로의 auth·core·Redis 장애),
 * 내부 경로(introspection·블랙리스트)는 {@code SERVICE_UNAVAILABLE}(design/openapi/auth-internal.yaml)이다.
 */
@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class AuthExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(AuthExceptionHandler.class);

    private final ErrorMessages messages;

    public AuthExceptionHandler(ErrorMessages messages) {
        this.messages = messages;
    }

    @ExceptionHandler(DependencyUnavailableException.class)
    public ResponseEntity<ErrorResponse> handleUnavailable(DependencyUnavailableException ex, HttpServletRequest request) {
        log.atWarn().addKeyValue("path", request.getRequestURI()).log("의존 서비스 장애로 거부(fail-closed): {}", ex.getMessage());
        CommonErrorCode code = request.getRequestURI().startsWith("/internal/")
                ? CommonErrorCode.SERVICE_UNAVAILABLE : CommonErrorCode.AUTH_UNAVAILABLE;
        return ResponseEntity.status(code.httpStatus())
                .header(HttpHeaders.RETRY_AFTER, "1")
                .body(ErrorResponse.of(code.code(), messages.resolve(code)));
    }
}
