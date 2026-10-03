package net.java21.data2flow.auth.common;

import java.util.function.Supplier;

/**
 * Redis 호출 실패(연결 끊김, 시간 초과, 명령 오류)를 {@link DependencyUnavailableException}으로 바꾼다.
 * 블랙리스트·호출 한도를 확인하지 못하면 통과시키지 않는다(fail-closed, IAM-07.10).
 */
public final class RedisCalls {

    private RedisCalls() {
    }

    public static <T> T call(String what, Supplier<T> action) {
        try {
            return action.get();
        } catch (DependencyUnavailableException ex) {
            throw ex;
        } catch (RuntimeException ex) {
            throw new DependencyUnavailableException("Redis " + what + " 실패: " + ex.getClass().getSimpleName(), ex);
        }
    }

    public static void run(String what, Runnable action) {
        call(what, () -> {
            action.run();
            return null;
        });
    }
}
