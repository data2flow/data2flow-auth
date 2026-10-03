package net.java21.data2flow.auth.revocation.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * 시작할 때와 Redis 재시작을 감지했을 때(표식 키가 사라짐) 폐기 목록을 다시 적재한다(design/auth.md §4.2, ADR-022).
 * 실패해도 기동은 막지 않는다. 표식이 없는 동안 introspection이 요청마다 다시 시도하고, 그래도 안 되면 503으로 거부한다.
 */
@Component
public class RevocationReloadScheduler {

    private static final Logger log = LoggerFactory.getLogger(RevocationReloadScheduler.class);

    private final RevocationService revocations;

    public RevocationReloadScheduler(RevocationService revocations) {
        this.revocations = revocations;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void reloadOnStartup() {
        try {
            revocations.reload();
        } catch (RuntimeException ex) {
            log.atWarn().log("시작 시 폐기 목록 재적재 실패. 표식이 없으면 introspection이 다시 시도합니다: {}", ex.getMessage());
        }
    }

    @Scheduled(fixedDelayString = "${data2flow.auth.revocation.watch-interval:15s}",
            initialDelayString = "${data2flow.auth.revocation.watch-interval:15s}")
    public void reloadWhenRedisRestarted() {
        try {
            if (revocations.reloadIfMarkerMissing()) {
                log.atWarn().log("Redis 재시작을 감지해 폐기 목록을 다시 적재했습니다");
            }
        } catch (RuntimeException ex) {
            log.atWarn().log("폐기 목록 재적재 확인 실패: {}", ex.getMessage());
        }
    }
}
