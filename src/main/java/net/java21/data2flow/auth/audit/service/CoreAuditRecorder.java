package net.java21.data2flow.auth.audit.service;

import net.java21.data2flow.auth.client.CoreClient;
import net.java21.data2flow.contracts.audit.AuditEvent;
import net.java21.data2flow.contracts.audit.AuditRecorder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;

/**
 * 감사 기록을 core에 보낸다(API-IAM-39, 202). 감사 실패가 로그인을 막지 않도록 가상 스레드에서 비동기로 보내고(IAM-api §6),
 * 실패는 로그로 남긴다. 종료할 때는 보내는 중인 기록을 최대 10초 기다린다(graceful shutdown, reliability-and-ha.md §4.1).
 */
@Component
public class CoreAuditRecorder implements AuditRecorder, DisposableBean {

    private static final Logger log = LoggerFactory.getLogger(CoreAuditRecorder.class);
    static final Duration DRAIN_TIMEOUT = Duration.ofSeconds(10);

    private final CoreClient core;
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();

    public CoreAuditRecorder(CoreClient core) {
        this.core = core;
    }

    @Override
    public void record(AuditEvent event) {
        try {
            executor.execute(() -> send(event));
        } catch (RejectedExecutionException ex) {
            send(event); // 종료 중이면 지금 스레드에서 보낸다
        }
    }

    private void send(AuditEvent event) {
        try {
            core.recordAudit(event);
        } catch (RuntimeException ex) {
            log.atWarn().addKeyValue("action", event.action()).addKeyValue("requestId", event.requestId())
                    .log("감사 기록 전송 실패: {}", ex.getMessage());
        }
    }

    @Override
    public void destroy() throws InterruptedException {
        executor.shutdown();
        if (!executor.awaitTermination(DRAIN_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)) {
            log.atWarn().log("종료 전에 보내지 못한 감사 기록이 있습니다");
            executor.shutdownNow();
        }
    }
}
