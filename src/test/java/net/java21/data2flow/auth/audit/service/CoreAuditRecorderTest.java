package net.java21.data2flow.auth.audit.service;

import net.java21.data2flow.auth.client.CoreClient;
import net.java21.data2flow.auth.common.DependencyUnavailableException;
import net.java21.data2flow.contracts.audit.AuditEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/** 감사 기록 전송(IAM-06.01): 비동기, 실패는 업무를 막지 않음, 종료 때 남은 기록을 보냄 */
class CoreAuditRecorderTest {

    private final AuditEvent event = AuditEvent.builder(1, "USER_LOGGED_IN").occurredAt(Instant.EPOCH).build();

    @Test
    @DisplayName("[IAM-06.01] core 전송 실패는 삼키고, 종료 뒤 기록은 호출 스레드에서 보낸다")
    void failureIsSwallowedAndDrained() throws Exception {
        CoreClient core = mock(CoreClient.class);
        willThrow(new DependencyUnavailableException("down")).given(core).recordAudit(any());
        CoreAuditRecorder recorder = new CoreAuditRecorder(core);

        recorder.record(event);
        verify(core, timeout(2000)).recordAudit(event);

        recorder.destroy();
        recorder.record(event);
        verify(core, times(2)).recordAudit(event);
    }
}
