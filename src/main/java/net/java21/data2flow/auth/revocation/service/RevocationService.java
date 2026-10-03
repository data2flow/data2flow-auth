package net.java21.data2flow.auth.revocation.service;

import net.java21.data2flow.auth.client.CoreClient;
import net.java21.data2flow.auth.client.dto.Revocations;
import net.java21.data2flow.auth.config.AuthProperties;
import net.java21.data2flow.auth.revocation.event.RevocationEvent;
import net.java21.data2flow.auth.revocation.event.RevocationPublisher;
import net.java21.data2flow.auth.revocation.repository.BlacklistRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 즉시 폐기(IAM-07.05, design/auth.md §4.2). 폐기하면 Redis 블랙리스트에 올리고 EVT-IAM-03을 발행해 gateway 캐시를 바로 지운다.
 * Redis는 사본이라 비워질 수 있으므로, 재적재 표식({@code data2flow:boot})이 없으면 core의 원천 기록(최근 Access 수명 안에 폐기된
 * sid·jti, API-IAM-39a)으로 다시 채운다(ADR-022). 다시 채우기 전까지 introspection은 503이다(fail-closed).
 */
@Service
public class RevocationService {

    private static final Logger log = LoggerFactory.getLogger(RevocationService.class);
    public static final String REASON_RELOAD = "RELOAD";

    private final BlacklistRepository blacklist;
    private final RevocationPublisher publisher;
    private final CoreClient core;
    private final AuthProperties properties;
    private final Clock clock;
    private final ReentrantLock reloadLock = new ReentrantLock();

    public RevocationService(BlacklistRepository blacklist, RevocationPublisher publisher, CoreClient core,
                             AuthProperties properties, Clock clock) {
        this.blacklist = blacklist;
        this.publisher = publisher;
        this.core = core;
        this.properties = properties;
        this.clock = clock;
    }

    /** 세션·토큰을 폐기 목록에 올리고 폐기 이벤트를 낸다(멱등) */
    public void revoke(Collection<String> sids, Collection<String> jtis, String reason) {
        Set<String> sidSet = clean(sids);
        Set<String> jtiSet = clean(jtis);
        if (sidSet.isEmpty() && jtiSet.isEmpty()) {
            return;
        }
        blacklist.revoke(sidSet, jtiSet, reason, properties.blacklistTtl());
        Instant now = clock.instant();
        sidSet.forEach(sid -> publisher.publish(new RevocationEvent(RevocationEvent.Type.SID, sid, reason, now)));
        jtiSet.forEach(jti -> publisher.publish(new RevocationEvent(RevocationEvent.Type.JTI, jti, reason, now)));
        log.atInfo().addKeyValue("sids", sidSet.size()).addKeyValue("jtis", jtiSet.size()).addKeyValue("reason", reason)
                .log("토큰 폐기 등록");
    }

    public void revokeSession(String sid, String reason) {
        revoke(List.of(sid), List.of(), reason);
    }

    /** API-IAM-38: core의 최근 폐기 기록으로 Redis를 다시 채우고 표식을 남긴다 */
    public ReloadResult reload() {
        reloadLock.lock();
        try {
            return doReload();
        } finally {
            reloadLock.unlock();
        }
    }

    /** 표식이 없을 때만 다시 채운다. 여러 요청이 동시에 와도 core는 한 번만 부른다 */
    public boolean reloadIfMarkerMissing() {
        if (blacklist.bootMarker().isPresent()) {
            return false;
        }
        reloadLock.lock();
        try {
            if (blacklist.bootMarker().isPresent()) {
                return false;
            }
            doReload();
            return true;
        } finally {
            reloadLock.unlock();
        }
    }

    private ReloadResult doReload() {
        Instant now = clock.instant();
        Revocations revocations = core.findRevocationsSince(now.minus(properties.revocationReloadWindow()));
        blacklist.revoke(clean(revocations.sids()), clean(revocations.jtis()), REASON_RELOAD, properties.blacklistTtl());
        blacklist.markBoot(now);
        log.atInfo().addKeyValue("sids", revocations.sids().size()).addKeyValue("jtis", revocations.jtis().size())
                .log("폐기 목록 재적재 완료(ADR-022)");
        return new ReloadResult(revocations.sids().size(), revocations.jtis().size());
    }

    private static Set<String> clean(Collection<String> values) {
        Set<String> set = new LinkedHashSet<>();
        if (values != null) {
            values.stream().filter(v -> v != null && !v.isBlank() && v.length() <= 64).map(String::trim).forEach(set::add);
        }
        return set;
    }

    /** 다시 등록한 개수 */
    public record ReloadResult(int sids, int jtis) {
    }
}
