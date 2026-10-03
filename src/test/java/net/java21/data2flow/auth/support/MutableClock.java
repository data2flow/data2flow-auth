package net.java21.data2flow.auth.support;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/** 테스트용 시계(design/testing/backend.md §3). Thread.sleep 대신 시간을 직접 옮긴다 */
public final class MutableClock extends Clock {

    public static final Instant DEFAULT_START = Instant.parse("2026-10-03T00:00:00Z");

    private volatile Instant now;

    private MutableClock(Instant start) {
        this.now = start;
    }

    public static MutableClock atUtc(Instant start) {
        return new MutableClock(start);
    }

    public static MutableClock atDefault() {
        return new MutableClock(DEFAULT_START);
    }

    public void set(Instant instant) {
        this.now = instant;
    }

    public void advance(Duration duration) {
        this.now = now.plus(duration);
    }

    @Override
    public ZoneId getZone() {
        return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return this;
    }

    @Override
    public Instant instant() {
        return now;
    }
}
