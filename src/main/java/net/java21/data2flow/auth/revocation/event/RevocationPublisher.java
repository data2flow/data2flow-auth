package net.java21.data2flow.auth.revocation.event;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

/**
 * EVT-IAM-03 발행. 놓쳐도 gateway 캐시 상한(30초) 안에 거부되고(IAM-07.05), 캐시 적중 요청도 gateway가 블랙리스트를 다시 보므로
 * 발행 실패는 요청을 실패시키지 않고 기록만 한다. 블랙리스트 등록(원천 사본)은 그 전에 끝나 있다.
 */
@Component
public class RevocationPublisher {

    private static final Logger log = LoggerFactory.getLogger(RevocationPublisher.class);

    private final StringRedisTemplate redis;
    private final JsonMapper jsonMapper;

    public RevocationPublisher(StringRedisTemplate redis, JsonMapper jsonMapper) {
        this.redis = redis;
        this.jsonMapper = jsonMapper;
    }

    public void publish(RevocationEvent event) {
        try {
            redis.convertAndSend(RevocationEvent.CHANNEL, jsonMapper.writeValueAsString(event));
        } catch (RuntimeException ex) {
            log.atWarn().addKeyValue("type", event.type()).log("폐기 이벤트 발행 실패(캐시 상한 안에 반영됨): {}", ex.toString());
        }
    }
}
