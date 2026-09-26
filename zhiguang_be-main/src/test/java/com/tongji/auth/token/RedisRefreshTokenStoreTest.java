package com.tongji.auth.token;

import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RedisRefreshTokenStoreTest {

    @Test
    void rotateTokenExecutesScriptWithSameUserAndTtl() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        when(redis.execute(
                any(DefaultRedisScript.class),
                eq(List.of("auth:rt:7:old", "auth:rt:7:new")),
                eq("60000")
        )).thenReturn(1L);

        RedisRefreshTokenStore store = new RedisRefreshTokenStore(redis);

        assertThat(store.rotateToken(7L, "old", "new", Duration.ofSeconds(60))).isTrue();
    }

    @Test
    void rotateTokenReturnsFalseWhenScriptRejectsConsumedToken() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        when(redis.execute(
                any(DefaultRedisScript.class),
                eq(List.of("auth:rt:7:old", "auth:rt:7:new")),
                eq("60000")
        )).thenReturn(0L);

        RedisRefreshTokenStore store = new RedisRefreshTokenStore(redis);

        assertThat(store.rotateToken(7L, "old", "new", Duration.ofSeconds(60))).isFalse();
    }
}
