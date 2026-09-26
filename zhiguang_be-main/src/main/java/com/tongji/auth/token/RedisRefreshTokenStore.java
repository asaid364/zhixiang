package com.tongji.auth.token;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * 基于 Redis 的刷新令牌白名单存储。
 * <p>
 * 键空间：`auth:rt:{userId}:{tokenId}`，值固定为 "1"，设置 TTL 控制过期；本次保持现有 Key 格式，避免已有白名单失效。
 * 支持校验令牌有效性、原子轮换、撤销单个令牌或撤销某用户全部令牌。
 */
@Component
public class RedisRefreshTokenStore implements RefreshTokenStore {

    private static final String TOKEN_VALUE = "1";

    /** 查询旧令牌、保存新令牌、撤销旧令牌必须在同一 Redis 原子脚本内完成。 */
    private static final DefaultRedisScript<Long> ROTATE_SCRIPT = new DefaultRedisScript<>("""
            local oldValue = redis.call('GET', KEYS[1])
            if oldValue ~= '1' then
                return 0
            end
            if KEYS[1] == KEYS[2] then
                return 0
            end
            redis.call('SET', KEYS[2], '1', 'PX', ARGV[1])
            redis.call('DEL', KEYS[1])
            return 1
            """, Long.class);

    private final StringRedisTemplate redisTemplate;

    public RedisRefreshTokenStore(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }
    /**
     * 原子轮换刷新令牌：查询旧白名单、保存新白名单并删除旧白名单。
     *
     * @return 旧令牌有效且轮换成功时返回 true；旧令牌已消费或不存在时返回 false。
     */
    @Override
    public boolean rotateToken(long userId, String oldTokenId, String newTokenId, Duration newTokenTtl) {
        long ttlMillis = newTokenTtl.toMillis();
        if (ttlMillis <= 0 || Objects.equals(oldTokenId, newTokenId)) {
            return false;
        }

        Long result = redisTemplate.execute(
                ROTATE_SCRIPT,
                List.of(key(userId, oldTokenId), key(userId, newTokenId)),
                String.valueOf(ttlMillis)
        );
        return Objects.equals(1L, result);
    }

    /**
     * 将刷新令牌写入白名单，设置过期时间。
     *
     * @param userId  用户 ID。
     * @param tokenId 刷新令牌 ID。
     * @param ttl     生存时间（Redis TTL）。
     */
    @Override
    public void storeToken(long userId, String tokenId, Duration ttl) {
        String key = key(userId, tokenId);
        redisTemplate.opsForValue().set(key, TOKEN_VALUE, ttl);
    }

    /**
     * 判断刷新令牌是否仍有效。
     *
     * @param userId  用户 ID。
     * @param tokenId 刷新令牌 ID。
     * @return 是否有效（键存在且值为 "1"）。
     */
    @Override
    public boolean isTokenValid(long userId, String tokenId) {
        String key = key(userId, tokenId);
        return Objects.equals(TOKEN_VALUE, redisTemplate.opsForValue().get(key));
    }

    /**
     * 撤销单个刷新令牌。
     *
     * @param userId  用户 ID。
     * @param tokenId 刷新令牌 ID。
     */
    @Override
    public void revokeToken(long userId, String tokenId) {
        redisTemplate.delete(key(userId, tokenId));
    }

    /**
     * 撤销该用户全部刷新令牌。
     *
     * @param userId 用户 ID。
     */
    @Override
    public void revokeAll(long userId) {
        String pattern = "auth:rt:%d:*".formatted(userId);
        var keys = redisTemplate.keys(pattern);
        if (!keys.isEmpty()) {
            redisTemplate.delete(keys);
        }
    }

    /**
     * 生成白名单键名。
     *
     * @param userId  用户 ID。
     * @param tokenId 刷新令牌 ID。
     * @return Redis 键名。
     */
    private static String key(long userId, String tokenId) {
        return "auth:rt:%d:%s".formatted(userId, tokenId);
    }
}
