package org.tinycloud.security.session;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.ListOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.exception.ConcurrentLoginOverLimitException;

import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Redis 会话仓储测试（基于 Mockito 验证与 Redis 的交互契约）。
 *
 * <p>核心回归点：① 账号在线列表 key 必须有 TTL（会话超时的 2 倍），并在每次登录、
 * 每次会话续期时刷新——修复默认配置（未启用并发限制）下在线列表永不清理、随登录次数
 * 无限累积的内存泄漏，同时保证常在线账号（会话滚动续期）的在线列表不会先于会话过期；
 * ② 未启用并发限制时，登录也要顺带清理在线列表中已失效的凭证。</p>
 *
 * @author liuxingyu01
 */
@ExtendWith(MockitoExtension.class)
class RedisSessionRepositoryTest {

    private static final String ONLINE_KEY = "tiny:security:online:10001";

    @Mock
    private StringRedisTemplate redisTemplate;
    @Mock
    private ValueOperations<String, String> valueOperations;
    @Mock
    private ListOperations<String, String> listOperations;

    private RedisSessionRepository repository;

    @BeforeEach
    void setUp() {
        repository = new RedisSessionRepository(redisTemplate);
    }

    /**
     * 登录时在线列表 key 必须被设置 2 倍会话超时的 TTL。
     */
    @Test
    void saveShouldSetOnlineListTtlToTwiceSessionTimeout() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(redisTemplate.opsForList()).thenReturn(listOperations);

        assertTrue(repository.save(buildSubject(10001L, "cred-1"), 60, 0));

        verify(listOperations).rightPush(ONLINE_KEY, "cred-1");
        verify(redisTemplate).expire(ONLINE_KEY, 120L, TimeUnit.SECONDS);
        verify(valueOperations).set(eq("tiny:security:credentials:cred-1"), anyString(), eq(60L), eq(TimeUnit.SECONDS));
    }

    /**
     * 未启用并发限制（maxConcurrentLogins=0）时，登录也要清理在线列表中的失效凭证：
     * 此前清理入口只在限制开启时才被触发，默认配置下失效凭证永久残留（内存泄漏）。
     */
    @Test
    void saveShouldCleanupDeadOnlineEntriesEvenWithoutLimit() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(redisTemplate.opsForList()).thenReturn(listOperations);
        when(listOperations.range(ONLINE_KEY, 0L, -1L)).thenReturn(List.of("dead-cred"), List.of());
        when(redisTemplate.hasKey("tiny:security:credentials:dead-cred")).thenReturn(false);

        assertTrue(repository.save(buildSubject(10001L, "cred-new"), 60, 0));

        verify(redisTemplate).hasKey("tiny:security:credentials:dead-cred");
        verify(listOperations).remove(ONLINE_KEY, 1L, "dead-cred");
        verify(redisTemplate).delete(ONLINE_KEY);
        verify(redisTemplate).expire(ONLINE_KEY, 120L, TimeUnit.SECONDS);
    }

    /**
     * 会话续期时必须同步刷新在线列表 TTL，常在线账号（会话滚动续期、可能远超单次超时）
     * 的在线列表才不会先于会话过期。
     */
    @Test
    void refreshShouldRenewOnlineListTtl() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);

        assertTrue(repository.refreshByCredentials("cred-1", buildSubject(10001L, "cred-1"), 60));

        verify(valueOperations).set(eq("tiny:security:credentials:cred-1"), anyString(), eq(60L), eq(TimeUnit.SECONDS));
        verify(redisTemplate).expire(ONLINE_KEY, 120L, TimeUnit.SECONDS);
    }

    /**
     * 启用并发限制时，超限登录被拒绝且不写入新会话（原有能力不回归）。
     */
    @Test
    void saveShouldRejectWhenConcurrentLimitReached() {
        when(redisTemplate.opsForList()).thenReturn(listOperations);
        when(listOperations.range(ONLINE_KEY, 0L, -1L)).thenReturn(List.of("other-cred"));
        when(redisTemplate.hasKey("tiny:security:credentials:other-cred")).thenReturn(true);

        assertThrows(ConcurrentLoginOverLimitException.class,
                () -> repository.save(buildSubject(10001L, "cred-2"), 60, 1));

        verify(valueOperations, never()).set(anyString(), anyString(), anyLong(), any(TimeUnit.class));
        verify(redisTemplate, never()).expire(anyString(), anyLong(), any(TimeUnit.class));
    }

    /**
     * 构造登录主体。
     */
    private LoginSubject buildSubject(Object loginId, String credentials) {
        LoginSubject subject = new LoginSubject();
        subject.setLoginId(loginId);
        subject.setCredentials(credentials);
        subject.setLoginTime(System.currentTimeMillis());
        subject.setLoginExpireTime(System.currentTimeMillis() + 60_000L);
        return subject;
    }
}
