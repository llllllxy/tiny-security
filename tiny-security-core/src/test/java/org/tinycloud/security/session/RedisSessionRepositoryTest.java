package org.tinycloud.security.session;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.ListOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.core.script.RedisScript;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.exception.ConcurrentLoginOverLimitException;
import org.tinycloud.security.util.JsonUtil;

import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
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
     *
     * <p>自 P1-7 起，"判断并发上限 + 入列 + 设置列表 TTL"三步合并为一个 Lua 脚本原子执行，
     * 所以这里断言的是脚本收到的参数（第三个参数即列表 TTL 秒数），不再是独立的 EXPIRE 命令。
     */
    @Test
    void saveShouldSetOnlineListTtlToTwiceSessionTimeout() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(redisTemplate.opsForList()).thenReturn(listOperations);
        when(valueOperations.setIfAbsent(anyString(), anyString(), anyLong(), any(TimeUnit.class))).thenReturn(true);
        when(redisTemplate.execute(any(RedisScript.class), anyList(), any(), any(), any())).thenReturn(1L);

        assertTrue(repository.save(buildSubject(10001L, "cred-1"), 60, 0));

        // ARGV[3] = 120 = 会话超时 60 秒 × 2
        verify(redisTemplate).execute(any(RedisScript.class), eq(List.of(ONLINE_KEY)), eq("cred-1"), eq("0"), eq("120"));
        verify(valueOperations).setIfAbsent(eq("tiny:security:credentials:cred-1"), anyString(), eq(60L), eq(TimeUnit.SECONDS));
    }

    /**
     * 未启用并发限制（maxConcurrentLogins=0）时，登录也要清理在线列表中的失效凭证：
     * 此前清理入口只在限制开启时才被触发，默认配置下失效凭证永久残留（内存泄漏）。
     *
     * <p>自 TCK 落地后，失效判定不再只看 key 是否存在（{@code hasKey}），而是与
     * {@code checkByCredentials} 同口径：读主体并按 {@code loginExpireTime} 判过期。
     * 因此这里用 {@code opsForValue().get()} 返回 {@code null}（key 不存在）来模拟失效凭证。
     */
    @Test
    void saveShouldCleanupDeadOnlineEntriesEvenWithoutLimit() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(redisTemplate.opsForList()).thenReturn(listOperations);
        when(listOperations.range(ONLINE_KEY, 0L, -1L)).thenReturn(List.of("dead-cred"), List.of());
        // dead-cred 已不存在（get 返回 null）→ 判为失效，应从在线列表移除
        when(valueOperations.get("tiny:security:credentials:dead-cred")).thenReturn(null);
        when(valueOperations.setIfAbsent(anyString(), anyString(), anyLong(), any(TimeUnit.class))).thenReturn(true);
        when(redisTemplate.execute(any(RedisScript.class), anyList(), any(), any(), any())).thenReturn(1L);

        assertTrue(repository.save(buildSubject(10001L, "cred-new"), 60, 0));

        verify(valueOperations).get("tiny:security:credentials:dead-cred");
        verify(listOperations).remove(ONLINE_KEY, 1L, "dead-cred");
        verify(redisTemplate).delete(ONLINE_KEY);
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
     *
     * <p>自 TCK 落地后，"在线列表里的凭证是否有效"不再只看 {@code hasKey}，而是读主体并按
     * {@code loginExpireTime} 判过期，因此这里用 {@code opsForValue().get()} 返回一个尚未过期的
     * 主体 JSON 来模拟"已有一个有效在线会话"。
     */
    @Test
    void saveShouldRejectWhenConcurrentLimitReached() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(redisTemplate.opsForList()).thenReturn(listOperations);
        when(listOperations.range(ONLINE_KEY, 0L, -1L)).thenReturn(List.of("other-cred"));
        when(valueOperations.get("tiny:security:credentials:other-cred"))
                .thenReturn(JsonUtil.writeValueAsString(buildSubject(10001L, "other-cred")));

        assertThrows(ConcurrentLoginOverLimitException.class,
                () -> repository.save(buildSubject(10001L, "cred-2"), 60, 1));

        verify(valueOperations, never()).setIfAbsent(anyString(), anyString(), anyLong(), any(TimeUnit.class));
        verify(redisTemplate, never()).expire(anyString(), anyLong(), any(TimeUnit.class));
    }

    /**
     * 凭证碰撞必须明确失败：不能静默覆盖已有会话（否则两个用户会共用同一条会话记录）。
     */
    @Test
    void saveShouldFailWhenCredentialsCollide() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(redisTemplate.opsForList()).thenReturn(listOperations);
        when(valueOperations.setIfAbsent(anyString(), anyString(), anyLong(), any(TimeUnit.class))).thenReturn(false);

        assertFalse(repository.save(buildSubject(10001L, "cred-dup"), 60, 0));

        // 碰撞时不得把该凭证写进在线列表，避免污染索引（入列的唯一入口就是那个原子脚本）
        verify(redisTemplate, never()).execute(any(RedisScript.class), anyList(), any(), any(), any());
        verify(listOperations, never()).rightPush(anyString(), anyString());
    }

    /**
     * 并发上限必须由**一个原子脚本**判定并入列（P1-7）。
     *
     * <p>本用例锁住的是修复的**结构性前提**：上限值随脚本下传（ARGV[2]），
     * 且代码里不再存在"先 rightPush 再用 size 事后发现超额、然后摘掉自己"的两步写法 ——
     * 那正是真实 Redis 实测中"上限为 1 时 4 个并发登录全部被拒"的成因。
     *
     * <p>并发语义本身无法在 Mockito 下验证（它不模拟 Redis 的原子性），
     * 因此另由真实 Redis 探针验证：修复前 0/4 成功，修复后恰好 1/4 成功。
     */
    @Test
    void saveShouldJudgeConcurrentLimitAtomicallyInScript() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(redisTemplate.opsForList()).thenReturn(listOperations);
        when(listOperations.range(ONLINE_KEY, 0L, -1L)).thenReturn(List.of());
        when(valueOperations.setIfAbsent(anyString(), anyString(), anyLong(), any(TimeUnit.class))).thenReturn(true);
        when(redisTemplate.execute(any(RedisScript.class), anyList(), any(), any(), any())).thenReturn(1L);

        assertTrue(repository.save(buildSubject(10001L, "cred-3"), 60, 3));

        // ARGV[2] = 并发上限；上限判定发生在脚本内，而非 Java 侧的先查后写
        verify(redisTemplate).execute(any(RedisScript.class), eq(List.of(ONLINE_KEY)), eq("cred-3"), eq("3"), eq("120"));
        verify(listOperations, never()).rightPush(anyString(), anyString());
        verify(listOperations, never()).size(anyString());
    }

    /**
     * 脚本判定"已达上限"（返回 0）时：必须**回滚刚写入的会话**并抛出超限异常。
     * 否则会留下一个不在在线列表里、却可以正常使用的会话，等于绕过并发上限。
     */
    @Test
    void saveShouldRollbackSessionWhenScriptRejectsOverLimit() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(redisTemplate.opsForList()).thenReturn(listOperations);
        when(listOperations.range(ONLINE_KEY, 0L, -1L)).thenReturn(List.of());
        when(valueOperations.setIfAbsent(anyString(), anyString(), anyLong(), any(TimeUnit.class))).thenReturn(true);
        when(redisTemplate.execute(any(RedisScript.class), anyList(), any(), any(), any())).thenReturn(0L);

        assertThrows(ConcurrentLoginOverLimitException.class,
                () -> repository.save(buildSubject(10001L, "cred-4"), 60, 1));

        verify(redisTemplate).delete("tiny:security:credentials:cred-4");
    }

    /**
     * 幂等语义（1.4.0）：在线列表为空/不存在时也返回 true——deleteByLoginId 表达的是
     * "操作是否成功执行"而非"实际删除了几个会话"，与 Single/Caffeine 本地仓储一致。
     */
    @Test
    void deleteByLoginIdShouldReturnTrueWhenNoOnlineSession() {
        when(redisTemplate.opsForList()).thenReturn(listOperations);
        when(listOperations.range(ONLINE_KEY, 0L, -1L)).thenReturn(null);

        assertTrue(repository.deleteByLoginId(10001L));

        // 即使无会话可删，也应删除在线列表 key（幂等清理）
        verify(redisTemplate).delete(ONLINE_KEY);
    }

    /**
     * 有会话时按凭证逐个删除会话 key，并清理在线列表 key。
     */
    @Test
    void deleteByLoginIdShouldDeleteAllSessions() {
        when(redisTemplate.opsForList()).thenReturn(listOperations);
        when(listOperations.range(ONLINE_KEY, 0L, -1L))
                .thenReturn(List.of("cred-a", "cred-b"));

        assertTrue(repository.deleteByLoginId(10001L));

        verify(redisTemplate).delete("tiny:security:credentials:cred-a");
        verify(redisTemplate).delete("tiny:security:credentials:cred-b");
        verify(redisTemplate).delete(ONLINE_KEY);
    }

    /**
     * getCredentialsByLoginId：复用失效清理逻辑，只返回仍有效的凭证。
     *
     * <p>自 TCK 落地后，失效判定改为"读主体 + 按 {@code loginExpireTime} 判过期"，不再只看
     * {@code hasKey}：因此这里让有效凭证返回一个未过期的 JSON，失效凭证返回 {@code null}。
     */
    @Test
    void getCredentialsByLoginIdShouldReturnOnlyValidCredentials() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(redisTemplate.opsForList()).thenReturn(listOperations);
        // 第一次读取在线列表（含失效项），清理后第二次读取只剩有效项
        when(listOperations.range(ONLINE_KEY, 0L, -1L))
                .thenReturn(List.of("cred-alive", "cred-dead"), List.of("cred-alive"));
        when(valueOperations.get("tiny:security:credentials:cred-alive"))
                .thenReturn(JsonUtil.writeValueAsString(buildSubject(10001L, "cred-alive")));
        when(valueOperations.get("tiny:security:credentials:cred-dead")).thenReturn(null);

        List<String> credentials = repository.getCredentialsByLoginId(10001L);

        assertEquals(1, credentials.size());
        assertTrue(credentials.contains("cred-alive"));
        // 失效凭证应从在线列表中被清理
        verify(listOperations).remove(ONLINE_KEY, 1L, "cred-dead");
    }

    /**
     * getCredentialsByLoginId：账号无在线会话时返回空列表（不返回 null）。
     */
    @Test
    void getCredentialsByLoginIdShouldReturnEmptyListWhenNoOnlineSession() {
        when(redisTemplate.opsForList()).thenReturn(listOperations);
        when(listOperations.range(ONLINE_KEY, 0L, -1L)).thenReturn(null);

        List<String> credentials = repository.getCredentialsByLoginId(10001L);

        assertNotNull(credentials);
        assertTrue(credentials.isEmpty());
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
