package org.tinycloud.security.session;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.exception.ConcurrentLoginOverLimitException;

import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Caffeine 本地缓存会话仓储测试。
 *
 * <p>核心回归点：① 过期语义由 {@code loginExpireTime} 驱动（过期即失效，不走 Caffeine 固定 TTL）；
 * ② 未启用并发限制时登录也要清理失效凭证索引（防泄漏）；③ 容量上限保护不破坏登录。</p>
 */
class CaffeineSessionRepositoryTest {

    private CaffeineSessionRepository repository;

    @BeforeEach
    void setUp() {
        repository = new CaffeineSessionRepository(10_000);
    }

    @AfterEach
    void tearDown() {
        repository.destroy();
    }

    @Test
    void shouldSaveAndReadSubject() {
        assertTrue(repository.save(buildSubject(10001L, "cred-1"), 60, 0));

        assertTrue(repository.checkByCredentials("cred-1"));
        LoginSubject loaded = repository.getSubject("cred-1");
        assertNotNull(loaded);
        assertEquals("cred-1", loaded.getCredentials());
        assertEquals(1, repository.countValidOnlineSessions(10001L));
    }

    /**
     * 登录主体缺 {@code loginExpireTime} 时按"已过期"处理，不得拆箱抛 NPE。
     *
     * <p>内核（`DefaultAuthenticationManager`）对同一输入的处理口径也是"视为已失效 → 401"，
     * 这里保持仓储侧与内核一致：写入即视为已过期，不会留下一个既能查到、内核又拒绝的"僵尸会话"。
     */
    @Test
    void sessionWithoutExpireTimeShouldBeTreatedAsExpired() {
        LoginSubject subject = buildSubject(10001L, "cred-null-expire");
        subject.setLoginExpireTime(null);

        assertTrue(repository.save(subject, 60, 0));
        assertFalse(repository.checkByCredentials("cred-null-expire"), "缺过期时间的会话不得被视为有效");
    }

    /**
     * 凭证碰撞必须明确失败：不能静默覆盖已有会话（否则两个用户会共用同一条会话记录）。
     */
    @Test
    void saveShouldFailWhenCredentialsCollide() {
        assertTrue(repository.save(buildSubject(10001L, "cred-dup"), 60, 0));

        // 后一个用户拿到了完全相同的凭证
        assertFalse(repository.save(buildSubject(10002L, "cred-dup"), 60, 0));

        // 原会话必须完好无损，不能被后一个用户覆盖
        LoginSubject kept = repository.getSubject("cred-dup");
        assertNotNull(kept);
        assertEquals(10001L, kept.getLoginId());
    }

    /**
     * 过期语义：loginExpireTime 已过 → 凭证视为失效（Caffeine 惰性驱逐返回 null）。
     */
    @Test
    void shouldBeInvalidWhenLoginExpireTimePassed() {
        LoginSubject expired = buildSubject(10002L, "cred-old");
        expired.setLoginExpireTime(System.currentTimeMillis() - 1_000L);
        assertTrue(repository.save(expired, 60, 0));

        assertFalse(repository.checkByCredentials("cred-old"));
        assertNull(repository.getSubject("cred-old"));
        assertEquals(0, repository.countValidOnlineSessions(10002L));
    }

    /**
     * 未启用并发限制时，同一账号新登录也应清理索引中已失效的凭证（防泄漏）。
     */
    @Test
    void saveShouldCleanupDeadIndexEntriesEvenWithoutLimit() {
        LoginSubject expired = buildSubject(10003L, "cred-old");
        expired.setLoginExpireTime(System.currentTimeMillis() - 1_000L);
        assertTrue(repository.save(expired, 60, 0));

        assertTrue(repository.save(buildSubject(10003L, "cred-new"), 60, 0));

        assertEquals(1, repository.countValidOnlineSessions(10003L));
    }

    /**
     * 启用并发限制时，超限登录被拒绝。
     */
    @Test
    void shouldRejectLoginWhenConcurrentLimitReached() {
        assertTrue(repository.save(buildSubject(10004L, "cred-a"), 60, 1));

        assertThrows(ConcurrentLoginOverLimitException.class,
                () -> repository.save(buildSubject(10004L, "cred-b"), 60, 1));
    }

    /**
     * 刷新（续期）后凭证仍有效。
     */
    @Test
    void shouldRefreshSession() {
        LoginSubject subject = buildSubject(10005L, "cred-refresh");
        assertTrue(repository.save(subject, 60, 0));

        subject.setLoginExpireTime(System.currentTimeMillis() + 120_000L);
        assertTrue(repository.refreshByCredentials("cred-refresh", subject, 120));

        LoginSubject loaded = repository.getSubject("cred-refresh");
        assertNotNull(loaded);
        assertTrue(loaded.getLoginExpireTime() > System.currentTimeMillis() + 60_000L);
    }

    /**
     * 删除指定凭证：缓存条目与在线索引同步移除。
     */
    @Test
    void shouldDeleteByCredentials() {
        assertTrue(repository.save(buildSubject(10006L, "cred-only"), 60, 0));

        assertTrue(repository.deleteByCredentials("cred-only"));

        assertFalse(repository.checkByCredentials("cred-only"));
        assertEquals(0, repository.countValidOnlineSessions(10006L));
    }

    /**
     * 删除账号下全部会话。
     */
    @Test
    void shouldDeleteByLoginId() {
        assertTrue(repository.save(buildSubject(10007L, "cred-a"), 60, 0));
        assertTrue(repository.save(buildSubject(10007L, "cred-b"), 60, 0));

        assertTrue(repository.deleteByLoginId(10007L));

        assertFalse(repository.checkByCredentials("cred-a"));
        assertFalse(repository.checkByCredentials("cred-b"));
    }

    /**
     * getCredentialsByLoginId：返回该账号全部有效凭证；账号无会话时返回空列表。
     */
    @Test
    void shouldGetCredentialsByLoginId() {
        assertTrue(repository.save(buildSubject(10008L, "cred-a"), 60, 0));
        assertTrue(repository.save(buildSubject(10008L, "cred-b"), 60, 0));

        List<String> credentials = repository.getCredentialsByLoginId(10008L);

        assertEquals(2, credentials.size());
        assertTrue(credentials.contains("cred-a"));
        assertTrue(credentials.contains("cred-b"));
        assertTrue(repository.getCredentialsByLoginId(99999L).isEmpty());
    }

    /**
     * getCredentialsByLoginId：已过期（loginExpireTime 已过）的凭证不应返回。
     */
    @Test
    void getCredentialsByLoginIdShouldExcludeExpiredCredentials() {
        LoginSubject expired = buildSubject(10009L, "cred-old");
        expired.setLoginExpireTime(System.currentTimeMillis() - 1000L);
        assertTrue(repository.save(expired, 60, 0));
        assertTrue(repository.save(buildSubject(10009L, "cred-new"), 60, 0));

        List<String> credentials = repository.getCredentialsByLoginId(10009L);

        assertEquals(1, credentials.size());
        assertTrue(credentials.contains("cred-new"));
    }

    /**
     * 并发登录上限必须**原子**生效，与 single / redis 仓储同口径。
     *
     * <p>修复前"判断上限"与"入列"是两步、各自内部才加锁，于是并发登录会出现两种错误结果：
     * 都通过上限判断后各自入列（实际在线数突破上限），或都入列后各自发现超额、各自摘掉自己
     * （即使还有空位也双双失败 —— 该现象已在真实 Redis 上复现：上限 1 时 4 个并发登录全部被拒）。
     */
    @Test
    void concurrentLoginsShouldNotExceedLimit() throws Exception {
        int maxConcurrentLogins = 3;
        int threads = 16;
        CyclicBarrier barrier = new CyclicBarrier(threads);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        AtomicInteger succeeded = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();
        AtomicReference<Throwable> unexpected = new AtomicReference<>();
        CountDownLatch finished = new CountDownLatch(threads);
        for (int i = 0; i < threads; i++) {
            final int index = i;
            pool.submit(() -> {
                try {
                    barrier.await();
                    if (repository.save(buildSubject(10020L, "cred-concurrent-" + index), 60, maxConcurrentLogins)) {
                        succeeded.incrementAndGet();
                    }
                } catch (ConcurrentLoginOverLimitException e) {
                    rejected.incrementAndGet();
                } catch (Throwable t) {
                    unexpected.set(t);
                } finally {
                    finished.countDown();
                }
            });
        }
        assertTrue(finished.await(30, TimeUnit.SECONDS), "并发登录未在超时时间内完成");
        pool.shutdownNow();

        assertNull(unexpected.get(), "并发登录过程中出现非预期异常");
        assertEquals(maxConcurrentLogins, succeeded.get(), "成功登录数必须恰好等于并发上限");
        assertEquals(threads - maxConcurrentLogins, rejected.get(), "其余请求必须被明确拒绝，不能静默超额");
        assertEquals(maxConcurrentLogins, repository.countValidOnlineSessions(10020L));
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
