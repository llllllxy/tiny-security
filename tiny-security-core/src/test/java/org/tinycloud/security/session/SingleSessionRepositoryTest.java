package org.tinycloud.security.session;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.tinycloud.security.consts.AuthConsts;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.exception.ConcurrentLoginOverLimitException;
import org.tinycloud.security.session.timedcache.LocalTimeCache;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 单机内存会话仓储测试。
 *
 * <p>核心回归点：① 存储层对 {@code timeout = -1} 的处理（{@code LocalTimeCache.NEVER_EXPIRE}）——
 * 有效性校验、读取、在线统计都必须把它当作有效会话。注意这是**缓存层语义**：配置层已不允许
 * `tiny-security.timeout` 取非正值，所以 {@code -1} 不会再从配置流到这里；保留该用例是为了锁住
 * 缓存层的既有能力，防止将来有人顺手改掉它；② 未启用并发登录限制（maxConcurrentLogins&lt;=0）
 * 时，登录也要顺带清理失效凭证索引，否则索引随登录次数无限累积（内存泄漏）。</p>
 *
 * @author liuxingyu01
 */
class SingleSessionRepositoryTest {

    private SingleSessionRepository repository;

    @BeforeEach
    void setUp() {
        repository = new SingleSessionRepository();
    }

    @AfterEach
    void tearDown() {
        repository.destroy();
    }

    /**
     * 存储层 timeout=-1 的会话（缓存标记为 NEVER_EXPIRE）：校验、读取、统计全部有效。
     * <p>这是 {@code LocalTimeCache} 的既有能力，与配置层是否允许 -1 无关。
     */
    @Test
    void neverExpireSessionShouldStayValid() {
        assertTrue(repository.save(buildSubject(10001L, "cred-never"), -1, 0));

        assertTrue(repository.checkByCredentials("cred-never"));
        LoginSubject loaded = repository.getSubject("cred-never");
        assertNotNull(loaded);
        assertEquals("cred-never", loaded.getCredentials());
        assertEquals(1, repository.countValidOnlineSessions(10001L));
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
     * 已过期的会话：校验失败、读取为空、不计入在线统计。
     */
    @Test
    void expiredSessionShouldBeInvalidAndNotCounted() throws Exception {
        assertTrue(repository.save(buildSubject(10002L, "cred-old"), 60, 0));
        backdateExpire("cred-old");

        assertFalse(repository.checkByCredentials("cred-old"));
        assertNull(repository.getSubject("cred-old"));
        assertEquals(0, repository.countValidOnlineSessions(10002L));
    }

    /**
     * 未启用并发限制时，同一账号新登录也应清理索引中已失效的凭证（防泄漏）。
     */
    @Test
    void saveShouldCleanupDeadIndexEntriesEvenWithoutLimit() throws Exception {
        assertTrue(repository.save(buildSubject(10003L, "cred-old"), 60, 0));
        backdateExpire("cred-old");

        assertTrue(repository.save(buildSubject(10003L, "cred-new"), 60, 0));

        Map<String, List<String>> index = fieldValue("loginIdToCredentialsMap", Map.class);
        assertEquals(Arrays.asList("cred-new"), index.get("10003"));
    }

    /**
     * 启用并发限制时，超限登录被拒绝（原有能力不回归）。
     */
    @Test
    void shouldRejectLoginWhenConcurrentLimitReached() {
        assertTrue(repository.save(buildSubject(10004L, "cred-a"), 60, 1));

        org.junit.jupiter.api.Assertions.assertThrows(
                org.tinycloud.security.exception.ConcurrentLoginOverLimitException.class,
                () -> repository.save(buildSubject(10004L, "cred-b"), 60, 1));
    }

    /**
     * 1.3.3 索引收敛：登出最后一个凭证后，在线索引 key 应被整体移除（而非残留空列表）。
     */
    @Test
    void deleteShouldRemoveIndexKeyWhenLastCredentialRemoved() throws Exception {
        assertTrue(repository.save(buildSubject(10005L, "cred-only"), 60, 0));

        assertTrue(repository.deleteByCredentials("cred-only"));

        Map<String, List<String>> index = fieldValue("loginIdToCredentialsMap", Map.class);
        assertNull(index.get("10005"));
    }

    /**
     * 1.3.3 索引收敛：deleteByLoginId 删除账号下全部会话后，在线索引 key 应被移除。
     */
    @Test
    void deleteByLoginIdShouldRemoveIndexKey() throws Exception {
        assertTrue(repository.save(buildSubject(10006L, "cred-a"), 60, 0));
        assertTrue(repository.save(buildSubject(10006L, "cred-b"), 60, 0));

        assertTrue(repository.deleteByLoginId(10006L));

        assertFalse(repository.checkByCredentials("cred-a"));
        assertFalse(repository.checkByCredentials("cred-b"));
        Map<String, List<String>> index = fieldValue("loginIdToCredentialsMap", Map.class);
        assertNull(index.get("10006"));
    }

    /**
     * getCredentialsByLoginId：返回该账号全部有效凭证（多会话场景）。
     */
    @Test
    void getCredentialsByLoginIdShouldReturnAllValidCredentials() {
        assertTrue(repository.save(buildSubject(10007L, "cred-a"), 60, 0));
        assertTrue(repository.save(buildSubject(10007L, "cred-b"), 60, 0));

        List<String> credentials = repository.getCredentialsByLoginId(10007L);

        assertEquals(2, credentials.size());
        assertTrue(credentials.contains("cred-a"));
        assertTrue(credentials.contains("cred-b"));
    }

    /**
     * getCredentialsByLoginId：不应包含已过期凭证，且顺带清理索引中的失效项。
     */
    @Test
    void getCredentialsByLoginIdShouldExcludeExpiredCredentials() throws Exception {
        assertTrue(repository.save(buildSubject(10008L, "cred-old"), 60, 0));
        assertTrue(repository.save(buildSubject(10008L, "cred-new"), 60, 0));
        backdateExpire("cred-old");

        List<String> credentials = repository.getCredentialsByLoginId(10008L);

        assertEquals(Arrays.asList("cred-new"), credentials);
        // 索引中的失效项应被就地清理
        Map<String, List<String>> index = fieldValue("loginIdToCredentialsMap", Map.class);
        assertEquals(Arrays.asList("cred-new"), index.get("10008"));
    }

    /**
     * getCredentialsByLoginId：账号无会话时返回空列表（不返回 null）。
     * <p>且必须是<b>可变</b>空列表：与"有会话时返回副本"保持行为一致，
     * 避免调用方对结果做 add/clear 时在"0 个会话"这一边界上抛
     * UnsupportedOperationException。
     */
    @Test
    void getCredentialsByLoginIdShouldReturnEmptyListWhenNoSession() {
        List<String> credentials = repository.getCredentialsByLoginId(99999L);

        assertNotNull(credentials);
        assertTrue(credentials.isEmpty());
        assertDoesNotThrow(() -> credentials.add("cred-x"));
    }

    /**
     * getCredentialsByLoginId：会话全部过期后同样返回可变空列表。
     */
    @Test
    void getCredentialsByLoginIdShouldReturnMutableEmptyListAfterAllExpired() throws Exception {
        assertTrue(repository.save(buildSubject(10010L, "cred-expired"), 60, 0));
        backdateExpire("cred-expired");

        List<String> credentials = repository.getCredentialsByLoginId(10010L);

        assertTrue(credentials.isEmpty());
        assertDoesNotThrow(() -> credentials.add("cred-x"));
    }

    /**
     * getCredentialsByLoginId：返回的是副本，调用方修改不会影响仓储内部索引。
     */
    @Test
    void getCredentialsByLoginIdShouldReturnDefensiveCopy() throws Exception {
        assertTrue(repository.save(buildSubject(10009L, "cred-a"), 60, 0));

        List<String> credentials = repository.getCredentialsByLoginId(10009L);
        credentials.clear();

        Map<String, List<String>> index = fieldValue("loginIdToCredentialsMap", Map.class);
        assertEquals(Arrays.asList("cred-a"), index.get("10009"));
    }

    /**
     * 把指定凭证的到期时间改到过去，模拟会话自然过期。
     */
    private void backdateExpire(String credentials) throws Exception {
        LocalTimeCache cache = fieldValue("timedCache", LocalTimeCache.class);
        cache.expireMap.put(AuthConsts.AUTH_CREDENTIALS_KEY + credentials, System.currentTimeMillis() - 1);
    }

    /**
     * 按字段名读取私有字段。
     */
    private <T> T fieldValue(String fieldName, Class<T> fieldType) throws Exception {
        Field field = SingleSessionRepository.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        return fieldType.cast(field.get(repository));
    }

    /**
     * 并发登录上限必须**原子**生效。
     *
     * <p>修复前"判断上限"与"入列"是两步、各自内部才加锁，于是并发登录会出现两种错误结果：
     * 都通过上限判断后各自入列（实际在线数突破上限），或都入列后各自发现超额、各自摘掉自己
     * （即使还有空位也双双失败 —— 该现象已在真实 Redis 上复现：上限 1 时 4 个并发登录全部被拒）。
     *
     * <p>本用例把 {@code threads} 个线程卡在同一个栅栏上同时发起登录，断言**恰好**
     * {@code maxConcurrentLogins} 个成功、其余被明确拒绝，且在线数与成功数一致。
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
