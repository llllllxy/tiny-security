package org.tinycloud.security.session.timedcache;

import org.junit.jupiter.api.Test;

import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;

/**
 * LocalTimeCache 过期语义单元测试。
 *
 * <p>核心回归点：NEVER_EXPIRE（-1）的 key 查询剩余存活时间时必须原样返回 -1 且不被删除，
 * 此前实现会把 -1 当成早已过期的时间戳参与计算，导致永不过期的 key 一查 TTL 就被销毁。</p>
 *
 * @author liuxingyu01
 */
class LocalTimeCacheTest {

    private final LocalTimeCache cache = new LocalTimeCache(
            new ConcurrentHashMap<>(),
            new ConcurrentHashMap<>());

    /**
     * 永不过期的 key：查询 TTL 返回 NEVER_EXPIRE，且数据仍在。
     */
    @Test
    void neverExpireKeyShouldNotBeDestroyedByTimeoutQuery() {
        cache.setObject("k", "v", LocalTimeCache.NEVER_EXPIRE);

        assertEquals(LocalTimeCache.NEVER_EXPIRE, cache.getObjectTimeout("k"));
        assertEquals("v", cache.getObject("k"));
    }

    /**
     * 永不过期的 key：updateObject 不应被拒绝（也不应顺带把 key 删掉）。
     */
    @Test
    void updateObjectShouldWorkOnNeverExpireKey() {
        cache.setObject("k", "v", LocalTimeCache.NEVER_EXPIRE);

        cache.updateObject("k", "v2");

        assertEquals("v2", cache.getObject("k"));
        assertEquals(LocalTimeCache.NEVER_EXPIRE, cache.getObjectTimeout("k"));
    }

    /**
     * 定时清理线程不应清掉永不过期的 key。
     */
    @Test
    void periodicRefreshShouldNotRemoveNeverExpireKey() {
        cache.setObject("k", "v", LocalTimeCache.NEVER_EXPIRE);

        cache.refreshDataMap();

        assertEquals("v", cache.getObject("k"));
    }

    /**
     * 已过期的 key：查询 TTL 返回 NOT_VALUE_EXPIRE，数据被清除。
     */
    @Test
    void expiredKeyShouldReportNotValueExpireAndBeRemoved() {
        cache.setObject("k", "v", 60);
        // 直接把到期时间改到过去，模拟已过期，避免测试等待真实时间流逝
        cache.expireMap.put("k", System.currentTimeMillis() - 1);

        assertEquals(LocalTimeCache.NOT_VALUE_EXPIRE, cache.getObjectTimeout("k"));
        assertNull(cache.getObject("k"));
    }

    /**
     * 不存在的 key：返回 NOT_VALUE_EXPIRE。
     */
    @Test
    void missingKeyShouldReportNotValueExpire() {
        assertEquals(LocalTimeCache.NOT_VALUE_EXPIRE, cache.getObjectTimeout("missing"));
        assertNull(cache.getObject("missing"));
    }

    /**
     * 普通 key：TTL 在有效期内返回正数秒。
     */
    @Test
    void normalKeyShouldReportRemainingSeconds() {
        cache.setObject("k", "v", 60);

        long timeout = cache.getObjectTimeout("k");

        assertTrue(timeout > 0 && timeout <= 60, "remaining timeout should be in (0, 60], but was: " + timeout);
    }
}
