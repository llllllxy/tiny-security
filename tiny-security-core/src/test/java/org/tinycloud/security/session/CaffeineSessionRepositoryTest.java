package org.tinycloud.security.session;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.exception.ConcurrentLoginOverLimitException;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
