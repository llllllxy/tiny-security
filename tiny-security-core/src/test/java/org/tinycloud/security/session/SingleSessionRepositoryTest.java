package org.tinycloud.security.session;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.tinycloud.security.consts.AuthConsts;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.session.timedcache.LocalTimeCache;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 单机内存会话仓储测试。
 *
 * <p>核心回归点：① timeout 传 -1（永不过期）时，会话在缓存中标记为 NEVER_EXPIRE，
 * 有效性校验、读取、在线统计都必须把它当作有效会话；② 未启用并发登录限制（maxConcurrentLogins&lt;=0）
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
     * timeout=-1 的会话（永不过期）：校验、读取、统计全部有效。
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
        assertEquals(List.of("cred-new"), index.get("10003"));
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
