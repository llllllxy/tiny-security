package org.tinycloud.security.session;

import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.tinycloud.security.session.timedcache.LocalTimeCache;

import java.lang.reflect.Field;
import java.util.concurrent.ScheduledExecutorService;

import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionRepositoryLifecycleTest {

    /**
     * 验证 JDBC 会话仓储销毁时会关闭过期会话清理线程。
     *
     * @throws Exception 读取调度线程字段失败时抛出
     */
    @Test
    void shouldShutdownJdbcCleanupExecutorOnDestroy() throws Exception {
        JdbcSessionRepository repository = new JdbcSessionRepository(new JdbcTemplate(), "t_auth_storage");

        repository.destroy();

        assertTrue(executorOf(repository, JdbcSessionRepository.class).isShutdown());
    }

    /**
     * 验证单机会话仓储销毁时会关闭本地缓存清理线程。
     *
     * @throws Exception 读取调度线程字段失败时抛出
     */
    @Test
    void shouldShutdownSingleSessionCleanupExecutorOnDestroy() throws Exception {
        SingleSessionRepository repository = new SingleSessionRepository();

        repository.destroy();

        LocalTimeCache timedCache = fieldValue(repository, SingleSessionRepository.class, "timedCache", LocalTimeCache.class);
        assertTrue(executorOf(timedCache, LocalTimeCache.class).isShutdown());
    }

    /**
     * 读取对象中的调度线程字段。
     *
     * @param target     目标对象
     * @param targetType 目标对象类型
     * @return 调度线程
     * @throws Exception 反射读取字段失败时抛出
     */
    private ScheduledExecutorService executorOf(Object target, Class<?> targetType) throws Exception {
        return fieldValue(target, targetType, "executorService", ScheduledExecutorService.class);
    }

    /**
     * 按字段名读取指定类型的私有字段。
     *
     * @param target     目标对象
     * @param targetType 目标对象类型
     * @param fieldName  字段名
     * @param valueType  字段类型
     * @param <T>        字段值类型
     * @return 字段值
     * @throws Exception 反射读取字段失败时抛出
     */
    private <T> T fieldValue(Object target, Class<?> targetType, String fieldName, Class<T> valueType) throws Exception {
        Field field = targetType.getDeclaredField(fieldName);
        field.setAccessible(true);
        return valueType.cast(field.get(target));
    }
}
