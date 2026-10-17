package org.tinycloud.security.session;

import org.junit.jupiter.api.BeforeEach;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SimpleDriverDataSource;

/**
 * {@link JdbcSessionRepository} 的契约测试（TCK 子类），跑在内嵌 H2 上。
 *
 * <p>建表语句从随包发布的 {@code sql/t_auth_storage.sql} 读取：此前测试内联复制
 * DDL，与真实发布的脚本存在漂移风险（例如唯一约束漏掉后碰撞路径就不可测）。这里改为
 * <b>加载同一份脚本</b>，让"测试通过"能代表"发布的 SQL 可用"。
 *
 * @author liuxingyu01
 */
class JdbcSessionRepositoryContractTest extends SessionRepositoryContractTest {

    private JdbcSessionRepository repository;
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void setUp() {
        jdbcTemplate = new JdbcTemplate(new SimpleDriverDataSource(
                new org.h2.Driver(), "jdbc:h2:mem:tck_jdbc;DB_CLOSE_DELAY=-1", "sa", ""));
        jdbcTemplate.execute("DROP TABLE IF EXISTS t_auth_storage");
        for (String statement : AuthStorageDdl.statements()) {
            jdbcTemplate.execute(statement);
        }
        repository = new JdbcSessionRepository(jdbcTemplate, "t_auth_storage");
    }

    @Override
    protected SessionRepository createRepository() {
        return repository;
    }

    /**
     * Jdbc 实现目前**不支持**原子并发上限（的已知残余）。
     *
     * <p>原因：该仓储只有裸 {@code JdbcTemplate}（每条语句自动提交）、没有事务管理器，
     * 而"先 COUNT 再 INSERT"要原子必须让两步同处一个临界区。三个**不改表结构**的候选方案
     * 已逐个实测否决（单条条件 INSERT 不原子、`SELECT COUNT ... FOR UPDATE` 在 H2 上语法不通、
     * 行锁 `SELECT ... FOR UPDATE` 锁不住"账号当前 0 个会话"这一最坏情形）。
     * 真正闭合需要破坏性 DDL（{@code slot} 列 + {@code UNIQUE (login_id, slot)}），见文档 §4.3 第 13 行。
     */
    @Override
    protected boolean supportsAtomicConcurrentLimit() {
        return false;
    }

    @Override
    protected void destroyRepository(SessionRepository repository) {
        ((JdbcSessionRepository) repository).destroy();
    }
}
