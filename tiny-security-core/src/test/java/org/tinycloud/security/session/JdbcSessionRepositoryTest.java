package org.tinycloud.security.session;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SimpleDriverDataSource;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.exception.ConcurrentLoginOverLimitException;

import java.util.List;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JdbcSessionRepository 针对内嵌 H2 数据库的行为验证。
 *
 * <p>核心回归点：login_id 列为 varchar，save 时 loginId 被 {@code String.valueOf}
 * 字符串化后入库，因此 countValidOnlineSessions / deleteByLoginId 传入 Number 类型
 * loginId 时也必须按字符串比较，否则在严格类型数据库上会直接报错（统计恒为 0、
 * 踢人失效），在 MySQL 上则因隐式转换导致 login_id 索引失效。</p>
 *
 * @author liuxingyu01
 */
class JdbcSessionRepositoryTest {

    private JdbcSessionRepository repository;
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void setUp() {
        jdbcTemplate = new JdbcTemplate(new SimpleDriverDataSource(
                new org.h2.Driver(), "jdbc:h2:mem:jdbc_session_test;DB_CLOSE_DELAY=-1", "sa", ""));
        jdbcTemplate.execute("DROP TABLE IF EXISTS t_auth_storage");
        jdbcTemplate.execute(
                "CREATE TABLE t_auth_storage ("
                        + "id BIGINT AUTO_INCREMENT PRIMARY KEY, "
                        + "credentials VARCHAR(256) NOT NULL, "
                        + "login_id VARCHAR(64) NOT NULL, "
                        + "login_subject VARCHAR(5000) NOT NULL, "
                        + "credentials_expire_time BIGINT NOT NULL"
                        + ")");
        repository = new JdbcSessionRepository(jdbcTemplate, "t_auth_storage");
    }

    @AfterEach
    void tearDown() {
        repository.destroy();
    }

    /**
     * Long 类型 loginId：写入、统计、删除必须全链路按同一字符串口径工作。
     */
    @Test
    void shouldCountAndDeleteSessionsByLongLoginId() {
        LoginSubject subject = buildSubject(10001L, "cred-long-10001");
        assertTrue(repository.save(subject, 60, 0));

        assertEquals(1, repository.countValidOnlineSessions(10001L));
        assertTrue(repository.deleteByLoginId(10001L));
        assertEquals(0, repository.countValidOnlineSessions(10001L));
    }

    /**
     * Integer 类型 loginId：与 Long 同理。
     */
    @Test
    void shouldCountAndDeleteSessionsByIntegerLoginId() {
        LoginSubject subject = buildSubject(10002, "cred-int-10002");
        assertTrue(repository.save(subject, 60, 0));

        assertEquals(1, repository.countValidOnlineSessions(10002));
        assertTrue(repository.deleteByLoginId(10002));
        assertEquals(0, repository.countValidOnlineSessions(10002));
    }

    /**
     * String 类型 loginId：原有正确路径不回归。
     */
    @Test
    void shouldCountAndDeleteSessionsByStringLoginId() {
        LoginSubject subject = buildSubject("user-10003", "cred-str-10003");
        assertTrue(repository.save(subject, 60, 0));

        assertEquals(1, repository.countValidOnlineSessions("user-10003"));
        assertTrue(repository.deleteByLoginId("user-10003"));
        assertEquals(0, repository.countValidOnlineSessions("user-10003"));
    }

    /**
     * Number 类型 loginId 的并发登录限制必须生效（依赖 countValidOnlineSessions 统计正确）。
     */
    @Test
    void shouldEnforceMaxConcurrentLoginsForNumberLoginId() {
        assertTrue(repository.save(buildSubject(10004L, "cred-limit-a"), 60, 1));
        assertThrows(ConcurrentLoginOverLimitException.class,
                () -> repository.save(buildSubject(10004L, "cred-limit-b"), 60, 1));
    }

    /**
     * 同一系统内混用 String 与 Number 两种 loginId（框架两者都允许）时，
     * 用 Number 统计/删除不能被非数字的字符串行干扰：否则 varchar 列被隐式转换为数字，
     * 碰到非数字行直接抛 Data conversion error，被吞掉后表现为统计恒为 0、踢人失效。
     */
    @Test
    void shouldIsolateNumberLoginIdFromNonNumericStringLoginId() {
        assertTrue(repository.save(buildSubject("admin", "cred-str-admin"), 60, 0));
        assertTrue(repository.save(buildSubject(10006L, "cred-long-10006"), 60, 0));

        assertEquals(1, repository.countValidOnlineSessions(10006L));
        assertTrue(repository.deleteByLoginId(10006L));
        assertEquals(0, repository.countValidOnlineSessions(10006L));
    }

    /**
     * 字符串 "0123" 与数字 123 是两个不同账号：隐式数字转换会把 '0123' 误算到 123 头上（多计、串号）。
     */
    @Test
    void shouldNotMixStringLoginIdWithEquivalentNumberLoginId() {
        assertTrue(repository.save(buildSubject("0123", "cred-str-0123"), 60, 0));

        assertEquals(0, repository.countValidOnlineSessions(123L));
        assertEquals(0, repository.countValidOnlineSessions(123));
    }

    /**
     * 已过期的会话不应计入有效在线数。
     */
    @Test
    void shouldNotCountExpiredSessions() {
        LoginSubject subject = buildSubject(10005L, "cred-expired-10005");
        subject.setLoginExpireTime(System.currentTimeMillis() - 1000L);
        assertTrue(repository.save(subject, 60, 0));

        assertEquals(0, repository.countValidOnlineSessions(10005L));
    }

    /**
     * 表名白名单校验：仅允许字母/下划线/数字/点号（支持 schema.table），杜绝 SQL 拼接注入。
     */
    @Test
    void shouldRejectInvalidTableName() {
        // 合法表名（含 schema.table 形式）不应抛异常——此处仅校验不抛错，不真正建表
        assertDoesNotThrow(() -> new JdbcSessionRepository(jdbcTemplate, "my_auth_storage").destroy());
        assertDoesNotThrow(() -> new JdbcSessionRepository(jdbcTemplate, "dbo.t_auth_storage").destroy());

        // 非法表名：含空格/分号/引号/特殊字符应被拒绝
        assertThrows(IllegalArgumentException.class, () -> new JdbcSessionRepository(jdbcTemplate, "t auth"));
        assertThrows(IllegalArgumentException.class, () -> new JdbcSessionRepository(jdbcTemplate, "t; DROP TABLE x"));
        assertThrows(IllegalArgumentException.class, () -> new JdbcSessionRepository(jdbcTemplate, "t' OR '1'='1"));
        assertThrows(IllegalArgumentException.class, () -> new JdbcSessionRepository(jdbcTemplate, "1auth"));
        assertThrows(IllegalArgumentException.class, () -> new JdbcSessionRepository(jdbcTemplate, ""));
        assertThrows(IllegalArgumentException.class, () -> new JdbcSessionRepository(jdbcTemplate, null));
    }

    /**
     * getCredentialsByLoginId：返回该账号全部有效凭证（Number 与 String loginId 口径一致），
     * 且不含已过期会话；无会话时返回空列表。
     */
    @Test
    void shouldGetCredentialsByLoginId() {
        assertTrue(repository.save(buildSubject(10007L, "cred-long-a"), 60, 0));
        assertTrue(repository.save(buildSubject(10007L, "cred-long-b"), 60, 0));
        assertTrue(repository.save(buildSubject("user-10008", "cred-str-a"), 60, 0));

        List<String> credentials = repository.getCredentialsByLoginId(10007L);
        assertEquals(2, credentials.size());
        assertTrue(credentials.contains("cred-long-a"));
        assertTrue(credentials.contains("cred-long-b"));
        assertEquals(Arrays.asList("cred-str-a"), repository.getCredentialsByLoginId("user-10008"));

        // 无会话时返回空列表（不返回 null）
        assertNotNull(repository.getCredentialsByLoginId("no-such-user"));
        assertTrue(repository.getCredentialsByLoginId("no-such-user").isEmpty());
    }

    /**
     * getCredentialsByLoginId：已过期会话不计入（与 countValidOnlineSessions 口径一致）。
     */
    @Test
    void shouldExcludeExpiredSessionsFromCredentialsQuery() {
        LoginSubject expired = buildSubject(10009L, "cred-expired");
        expired.setLoginExpireTime(System.currentTimeMillis() - 1000L);
        assertTrue(repository.save(expired, 60, 0));

        assertTrue(repository.getCredentialsByLoginId(10009L).isEmpty());
    }

    /**
     * 幂等语义（1.4.0）：无会话可删时也返回 true——deleteByLoginId 表达的是
     * "操作是否成功执行"而非"实际删除了几个会话"，与 Single/Caffeine 本地仓储一致。
     */
    @Test
    void shouldReturnTrueWhenNoSessionToDelete() {
        assertTrue(repository.deleteByLoginId("no-such-user"));
        assertTrue(repository.deleteByLoginId(99999L));
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
