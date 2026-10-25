package org.tinycloud.security.session;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.exception.ConcurrentLoginOverLimitException;
import org.tinycloud.security.util.JsonUtil;

import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link SessionRepository} 契约测试（TCK）。
 *
 * <p><b>存在意义</b>：框架内置四种仓储（single / caffeine / redis / jdbc），README 也鼓励用户
 * 自定义实现。此前"四个仓储行为一致"只靠人工比对与零散用例保证，多次出现同一语义在不同仓储下
 * 表现不同（过期会话复活、并发上限强度不一、`timeout` 四种语义、共享引用与类型漂移）。
 * 本类把"契约"写成**一套可执行的断言**，四个实现各自继承即可验证。
 *
 * <p><b>如何扩展</b>：新增仓储实现时，写一个子类实现 {@link #createRepository()} 与
 * {@link #destroyRepository(SessionRepository)} 即可获得全部契约校验。
 *
 * <p><b>本类只断言四种仓储**应当一致**的部分</b>。明确**不**纳入契约的差异（避免写出无法同时通过的断言）：
 * <ul>
 *     <li>{@code extraInfo} 的引用语义：内存版共享、Redis/JDBC 每次反序列化重建；</li>
 *     <li>存储层清理时机：内存版靠缓存过期、JDBC 靠定时 DELETE 语句；</li>
 *     <li>Redis 的原子并发上限依赖 Lua，Mockito 无法验证（由真实 Redis 探针覆盖）。</li>
 * </ul>
 *
 * @author liuxingyu01
 */
abstract class SessionRepositoryContractTest {

    /**
     * 创建被测仓储（每个用例前调用一次，保证相互隔离）。
     */
    protected abstract SessionRepository createRepository();

    /**
     * 释放被测仓储持有的资源（后台线程、连接等）。
     */
    protected abstract void destroyRepository(SessionRepository repository);

    /**
     * 该实现是否满足"并发登录上限原子生效"。
     *
     * <p>默认 {@code true}。已知 Jdbc 实现因缺少事务/无法在不改表结构的前提下原子化而不满足，
     * 其子类覆盖为 {@code false} 并附说明 —— 豁免必须是**显式且记录在案**的。
     *
     * @return true 表示支持原子并发上限
     */
    protected boolean supportsAtomicConcurrentLimit() {
        return true;
    }

    private SessionRepository repository;

    @AfterEach
    void tearDown() {
        if (this.repository != null) {
            this.destroyRepository(this.repository);
            this.repository = null;
        }
    }

    /**
     * 每个用例前重建仓储：TCK 要能独立跑每个实现，不能依赖前一个用例的残留状态。
     */
    private SessionRepository repository() {
        if (this.repository == null) {
            this.repository = createRepository();
        }
        return this.repository;
    }

    // ==================== save / 读取往返 ====================

    /**
     * save 后必须能读到，且关键字段逐一保真 —— 这是所有仓储的最低契约。
     */
    @Test
    void savedSubjectShouldBeReadableWithAllFields() {
        LoginSubject subject = buildSubject(10001L, "cred-roundtrip");

        assertTrue(repository().save(subject, 60, 0), "save 应返回 true");

        assertTrue(repository().checkByCredentials("cred-roundtrip"));
        LoginSubject loaded = repository().getSubject("cred-roundtrip");
        assertNotNull(loaded, "save 之后必须能读到");
        assertEquals("cred-roundtrip", loaded.getCredentials());
        assertEquals(10001L, loaded.getLoginId(), "loginId 必须保真");
        assertEquals(subject.getLoginTime(), loaded.getLoginTime());
        assertEquals(subject.getLoginExpireTime(), loaded.getLoginExpireTime());
    }

    /**
     * 不存在的凭证：check 返回 false、getSubject 返回 null（而不是抛异常或空对象）。
     */
    @Test
    void unknownCredentialsShouldBeReportedAsAbsent() {
        assertFalse(repository().checkByCredentials("no-such-cred"), "未知凭证必须是无效的");
        assertNull(repository().getSubject("no-such-cred"), "未知凭证必须返回 null");
    }

    /**
     * 凭证为空必须显式报错（各仓储都用 Assert.hasText 拦住），不能静默当成"查不到"。
     */
    @Test
    void blankCredentialsShouldBeRejected() {
        assertThrows(IllegalArgumentException.class, () -> repository().checkByCredentials(""));
        assertThrows(IllegalArgumentException.class, () -> repository().getSubject(" "));
    }

    // ==================== 凭证碰撞 ====================

    /**
     * 同一凭证重复 save 必须失败（返回 false 或抛异常），**绝不能静默覆盖**已有会话 ——
     * 否则两个用户会共用同一条会话记录（会话固定攻击面）。
     */
    @Test
    void duplicateCredentialsShouldNotSilentlyOverwrite() {
        LoginSubject first = buildSubject(10001L, "cred-dup");
        assertTrue(repository().save(first, 60, 0));

        LoginSubject second = buildSubject(20002L, "cred-dup");
        boolean saved;
        try {
            saved = repository().save(second, 60, 0);
        } catch (RuntimeException ex) {
            saved = false;
        }
        assertFalse(saved, "凭证碰撞必须失败，不能静默覆盖");

        LoginSubject loaded = repository().getSubject("cred-dup");
        assertNotNull(loaded);
        assertEquals(10001L, loaded.getLoginId(), "原会话必须保持不变");
    }

    // ==================== loginId 类型契约 ====================

    /**
     * loginId 的类型必须在存储往返后保持稳定。
     *
     * <p>Redis/JDBC 走 JSON 往返，数值默认会漂移成 {@code Integer}，导致
     * {@code (Long) subject.getLoginId} 抛 {@code ClassCastException}；内存版存引用则不会漂移。
     * 契约要求四种仓储**读出来的类型与写进去的一致**。
     */
    @Test
    void loginIdTypeShouldSurviveRoundTrip() {
        LoginSubject subject = buildSubject(10001L, "cred-type");
        assertTrue(repository().save(subject, 60, 0));

        Object loaded = repository().getSubject("cred-type").getLoginId();
        assertEquals(Long.class, loaded.getClass(),
                "数值 loginId 经存储往返后必须仍是 Long（否则 (Long) 强转会 ClassCastException）");
        assertEquals(10001L, loaded);
    }

    /**
     * JSON 反序列化本身的类型归一化（这是 Redis/JDBC 的底层依赖）。
     */
    @Test
    void jsonRoundTripShouldNotDriftNumericLoginId() {
        LoginSubject subject = buildSubject(10001L, "cred-json");
        LoginSubject back = JsonUtil.readValue(JsonUtil.writeValueAsString(subject), LoginSubject.class);

        assertEquals(Long.class, back.getLoginId().getClass(),
                "JSON 往返后 loginId 不应从 Long 漂移为 Integer");
        assertEquals(10001L, back.getLoginId());
    }

    // ==================== getSubject 返回副本 ====================

    /**
     * {@code getSubject} 必须返回**副本**：调用方修改读到的对象不得影响存储。
     *
     * <p>否则同样的用户代码在内存版会"改一下就持久生效"，在 Redis/JDBC 版则不会 —— 语义分叉。
     */
    @Test
    void getSubjectShouldReturnDefensiveCopy() {
        assertTrue(repository().save(buildSubject(10001L, "cred-copy"), 60, 0));

        LoginSubject first = repository().getSubject("cred-copy");
        assertNotNull(first);
        first.setLoginId(99999L);
        first.setCredentials("tampered");

        LoginSubject second = repository().getSubject("cred-copy");
        assertNotNull(second, "篡改返回值不应破坏存储中的会话");
        assertEquals(10001L, second.getLoginId(), "篡改返回值不得影响存储");
        assertEquals("cred-copy", second.getCredentials(), "篡改返回值不得影响存储");
    }

    /**
     * 连续两次 {@code getSubject} 不应返回同一实例（内存版存引用时最容易违反）。
     */
    @Test
    void getSubjectShouldNotReturnSharedInstance() {
        assertTrue(repository().save(buildSubject(10001L, "cred-share"), 60, 0));

        LoginSubject first = repository().getSubject("cred-share");
        LoginSubject second = repository().getSubject("cred-share");
        assertNotSame(first, second, "两次读取不应返回同一个实例（内存版会，Redis/JDBC 不会）");
    }

    // ==================== 有效性与过期 ====================

    /**
     * 已过期的会话：check 为 false、getSubject 为 null，四种仓储必须一致。
     */
    @Test
    void expiredSessionShouldBeTreatedAsAbsent() {
        LoginSubject subject = buildSubject(10001L, "cred-expired");
        subject.setLoginExpireTime(System.currentTimeMillis() - 1_000L);
        repository().save(subject, 60, 0);

        assertFalse(repository().checkByCredentials("cred-expired"), "已过期会话必须无效");
        assertNull(repository().getSubject("cred-expired"), "已过期会话必须读不到");
    }

    /**
     * 缺少 {@code loginExpireTime} 的主体按"已过期"处理（与内核的绝对过期口径一致），
     * 不得被视为有效会话。
     */
    @Test
    void sessionWithoutExpireTimeShouldNotBeValid() {
        LoginSubject subject = buildSubject(10001L, "cred-null-expire");
        subject.setLoginExpireTime(null);

        boolean saved;
        try {
            saved = repository().save(subject, 60, 0);
        } catch (RuntimeException ex) {
            saved = false;
        }
        if (saved) {
            assertFalse(repository().checkByCredentials("cred-null-expire"),
                    "缺过期时间的会话不得被视为有效");
        }
    }

    // ==================== refresh ====================

    /**
     * 续期后会话仍然有效，且过期时间被推进。
     */
    @Test
    void refreshShouldKeepSessionAliveAndExtendExpiry() {
        LoginSubject subject = buildSubject(10001L, "cred-refresh");
        assertTrue(repository().save(subject, 60, 0));

        long newExpireTime = System.currentTimeMillis() + 600_000L;
        subject.setLoginExpireTime(newExpireTime);

        assertTrue(repository().refreshByCredentials("cred-refresh", subject, 600),
                "续期应返回 true");

        LoginSubject loaded = repository().getSubject("cred-refresh");
        assertNotNull(loaded, "续期后会话应仍可读");
        assertEquals(newExpireTime, loaded.getLoginExpireTime(), "续期应写回过期时间");
        assertTrue(repository().checkByCredentials("cred-refresh"));
    }

    // ==================== 删除 ====================

    /**
     * 按凭证删除后：check 为 false、getSubject 为 null。
     */
    @Test
    void deleteByCredentialsShouldRemoveSession() {
        assertTrue(repository().save(buildSubject(10001L, "cred-del"), 60, 0));

        repository().deleteByCredentials("cred-del");

        assertFalse(repository().checkByCredentials("cred-del"), "删除后必须无效");
        assertNull(repository().getSubject("cred-del"), "删除后必须读不到");
    }

    /**
     * 按账号删除会清掉该账号的**全部**会话（踢人场景）。
     */
    @Test
    void deleteByLoginIdShouldRemoveAllSessionsOfThatAccount() {
        assertTrue(repository().save(buildSubject(10001L, "cred-a"), 60, 0));
        assertTrue(repository().save(buildSubject(10001L, "cred-b"), 60, 0));
        assertTrue(repository().save(buildSubject(20002L, "cred-c"), 60, 0));

        repository().deleteByLoginId(10001L);

        assertFalse(repository().checkByCredentials("cred-a"));
        assertFalse(repository().checkByCredentials("cred-b"));
        assertTrue(repository().checkByCredentials("cred-c"), "不得误删其它账号的会话");
    }

    /**
     * 删除不存在的会话返回 true（幂等语义：表达"操作是否成功执行"，而非"删掉了几个"）。
     */
    @Test
    void deleteByLoginIdShouldBeIdempotent() {
        assertTrue(repository().deleteByLoginId(88888L), "无会话时删除也应返回 true（幂等）");
    }

    // ==================== 在线统计与反查 ====================

    /**
     * 有效会话计数只统计该账号的、且未过期的会话。
     */
    @Test
    void countValidOnlineSessionsShouldCountOnlyValidOnes() {
        assertTrue(repository().save(buildSubject(10001L, "cred-c1"), 60, 0));
        assertTrue(repository().save(buildSubject(10001L, "cred-c2"), 60, 0));
        assertTrue(repository().save(buildSubject(20002L, "cred-c3"), 60, 0));

        LoginSubject expired = buildSubject(10001L, "cred-c4");
        expired.setLoginExpireTime(System.currentTimeMillis() - 1_000L);
        repository().save(expired, 60, 0);

        assertEquals(2, repository().countValidOnlineSessions(10001L), "只应统计有效会话");
        assertEquals(1, repository().countValidOnlineSessions(20002L));
        assertEquals(0, repository().countValidOnlineSessions(77777L), "无会话账号应为 0");
    }

    /**
     * 按账号反查凭证：只返回有效会话的凭证，无会话时空列表（不返回 null）。
     */
    @Test
    void getCredentialsByLoginIdShouldReturnOnlyValidOnes() {
        assertTrue(repository().save(buildSubject(10001L, "cred-g1"), 60, 0));
        assertTrue(repository().save(buildSubject(10001L, "cred-g2"), 60, 0));

        List<String> credentials = repository().getCredentialsByLoginId(10001L);
        assertNotNull(credentials, "无会话时应返回空列表而非 null");
        assertEquals(2, credentials.size());
        assertTrue(credentials.contains("cred-g1"));
        assertTrue(credentials.contains("cred-g2"));

        assertTrue(repository().getCredentialsByLoginId(66666L).isEmpty());
    }

    /**
     * 登出（删除凭证）后，该凭证不再出现在反查结果里。
     */
    @Test
    void getCredentialsByLoginIdShouldExcludeDeletedOnes() {
        assertTrue(repository().save(buildSubject(10001L, "cred-d1"), 60, 0));
        assertTrue(repository().save(buildSubject(10001L, "cred-d2"), 60, 0));

        repository().deleteByCredentials("cred-d1");

        List<String> credentials = repository().getCredentialsByLoginId(10001L);
        assertEquals(1, credentials.size());
        assertTrue(credentials.contains("cred-d2"));
    }

    // ==================== 全局在线查询 ====================

    /**
     * 无人在线时返回空列表（不返回 null），账号数为 0。
     */
    @Test
    void getOnlineLoginIdsShouldReturnEmptyWhenNobodyOnline() {
        List<Object> loginIds = repository().getOnlineLoginIds();
        assertNotNull(loginIds, "必须返回空列表而非 null");
        assertTrue(loginIds.isEmpty());
        assertEquals(0, repository().countOnlineUsers());
    }

    /**
     * 全量在线账号：多个账号登录后都应出现在结果里。
     *
     * <p><b>统一按 String 返回</b>是本契约的一部分：jdbc 存的是 varchar 列、redis 存的是 key 后缀，
     * 内存版也刻意 {@code String.valueOf(...)} —— 否则同一份业务代码切换 {@code store-type}
     * 后拿到的 loginId 类型会漂移（内存版 Long、redis 版 String）。
     */
    @Test
    void getOnlineLoginIdsShouldReturnAllAccountsWithValidSessions() {
        assertTrue(repository().save(buildSubject(10001L, "cred-o1"), 60, 0));
        assertTrue(repository().save(buildSubject(20002L, "cred-o2"), 60, 0));

        List<Object> loginIds = repository().getOnlineLoginIds();
        assertEquals(2, loginIds.size(), "实际结果：" + loginIds);
        assertTrue(loginIds.contains("10001"), "应包含 10001（字符串形式），实际：" + loginIds);
        assertTrue(loginIds.contains("20002"), "应包含 20002（字符串形式），实际：" + loginIds);
    }

    /**
     * 同一账号多端登录：全量名单里只应出现一次（去重）。
     *
     * <p>这是"在线账号"与"在线会话"的分水岭 —— 名单按账号去重，会话明细才按份计。
     */
    @Test
    void getOnlineLoginIdsShouldDeduplicateAccountsWithMultipleSessions() {
        assertTrue(repository().save(buildSubject(10001L, "cred-m1"), 60, 0));
        assertTrue(repository().save(buildSubject(10001L, "cred-m2"), 60, 0));
        assertTrue(repository().save(buildSubject(10001L, "cred-m3"), 60, 0));

        List<Object> loginIds = repository().getOnlineLoginIds();
        assertEquals(1, loginIds.size(), "同一账号的 3 个会话只应产生 1 个账号，实际：" + loginIds);
        assertEquals("10001", loginIds.get(0));
    }

    /**
     * 已过期的会话不能让其账号继续留在在线名单里。
     *
     * <p>对 redis 仓储尤其关键：在线列表 key 的 TTL 是会话超时的 <b>2 倍</b>，会话过期后列表 key
     * 仍会存活一段时间。若直接把 SCAN 到的 key 后缀当作在线账号返回，名单会虚高
     * （用户已掉线却仍显示在线，最长可达一个会话周期）。
     */
    @Test
    void getOnlineLoginIdsShouldExcludeExpiredOnes() {
        assertTrue(repository().save(buildSubject(10001L, "cred-e1"), 60, 0));
        LoginSubject expired = buildSubject(20002L, "cred-e2");
        expired.setLoginExpireTime(System.currentTimeMillis() - 1_000L);
        repository().save(expired, 60, 0);

        List<Object> loginIds = repository().getOnlineLoginIds();
        assertTrue(loginIds.contains("10001"), "有效会话的账号必须出现，实际：" + loginIds);
        assertFalse(loginIds.contains("20002"), "已过期会话的账号不应出现在线，实际：" + loginIds);
    }

    /**
     * 会话被删除（单个凭证登出 / 整账号踢出）后，对应账号不应再出现在在线名单里。
     */
    @Test
    void getOnlineLoginIdsShouldExcludeDeletedOnes() {
        assertTrue(repository().save(buildSubject(10001L, "cred-x1"), 60, 0));
        assertTrue(repository().save(buildSubject(20002L, "cred-x2"), 60, 0));

        assertTrue(repository().deleteByCredentials("cred-x1"));
        List<Object> afterSingleDelete = repository().getOnlineLoginIds();
        assertFalse(afterSingleDelete.contains("10001"),
                "10001 的唯一会话已删除，不应再算在线，实际：" + afterSingleDelete);
        assertTrue(afterSingleDelete.contains("20002"));

        assertTrue(repository().deleteByLoginId(20002L));
        assertTrue(repository().getOnlineLoginIds().isEmpty(), "全部踢出后名单应为空");
    }

    /**
     * {@code countOnlineUsers} 数的是"账号数"而不是"会话数"。
     *
     * <p>这是最容易和 {@link #countValidOnlineSessions(Object)} 混淆的地方：一个账号 2 台设备登录，
     * 在线"人"数是 1，在线"会话"数是 2。报表上的"当前在线人数"要的是前者。
     */
    @Test
    void countOnlineUsersShouldCountAccountsNotSessions() {
        assertTrue(repository().save(buildSubject(10001L, "cred-n1"), 60, 0));
        assertTrue(repository().save(buildSubject(10001L, "cred-n2"), 60, 0));
        assertTrue(repository().save(buildSubject(20002L, "cred-n3"), 60, 0));

        assertEquals(2, repository().countOnlineUsers(),
                "在线账号数应为 2（按账号去重），而不是会话数 3");
        assertEquals(2, repository().countValidOnlineSessions(10001L), "该账号的会话数是 2");
        assertEquals(1, repository().countValidOnlineSessions(20002L));
    }

    // ==================== 并发登录上限 ====================

    /**
     * 并发登录上限必须**原子**生效：恰好放行 {@code max} 个，其余被明确拒绝，
     * 且不得有静默超额。
     *
     * <p><b>已知豁免</b>：Jdbc 实现目前**不满足**本条 —— 它只有裸 {@code JdbcTemplate}
     * （每条语句自动提交）、没有事务管理器，"先 COUNT 再 INSERT"无法原子化。三个免改表结构的
     * 候选方案已实测否决，真正闭合需要破坏性 DDL（`slot` 列 + `UNIQUE (login_id, slot)`），
     * 见文档 §4.3 第 13 行。子类可通过 {@link #supportsAtomicConcurrentLimit()} 声明豁免，
     * 但**必须显式声明**：豁免是"记录在案的已知缺口"，不是"测试放过"。
     *
     * <p>Redis 实现的原子性依赖 Lua 脚本，Mockito 下无法验证，由真实 Redis 探针覆盖。
     */
    @Test
    void concurrentLoginsShouldNotExceedLimit() throws Exception {
        if (!supportsAtomicConcurrentLimit()) {
            // 显式豁免：此处不做断言，但由 @Disabled 语义之外的显式分支记录，避免误以为已验证
            return;
        }
        int maxConcurrentLogins = 3;
        int threads = 16;
        SessionRepository repo = repository();

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
                    if (repo.save(buildSubject(70001L, "cred-concurrent-" + index), 60, maxConcurrentLogins)) {
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

        assertTrue(finished.await(60, TimeUnit.SECONDS), "并发登录未在超时时间内完成");
        pool.shutdownNow();

        assertNull(unexpected.get(), "并发登录过程中出现非预期异常");
        assertEquals(maxConcurrentLogins, succeeded.get(),
                "成功登录数必须恰好等于并发上限（多一个即为静默超额，少一个即为误拒）");
        assertEquals(threads - maxConcurrentLogins, rejected.get(), "其余请求必须被明确拒绝");
    }

    /**
     * 串行场景下，达到上限后继续登录必须被拒绝。
     */
    @Test
    void sequentialLoginsBeyondLimitShouldBeRejected() {
        assertTrue(repository().save(buildSubject(70002L, "cred-s1"), 60, 1));

        assertThrows(ConcurrentLoginOverLimitException.class,
                () -> repository().save(buildSubject(70002L, "cred-s2"), 60, 1),
                "超过上限必须抛 ConcurrentLoginOverLimitException");
    }

    /**
     * {@code maxConcurrentLogins <= 0} 表示不限制，可以无限登录。
     */
    @Test
    void nonPositiveLimitShouldMeanUnlimited() {
        for (int i = 0; i < 5; i++) {
            assertTrue(repository().save(buildSubject(70003L, "cred-u" + i), 60, 0),
                    "0 表示不限制，不应拒绝");
        }
        assertEquals(5, repository().countValidOnlineSessions(70003L));
    }

    /**
     * 构造登录主体。
     */
    protected static LoginSubject buildSubject(Object loginId, String credentials) {
        LoginSubject subject = new LoginSubject();
        subject.setLoginId(loginId);
        subject.setCredentials(credentials);
        subject.setLoginTime(System.currentTimeMillis());
        subject.setLoginExpireTime(System.currentTimeMillis() + 60_000L);
        return subject;
    }
}
