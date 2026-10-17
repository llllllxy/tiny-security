package org.tinycloud.security.authentication;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.tinycloud.security.config.AuthProperties;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.context.SecurityContext;
import org.tinycloud.security.exception.UnAuthorizedException;
import org.tinycloud.security.provider.AuthProvider;
import org.tinycloud.security.session.SessionRepository;
import org.tinycloud.security.session.SingleSessionRepository;

import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;

class DefaultAuthenticationManagerTest {

    @Test
    void shouldAuthenticateAndRefreshExpiringSubject() {
        long now = System.currentTimeMillis();
        LoginSubject subject = new LoginSubject();
        subject.setLoginId("user-1");
        subject.setCredentials("cred-1");
        subject.setLoginTime(now);
        subject.setLoginExpireTime(now + 1_000);

        FakeSessionRepository sessionRepository = new FakeSessionRepository();
        sessionRepository.putSubject(subject);
        AuthProvider authProvider = new SimpleAuthProvider(sessionRepository);

        DefaultAuthenticationManager authenticationManager = new DefaultAuthenticationManager(authProvider, sessionRepository, 60);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("token", "cred-1");
        SecurityContext result = authenticationManager.authenticate(request);

        assertEquals("cred-1", result.getLoginSubject().getCredentials());
        assertEquals("user-1", result.getLoginSubject().getLoginId());
        assertTrue(sessionRepository.wasRefreshed());
        assertTrue(result.getLoginSubject().getLoginExpireTime() > now + 1_000);
    }

    @Test
    void shouldThrowUnauthorizedWhenSubjectNotFound() {
        FakeSessionRepository sessionRepository = new FakeSessionRepository();
        AuthProvider authProvider = new SimpleAuthProvider(sessionRepository);
        DefaultAuthenticationManager authenticationManager = new DefaultAuthenticationManager(authProvider, sessionRepository, 60);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("token", "missing");

        assertThrows(UnAuthorizedException.class, () -> authenticationManager.authenticate(request));
    }

    /**
     * 滑动续期阈值（1.3.3 修正为 20%）：剩余 TTL 大于 timeout*0.2 时不应触发存储写。
     * timeout=60s，阈值=12s；剩余 50s 时不应刷新。
     */
    @Test
    void shouldNotRefreshWhenRemainingTtlAboveThreshold() {
        long now = System.currentTimeMillis();
        LoginSubject subject = new LoginSubject();
        subject.setLoginId("user-1");
        subject.setCredentials("cred-1");
        subject.setLoginTime(now);
        subject.setLoginExpireTime(now + 50_000); // 剩余 50s > 60s*0.2=12s

        FakeSessionRepository sessionRepository = new FakeSessionRepository();
        sessionRepository.putSubject(subject);
        AuthProvider authProvider = new SimpleAuthProvider(sessionRepository);
        DefaultAuthenticationManager authenticationManager = new DefaultAuthenticationManager(authProvider, sessionRepository, 60);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("token", "cred-1");
        SecurityContext result = authenticationManager.authenticate(request);

        assertEquals("user-1", result.getLoginSubject().getLoginId());
        assertFalse(sessionRepository.wasRefreshed());
        assertEquals(now + 50_000, result.getLoginSubject().getLoginExpireTime());
    }

    /**
     * 滑动续期阈值边界（1.3.3 修正为 20%）：剩余 TTL 恰好等于 timeout*0.2 时应触发续期（<= 语义）。
     */
    @Test
    void shouldRefreshWhenRemainingTtlEqualsThreshold() {
        long now = System.currentTimeMillis();
        LoginSubject subject = new LoginSubject();
        subject.setLoginId("user-1");
        subject.setCredentials("cred-1");
        subject.setLoginTime(now);
        subject.setLoginExpireTime(now + 12_000); // 剩余 12s == 60s*0.2

        FakeSessionRepository sessionRepository = new FakeSessionRepository();
        sessionRepository.putSubject(subject);
        AuthProvider authProvider = new SimpleAuthProvider(sessionRepository);
        DefaultAuthenticationManager authenticationManager = new DefaultAuthenticationManager(authProvider, sessionRepository, 60);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("token", "cred-1");
        SecurityContext result = authenticationManager.authenticate(request);

        assertTrue(sessionRepository.wasRefreshed());
        assertTrue(result.getLoginSubject().getLoginExpireTime() > now + 50_000);
    }

    /**
     * 已过期的会话必须被直接拒绝，绝不能被续期复活。
     *
     * <p>修复前这里不会抛 401：因为「剩余 TTL ≤ 阈值」对已过期会话恒成立（剩余为负数），
     * 于是走续期分支把过期时间改写成 now + timeout，一个早已失效的会话就这么被无限复活了。
     * 四个内置仓储自己过滤了过期，但 README 明确鼓励用户自定义仓储 —— 核心判定不该外包。
     */
    @Test
    void shouldRejectExpiredSubjectInsteadOfRefreshingIt() {
        long now = System.currentTimeMillis();
        LoginSubject subject = new LoginSubject();
        subject.setLoginId("user-1");
        subject.setCredentials("cred-1");
        subject.setLoginTime(now - 120_000);
        subject.setLoginExpireTime(now - 60_000); // 已过期 60s

        FakeSessionRepository sessionRepository = new FakeSessionRepository();
        sessionRepository.putSubject(subject);
        AuthProvider authProvider = new SimpleAuthProvider(sessionRepository);
        DefaultAuthenticationManager authenticationManager = new DefaultAuthenticationManager(authProvider, sessionRepository, 60);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("token", "cred-1");

        assertThrows(UnAuthorizedException.class, () -> authenticationManager.authenticate(request));
        assertFalse(sessionRepository.wasRefreshed(), "过期会话不能被续期");
        assertEquals(now - 60_000, subject.getLoginExpireTime(), "过期时间不应被改写");
    }

    /**
     * 内核的绝对过期校验必须**独立于仓储**生效。
     *
     * <p><b>本用例的前置条件在 TCK 落地后发生了变化，这里说明清楚</b>：本用例原本用**内置**
     * {@code SingleSessionRepository} 构造"存储层有效、但 loginExpireTime 已过期"的会话，
     * 断言"仓储会把它原样返回（因此内核必须自己判）"。但 TCK 落地时发现 single / redis 两个
     * 仓储**只按存储层 TTL 判有效性、不看 loginExpireTime**（同一缺陷藏在两个实现里），
     * 已一并修复 —— 所以现在仓储自己就会返回 {@code null}，原前置条件不再成立。
     *
     * <p>这恰好说明内核这道校验的价值：它守的是 **SPI 边界**，而不是某个具体实现的当前行为。
     * 因此用例改写为用**一个不做过期过滤的仓储**（模拟用户自定义实现）来验证内核仍然拦得住 ——
     * 若内核校验被移除，本用例立刻变红。
     */
    @Test
    void shouldRejectExpiredSubjectWhenRepositoryDoesNotFilterIt() {
        long now = System.currentTimeMillis();
        LoginSubject stale = new LoginSubject();
        stale.setLoginId(10001L);
        stale.setCredentials("stale-cred");
        stale.setLoginTime(now - 3600_000L);
        stale.setLoginExpireTime(now - 60_000L); // 已过期 60 秒

        // 模拟"不做过期过滤"的自定义仓储：getSubject 原样返回、checkByCredentials 恒 true
        FakeSessionRepository sessionRepository = new FakeSessionRepository();
        sessionRepository.putSubject(stale);
        AuthProvider authProvider = new SimpleAuthProvider(sessionRepository);
        DefaultAuthenticationManager authenticationManager = new DefaultAuthenticationManager(
                authProvider, sessionRepository, 1800);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("token", "stale-cred");

        // 内核必须在续期分支之前拦下它，否则会被改写成 now + timeout 而复活
        assertThrows(UnAuthorizedException.class, () -> authenticationManager.authenticate(request));
        assertFalse(sessionRepository.wasRefreshed(), "过期会话不得触发续期");
        assertEquals(now - 60_000L, stale.getLoginExpireTime(), "过期时间不应被改写");
    }

    /**
     * 内置仓储在 TCK 落地后也会自行过滤过期会话（与其它仓储口径一致）。
     *
     * <p>这是 TCK 的产物：single 与 redis 原先把"存储层 TTL"当作唯一有效性依据，
     * 与 caffeine / jdbc 不一致。本用例把这个一致性固定下来。
     */
    @Test
    void builtInRepositoryShouldAlsoFilterExpiredSubject() {
        long now = System.currentTimeMillis();
        SingleSessionRepository sessionRepository = new SingleSessionRepository();
        try {
            LoginSubject stale = new LoginSubject();
            stale.setLoginId(10001L);
            stale.setCredentials("stale-cred");
            stale.setLoginTime(now - 3600_000L);
            stale.setLoginExpireTime(now - 60_000L); // 已过期 60 秒
            // 存储层 TTL 给 60 秒，与上面已过期的 loginExpireTime 刻意不一致
            assertTrue(sessionRepository.save(stale, 60, 0));

            assertNull(sessionRepository.getSubject("stale-cred"),
                    "内置仓储也必须按 loginExpireTime 过滤过期会话，不能只看存储层 TTL");
            assertFalse(sessionRepository.checkByCredentials("stale-cred"));
            assertEquals(0, sessionRepository.countValidOnlineSessions(10001L));
        } finally {
            sessionRepository.destroy();
        }
    }

    static class SimpleAuthProvider extends AuthProvider {
        SimpleAuthProvider(SessionRepository sessionRepository) {
            super(sessionRepository, defaultProperties(), null);
        }

        @Override
        public String getCredentials(HttpServletRequest request) {
            return request.getHeader("token");
        }
    }

    private static AuthProperties defaultProperties() {
        AuthProperties properties = new AuthProperties();
        properties.setBanner(false);
        properties.setTokenName("token");
        properties.setTokenSecret("test-secret");
        return properties;
    }

    static class FakeSessionRepository implements SessionRepository {
        private final ConcurrentHashMap<String, LoginSubject> subjects = new ConcurrentHashMap<>();
        private boolean refreshed;

        void putSubject(LoginSubject subject) {
            subjects.put(subject.getCredentials(), subject);
        }

        boolean wasRefreshed() {
            return refreshed;
        }

        @Override
        public boolean save(LoginSubject subject, int timeoutSeconds, int maxConcurrentLogins) {
            subjects.put(subject.getCredentials(), subject);
            return true;
        }

        @Override
        public boolean checkByCredentials(String credentials) {
            return subjects.containsKey(credentials);
        }

        @Override
        public LoginSubject getSubject(String credentials) {
            return subjects.get(credentials);
        }

        @Override
        public boolean refreshByCredentials(String credentials, LoginSubject subject, int timeoutSeconds) {
            this.refreshed = true;
            subjects.put(credentials, subject);
            return true;
        }

        @Override
        public boolean deleteByCredentials(String credentials) {
            return subjects.remove(credentials) != null;
        }

        @Override
        public boolean deleteByLoginId(Object loginId) {
            return false;
        }

        @Override
        public int countValidOnlineSessions(Object loginId) {
            return 0;
        }
    }
}
