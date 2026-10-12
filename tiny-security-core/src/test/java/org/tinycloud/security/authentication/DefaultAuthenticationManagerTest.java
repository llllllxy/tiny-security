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
     * 已过期的会话必须被直接拒绝，绝不能被续期复活（P1-6）。
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
     * 使用**内置** single 仓储时，内核的绝对过期校验同样必须生效（P1-6）。
     *
     * <p>本用例回答一个合理的质疑："仓储既然已经过滤了过期，内核再判一次还有意义吗？"
     * 答案是肯定的，原因有两点：
     * <ol>
     *   <li>{@code SessionRepository.getSubject} 的契约只承诺"返回登录主体"，**从未承诺**过期时返回 null
     *       （对比同一接口的 {@code getCredentialsByLoginId}，那里明确写了"有效（未过期）"）；
     *       内核消费的是 SPI，不能依赖一条没有写下来的义务；</li>
     *   <li>即便用内置仓储，「存储层的 TTL」与「{@code subject.loginExpireTime}」也是**两个互相独立的量**：
     *       {@code save(subject, timeoutSeconds, max)} 的这两个参数由调用方分别给出，single 仓储并不校验二者一致。
     *       本用例就构造了这种"存储层仍有效、loginExpireTime 已过期"的会话。</li>
     * </ol>
     *
     * <p>没有这道校验时，实测结果是：过期会话被**放行并被续期复活**（改写成 now + timeout），
     * 而续期分支的条件"剩余 ≤ 阈值"对已过期会话恒成立，所以它永远不会自己纠正回来。
     */
    @Test
    void shouldRejectStoreValidButExpiredSubjectOnBuiltInSingleRepository() {
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

            // 前置条件：仓储确实把这条"已过期"的会话原样返回了（这正是不能依赖仓储过滤的原因）
            assertNotNull(sessionRepository.getSubject("stale-cred"));
            assertTrue(sessionRepository.checkByCredentials("stale-cred"));

            DefaultAuthenticationManager authenticationManager = new DefaultAuthenticationManager(
                    new SimpleAuthProvider(sessionRepository), sessionRepository, 1800);
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("token", "stale-cred");

            assertThrows(UnAuthorizedException.class, () -> authenticationManager.authenticate(request));
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
