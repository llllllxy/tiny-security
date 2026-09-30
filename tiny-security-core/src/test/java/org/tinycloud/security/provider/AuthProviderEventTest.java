package org.tinycloud.security.provider;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.tinycloud.security.config.AuthProperties;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.event.AuthorizationFailureEvent;
import org.tinycloud.security.event.LoginFailureEvent;
import org.tinycloud.security.event.LoginSuccessEvent;
import org.tinycloud.security.event.SecurityEventPublisher;
import org.tinycloud.security.exception.TinySecurityException;
import org.tinycloud.security.session.SessionRepository;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class AuthProviderEventTest {

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void shouldPublishLoginSuccessEvent() {
        CapturingSecurityEventPublisher publisher = new CapturingSecurityEventPublisher();
        AuthProvider authProvider = new AuthProvider(new FakeSessionRepository(false), defaultProperties(), publisher);
        bindRequestContext();

        authProvider.login("user-1", null);

        assertEquals(1, publisher.loginSuccessCount.get());
        assertEquals(0, publisher.loginFailureCount.get());
    }

    @Test
    void shouldPublishLoginFailureEvent() {
        CapturingSecurityEventPublisher publisher = new CapturingSecurityEventPublisher();
        AuthProvider authProvider = new AuthProvider(new FakeSessionRepository(true), defaultProperties(), publisher);
        bindRequestContext();

        assertThrows(TinySecurityException.class, () -> authProvider.login("user-1", null));

        assertEquals(0, publisher.loginSuccessCount.get());
        assertEquals(1, publisher.loginFailureCount.get());
    }

    /**
     * 1.3.3：成功事件监听器抛异常时，会话已创建成功，login() 必须仍返回 token、
     * 且不得误发 LoginFailureEvent（仅内部记录 WARN）。
     */
    @Test
    void shouldReturnTokenWhenSuccessListenerThrows() {
        CapturingSecurityEventPublisher publisher = new CapturingSecurityEventPublisher();
        publisher.throwOnSuccess = true;
        AuthProvider authProvider = new AuthProvider(new FakeSessionRepository(false), defaultProperties(), publisher);
        bindRequestContext();

        String token = authProvider.login("user-1", null);

        assertNotNull(token);
        assertTrue(token.startsWith("Bearer "));
        assertEquals(1, publisher.loginSuccessCount.get());
        assertEquals(0, publisher.loginFailureCount.get());
    }

    /**
     * 凭证格式回归：credentials 固定为「UUID 去横线」（32 位小写十六进制，内部走 SecureRandom），
     * 不再有 credentials-style 配置项可切换——避免用户选到弱随机源。
     *
     * <p>同时锁定 token 形态：{@code Bearer <credentials>.<base64url(HMAC-SHA256)>}。
     */
    @Test
    void shouldAlwaysUseUuidCredentialsWithoutDashes() {
        AuthProvider authProvider = new AuthProvider(new FakeSessionRepository(false), defaultProperties(), new CapturingSecurityEventPublisher());
        bindRequestContext();

        String token = authProvider.login("user-1", null);

        assertNotNull(token);
        assertTrue(token.startsWith("Bearer "), token);
        String signedToken = token.substring("Bearer ".length());
        int separatorIndex = signedToken.lastIndexOf('.');
        assertTrue(separatorIndex > 0, "token 应形如 credentials.signature，实际为: " + token);

        String credentials = signedToken.substring(0, separatorIndex);
        assertTrue(credentials.matches("[0-9a-f]{32}"), "credentials 应为 32 位小写十六进制 UUID，实际为: " + credentials);
    }

    private void bindRequestContext() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
    }

    private AuthProperties defaultProperties() {
        AuthProperties properties = new AuthProperties();
        properties.setBanner(false);
        properties.setTokenName("token");
        properties.setTimeout(1800);
        properties.setMaxConcurrentLogins(0);
        properties.setTokenSecret("test-secret");
        return properties;
    }

    static class CapturingSecurityEventPublisher implements SecurityEventPublisher {
        private final AtomicInteger loginSuccessCount = new AtomicInteger(0);
        private final AtomicInteger loginFailureCount = new AtomicInteger(0);
        private volatile boolean throwOnSuccess;

        @Override
        public void publishLoginSuccess(LoginSuccessEvent event) {
            loginSuccessCount.incrementAndGet();
            if (throwOnSuccess) {
                throw new RuntimeException("listener failure");
            }
        }

        @Override
        public void publishLoginFailure(LoginFailureEvent event) {
            loginFailureCount.incrementAndGet();
        }

        @Override
        public void publishAuthorizationFailure(AuthorizationFailureEvent event) {
        }
    }

    static class FakeSessionRepository implements SessionRepository {
        private final boolean throwOnSave;

        FakeSessionRepository(boolean throwOnSave) {
            this.throwOnSave = throwOnSave;
        }

        @Override
        public boolean save(LoginSubject subject, int timeoutSeconds, int maxConcurrentLogins) {
            if (throwOnSave) {
                throw new TinySecurityException("create auth failed");
            }
            return true;
        }

        @Override
        public boolean checkByCredentials(String credentials) {
            return false;
        }

        @Override
        public LoginSubject getSubject(String credentials) {
            return null;
        }

        @Override
        public boolean refreshByCredentials(String credentials, LoginSubject subject, int timeoutSeconds) {
            return true;
        }

        @Override
        public boolean deleteByCredentials(String credentials) {
            return true;
        }

        @Override
        public boolean deleteByLoginId(Object loginId) {
            return true;
        }

        @Override
        public int countValidOnlineSessions(Object loginId) {
            return 0;
        }
    }
}
