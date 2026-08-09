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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
        properties.setCredentialsStyle("uuid");
        properties.setMaxConcurrentLogins(0);
        properties.setJwtSecret("test-secret");
        properties.setJwtSubject("test-subject");
        return properties;
    }

    static class CapturingSecurityEventPublisher implements SecurityEventPublisher {
        private final AtomicInteger loginSuccessCount = new AtomicInteger(0);
        private final AtomicInteger loginFailureCount = new AtomicInteger(0);

        @Override
        public void publishLoginSuccess(LoginSuccessEvent event) {
            loginSuccessCount.incrementAndGet();
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
