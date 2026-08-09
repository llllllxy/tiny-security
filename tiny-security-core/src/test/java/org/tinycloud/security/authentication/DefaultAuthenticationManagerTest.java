package org.tinycloud.security.authentication;

import javax.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.tinycloud.security.config.AuthProperties;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.context.SecurityContext;
import org.tinycloud.security.exception.UnAuthorizedException;
import org.tinycloud.security.provider.AuthProvider;
import org.tinycloud.security.session.SessionRepository;

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
        properties.setJwtSecret("test-secret");
        properties.setJwtSubject("test-subject");
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
