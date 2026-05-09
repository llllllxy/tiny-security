package org.tinycloud.security.interceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.method.HandlerMethod;
import org.tinycloud.security.authentication.DefaultAuthenticationManager;
import org.tinycloud.security.config.GlobalConfig;
import org.tinycloud.security.config.GlobalConfigUtils;
import org.tinycloud.security.context.SecurityContext;
import org.tinycloud.security.context.SecurityContextRepository;
import org.tinycloud.security.context.ThreadLocalSecurityContextRepository;
import org.tinycloud.security.context.ThreadLocalSecurityContextHolder;
import org.tinycloud.security.exception.UnAuthorizedException;
import org.tinycloud.security.provider.AuthProvider;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.session.SessionRepository;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthenticationInterceptorTest {

    @AfterEach
    void tearDown() {
        ThreadLocalSecurityContextHolder.clearContext();
        GlobalConfigUtils.clearGlobalConfig();
    }

    @Test
    void shouldAuthenticateSuccessfullyWhenCredentialsExist() throws Exception {
        LoginSubject subject = new LoginSubject();
        subject.setLoginId("user-1");
        subject.setCredentials("cred-1");
        subject.setLoginTime(System.currentTimeMillis());
        subject.setLoginExpireTime(System.currentTimeMillis() + 60_000);

        FakeSessionRepository sessionRepository = new FakeSessionRepository();
        sessionRepository.putSubject(subject);
        initGlobalConfig(sessionRepository);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        request.addHeader("token", "cred-1");

        boolean allowed = new AuthenticationInterceptor().preHandle(
                request,
                new MockHttpServletResponse(),
                handlerMethod("secured")
        );

        assertTrue(allowed);
        assertEquals("user-1", ThreadLocalSecurityContextHolder.getContext().getLoginSubject().getLoginId());
    }

    @Test
    void shouldThrowUnauthorizedWhenCredentialsMissing() throws Exception {
        initGlobalConfig(new FakeSessionRepository());

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");

        assertThrows(UnAuthorizedException.class, () -> new AuthenticationInterceptor().preHandle(
                request,
                new MockHttpServletResponse(),
                handlerMethod("secured")
        ));
    }

    @Test
    void shouldCallClearContextInAfterCompletion() throws Exception {
        LoginSubject subject = new LoginSubject();
        subject.setLoginId("user-1");
        subject.setCredentials("cred-1");
        subject.setLoginTime(System.currentTimeMillis());
        subject.setLoginExpireTime(System.currentTimeMillis() + 60_000);

        FakeSessionRepository sessionRepository = new FakeSessionRepository();
        sessionRepository.putSubject(subject);
        CountingSecurityContextRepository repository = new CountingSecurityContextRepository();
        initGlobalConfig(sessionRepository, repository);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        request.addHeader("token", "cred-1");
        MockHttpServletResponse response = new MockHttpServletResponse();

        AuthenticationInterceptor interceptor = new AuthenticationInterceptor();
        interceptor.preHandle(request, response, handlerMethod("secured"));
        interceptor.afterCompletion(request, response, handlerMethod("secured"), null);

        assertEquals(1, repository.clearCount.get());
    }

    private void initGlobalConfig(SessionRepository sessionRepository) {
        initGlobalConfig(sessionRepository, new ThreadLocalSecurityContextRepository());
    }

    private void initGlobalConfig(SessionRepository sessionRepository, SecurityContextRepository securityContextRepository) {
        GlobalConfig globalConfig = new GlobalConfig();
        globalConfig.setBanner(false);
        globalConfig.setTimeout(1800);
        AuthProvider authProvider = new SimpleAuthProvider(sessionRepository);
        globalConfig.setAuthProvider(authProvider);
        globalConfig.setSessionRepository(sessionRepository);
        globalConfig.setSecurityContextRepository(securityContextRepository);
        globalConfig.setAuthenticationManager(new DefaultAuthenticationManager(authProvider, sessionRepository, 1800));
        GlobalConfigUtils.setGlobalConfig(globalConfig);
    }

    private HandlerMethod handlerMethod(String methodName) throws NoSuchMethodException {
        Method method = TestController.class.getMethod(methodName);
        return new HandlerMethod(new TestController(), method);
    }

    static class TestController {
        public void secured() {
        }
    }

    static class SimpleAuthProvider extends AuthProvider {
        SimpleAuthProvider(SessionRepository sessionRepository) {
            super(sessionRepository);
        }

        @Override
        public String getCredentials(HttpServletRequest request) {
            return request.getHeader("token");
        }
    }

    static class FakeSessionRepository implements SessionRepository {
        private final Map<String, LoginSubject> subjects = new ConcurrentHashMap<>();

        void putSubject(LoginSubject subject) {
            subjects.put(subject.getCredentials(), subject);
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

    static class CountingSecurityContextRepository implements SecurityContextRepository {
        private final AtomicInteger clearCount = new AtomicInteger(0);

        @Override
        public SecurityContext loadContext(HttpServletRequest request) {
            return ThreadLocalSecurityContextHolder.getContext();
        }

        @Override
        public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
            ThreadLocalSecurityContextHolder.setContext(context);
        }

        @Override
        public void clearContext(HttpServletRequest request, HttpServletResponse response) {
            clearCount.incrementAndGet();
            ThreadLocalSecurityContextHolder.clearContext();
        }
    }
}
