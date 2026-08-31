package org.tinycloud.security.interceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.method.HandlerMethod;
import org.tinycloud.security.authentication.AuthenticationManager;
import org.tinycloud.security.authentication.DefaultAuthenticationManager;
import org.tinycloud.security.config.AuthProperties;
import org.tinycloud.security.context.*;
import org.tinycloud.security.exception.UnAuthorizedException;
import org.tinycloud.security.provider.AuthProvider;
import org.tinycloud.security.session.SessionRepository;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class AuthenticationInterceptorTest {

    @AfterEach
    void tearDown() {
        ThreadLocalSecurityContextHolder.clearContext();
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

        AuthenticationInterceptor interceptor = buildInterceptor(sessionRepository, new ThreadLocalSecurityContextRepository());

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        request.addHeader("token", "Bearer cred-1");

        boolean allowed = interceptor.preHandle(
                request,
                new MockHttpServletResponse(),
                handlerMethod("secured")
        );

        assertTrue(allowed);
        assertEquals("user-1", ThreadLocalSecurityContextHolder.getContext().getLoginSubject().getLoginId());
    }

    @Test
    void shouldThrowUnauthorizedWhenCredentialsMissing() throws Exception {
        AuthenticationInterceptor interceptor = buildInterceptor(new FakeSessionRepository(), new ThreadLocalSecurityContextRepository());

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");

        assertThrows(UnAuthorizedException.class, () -> interceptor.preHandle(
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

        AuthenticationInterceptor interceptor = buildInterceptor(sessionRepository, repository);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        request.addHeader("token", "Bearer cred-1");
        MockHttpServletResponse response = new MockHttpServletResponse();

        interceptor.preHandle(request, response, handlerMethod("secured"));
        interceptor.afterCompletion(request, response, handlerMethod("secured"), null);

        // clearContext 在 preHandle 入口防御性清理一次 + afterCompletion 收尾清理一次，共 2 次
        assertEquals(2, repository.clearCount.get());
    }

    /**
     * 1.3.3 防御性清理：preHandle 入口应先清除上一次请求遗留的 ThreadLocal 上下文
     * （Servlet 异步/异常场景 afterCompletion 可能未执行，线程回池后残留旧身份），
     * 再写入本次认证结果，避免"用户串号"。
     */
    @Test
    void shouldClearStaleContextAtPreHandleEntry() throws Exception {
        // 模拟上一个请求遗留的残留上下文（线程池复用场景）
        LoginSubject staleSubject = new LoginSubject();
        staleSubject.setLoginId("stale-user");
        staleSubject.setCredentials("stale-cred");
        SecurityContext staleContext = new SecurityContext();
        staleContext.setLoginSubject(staleSubject);
        ThreadLocalSecurityContextHolder.setContext(staleContext);

        LoginSubject subject = new LoginSubject();
        subject.setLoginId("user-1");
        subject.setCredentials("cred-1");
        subject.setLoginTime(System.currentTimeMillis());
        subject.setLoginExpireTime(System.currentTimeMillis() + 60_000);

        FakeSessionRepository sessionRepository = new FakeSessionRepository();
        sessionRepository.putSubject(subject);

        AuthenticationInterceptor interceptor = buildInterceptor(sessionRepository, new ThreadLocalSecurityContextRepository());

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        request.addHeader("token", "Bearer cred-1");

        boolean allowed = interceptor.preHandle(
                request,
                new MockHttpServletResponse(),
                handlerMethod("secured")
        );

        assertTrue(allowed);
        // 残留上下文被清除，当前线程读到的是本次认证的新用户
        assertNotNull(ThreadLocalSecurityContextHolder.getContext());
        assertEquals("user-1", ThreadLocalSecurityContextHolder.getContext().getLoginSubject().getLoginId());
    }

    private AuthenticationInterceptor buildInterceptor(SessionRepository sessionRepository, SecurityContextRepository securityContextRepository) {
        AuthProperties properties = new AuthProperties();
        properties.setTokenName("token");
        properties.setTimeout(1800);
        properties.setJwtSecret("test-secret");
        properties.setJwtSubject("test-subject");
        AuthProvider authProvider = new SimpleAuthProvider(sessionRepository, properties);
        AuthenticationManager am = new DefaultAuthenticationManager(authProvider, sessionRepository, 1800);
        return new AuthenticationInterceptor(am, securityContextRepository);
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
        SimpleAuthProvider(SessionRepository sessionRepository, AuthProperties properties) {
            super(sessionRepository, properties, null);
        }

        @Override
        public String getCredentials(HttpServletRequest request) {
            String token = request.getHeader("token");
            if (token != null && token.startsWith("Bearer ")) {
                return token.substring(7);
            }
            return token;
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
