package org.tinycloud.security.provider;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.tinycloud.security.TinySecurityFacade;
import org.tinycloud.security.config.AuthProperties;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.context.SecurityContext;
import org.tinycloud.security.context.ThreadLocalSecurityContextRepository;
import org.tinycloud.security.context.ThreadLocalSecurityContextRepository;
import org.tinycloud.security.exception.UnAuthorizedException;
import org.tinycloud.security.session.SessionRepository;
import org.tinycloud.security.util.AuthUtil;

import static org.junit.jupiter.api.Assertions.*;

/**
 * AuthProvider 安全上下文获取测试。
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
class AuthProviderSecurityContextTest {

    @AfterEach
    void tearDown() {
        ThreadLocalSecurityContextRepository.clearContext();
        AuthUtil.setFacade(null);
        RequestContextHolder.resetRequestAttributes();
    }

    /**
     * 已有上下文时应直接复用，不再从仓储重新查询。
     */
    @Test
    void shouldReturnExistingSecurityContextWhenContextAlreadyExists() {
        SecurityContext existingContext = buildContext("existing-user");
        ThreadLocalSecurityContextRepository.setContext(existingContext);
        bindRequestAndRepository();

        AuthProvider authProvider = new AuthProvider(new ThrowingSessionRepository(), defaultProperties(), null);
        SecurityContext actual = authProvider.getSecurityContext();

        assertSame(existingContext, actual);
        assertEquals("existing-user", actual.getLoginSubject().getLoginId());
    }

    /**
     * 无上下文且仓储查不到主体时应抛未认证异常。
     */
    @Test
    void shouldThrowUnauthorizedWhenContextMissingAndSubjectNotFound() {
        bindRequestAndRepository();
        AuthProvider authProvider = new AuthProvider(new FixedSessionRepository(null), defaultProperties(), null);
        assertThrows(UnAuthorizedException.class, authProvider::getSecurityContext);
    }

    private void bindRequestAndRepository() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        AuthUtil.setFacade(new TinySecurityFacade(new ThreadLocalSecurityContextRepository()));
    }

    private AuthProperties defaultProperties() {
        AuthProperties properties = new AuthProperties();
        properties.setBanner(false);
        properties.setTokenName("token");
        properties.setJwtSecret("test-secret");
        properties.setJwtSubject("test-subject");
        return properties;
    }

    private SecurityContext buildContext(String loginId) {
        LoginSubject subject = new LoginSubject();
        subject.setLoginId(loginId);
        SecurityContext context = new SecurityContext();
        context.setLoginSubject(subject);
        return context;
    }

    static class FixedSessionRepository implements SessionRepository {
        private final LoginSubject subject;

        FixedSessionRepository(LoginSubject subject) {
            this.subject = subject;
        }

        @Override
        public boolean save(LoginSubject subject, int timeoutSeconds, int maxConcurrentLogins) {
            return true;
        }

        @Override
        public boolean checkByCredentials(String credentials) {
            return subject != null && subject.getCredentials().equals(credentials);
        }

        @Override
        public LoginSubject getSubject(String credentials) {
            if (subject == null) {
                return null;
            }
            return subject;
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

    static class ThrowingSessionRepository implements SessionRepository {
        @Override
        public boolean save(LoginSubject subject, int timeoutSeconds, int maxConcurrentLogins) {
            return true;
        }

        @Override
        public boolean checkByCredentials(String credentials) {
            return false;
        }

        @Override
        public LoginSubject getSubject(String credentials) {
            throw new AssertionError("should not query sessionRepository when context already exists");
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
