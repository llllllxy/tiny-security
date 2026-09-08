package org.tinycloud.security.util;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.tinycloud.security.TinySecurityFacade;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.context.SecurityContext;
import org.tinycloud.security.context.SecurityContextRepository;
import org.tinycloud.security.context.ThreadLocalSecurityContextRepository;

import static org.junit.jupiter.api.Assertions.*;

class AuthUtilTest {

    @AfterEach
    void tearDown() {
        ThreadLocalSecurityContextRepository.clearContext();
        AuthUtil.setFacade(null);
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void shouldPreferSecurityContextRepositoryWhenCustomRepositoryIsConfigured() {
        SecurityContext holderContext = createContext("holder-user");
        ThreadLocalSecurityContextRepository.setContext(holderContext);

        SecurityContext repositoryContext = createContext("repo-user");
        AuthUtil.setFacade(new TinySecurityFacade(new FixedSecurityContextRepository(repositoryContext)));

        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        SecurityContext actual = AuthUtil.getSecurityContext();
        assertSame(repositoryContext, actual);
        assertEquals("repo-user", actual.getLoginSubject().getLoginId());
    }

    @Test
    void shouldThrowWhenNoRequestContext() {
        SecurityContext holderContext = createContext("holder-user");
        ThreadLocalSecurityContextRepository.setContext(holderContext);

        AuthUtil.setFacade(new TinySecurityFacade(new FixedSecurityContextRepository(holderContext)));

        // 1.3.4 行为统一：无请求上下文时 AuthUtil（委托 Facade）统一抛 UnAuthorizedException
        org.junit.jupiter.api.Assertions.assertThrows(
                org.tinycloud.security.exception.UnAuthorizedException.class,
                AuthUtil::getSecurityContext);
    }

    private SecurityContext createContext(String loginId) {
        LoginSubject subject = new LoginSubject();
        subject.setLoginId(loginId);
        SecurityContext context = new SecurityContext();
        context.setLoginSubject(subject);
        return context;
    }

    static class FixedSecurityContextRepository implements SecurityContextRepository {
        private final SecurityContext context;

        FixedSecurityContextRepository(SecurityContext context) {
            this.context = context;
        }

        @Override
        public SecurityContext loadContext(HttpServletRequest request) {
            return context;
        }

        @Override
        public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        }

        @Override
        public void clearContext(HttpServletRequest request, HttpServletResponse response) {
        }
    }
}
