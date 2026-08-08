package org.tinycloud.security.util;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.tinycloud.security.TinySecurityFacade;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.context.SecurityContext;
import org.tinycloud.security.context.SecurityContextRepository;
import org.tinycloud.security.context.ThreadLocalSecurityContextHolder;

import static org.junit.jupiter.api.Assertions.*;

class AuthUtilTest {

    @AfterEach
    void tearDown() {
        ThreadLocalSecurityContextHolder.clearContext();
        AuthUtil.setFacade(null);
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void shouldPreferSecurityContextRepositoryWhenCustomRepositoryIsConfigured() {
        SecurityContext holderContext = createContext("holder-user");
        ThreadLocalSecurityContextHolder.setContext(holderContext);

        SecurityContext repositoryContext = createContext("repo-user");
        AuthUtil.setFacade(new TinySecurityFacade(new FixedSecurityContextRepository(repositoryContext)));

        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        SecurityContext actual = AuthUtil.getSecurityContext();
        assertSame(repositoryContext, actual);
        assertEquals("repo-user", actual.getLoginSubject().getLoginId());
    }

    @Test
    void shouldReturnNullWhenNoRequestContext() {
        SecurityContext holderContext = createContext("holder-user");
        ThreadLocalSecurityContextHolder.setContext(holderContext);

        AuthUtil.setFacade(new TinySecurityFacade(new FixedSecurityContextRepository(holderContext)));

        SecurityContext actual = AuthUtil.getSecurityContext();
        assertNull(actual);
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
