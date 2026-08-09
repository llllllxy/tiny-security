package org.tinycloud.security.util;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.tinycloud.security.config.GlobalConfig;
import org.tinycloud.security.config.GlobalConfigUtils;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.context.SecurityContext;
import org.tinycloud.security.context.SecurityContextRepository;
import org.tinycloud.security.context.ThreadLocalSecurityContextHolder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.junit.jupiter.api.Assertions.*;

class AuthUtilTest {

    @AfterEach
    void tearDown() {
        ThreadLocalSecurityContextHolder.clearContext();
        GlobalConfigUtils.clearGlobalConfig();
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void shouldPreferSecurityContextRepositoryWhenCustomRepositoryIsConfigured() {
        SecurityContext holderContext = createContext("holder-user");
        ThreadLocalSecurityContextHolder.setContext(holderContext);

        SecurityContext repositoryContext = createContext("repo-user");
        GlobalConfig globalConfig = new GlobalConfig();
        globalConfig.setBanner(false);
        globalConfig.setSecurityContextRepository(new FixedSecurityContextRepository(repositoryContext));
        GlobalConfigUtils.setGlobalConfig(globalConfig);

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
