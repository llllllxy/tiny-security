package org.tinycloud.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.context.SecurityContext;
import org.tinycloud.security.context.SecurityContextRepository;
import org.tinycloud.security.util.AuthUtil;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * TinySecurityFacade 单元测试。
 *
 * @author liuxingyu01
 * @since 2026-08-08
 */
class TinySecurityFacadeTest {

    private TinySecurityFacade facade;
    private StubSecurityContextRepository repository;

    @BeforeEach
    void setUp() {
        repository = new StubSecurityContextRepository();
        facade = new TinySecurityFacade(repository);
        AuthUtil.setFacade(facade);
    }

    @AfterEach
    void tearDown() {
        AuthUtil.setFacade(null);
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void shouldReturnNullWhenNoRequestContext() {
        assertNull(facade.getSecurityContext());
        assertNull(facade.getLoginSubject());
        assertNull(facade.getLoginId());
    }

    @Test
    void shouldReturnSecurityContextFromRepository() {
        bindRequest();
        SecurityContext context = createContext("user-1", Set.of("admin"), Set.of("user:read"));
        repository.setContext(context);

        SecurityContext actual = facade.getSecurityContext();
        assertSame(context, actual);
    }

    @Test
    void shouldReturnLoginIdFromContext() {
        bindRequest();
        repository.setContext(createContext("user-1", Collections.emptySet(), Collections.emptySet()));

        assertEquals("user-1", facade.getLoginId());
        assertEquals("user-1", facade.getLoginIdAsString());
    }

    @Test
    void shouldReturnNullLoginIdWhenNoContext() {
        bindRequest();
        repository.setContext(null);

        assertNull(facade.getLoginId());
        assertNull(facade.getLoginIdAsString());
        assertNull(facade.getLoginIdAsInt());
        assertNull(facade.getLoginIdAsLong());
    }

    @Test
    void shouldReturnNumericLoginId() {
        bindRequest();
        repository.setContext(createContext(12345L, Collections.emptySet(), Collections.emptySet()));

        assertEquals(12345L, facade.getLoginId());
        assertEquals("12345", facade.getLoginIdAsString());
        assertEquals(12345, facade.getLoginIdAsInt());
        assertEquals(12345L, facade.getLoginIdAsLong());
    }

    /**
     * 1.3.3 语义统一：loginId 为非数字字符串时，getLoginIdAsInt/Long 抛 TinySecurityException
     * （而非 NumberFormatException 导致 500），getLoginIdAsString 保持宽松返回原值。
     */
    @Test
    void shouldThrowTinySecurityExceptionWhenLoginIdIsNotNumeric() {
        bindRequest();
        repository.setContext(createContext("not-a-number", Collections.emptySet(), Collections.emptySet()));

        assertEquals("not-a-number", facade.getLoginIdAsString());
        assertThrows(org.tinycloud.security.exception.TinySecurityException.class, facade::getLoginIdAsInt);
        assertThrows(org.tinycloud.security.exception.TinySecurityException.class, facade::getLoginIdAsLong);
    }

    @Test
    void shouldCheckRoleCorrectly() {
        bindRequest();
        repository.setContext(createContext("user-1", Set.of("admin", "user"), Collections.emptySet()));

        assertTrue(facade.hasRole("admin"));
        assertTrue(facade.hasRole("user"));
        assertFalse(facade.hasRole("guest"));
        assertTrue(facade.hasAnyRole("admin", "guest"));
        assertFalse(facade.hasAnyRole("guest", "root"));
        assertTrue(facade.hasAllRole("admin", "user"));
        assertFalse(facade.hasAllRole("admin", "guest"));
    }

    @Test
    void shouldCheckPermissionCorrectly() {
        bindRequest();
        repository.setContext(createContext("user-1", Collections.emptySet(), Set.of("user:read", "user:write")));

        assertTrue(facade.hasPermission("user:read"));
        assertTrue(facade.hasPermission("user:write"));
        assertFalse(facade.hasPermission("user:delete"));
        assertTrue(facade.hasAnyPermission("user:read", "user:delete"));
        assertFalse(facade.hasAnyPermission("user:delete", "user:export"));
        assertTrue(facade.hasAllPermission("user:read", "user:write"));
        assertFalse(facade.hasAllPermission("user:read", "user:delete"));
    }

    @Test
    void shouldDelegateThroughAuthUtil() {
        bindRequest();
        repository.setContext(createContext("user-1", Set.of("admin"), Set.of("user:read")));

        // AuthUtil 应该 delegate 到 facade
        assertEquals("user-1", AuthUtil.getLoginId());
        assertTrue(AuthUtil.hasRole("admin"));
        assertTrue(AuthUtil.hasPermission("user:read"));
    }

    @Test
    void shouldReturnEmptySetsWhenContextIsNull() {
        bindRequest();
        repository.setContext(null);

        assertNull(facade.getRoleSet());
        assertNull(facade.getPermissionSet());
    }

    private void bindRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    private SecurityContext createContext(Object loginId, Set<String> roles, Set<String> permissions) {
        LoginSubject subject = new LoginSubject();
        subject.setLoginId(loginId);
        SecurityContext context = new SecurityContext();
        context.setLoginSubject(subject);
        context.setRoleSet(new HashSet<>(roles));
        context.setPermissionSet(new HashSet<>(permissions));
        return context;
    }

    static class StubSecurityContextRepository implements SecurityContextRepository {
        private SecurityContext context;

        void setContext(SecurityContext context) {
            this.context = context;
        }

        @Override
        public SecurityContext loadContext(HttpServletRequest request) {
            return context;
        }

        @Override
        public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
            this.context = context;
        }

        @Override
        public void clearContext(HttpServletRequest request, HttpServletResponse response) {
            this.context = null;
        }
    }
}
