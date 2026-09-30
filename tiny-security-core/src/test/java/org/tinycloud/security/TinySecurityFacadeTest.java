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
import org.tinycloud.security.interfaces.AuthorizationInfoGet;
import org.tinycloud.security.util.AuthUtil;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

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
    void shouldThrowWhenNoRequestContext() {
        // 1.3.4 行为统一：无请求上下文时 get* 系列统一抛 UnAuthorizedException（不再返回 null）
        assertThrows(org.tinycloud.security.exception.UnAuthorizedException.class, facade::getSecurityContext);
        assertThrows(org.tinycloud.security.exception.UnAuthorizedException.class, facade::getLoginSubject);
        assertThrows(org.tinycloud.security.exception.UnAuthorizedException.class, facade::getLoginId);
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
    void shouldThrowWhenContextIsNull() {
        bindRequest();
        repository.setContext(null);

        // 1.3.4 行为统一：会话为空时所有 get* / 数字转换系列统一抛 UnAuthorizedException
        assertThrows(org.tinycloud.security.exception.UnAuthorizedException.class, facade::getLoginId);
        assertThrows(org.tinycloud.security.exception.UnAuthorizedException.class, facade::getLoginIdAsString);
        assertThrows(org.tinycloud.security.exception.UnAuthorizedException.class, facade::getLoginIdAsInt);
        assertThrows(org.tinycloud.security.exception.UnAuthorizedException.class, facade::getLoginIdAsLong);
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
    void shouldThrowWhenContextIsNullForRoleAndPermission() {
        bindRequest();
        repository.setContext(null);

        // 1.3.4 行为统一：会话为空时 getRoleSet/getPermissionSet 及 has* 系列统一抛 UnAuthorizedException
        assertThrows(org.tinycloud.security.exception.UnAuthorizedException.class, facade::getRoleSet);
        assertThrows(org.tinycloud.security.exception.UnAuthorizedException.class, facade::getPermissionSet);
        assertThrows(org.tinycloud.security.exception.UnAuthorizedException.class, () -> facade.hasRole("admin"));
        assertThrows(org.tinycloud.security.exception.UnAuthorizedException.class, () -> facade.hasPermission("user:read"));
    }

    /**
     * P0-1 回归：接口上没有权限注解时，授权管理器不会为注解调用 SPI，上下文里的角色集合
     * 处于「未加载」状态。此时 hasRole 必须按需从数据源加载，而不是恒返回 false。
     * 修复前本用例会失败。
     */
    @Test
    void shouldLazilyLoadRoleSetWhenNotLoadedYet() {
        bindRequest();
        repository.setContext(createContextWithoutAuthorization("user-1"));
        TinySecurityFacade lazyFacade = new TinySecurityFacade(repository,
                stubAuthorizationInfo(Set.of("admin"), Set.of("user:read")));

        assertTrue(lazyFacade.hasRole("admin"));
        assertFalse(lazyFacade.hasRole("guest"));
        assertTrue(lazyFacade.hasAnyRole("admin", "guest"));
        assertTrue(lazyFacade.hasAllRole("admin"));
        assertTrue(lazyFacade.getRoleSet().contains("admin"));
    }

    /**
     * P0-1 回归：权限集合同理，未加载时按需从数据源加载。
     */
    @Test
    void shouldLazilyLoadPermissionSetWhenNotLoadedYet() {
        bindRequest();
        repository.setContext(createContextWithoutAuthorization("user-1"));
        TinySecurityFacade lazyFacade = new TinySecurityFacade(repository,
                stubAuthorizationInfo(Set.of("admin"), Set.of("user:read", "user:write")));

        assertTrue(lazyFacade.hasPermission("user:read"));
        assertTrue(lazyFacade.hasPermission("user:write"));
        assertFalse(lazyFacade.hasPermission("user:delete"));
        assertTrue(lazyFacade.getPermissionSet().contains("user:write"));
    }

    /**
     * 懒加载每次请求只查一次：结果缓存回本次请求的上下文，后续 has* 调用不再触发 SPI 查询。
     */
    @Test
    void shouldQueryAuthorizationInfoOnlyOncePerRequest() {
        bindRequest();
        repository.setContext(createContextWithoutAuthorization("user-1"));
        AtomicInteger roleQueryCount = new AtomicInteger();
        AtomicInteger permissionQueryCount = new AtomicInteger();
        TinySecurityFacade lazyFacade = new TinySecurityFacade(repository,
                new CountingAuthorizationInfoGet(roleQueryCount, permissionQueryCount));

        lazyFacade.hasRole("admin");
        lazyFacade.hasAnyRole("admin", "guest");
        lazyFacade.hasAllRole("admin");
        lazyFacade.hasPermission("user:read");
        lazyFacade.hasAnyPermission("user:read", "user:delete");
        lazyFacade.getRoleSet();
        lazyFacade.getPermissionSet();

        assertEquals(1, roleQueryCount.get());
        assertEquals(1, permissionQueryCount.get());
    }

    /**
     * 已加载过的集合不再回查数据源（授权管理器为注解查过的，门面直接复用）。
     */
    @Test
    void shouldNotReloadWhenAlreadyLoaded() {
        bindRequest();
        repository.setContext(createContext("user-1", Set.of("admin"), Set.of("user:read")));
        AtomicInteger roleQueryCount = new AtomicInteger();
        AtomicInteger permissionQueryCount = new AtomicInteger();
        TinySecurityFacade lazyFacade = new TinySecurityFacade(repository,
                new CountingAuthorizationInfoGet(roleQueryCount, permissionQueryCount));

        assertTrue(lazyFacade.hasRole("admin"));
        assertTrue(lazyFacade.hasPermission("user:read"));

        assertEquals(0, roleQueryCount.get());
        assertEquals(0, permissionQueryCount.get());
    }

    /**
     * 未提供 AuthorizationInfoGet 时（1 参构造），行为与旧版一致：只返回上下文中已有的数据，不抛异常。
     */
    @Test
    void shouldReturnEmptyWhenNoAuthorizationInfoGetProvided() {
        bindRequest();
        repository.setContext(createContextWithoutAuthorization("user-1"));
        TinySecurityFacade noSpiFacade = new TinySecurityFacade(repository);

        assertFalse(noSpiFacade.hasRole("admin"));
        assertFalse(noSpiFacade.hasPermission("user:read"));
        assertTrue(noSpiFacade.getRoleSet().isEmpty());
        assertTrue(noSpiFacade.getPermissionSet().isEmpty());
    }

    /**
     * 用户侧表现：AuthUtil 静态外观同样走懒加载（P0-1 的实际调用路径）。
     */
    @Test
    void shouldLazilyLoadThroughAuthUtil() {
        bindRequest();
        repository.setContext(createContextWithoutAuthorization("user-1"));
        AuthUtil.setFacade(new TinySecurityFacade(repository,
                stubAuthorizationInfo(Set.of("admin"), Set.of("user:read"))));

        assertTrue(AuthUtil.hasRole("admin"));
        assertTrue(AuthUtil.hasPermission("user:read"));
    }

    /**
     * 构造「已登录、但角色/权限集合尚未加载」的上下文——这正是无权限注解接口上的真实状态（P0-1 场景）。
     */
    private SecurityContext createContextWithoutAuthorization(Object loginId) {
        LoginSubject subject = new LoginSubject();
        subject.setLoginId(loginId);
        SecurityContext context = new SecurityContext();
        context.setLoginSubject(subject);
        return context;
    }

    private AuthorizationInfoGet stubAuthorizationInfo(Set<String> roles, Set<String> permissions) {
        return new AuthorizationInfoGet() {
            @Override
            public Set<String> getPermissionSet(LoginSubject subject) {
                return permissions;
            }

            @Override
            public Set<String> getRoleSet(LoginSubject subject) {
                return roles;
            }
        };
    }

    static class CountingAuthorizationInfoGet implements AuthorizationInfoGet {
        private final AtomicInteger roleQueryCount;
        private final AtomicInteger permissionQueryCount;

        CountingAuthorizationInfoGet(AtomicInteger roleQueryCount, AtomicInteger permissionQueryCount) {
            this.roleQueryCount = roleQueryCount;
            this.permissionQueryCount = permissionQueryCount;
        }

        @Override
        public Set<String> getPermissionSet(LoginSubject subject) {
            this.permissionQueryCount.incrementAndGet();
            return Set.of("user:read", "user:write");
        }

        @Override
        public Set<String> getRoleSet(LoginSubject subject) {
            this.roleQueryCount.incrementAndGet();
            return Set.of("admin", "user");
        }
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
