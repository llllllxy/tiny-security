package org.tinycloud.security.util;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.context.request.RequestContextHolder;
import org.tinycloud.security.AuthTestSupport;
import org.tinycloud.security.config.AuthProperties;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.context.SecurityContext;
import org.tinycloud.security.context.SecurityContextRepository;
import org.tinycloud.security.context.ThreadLocalSecurityContextRepository;
import org.tinycloud.security.exception.UnAuthorizedException;
import org.tinycloud.security.interfaces.AuthorizationInfoGet;
import org.tinycloud.security.provider.AuthProvider;
import org.tinycloud.security.session.SessionRepository;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * AuthUtil 静态外观测试。
 *
 * <p>1.5.0 起 AuthUtil 不再持有任何可变静态全局变量，而是每次调用都从「当前请求的
 * WebApplicationContext」解析 {@link AuthProvider}，因此这里的用例都要预先把门面装进容器
 * （见 {@link AuthTestSupport}）。
 *
 * @author liuxingyu01
 * @since 2026-08-08
 */
class AuthUtilTest {

    @AfterEach
    void tearDown() {
        ThreadLocalSecurityContextRepository.clearContext();
        RequestContextHolder.resetRequestAttributes();
    }

    /**
     * 用的是容器里那个 AuthProvider 的 SecurityContextRepository，而不是别处的上下文。
     */
    @Test
    void shouldUseSecurityContextRepositoryOfResolvedAuthProvider() {
        SecurityContext holderContext = createContext("holder-user");
        ThreadLocalSecurityContextRepository.setContext(holderContext);

        SecurityContext repositoryContext = createContext("repo-user");
        AuthTestSupport.bindRequestWithAuthProvider(
                authProvider(new FixedSecurityContextRepository(repositoryContext), null));

        SecurityContext actual = AuthUtil.getSecurityContext();
        assertSame(repositoryContext, actual);
        assertEquals("repo-user", actual.getLoginSubject().getLoginId());
    }

    /**
     * P1-1 回归：AuthUtil 跟随「当前请求所属容器」里注册的 AuthProvider，不存在任何可能失同步的
     * 静态全局变量。修复前 AuthUtil 由一个静态 facade 变量驱动，只要那个赋值点没被执行
     * （例如用户自定义了门面 Bean），AuthUtil 就会整体瘫痪。
     */
    @Test
    void shouldFollowCurrentRequestContainerInsteadOfAnyStaticState() {
        AuthProvider first = authProvider(new FixedSecurityContextRepository(createContext("first-user")), null);
        AuthProvider second = authProvider(new FixedSecurityContextRepository(createContext("second-user")), null);

        AuthTestSupport.bindRequestWithAuthProvider(first);
        assertEquals("first-user", AuthUtil.getLoginId());

        // 换一个容器/请求，AuthUtil 必须立刻跟着换，不能残留上一次的实例
        AuthTestSupport.bindRequestWithAuthProvider(second);
        assertEquals("second-user", AuthUtil.getLoginId());
    }

    /**
     * 无请求上下文（非 Web 线程）时统一抛 UnAuthorizedException。
     */
    @Test
    void shouldThrowUnauthorizedWhenNoRequestContext() {
        ThreadLocalSecurityContextRepository.setContext(createContext("holder-user"));

        assertThrows(UnAuthorizedException.class, AuthUtil::getSecurityContext);
        assertThrows(UnAuthorizedException.class, AuthUtil::getLoginId);
        assertThrows(UnAuthorizedException.class, () -> AuthUtil.hasRole("admin"));
    }

    /**
     * 有请求但取不到 Spring 容器时，属于配置错误，抛 IllegalStateException 并给出可定位的信息。
     */
    @Test
    void shouldThrowIllegalStateWhenRequestHasNoWebApplicationContext() {
        AuthTestSupport.bindRequestWithoutApplicationContext();

        IllegalStateException exception = assertThrows(IllegalStateException.class, AuthUtil::getLoginId);
        assertTrue(exception.getMessage().contains("No WebApplicationContext"));
    }

    /**
     * 有容器但没有 AuthProvider Bean 时，同样属于配置错误。
     */
    @Test
    void shouldThrowIllegalStateWhenNoAuthProviderBean() {
        AuthTestSupport.bindRequestWithoutAuthProviderBean();

        IllegalStateException exception = assertThrows(IllegalStateException.class, AuthUtil::getLoginId);
        assertTrue(exception.getMessage().contains("No AuthProvider bean"));
    }

    /**
     * 容器里有多个 AuthProvider 候选 Bean 时，报错必须指向「不唯一」而不是「不存在」。
     *
     * <p>{@code NoUniqueBeanDefinitionException} 是 {@code NoSuchBeanDefinitionException} 的子类，
     * 若只捕获后者，就会把「有两个」误报成「一个都没有」，把排查方向带反。
     */
    @Test
    void shouldReportMultipleCandidatesInsteadOfMissingBean() {
        AuthTestSupport.bindRequestWithAuthProvider(
                authProvider(new FixedSecurityContextRepository(createContext("first-user")), null),
                authProvider(new FixedSecurityContextRepository(createContext("second-user")), null));

        IllegalStateException exception = assertThrows(IllegalStateException.class, AuthUtil::getLoginId);
        assertTrue(exception.getMessage().contains("Multiple AuthProvider beans"));
        assertFalse(exception.getMessage().contains("No AuthProvider bean"));
    }

    /**
     * AuthUtil 的 get* 系列应当直接转发到解析出来的 AuthProvider。
     */
    @Test
    void shouldDelegateGetLoginIdToResolvedAuthProvider() {
        AuthTestSupport.bindRequestWithAuthProvider(
                authProvider(new FixedSecurityContextRepository(createContext("user-1")), null));

        assertEquals("user-1", AuthUtil.getLoginId());
        assertEquals("user-1", AuthUtil.getLoginIdAsString());
        assertEquals("user-1", AuthUtil.getLoginSubject().getLoginId());
    }

    /**
     * P0-1 的实际用户路径：接口上没有权限注解时上下文里的角色/权限是「未加载」状态，
     * AuthUtil.hasRole/hasPermission 必须经由 AuthProvider 按需懒加载，而不是恒返回 false。
     */
    @Test
    void shouldLazilyLoadRoleAndPermissionThroughAuthUtil() {
        // 只放 loginSubject、不塞角色/权限集合 —— 这正是无权限注解接口上的真实状态
        SecurityContext context = createContext("lazy-user");
        AuthTestSupport.bindRequestWithAuthProvider(authProvider(
                new FixedSecurityContextRepository(context),
                stubAuthorizationInfo(Set.of("admin"), Set.of("user:read"))));

        assertTrue(AuthUtil.hasRole("admin"));
        assertFalse(AuthUtil.hasRole("guest"));
        assertTrue(AuthUtil.hasAnyRole("admin", "guest"));
        assertTrue(AuthUtil.hasAllRole("admin"));
        assertTrue(AuthUtil.hasPermission("user:read"));
        assertFalse(AuthUtil.hasPermission("user:delete"));
        assertTrue(AuthUtil.getRoleSet().contains("admin"));
        assertTrue(AuthUtil.getPermissionSet().contains("user:read"));
    }

    private AuthProvider authProvider(SecurityContextRepository repository, AuthorizationInfoGet authorizationInfoGet) {
        AuthProperties properties = new AuthProperties();
        properties.setBanner(false);
        properties.setTokenName("token");
        properties.setTokenSecret("test-secret");
        return new AuthProvider(new NoopSessionRepository(), properties, null, repository, authorizationInfoGet);
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

    /**
     * 只用于构造 AuthProvider —— AuthUtil 的用例都不涉及会话仓储。
     */
    static class NoopSessionRepository implements SessionRepository {
        @Override
        public boolean save(LoginSubject subject, int timeoutSeconds, int maxConcurrentLogins) {
            return false;
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
            return false;
        }

        @Override
        public boolean deleteByCredentials(String credentials) {
            return false;
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
