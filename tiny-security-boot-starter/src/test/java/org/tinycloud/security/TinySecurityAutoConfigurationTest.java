package org.tinycloud.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.tinycloud.security.config.AuthProperties;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.context.SecurityContext;
import org.tinycloud.security.context.SecurityContextRepository;
import org.tinycloud.security.context.ThreadLocalSecurityContextRepository;
import org.tinycloud.security.exception.UnAuthorizedException;
import org.tinycloud.security.interfaces.AuthorizationInfoGet;
import org.tinycloud.security.provider.AuthProvider;
import org.tinycloud.security.session.SessionRepository;
import org.tinycloud.security.util.AuthUtil;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Spring Boot 自动装配集成测试。
 *
 * <p>验证 GlobalConfig 改造后，AuthAutoConfiguration 能正确装配所有 Bean，
 * 且 AuthUtil 静态外观已注册 Facade，端到端流程正常。
 *
 * @author liuxingyu01
 * @since 2026-08-08
 */
@SpringBootTest(classes = TinySecurityAutoConfigurationTest.TestApp.class,
        properties = "tiny-security.store-type=test")
class TinySecurityAutoConfigurationTest {

    @Configuration
    @Import(AuthAutoConfiguration.class)
    static class TestApp {
        @Bean
        SessionRepository sessionRepository() {
            return new InMemorySessionRepository();
        }

        /**
         * P0-1 需要容器里存在 AuthorizationInfoGet，Facade 才能按需懒加载角色/权限。
         */
        @Bean
        AuthorizationInfoGet authorizationInfoGet() {
            return new AuthorizationInfoGet() {
                @Override
                public Set<String> getPermissionSet(LoginSubject subject) {
                    return Set.of("user:read");
                }

                @Override
                public Set<String> getRoleSet(LoginSubject subject) {
                    return Set.of("admin");
                }
            };
        }
    }

    @Autowired
    private AuthProvider authProvider;

    @Autowired
    private TinySecurityFacade facade;

    @Autowired
    private AuthProperties properties;

    @Autowired
    private SessionRepository sessionRepository;

    @Autowired
    private SecurityContextRepository securityContextRepository;

    @org.junit.jupiter.api.BeforeEach
    void setUp() {
        // 每个测试前重新注册 facade（@AfterEach 会清掉）
        AuthUtil.setFacade(facade);
    }

    @AfterEach
    void tearDown() {
        AuthUtil.setFacade(null);
        RequestContextHolder.resetRequestAttributes();
        // ThreadLocalSecurityContextRepository 用的是静态 ThreadLocal，不清理会跨用例泄漏上下文，
        // 导致 shouldThrowWhenNoSession 之类依赖"无会话"的用例受执行顺序影响
        ThreadLocalSecurityContextRepository.clearContext();
        ((InMemorySessionRepository) sessionRepository).clear();
    }

    /**
     * 所有核心 Bean 都应被正确装配
     */
    @Test
    void shouldWireAllCoreBeans() {
        assertNotNull(authProvider);
        assertNotNull(facade);
        assertNotNull(properties);
        assertNotNull(sessionRepository);
        assertNotNull(securityContextRepository);
    }

    /**
     * AuthProperties 默认值应正确
     */
    @Test
    void shouldHaveDefaultProperties() {
        assertEquals("token", properties.getTokenName());
        assertEquals(1800, properties.getTimeout());
        assertEquals(0, properties.getMaxConcurrentLogins());
    }

    /**
     * AuthUtil 静态外观应已注册 Facade
     */
    @Test
    void shouldRegisterFacadeWithAuthUtil() {
        // AuthUtil.getFacade() 不抛异常即说明 Facade 已注册
        assertNotNull(AuthUtil.getFacade());
        assertSame(facade, AuthUtil.getFacade());
    }

    /**
     * 端到端：login → 存会话 → AuthUtil 能读到 loginId
     */
    @Test
    void shouldCompleteLoginAndReadLoginIdViaAuthUtil() {
        bindRequest();

        String token = authProvider.login("integration-user");
        assertNotNull(token);
        assertTrue(token.startsWith("Bearer "));

        // 将 SecurityContext 存入上下文（模拟拦截器行为）
        String credentials = authProvider.getCredentialsByToken(token);
        LoginSubject subject = sessionRepository.getSubject(credentials);
        assertNotNull(subject);

        SecurityContext context = new SecurityContext();
        context.setLoginSubject(subject);
        securityContextRepository.saveContext(context, currentRequest(), currentResponse());

        // AuthUtil 通过 Facade 读到 loginId
        assertEquals("integration-user", AuthUtil.getLoginId());
        assertEquals("integration-user", AuthUtil.getLoginIdAsString());
    }

    /**
     * 端到端：登出后会话失效
     */
    @Test
    void shouldLogoutAndInvalidateSession() {
        bindRequest();

        String token = authProvider.login("logout-user");
        String credentials = authProvider.getCredentialsByToken(token);
        assertTrue(sessionRepository.checkByCredentials(credentials));

        // 将 token 放入请求头，logout() 才能从请求中取到
        MockHttpServletRequest req = (MockHttpServletRequest) currentRequest();
        req.addHeader("token", token);

        authProvider.logout();

        assertFalse(sessionRepository.checkByCredentials(credentials));
    }

    /**
     * P0-1 端到端（自动装配层）：容器里的 AuthorizationInfoGet 必须被注入到 Facade，
     * 这样在接口上没有权限注解、上下文里也没加载过角色/权限时，AuthUtil.hasRole/hasPermission 依然正确。
     * 修复前这里会返回 false —— 因为它读到的是永不被填充的空集。
     */
    @Test
    void shouldLazilyLoadRoleAndPermissionThroughAutoConfiguredFacade() {
        bindRequest();

        String token = authProvider.login("authz-user");
        String credentials = authProvider.getCredentialsByToken(token);
        LoginSubject subject = sessionRepository.getSubject(credentials);
        assertNotNull(subject);

        // 只放 loginSubject，不手工塞角色/权限集合——与无权限注解接口上的真实状态一致
        SecurityContext context = new SecurityContext();
        context.setLoginSubject(subject);
        securityContextRepository.saveContext(context, currentRequest(), currentResponse());

        assertTrue(AuthUtil.hasRole("admin"));
        assertTrue(AuthUtil.hasPermission("user:read"));
        assertFalse(AuthUtil.hasRole("guest"));
        assertFalse(AuthUtil.hasPermission("user:delete"));
    }

    /**
     * 1.4.0 行为统一：无会话时 AuthUtil（委托 Facade）统一抛 UnAuthorizedException（不再返回 null）
     */
    @Test
    void shouldThrowWhenNoSession() {
        bindRequest();
        assertThrows(UnAuthorizedException.class, AuthUtil::getLoginId);
        assertThrows(UnAuthorizedException.class, AuthUtil::getSecurityContext);
    }

    private void bindRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
    }

    private HttpServletRequest currentRequest() {
        return ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
    }

    private HttpServletResponse currentResponse() {
        return ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getResponse();
    }

    // ===== 内存版 SessionRepository =====
    static class InMemorySessionRepository implements SessionRepository {
        private final Map<String, LoginSubject> store = new ConcurrentHashMap<>();

        @Override
        public boolean save(LoginSubject subject, int timeoutSeconds, int maxConcurrentLogins) {
            store.put(subject.getCredentials(), subject);
            return true;
        }

        @Override
        public boolean checkByCredentials(String credentials) {
            return store.containsKey(credentials);
        }

        @Override
        public LoginSubject getSubject(String credentials) {
            return store.get(credentials);
        }

        @Override
        public boolean refreshByCredentials(String credentials, LoginSubject subject, int timeoutSeconds) {
            store.put(credentials, subject);
            return true;
        }

        @Override
        public boolean deleteByCredentials(String credentials) {
            return store.remove(credentials) != null;
        }

        @Override
        public boolean deleteByLoginId(Object loginId) {
            store.entrySet().removeIf(e -> e.getValue().getLoginId().equals(loginId));
            return true;
        }

        @Override
        public int countValidOnlineSessions(Object loginId) {
            return (int) store.values().stream()
                    .filter(s -> s.getLoginId().equals(loginId))
                    .count();
        }

        void clear() {
            store.clear();
        }
    }
}
