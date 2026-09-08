package org.tinycloud.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.tinycloud.security.config.AuthProperties;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.context.SecurityContext;
import org.tinycloud.security.context.ThreadLocalSecurityContextRepository;
import org.tinycloud.security.context.ThreadLocalSecurityContextRepository;
import org.tinycloud.security.event.AuthorizationFailureEvent;
import org.tinycloud.security.event.LoginFailureEvent;
import org.tinycloud.security.event.LoginSuccessEvent;
import org.tinycloud.security.event.SecurityEventPublisher;
import org.tinycloud.security.exception.UnAuthorizedException;
import org.tinycloud.security.provider.AuthProvider;
import org.tinycloud.security.session.SessionRepository;
import org.tinycloud.security.util.AuthUtil;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 端到端流程测试：验证 GlobalConfig 改造后完整链路是否跑通。
 *
 * <p>测试链路：AuthProvider.login() → SessionRepository 存储 →
 *           SecurityContextRepository 加载 → AuthUtil.getLoginId() / hasRole()
 *
 * @author liuxingyu01
 * @since 2026-08-08
 */
class EndToEndFlowTest {

    private AuthProvider authProvider;
    private InMemorySessionRepository sessionRepository;
    private ThreadLocalSecurityContextRepository securityContextRepository;

    @BeforeEach
    void setUp() {
        sessionRepository = new InMemorySessionRepository();
        securityContextRepository = new ThreadLocalSecurityContextRepository();

        AuthProperties properties = new AuthProperties();
        properties.setBanner(false);
        properties.setTokenName("token");
        properties.setTimeout(1800);
        properties.setCredentialsStyle("uuid");
        properties.setMaxConcurrentLogins(0);
        properties.setJwtSecret("test-secret-key-for-e2e");
        properties.setJwtSubject("tiny-security-test");

        authProvider = new AuthProvider(sessionRepository, properties, new NoopEventPublisher());

        // 注册 Facade，让 AuthUtil 能工作
        AuthUtil.setFacade(new TinySecurityFacade(securityContextRepository));

        // 绑定请求上下文（模拟 HTTP 请求环境）
        bindRequest();
    }

    @AfterEach
    void tearDown() {
        ThreadLocalSecurityContextRepository.clearContext();
        AuthUtil.setFacade(null);
        RequestContextHolder.resetRequestAttributes();
        sessionRepository.clear();
    }

    /**
     * 完整登录流程：login → 存储会话 → AuthUtil 能读到 loginId
     */
    @Test
    void shouldCompleteFullLoginFlowAndAuthUtilCanReadLoginId() {
        // 1. 登录
        String token = authProvider.login("user-001");
        assertNotNull(token);
        assertTrue(token.startsWith("Bearer "));

        // 2. 会话已存储
        assertTrue(sessionRepository.size() > 0);

        // 3. 模拟拦截器将 SecurityContext 存入上下文
        String credentials = authProvider.getCredentialsByToken(token);
        LoginSubject subject = sessionRepository.getSubject(credentials);
        assertNotNull(subject);
        SecurityContext context = new SecurityContext();
        context.setLoginSubject(subject);
        securityContextRepository.saveContext(context, currentRequest(), currentResponse());

        // 4. AuthUtil 能读到 loginId（验证静态外观 → Facade 链路）
        assertEquals("user-001", AuthUtil.getLoginId());
        assertEquals("user-001", AuthUtil.getLoginIdAsString());

        // 5. AuthUtil 能读到 LoginSubject
        LoginSubject utilSubject = AuthUtil.getLoginSubject();
        assertNotNull(utilSubject);
        assertEquals("user-001", utilSubject.getLoginId());
    }

    /**
     * 登录带扩展信息 → 扩展信息可通过 LoginSubject 获取
     */
    @Test
    void shouldPreserveExtraInfoThroughFullFlow() {
        Map<String, Object> extraInfo = new java.util.HashMap<>();
        extraInfo.put("role", "admin");
        extraInfo.put("dept", "tech");

        String token = authProvider.login("user-002", extraInfo);
        assertNotNull(token);

        String credentials = authProvider.getCredentialsByToken(token);
        LoginSubject subject = sessionRepository.getSubject(credentials);
        assertNotNull(subject);
        assertNotNull(subject.getExtraInfo());
        assertEquals("admin", subject.getExtraInfo().get("role"));
        assertEquals("tech", subject.getExtraInfo().get("dept"));
    }

    /**
     * 注销流程：logout → 会话删除 → AuthUtil 读不到
     */
    @Test
    void shouldLogoutAndClearSession() {
        String token = authProvider.login("user-003");
        String credentials = authProvider.getCredentialsByToken(token);
        assertTrue(sessionRepository.checkByCredentials(credentials));

        // 将 token 放入请求头，模拟前端传递，logout() 才能从请求中取到 token
        MockHttpServletRequest req = (MockHttpServletRequest) currentRequest();
        req.addHeader("token", token);

        authProvider.logout();

        assertFalse(sessionRepository.checkByCredentials(credentials));
    }

    /**
     * 按 loginId 批量注销
     */
    @Test
    void shouldDeleteAllSessionsByLoginId() {
        String token1 = authProvider.login("user-004");
        String token2 = authProvider.login("user-004");

        assertEquals(2, sessionRepository.countValidOnlineSessions("user-004"));

        authProvider.deleteByLoginId("user-004");

        assertEquals(0, sessionRepository.countValidOnlineSessions("user-004"));
    }

    /**
     * 权限校验流程：设置角色/权限 → AuthUtil.hasRole/hasPermission 返回正确结果
     */
    @Test
    void shouldCheckRoleAndPermissionViaAuthUtil() {
        String token = authProvider.login("user-005");
        String credentials = authProvider.getCredentialsByToken(token);
        LoginSubject subject = sessionRepository.getSubject(credentials);

        SecurityContext context = new SecurityContext();
        context.setLoginSubject(subject);
        Set<String> roles = new HashSet<>();
        roles.add("admin");
        Set<String> permissions = new HashSet<>();
        permissions.add("user:read");
        permissions.add("user:write");
        context.setRoleSet(roles);
        context.setPermissionSet(permissions);
        securityContextRepository.saveContext(context, currentRequest(), currentResponse());

        assertTrue(AuthUtil.hasRole("admin"));
        assertFalse(AuthUtil.hasRole("guest"));
        assertTrue(AuthUtil.hasAnyRole("admin", "guest"));
        assertTrue(AuthUtil.hasAllRole("admin"));

        assertTrue(AuthUtil.hasPermission("user:read"));
        assertTrue(AuthUtil.hasPermission("user:write"));
        assertFalse(AuthUtil.hasPermission("user:delete"));
        assertTrue(AuthUtil.hasAnyPermission("user:read", "user:delete"));
        assertTrue(AuthUtil.hasAllPermission("user:read", "user:write"));
    }

    /**
     * 1.3.4 行为统一：无会话时 AuthUtil（委托 Facade）统一抛 UnAuthorizedException（不再返回 null）
     */
    @Test
    void shouldThrowWhenNoSession() {
        assertThrows(UnAuthorizedException.class, AuthUtil::getLoginId);
        assertThrows(UnAuthorizedException.class, AuthUtil::getLoginSubject);
        assertThrows(UnAuthorizedException.class, AuthUtil::getSecurityContext);
    }

    /**
     * isLogin 判断
     */
    @Test
    void shouldReturnFalseForIsLoginWhenNoValidCredentials() {
        assertFalse(authProvider.isLogin());
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

        int size() {
            return store.size();
        }

        void clear() {
            store.clear();
        }
    }

    static class NoopEventPublisher implements SecurityEventPublisher {
        @Override
        public void publishLoginSuccess(LoginSuccessEvent event) {}
        @Override
        public void publishLoginFailure(LoginFailureEvent event) {}
        @Override
        public void publishAuthorizationFailure(AuthorizationFailureEvent event) {}
    }
}
