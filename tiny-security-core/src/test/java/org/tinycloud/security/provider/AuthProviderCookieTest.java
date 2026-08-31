package org.tinycloud.security.provider;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.tinycloud.security.config.AuthProperties;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.enums.CookieSameSite;
import org.tinycloud.security.exception.UnAuthorizedException;
import org.tinycloud.security.session.SessionRepository;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthProviderCookieTest {

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }

    /**
     * 模拟定时任务/MQ 消费者线程：未绑定任何请求上下文时调用 login，
     * 不应因写 Cookie 而抛 NPE，token 应正常返回。
     */
    @Test
    void shouldLoginWithoutNpeOnNonWebRequestThread() {
        RequestContextHolder.resetRequestAttributes();
        AuthProvider authProvider = new AuthProvider(new FakeSessionRepository(), defaultProperties(), null);

        String token = authProvider.login("user-1", null);

        assertNotNull(token);
        assertTrue(token.startsWith("Bearer "));
    }

    /**
     * enable-cookie 默认关闭（纯 token 模式）：即使存在请求上下文，登录也不写 Cookie。
     */
    @Test
    void shouldNotWriteCookieWhenCookieDisabled() {
        AuthProvider authProvider = new AuthProvider(new FakeSessionRepository(), defaultProperties(), null);
        MockHttpServletResponse response = bindRequestContext();

        authProvider.login("user-1", null);

        assertNull(response.getCookie("token"));
    }

    /**
     * enable-cookie 关闭时，token 不再从 Cookie 中读取（仅 header 与 URL 参数）。
     */
    @Test
    void shouldNotReadTokenFromCookieWhenCookieDisabled() {
        AuthProvider authProvider = new AuthProvider(new FakeSessionRepository(), defaultProperties(), null);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("token", "Bearer some-jwt"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));

        assertThrows(UnAuthorizedException.class, authProvider::getToken);
    }

    /**
     * enable-cookie 开启时，token 仍可从 Cookie 中读取（前后端不分离模式）。
     */
    @Test
    void shouldReadTokenFromCookieWhenCookieEnabled() {
        AuthProperties properties = defaultProperties();
        properties.setEnableCookie(true);
        AuthProvider authProvider = new AuthProvider(new FakeSessionRepository(), properties, null);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("token", "Bearer some-jwt"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));

        assertEquals("some-jwt", authProvider.getToken());
    }

    /**
     * Cookie 生存期应与会话 timeout 保持一致（而非硬编码86400秒），
     * 且默认带上 HttpOnly 与 SameSite=Lax 属性。
     */
    @Test
    void shouldWriteCookieWithSessionTimeoutAndSecurityAttributes() {
        AuthProperties properties = defaultProperties();
        properties.setEnableCookie(true);
        AuthProvider authProvider = new AuthProvider(new FakeSessionRepository(), properties, null);
        MockHttpServletResponse response = bindRequestContext();

        authProvider.login("user-1", null);

        Cookie cookie = response.getCookie("token");
        assertNotNull(cookie);
        assertEquals(1800, cookie.getMaxAge());
        assertTrue(cookie.isHttpOnly());
        assertFalse(cookie.getSecure());
        assertEquals("Lax", cookie.getAttribute("SameSite"));
    }

    @Test
    void shouldHonorCookieSecureAndSameSiteConfig() {
        AuthProperties properties = defaultProperties();
        properties.setEnableCookie(true);
        properties.setCookieSecure(true);
        properties.setCookieSameSite(CookieSameSite.NONE);
        AuthProvider authProvider = new AuthProvider(new FakeSessionRepository(), properties, null);
        MockHttpServletResponse response = bindRequestContext();

        authProvider.login("user-1", null);

        Cookie cookie = response.getCookie("token");
        assertNotNull(cookie);
        assertTrue(cookie.getSecure());
        assertEquals("None", cookie.getAttribute("SameSite"));
    }

    /**
     * 登出时应向浏览器写回 maxAge=0 的同名 Cookie，使浏览器侧凭证立即失效。
     */
    @Test
    void shouldClearCookieOnLogout() {
        AuthProperties properties = defaultProperties();
        properties.setEnableCookie(true);
        AuthProvider authProvider = new AuthProvider(new FakeSessionRepository(), properties, null);
        MockHttpServletResponse response = bindRequestContext();

        String token = authProvider.login("user-1", null);

        // 模拟新的登出请求：重新绑定携带 token 的请求上下文
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("token", token);
        MockHttpServletResponse logoutResponse = new MockHttpServletResponse();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, logoutResponse));

        authProvider.logout();

        Cookie cookie = logoutResponse.getCookie("token");
        assertNotNull(cookie);
        assertEquals(0, cookie.getMaxAge());
    }

    /**
     * enable-cookie 关闭时，登出不写任何清理 Cookie。
     */
    @Test
    void shouldNotClearCookieOnLogoutWhenCookieDisabled() {
        AuthProvider authProvider = new AuthProvider(new FakeSessionRepository(), defaultProperties(), null);
        MockHttpServletResponse response = bindRequestContext();

        String token = authProvider.login("user-1", null);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("token", token);
        MockHttpServletResponse logoutResponse = new MockHttpServletResponse();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, logoutResponse));

        authProvider.logout();

        assertNull(logoutResponse.getCookie("token"));
    }

    /**
     * 1.3.3：enable-url-token 默认关闭——URL 参数中的 token 不被读取（避免进入访问日志/Referer 泄露），
     * header 无 token 时直接 401。
     */
    @Test
    void shouldNotReadTokenFromUrlParameterWhenUrlTokenDisabled() {
        AuthProvider authProvider = new AuthProvider(new FakeSessionRepository(), defaultProperties(), null);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("token", "Bearer some-jwt");
        MockHttpServletResponse response = new MockHttpServletResponse();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));

        assertThrows(UnAuthorizedException.class, authProvider::getToken);
    }

    /**
     * 1.3.3：开启 enable-url-token 后，URL 参数中的 token 可被读取（兼容历史行为）。
     */
    @Test
    void shouldReadTokenFromUrlParameterWhenUrlTokenEnabled() {
        AuthProperties properties = defaultProperties();
        properties.setEnableUrlToken(true);
        AuthProvider authProvider = new AuthProvider(new FakeSessionRepository(), properties, null);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("token", "Bearer some-jwt");
        MockHttpServletResponse response = new MockHttpServletResponse();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));

        assertEquals("some-jwt", authProvider.getToken());
    }

    private MockHttpServletResponse bindRequestContext() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
        return response;
    }

    private AuthProperties defaultProperties() {
        AuthProperties properties = new AuthProperties();
        properties.setBanner(false);
        properties.setTokenName("token");
        properties.setTimeout(1800);
        properties.setCredentialsStyle("uuid");
        properties.setMaxConcurrentLogins(0);
        properties.setJwtSecret("test-secret");
        properties.setJwtSubject("test-subject");
        return properties;
    }

    static class FakeSessionRepository implements SessionRepository {
        @Override
        public boolean save(LoginSubject subject, int timeoutSeconds, int maxConcurrentLogins) {
            return true;
        }

        @Override
        public boolean checkByCredentials(String credentials) {
            return true;
        }

        @Override
        public LoginSubject getSubject(String credentials) {
            return null;
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
