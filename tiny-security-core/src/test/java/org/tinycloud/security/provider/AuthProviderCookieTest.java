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

import static org.junit.jupiter.api.Assertions.*;

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
        // 必须显式开启 Cookie：否则 login 根本不会走到「写 Cookie」这一段，
        // 本用例声称保护的非 Web 线程 NPE 回归就失去意义（空转断言）。
        AuthProperties properties = defaultProperties();
        properties.setEnableCookie(true);
        AuthProvider authProvider = new AuthProvider(new FakeSessionRepository(), properties, null);

        String token = authProvider.login("user-1", null);

        assertNotNull(token);
        assertTrue(token.startsWith("Bearer "));
        // 非 Web 线程上 CookieUtil 应静默跳过：既不能抛异常，也不能改写任何响应
        assertNull(RequestContextHolder.getRequestAttributes());
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
        request.setCookies(new Cookie("token", "Bearer some-token"));
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
        request.setCookies(new Cookie("token", "Bearer some-token"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));

        // getToken 返回**带前缀**的完整值（与 login 对称），裸值走 getRawToken
        assertEquals("Bearer some-token", authProvider.getToken());
        assertEquals("some-token", authProvider.getRawToken());
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
     * 删除 Cookie 必须带上与写入时**一致**的属性，否则浏览器会忽略删除指令。
     *
     * <p>删除 Cookie 的本质是"写回一个同名同属性的 maxAge=0 Cookie"，属性必须逐字匹配
     * 才会被浏览器视为同一条。此前的 {@code removeCookie} 只带 path/maxAge/HttpOnly，
     * 丢了 Secure 与 SameSite —— {@code SameSite=None} 时浏览器要求删除指令也必须带
     * {@code SameSite=None; Secure}，否则**删除被忽略**，表现为"登出后仍是登录态"。
     */
    @Test
    void shouldClearCookieWithSameSecurityAttributesAsWritten() {
        AuthProperties properties = defaultProperties();
        properties.setEnableCookie(true);
        properties.setCookieSecure(true);
        properties.setCookieSameSite(CookieSameSite.NONE);
        AuthProvider authProvider = new AuthProvider(new FakeSessionRepository(), properties, null);

        MockHttpServletResponse loginResponse = bindRequestContext();
        String token = authProvider.login("user-1", null);
        Cookie written = loginResponse.getCookie("token");
        assertNotNull(written);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("token", token);
        MockHttpServletResponse logoutResponse = new MockHttpServletResponse();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, logoutResponse));

        authProvider.logout();

        Cookie removed = logoutResponse.getCookie("token");
        assertNotNull(removed);
        assertEquals(0, removed.getMaxAge(), "必须是删除指令");
        // 关键：删除指令的属性必须与写入时一致，否则浏览器不认
        assertEquals(written.getSecure(), removed.getSecure(),
                "删除 Cookie 的 Secure 必须与写入时一致，否则 SameSite=None 下删除会被浏览器忽略");
        assertEquals(written.getAttribute("SameSite"), removed.getAttribute("SameSite"),
                "删除 Cookie 的 SameSite 必须与写入时一致");
        assertEquals(written.getPath(), removed.getPath(), "path 必须一致");
        assertTrue(removed.isHttpOnly(), "HttpOnly 必须一致");
    }

    /**
     * 默认配置（SameSite=Lax、非 Secure）下同样要带齐属性。
     * <p>即便 Lax 场景浏览器较宽松，属性不一致也属于隐患，必须与写入保持一致。
     */
    @Test
    void shouldClearCookieWithDefaultSecurityAttributes() {
        AuthProperties properties = defaultProperties();
        properties.setEnableCookie(true);
        AuthProvider authProvider = new AuthProvider(new FakeSessionRepository(), properties, null);

        MockHttpServletResponse loginResponse = bindRequestContext();
        String token = authProvider.login("user-1", null);
        Cookie written = loginResponse.getCookie("token");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("token", token);
        MockHttpServletResponse logoutResponse = new MockHttpServletResponse();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, logoutResponse));

        authProvider.logout();

        Cookie removed = logoutResponse.getCookie("token");
        assertNotNull(removed);
        assertEquals(written.getAttribute("SameSite"), removed.getAttribute("SameSite"),
                "默认 SameSite=Lax 也必须带到删除指令上");
    }

    /**
     * {@code logout(request)} 在**传入的 request 与线程绑定的不是同一个**时，
     * 宁可放弃清理，也不能把 Cookie 删到另一个请求的响应上。
     *
     * <p>Servlet API 无法从请求反查响应，响应只能来自线程绑定。此前实现无条件用
     * {@code WebRequestUtils.getResponse返回}，于是当两者不一致时，清理指令会落到**别的请求**
     * 的响应里 —— 当前请求的 Cookie 没被清理（静默失效），却污染了另一个响应。
     */
    @Test
    void logoutWithRequestShouldNotWriteToUnrelatedResponse() {
        AuthProperties properties = defaultProperties();
        properties.setEnableCookie(true);
        AuthProvider authProvider = new AuthProvider(new FakeSessionRepository(), properties, null);

        // 先正常登录拿到一个签名合法的 token
        MockHttpServletResponse loginResponse = bindRequestContext();
        String token = authProvider.login("user-1", null);
        assertNotNull(loginResponse.getCookie("token"));

        // 线程绑定一个无关请求（其 response 不应被本方法写入）
        MockHttpServletResponse unrelatedResponse = new MockHttpServletResponse();
        RequestContextHolder.setRequestAttributes(
                new ServletRequestAttributes(new MockHttpServletRequest(), unrelatedResponse));

        // 调用方传入的是另一个 request（未与线程绑定）
        MockHttpServletRequest explicitRequest = new MockHttpServletRequest();
        explicitRequest.addHeader("token", token);

        authProvider.logout(explicitRequest);

        assertNull(unrelatedResponse.getCookie("token"),
                "不得把 Cookie 清理写到与传入 request 无关的响应上");
    }

    /**
     * 对照：传入的 request 与线程绑定的一致时（正常 Web 请求），清理照常落在该响应上。
     */
    @Test
    void logoutWithRequestShouldClearCookieWhenRequestMatchesThreadBoundOne() {
        AuthProperties properties = defaultProperties();
        properties.setEnableCookie(true);
        AuthProvider authProvider = new AuthProvider(new FakeSessionRepository(), properties, null);

        MockHttpServletResponse loginResponse = bindRequestContext();
        String token = authProvider.login("user-1", null);
        assertNotNull(loginResponse.getCookie("token"));

        MockHttpServletRequest sameRequest = new MockHttpServletRequest();
        sameRequest.addHeader("token", token);
        MockHttpServletResponse sameResponse = new MockHttpServletResponse();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(sameRequest, sameResponse));

        authProvider.logout(sameRequest);

        Cookie cookie = sameResponse.getCookie("token");
        assertNotNull(cookie, "同一请求下必须正常清理 Cookie");
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
        request.addParameter("token", "Bearer some-token");
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
        request.addParameter("token", "Bearer some-token");
        MockHttpServletResponse response = new MockHttpServletResponse();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));

        // getToken 返回**带前缀**的完整值（与 login 对称），裸值走 getRawToken
        assertEquals("Bearer some-token", authProvider.getToken());
        assertEquals("some-token", authProvider.getRawToken());
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
        properties.setMaxConcurrentLogins(0);
        properties.setTokenSecret("test-secret");
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
