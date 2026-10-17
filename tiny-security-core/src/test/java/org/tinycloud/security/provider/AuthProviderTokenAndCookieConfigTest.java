package org.tinycloud.security.provider;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.tinycloud.security.config.AuthProperties;
import org.tinycloud.security.consts.AuthConsts;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.enums.CookieSameSite;
import org.tinycloud.security.session.SessionRepository;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 门面行为回归：token 前缀语义、SameSite/Secure 组合、弱密钥告警。
 *
 * <p>这三条都属于「框架职责内的默认值与契约」问题：它们不会让框架崩溃，但会让用户
 * 在按文档操作时得到相反的结果，或让安全性在无声中退化。
 *
 * @author liuxingyu01
 */
class AuthProviderTokenAndCookieConfigTest {

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }

    // ==================== getToken 与 login 的前缀语义必须对称 ====================

    /**
     * 核心回归：`login` 返回带 `Bearer ` 前缀的值，`getToken` 此前却返回**去掉前缀**的值。
     * 用户按直觉把 `getToken` 的返回值放回 `Authorization` 头会直接 401。
     *
     * <p>修复后两者形态一致：`getToken` 带前缀、`getRawToken` 去前缀。
     */
    @Test
    void getTokenShouldMatchLoginReturnShape() {
        AuthProvider authProvider = new AuthProvider(new FakeSessionRepository(), defaultProperties(), null);
        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(
                new ServletRequestAttributes(request, new MockHttpServletResponse()));

        String loginToken = authProvider.login("user-1", null);
        assertTrue(loginToken.startsWith(AuthConsts.TOKEN_PREFIX), "login 返回带前缀");

        // 把 login 的返回值放进请求头（header 名即 tokenName），再读出来，形态必须一致
        request.addHeader("token", loginToken);
        String fromRequest = authProvider.getToken();

        assertEquals(loginToken, fromRequest, "getToken() 应与 login() 同形，可直接放回请求头");
    }

    /**
     * 裸值（去前缀）由 `getRawToken` 提供，且它正是 token 的信封形态 `credentials.signature`。
     */
    @Test
    void getRawTokenShouldStripPrefix() {
        AuthProvider authProvider = new AuthProvider(new FakeSessionRepository(), defaultProperties(), null);
        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(
                new ServletRequestAttributes(request, new MockHttpServletResponse()));

        String loginToken = authProvider.login("user-1", null);
        request.addHeader("token", loginToken);

        String raw = authProvider.getRawToken();
        assertEquals(loginToken.substring(AuthConsts.TOKEN_PREFIX.length()), raw);
        assertFalse(raw.startsWith(AuthConsts.TOKEN_PREFIX), "裸值不应含前缀");
    }

    // ==================== SameSite=None 必须与 Secure 同用 ====================

    /**
     * `SameSite=None` + `cookie-secure=false` 是**非法组合** —— 浏览器会直接丢弃该 Cookie，
     * 表现为「登录成功但下一个请求又未登录」。框架只告警、不擅自改写配置值。
     *
     * <p>本用例锁定「不抛异常」这一契约（告警内容由实现负责，测试不去断言日志文本，
     * 避免把测试耦合到日志措辞上）。
     */
    @Test
    void shouldNotFailOnSameSiteNoneWithoutSecure() {
        AuthProperties properties = defaultProperties();
        properties.setEnableCookie(true);
        properties.setCookieSameSite(CookieSameSite.NONE);
        properties.setCookieSecure(false);

        assertDoesNotThrow(() -> new AuthProvider(new FakeSessionRepository(), properties, null),
                "非法组合应只告警，不应阻止装配");
    }

    /**
     * 合法组合（SameSite=None + Secure=true）与默认（LAX）都不应告警/报错。
     */
    @Test
    void shouldAcceptLegalSameSiteCombinations() {
        AuthProperties noneWithSecure = defaultProperties();
        noneWithSecure.setEnableCookie(true);
        noneWithSecure.setCookieSameSite(CookieSameSite.NONE);
        noneWithSecure.setCookieSecure(true);
        assertDoesNotThrow(() -> new AuthProvider(new FakeSessionRepository(), noneWithSecure, null));

        // 未开启 cookie 时，即使是 None+false 也不该告警（该组合根本不会被使用）
        AuthProperties cookieDisabled = defaultProperties();
        cookieDisabled.setEnableCookie(false);
        cookieDisabled.setCookieSameSite(CookieSameSite.NONE);
        cookieDisabled.setCookieSecure(false);
        assertDoesNotThrow(() -> new AuthProvider(new FakeSessionRepository(), cookieDisabled, null));
    }

    // ==================== 弱密钥只告警，不阻止启动 ====================

    /**
     * 短密钥必须**能装起来**（否则存量 `token-secret: 123` 升级后直接启动失败，
     * 属破坏性变更），安全性通过 WARN 提示。
     */
    @Test
    void shouldTolerateShortTokenSecretButKeepWorking() {
        AuthProperties properties = defaultProperties();
        properties.setTokenSecret("123");

        AuthProvider authProvider = assertDoesNotThrow(
                () -> new AuthProvider(new FakeSessionRepository(), properties, null),
                "弱密钥只应告警，不应阻止启动");

        // 且框架仍可正常签名/验签（说明它确实只是告警）
        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(
                new ServletRequestAttributes(request, new MockHttpServletResponse()));
        String token = authProvider.login("user-1", null);
        assertNotNull(token);
    }

    /**
     * 未配置密钥时走随机密钥路径（128 位），不应被弱密钥告警误伤 —— 该路径本身是安全的强度。
     */
    @Test
    void shouldTolerateMissingTokenSecret() {
        AuthProperties properties = defaultProperties();
        properties.setTokenSecret(null);

        assertDoesNotThrow(() -> new AuthProvider(new FakeSessionRepository(), properties, null));
    }

    private AuthProperties defaultProperties() {
        AuthProperties properties = new AuthProperties();
        properties.setBanner(false);
        properties.setTokenName("token");
        properties.setTimeout(1800);
        properties.setMaxConcurrentLogins(0);
        properties.setTokenSecret("test-token-secret-at-least-32-bytes-long!!");
        return properties;
    }

    /**
     * 最小可用仓储：仅 `getSubject` 被调用（login 后取登录态用）。
     */
    static class FakeSessionRepository implements SessionRepository {
        private LoginSubject stored;

        @Override
        public boolean save(LoginSubject subject, int timeoutSeconds, int maxConcurrentLogins) {
            this.stored = subject;
            return true;
        }

        @Override
        public boolean checkByCredentials(String credentials) {
            return stored != null && stored.getCredentials().equals(credentials);
        }

        @Override
        public LoginSubject getSubject(String credentials) {
            if (stored == null || !stored.getCredentials().equals(credentials)) {
                return null;
            }
            return stored.copy();
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
