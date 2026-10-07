package org.tinycloud.security.web;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * WebRequestUtils 测试。
 *
 * <p>核心回归点（1.5.0 · P0-6）：便捷重载默认<b>不</b>从 URL 参数读取 token，与框架自身的默认策略
 * （{@code tiny-security.enable-url-token} 默认 {@code false}）保持一致——否则用户直接调用
 * {@code getToken(request, "token")} 就把凭证重新暴露到访问日志 / Referer 头。
 */
class WebRequestUtilsTest {

    private static final String TOKEN_NAME = "token";

    @Test
    void shouldReadTokenFromHeader() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(TOKEN_NAME, "Bearer from-header");

        assertEquals("Bearer from-header", WebRequestUtils.getToken(request, TOKEN_NAME));
    }

    @Test
    void shouldReadTokenFromCookie() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie(TOKEN_NAME, "Bearer from-cookie"));

        assertEquals("Bearer from-cookie", WebRequestUtils.getToken(request, TOKEN_NAME));
    }

    /**
     * P0-6 回归：便捷重载不再从 URL 参数读取 token。
     * 修复前这三个调用都会返回 {@code "Bearer from-url"}。
     */
    @Test
    void shouldNotReadTokenFromUrlByDefault() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter(TOKEN_NAME, "Bearer from-url");

        assertNull(WebRequestUtils.getToken(request, TOKEN_NAME));
        assertNull(WebRequestUtils.getToken(request, TOKEN_NAME, true));
        assertNull(WebRequestUtils.getToken(request, TOKEN_NAME, false));
    }

    /**
     * 显式传入 {@code enableUrlToken=true} 时仍可从 URL 读取——保留逃生通道，不搞一刀切。
     */
    @Test
    void shouldReadTokenFromUrlWhenExplicitlyEnabled() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter(TOKEN_NAME, "Bearer from-url");

        assertEquals("Bearer from-url", WebRequestUtils.getToken(request, TOKEN_NAME, true, true));
    }

    /**
     * 取值顺序不变：header 优先于 cookie，cookie 优先于 URL。
     */
    @Test
    void headerShouldTakePrecedenceOverCookieAndUrl() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(TOKEN_NAME, "Bearer from-header");
        request.setCookies(new Cookie(TOKEN_NAME, "Bearer from-cookie"));
        request.setParameter(TOKEN_NAME, "Bearer from-url");

        assertEquals("Bearer from-header", WebRequestUtils.getToken(request, TOKEN_NAME, true, true));
    }

    /**
     * {@code enableCookie=false} 时忽略 Cookie；此时 URL 也已默认关闭，故结果为 null。
     */
    @Test
    void shouldIgnoreCookieWhenCookieDisabled() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie(TOKEN_NAME, "Bearer from-cookie"));

        assertNull(WebRequestUtils.getToken(request, TOKEN_NAME, false));
    }

    /**
     * 无任何来源时返回 null，而不是抛异常。
     */
    @Test
    void shouldReturnNullWhenNoTokenPresent() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        assertNull(WebRequestUtils.getToken(request, TOKEN_NAME));
        assertNull(WebRequestUtils.getToken(request, TOKEN_NAME, true, true));
    }
}
