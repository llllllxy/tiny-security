package org.tinycloud.security.util;

import javax.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link CookieUtil} 的回归测试。
 *
 * <p>此前该类没有任何直接测试，仅被 {@code AuthProvider} 的用例间接覆盖 ——
 * 而它正是「登出后仍是登录态」那个缺陷的修复点：删除 Cookie 必须写回一个同名且
 * **安全属性一致**（Secure / SameSite）的 Cookie，否则浏览器会忽略删除指令。
 *
 * @author liuxingyu01
 */
class CookieUtilTest {


    /**
     * 从 Set-Cookie 响应头中取出 SameSite 属性值。
     *
     * <p>Servlet 3.1（javax）的 Cookie 没有 getAttribute，SameSite 通过 Set-Cookie 头下发，
     * 因此这里直接解析响应头。
     */
    private static String sameSiteOf(MockHttpServletResponse response, String cookieName) {
        for (String header : response.getHeaders("Set-Cookie")) {
            if (header.startsWith(cookieName + "=")) {
                java.util.regex.Matcher m = java.util.regex.Pattern
                        .compile(";\\s*SameSite=([^;]+)", java.util.regex.Pattern.CASE_INSENSITIVE)
                        .matcher(header);
                return m.find() ? m.group(1) : null;
            }
        }
        return null;
    }

    /**
     * 写入时带齐的属性必须能被读回来（HttpOnly / Secure / SameSite / Path / MaxAge）。
     */
    @Test
    void shouldWriteCookieWithSecurityAttributes() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        CookieUtil.setCookie(response, "token", "abc", "/", 1800, true, "None");

        Cookie cookie = response.getCookie("token");
        assertNotNull(cookie, "应写入 token Cookie");
        assertEquals("abc", cookie.getValue());
        assertEquals("/", cookie.getPath());
        assertEquals(1800, cookie.getMaxAge());
        assertTrue(cookie.isHttpOnly(), "必须 HttpOnly");
        assertTrue(cookie.getSecure(), "Secure 应透传");
        assertEquals("None", sameSiteOf(response, "token"), "SameSite 应通过 Set-Cookie 头下发");
    }

    /**
     * 核心回归：删除指令必须带上与写入时一致的 Secure / SameSite。
     *
     * <p>若删除时丢了这两个属性，{@code SameSite=None} 的 Cookie 将被浏览器忽略，
     * 表现为「点了登出，但仍是登录态」。
     */
    @Test
    void removeCookieShouldCarrySameSecurityAttributesAsWrite() {
        MockHttpServletResponse write = new MockHttpServletResponse();
        CookieUtil.setCookie(write, "token", "abc", "/", 1800, true, "None");
        Cookie written = write.getCookie("token");
        assertNotNull(written);

        MockHttpServletResponse remove = new MockHttpServletResponse();
        CookieUtil.removeCookie(remove, "token", "/", true, "None");
        Cookie removed = remove.getCookie("token");

        assertNotNull(removed, "应写回同名 Cookie 以触发删除");
        assertEquals(0, removed.getMaxAge(), "删除指令 maxAge 必须为 0");
        assertEquals(written.getPath(), removed.getPath(), "删除的 path 必须与写入一致");
        assertEquals(written.getSecure(), removed.getSecure(), "删除的 Secure 必须与写入一致");
        assertEquals(sameSiteOf(write, "token"), sameSiteOf(remove, "token"),
                "删除的 SameSite 必须与写入一致，否则浏览器会忽略该删除指令");
    }

    /**
     * SameSite 为空时不设置该属性（而不是写一个空值）。
     */
    @Test
    void shouldNotSetSameSiteWhenBlank() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        CookieUtil.setCookie(response, "token", "abc", "/", 60, false, null);

        Cookie cookie = response.getCookie("token");
        assertNotNull(cookie);
        assertNull(sameSiteOf(response, "token"), "未指定 SameSite 时不应写入该属性");
        assertFalse(cookie.getSecure());
    }

    /**
     * 读取时要做 URL 解码，与写入时的 URL 编码对称。
     *
     * <p>token 的信封形态含 {@code .} 与 base64url 字符，虽然多为安全字符，
     * 但 Cookie 值可能含需要编码的字符，编解码必须成对。
     */
    @Test
    void shouldRoundTripValueThroughUrlEncoding() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        String value = "abc.def-ghi_123+/=";
        CookieUtil.setCookie(response, "token", value, "/", 60);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(response.getCookie("token"));

        assertEquals(value, CookieUtil.getCookie(request, "token"), "写入再读出必须还原原值");
    }

    /**
     * 读不到同名 Cookie 时返回 null（调用方据此判定未登录）。
     */
    @Test
    void shouldReturnNullWhenCookieMissing() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("other", "x"));

        assertNull(CookieUtil.getCookie(request, "token"));
    }

    /**
     * 请求上没有任何 Cookie 时不应抛 NPE。
     */
    @Test
    void shouldReturnNullWhenNoCookiesAtAll() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        assertNull(CookieUtil.getCookie(request, "token"));
    }

    /**
     * isRemove=true 时读取后应顺带写回一个 maxAge=0 的同名 Cookie。
     */
    @Test
    void shouldRemoveCookieWhenFlagSet() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("token", "abc"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertEquals("abc", CookieUtil.getCookie(request, response, "token", true));

        Cookie removed = response.getCookie("token");
        assertNotNull(removed, "应写回删除指令");
        assertEquals(0, removed.getMaxAge());
    }

    /**
     * response 为 null 表示当前线程未绑定 Web 请求（定时任务 / MQ 消费者），
     * 此时必须静默跳过，不得抛 NPE —— 否则非 Web 线程调用 login 会直接崩。
     */
    @Test
    void shouldSilentlySkipWhenResponseIsNull() {
        assertDoesNotThrow(() -> CookieUtil.setCookie(null, "token", "abc", "/", 60, false, "Lax"));
        assertDoesNotThrow(() -> CookieUtil.removeCookie(null, "token"));
        assertDoesNotThrow(() -> CookieUtil.removeCookie(null, "token", "/", true, "None"));
    }

    /**
     * 名称为空时不应写入任何 Cookie（避免产生无意义甚至非法的 Cookie）。
     */
    @Test
    void shouldIgnoreBlankName() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        CookieUtil.setCookie(response, "", "abc");
        CookieUtil.setCookie(response, null, "abc");

        assertEquals(0, response.getCookies().length, "名称为空时不应写入 Cookie");
    }
}
