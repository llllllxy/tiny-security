package org.tinycloud.security.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Method;
import java.net.URLDecoder;
import java.net.URLEncoder;

/**
 * Cookie工具类
 *
 * @author liuxingyu01
 * @since 2021-01-30-11:18
 **/
public class CookieUtil {

    /**
     * 工具类，禁止实例化。
     */
    private CookieUtil() {
    }
    private static final Logger logger = LoggerFactory.getLogger(CookieUtil.class);

    /**
     * 设置 Cookie（生成时间为1天）
     *
     * @param response 响应对象
     * @param name     名称
     * @param value    值
     */
    public static void setCookie(HttpServletResponse response, String name, String value) {
        setCookie(response, name, value, 60 * 60 * 24);
    }

    /**
     * 设置 Cookie
     *
     * @param response 响应对象
     * @param name     名称
     * @param value    值
     * @param path     上下文路径
     */
    public static void setCookie(HttpServletResponse response, String name, String value, String path) {
        setCookie(response, name, value, path, 60 * 60 * 24);
    }

    /**
     * 设置 Cookie
     *
     * @param response 响应对象
     * @param name     名称
     * @param value    值
     * @param maxAge   生存时间（单位秒）
     */
    public static void setCookie(HttpServletResponse response, String name, String value, int maxAge) {
        setCookie(response, name, value, "/", maxAge);
    }

    /**
     * 设置 Cookie
     *
     * @param response 响应对象
     * @param name     名称
     * @param value    值
     * @param path     上下文路径
     * @param maxAge   生存时间（单位秒）
     */
    public static void setCookie(HttpServletResponse response, String name, String value, String path, int maxAge) {
        setCookie(response, name, value, path, maxAge, false, null);
    }

    /**
     * 设置 Cookie（完整安全属性）
     *
     * @param response 响应对象（为 null 时说明当前线程未绑定 Web 请求，直接跳过写入）
     * @param name     名称
     * @param value    值
     * @param path     上下文路径
     * @param maxAge   生存时间（单位秒）
     * @param secure   是否仅通过 HTTPS 传输
     * @param sameSite SameSite 属性（Strict/Lax/None），为 null 时不设置
     */
    public static void setCookie(HttpServletResponse response, String name, String value, String path,
                                 int maxAge, boolean secure, String sameSite) {
        if (response == null) {
            logger.debug("CookieUtil setCookie skipped: no response bound to current thread (non-web thread).");
            return;
        }
        if (StringUtils.hasText(name)) {
            Cookie cookie = new Cookie(name, null);
            cookie.setPath(path);
            cookie.setMaxAge(maxAge);
            cookie.setHttpOnly(true);
            cookie.setSecure(secure);
            if (StringUtils.hasText(sameSite)) {
                // Servlet 6 / jakarta 才提供 Cookie#setAttribute；javax.servlet 3.1 通过反射调用，
                // 找不到方法时静默跳过，保证两分支共用同一份源码
                trySetCookieAttribute(cookie, "SameSite", sameSite);
            }
            try {
                cookie.setValue(URLEncoder.encode(value, "utf-8"));
            } catch (UnsupportedEncodingException e) {
                logger.error("CookieUtil setCookie url encode failed!", e);
            }
            response.addCookie(cookie);
        }
    }

    /**
     * 删除指定名称的 Cookie（写回 maxAge=0 的同名 Cookie 使浏览器立即失效）。
     *
     * @param response 响应对象（为 null 时说明当前线程未绑定 Web 请求，直接跳过删除）
     * @param name     名称
     */
    public static void removeCookie(HttpServletResponse response, String name) {
        removeCookie(response, name, "/", false, null);
    }

    /**
     * 删除指定名称的 Cookie（写回 maxAge=0 的同名 Cookie 使浏览器立即失效）。
     *
     * @param response 响应对象（为 null 时说明当前线程未绑定 Web 请求，直接跳过删除）
     * @param name     名称
     * @param path     上下文路径
     */
    public static void removeCookie(HttpServletResponse response, String name, String path) {
        removeCookie(response, name, path, false, null);
    }

    /**
     * 删除指定名称的 Cookie，并带上与写入时一致的安全属性。
     *
     * <p><b>为什么必须带属性</b>：删除 Cookie 的本质是"写回一个同名 Cookie 并令其 maxAge=0"，
     * 浏览器只有在该 Cookie 的 {@code path}/{@code domain} 与**安全属性**都与原 Cookie 匹配时才认这条删除指令。
     * 尤其是 {@code SameSite=None} 的 Cookie，规范要求它必须同时带 {@code Secure}，
     * 删除指令若不带这两个属性会被浏览器**直接忽略** —— 表现为"点了登出，但仍是登录态"。
     *
     * <p>因此这里的 {@code secure} 与 {@code sameSite} 必须与
     * {@link #setCookie(HttpServletResponse, String, String, String, int, boolean, String)} 写入时传入的一致。
     *
     * @param response 响应对象（为 null 时说明当前线程未绑定 Web 请求，直接跳过删除）
     * @param name     名称
     * @param path     上下文路径
     * @param secure   是否仅通过 HTTPS 传输（必须与写入时一致）
     * @param sameSite SameSite 属性（必须与写入时一致；为 null 时不设置）
     */
    public static void removeCookie(HttpServletResponse response, String name, String path,
                                    boolean secure, String sameSite) {
        if (response == null || !StringUtils.hasText(name)) {
            return;
        }
        Cookie cookie = new Cookie(name, "");
        cookie.setPath(path);
        cookie.setMaxAge(0);
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        if (StringUtils.hasText(sameSite)) {
            // 同 setCookie：Servlet 6 才有 Cookie#setAttribute，旧版 javax 走反射降级
            trySetCookieAttribute(cookie, "SameSite", sameSite);
        }
        response.addCookie(cookie);
    }

    /**
     * 获得指定Cookie的值
     *
     * @param request 请求对象
     * @param name    名称
     * @return 值
     */
    public static String getCookie(HttpServletRequest request, String name) {
        return getCookie(request, null, name, false);
    }

    /**
     * 获得指定Cookie的值，并删除。
     *
     * @param request  请求对象
     * @param response 响应对象
     * @param name     名称
     * @return 值
     */
    public static String getCookie(HttpServletRequest request, HttpServletResponse response, String name) {
        return getCookie(request, response, name, false);
    }

    /**
     * 获得指定Cookie的值
     *
     * @param request  请求对象
     * @param response 响应对象
     * @param name     名字
     * @param path     上下文路径
     * @return 值
     */
    public static String getCookie(HttpServletRequest request, HttpServletResponse response, String name, String path) {
        return getCookie(request, response, name, path, false);
    }

    /**
     * 获得指定Cookie的值
     *
     * @param request  请求对象
     * @param response 响应对象
     * @param name     名字
     * @param isRemove 是否移除
     * @return 值
     */
    public static String getCookie(HttpServletRequest request, HttpServletResponse response, String name, boolean isRemove) {
        return getCookie(request, response, name, "/", isRemove);
    }

    /**
     * 获得指定Cookie的值
     *
     * @param request  请求对象
     * @param response 响应对象
     * @param name     名字
     * @param isRemove 是否移除
     * @return 值
     */
    public static String getCookie(HttpServletRequest request, HttpServletResponse response, String name, String path, boolean isRemove) {
        String value = null;
        if (StringUtils.hasText(name)) {
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if (cookie.getName().equals(name)) {
                        try {
                            value = URLDecoder.decode(cookie.getValue(), "utf-8");
                        } catch (UnsupportedEncodingException e) {
                            logger.error("CookieUtil getCookie url decode failed!", e);
                        }
                        if (isRemove && response != null) {
                            cookie.setPath(path);
                            cookie.setMaxAge(0);
                            response.addCookie(cookie);
                        }
                    }
                }
            }
        }
        return value;
    }

    /**
     * 通过反射尝试调用 {@code Cookie#setAttribute(String, String)}（Servlet 6 / jakarta 新增）。
     *
     * <p>本框架的 springboot3 分支基于 jakarta.servlet 6，可直接调用；master 分支基于
     * javax.servlet 3.1（Spring Boot 2.x / JDK 8），该方法不存在。为保证两分支共用同一份源码，
     * 这里统一走反射：方法不存在时静默跳过，仅影响 SameSite 属性写入，不影响 Cookie 其它属性。
     *
     * @param cookie Cookie 实例
     * @param name   属性名（如 SameSite）
     * @param value  属性值（如 Lax / Strict / None）
     */
    private static void trySetCookieAttribute(Cookie cookie, String name, String value) {
        try {
            Method method = Cookie.class.getMethod("setAttribute", String.class, String.class);
            method.invoke(cookie, name, value);
        } catch (NoSuchMethodException e) {
            // javax.servlet 3.1 无此方法，属预期内降级
            logger.debug("CookieUtil trySetCookieAttribute skipped: Cookie#setAttribute not supported by current Servlet API.");
        } catch (Exception e) {
            logger.debug("CookieUtil trySetCookieAttribute failed: name={}, value={}", name, value, e);
        }
    }

}