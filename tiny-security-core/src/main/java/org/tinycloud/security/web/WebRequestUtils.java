package org.tinycloud.security.web;

import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.tinycloud.security.util.CookieUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Web请求上下文工具类。
 *
 * @author liuxingyu01
 * @since 2026-05-26
 */
public final class WebRequestUtils {

    /**
     * 禁止实例化Web请求上下文工具类。
     */
    private WebRequestUtils() {
    }

    /**
     * 获取当前请求对象。
     *
     * @return HTTP请求
     */
    public static HttpServletRequest getRequest() {
        try {
            return ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 获取当前响应对象。
     *
     * @return HTTP响应
     */
    public static HttpServletResponse getResponse() {
        try {
            return ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getResponse();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 从当前请求中获取用户token（兼容 Cookie 读取，历史行为）。
     *
     * @param tokenName token名称
     * @return token
     */
    public static String getToken(String tokenName) {
        return getToken(tokenName, true);
    }

    /**
     * 从当前请求中获取用户token。
     *
     * @param tokenName    token名称
     * @param enableCookie 是否允许从 Cookie 中读取 token
     * @return token
     */
    public static String getToken(String tokenName, boolean enableCookie) {
        return getToken(tokenName, enableCookie, true);
    }

    /**
     * 从当前请求中获取用户token。
     *
     * @param tokenName      token名称
     * @param enableCookie   是否允许从 Cookie 中读取 token
     * @param enableUrlToken 是否允许从 URL 参数读取 token（默认建议 false：URL 传 token 会进入访问日志/Referer，造成凭证泄露）
     * @return token
     */
    public static String getToken(String tokenName, boolean enableCookie, boolean enableUrlToken) {
        HttpServletRequest request = getRequest();
        return request == null ? null : getToken(request, tokenName, enableCookie, enableUrlToken);
    }

    /**
     * 从指定请求中获取用户token（兼容 Cookie 读取，历史行为）。
     *
     * @param request   HTTP请求
     * @param tokenName token名称
     * @return token
     */
    public static String getToken(HttpServletRequest request, String tokenName) {
        return getToken(request, tokenName, true);
    }

    /**
     * 从指定请求中获取用户token。
     *
     * @param request      HTTP请求
     * @param tokenName    token名称
     * @param enableCookie 是否允许从 Cookie 中读取 token（false 时仅从 header 与 URL 参数读取）
     * @return token
     */
    public static String getToken(HttpServletRequest request, String tokenName, boolean enableCookie) {
        return getToken(request, tokenName, enableCookie, true);
    }

    /**
     * 从指定请求中获取用户token。
     *
     * @param request        HTTP请求
     * @param tokenName      token名称
     * @param enableCookie   是否允许从 Cookie 中读取 token
     * @param enableUrlToken 是否允许从 URL 参数读取 token（默认建议 false：URL 传 token 会进入访问日志/Referer，造成凭证泄露）
     * @return token
     */
    public static String getToken(HttpServletRequest request, String tokenName, boolean enableCookie, boolean enableUrlToken) {
        String token = request.getHeader(tokenName);
        if (!StringUtils.hasText(token) && enableCookie) {
            token = CookieUtil.getCookie(request, tokenName);
        }
        if (!StringUtils.hasText(token) && enableUrlToken) {
            token = request.getParameter(tokenName);
        }
        return token;
    }
}
