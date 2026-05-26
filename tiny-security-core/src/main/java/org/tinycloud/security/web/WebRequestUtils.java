package org.tinycloud.security.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.tinycloud.security.util.CookieUtil;

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
     * 从当前请求中获取用户token。
     *
     * @param tokenName token名称
     * @return token
     */
    public static String getToken(String tokenName) {
        HttpServletRequest request = getRequest();
        return request == null ? null : getToken(request, tokenName);
    }

    /**
     * 从指定请求中获取用户token。
     *
     * @param request   HTTP请求
     * @param tokenName token名称
     * @return token
     */
    public static String getToken(HttpServletRequest request, String tokenName) {
        String token = request.getHeader(tokenName);
        if (!StringUtils.hasText(token)) {
            token = CookieUtil.getCookie(request, tokenName);
        }
        if (!StringUtils.hasText(token)) {
            token = request.getParameter(tokenName);
        }
        return token;
    }
}
