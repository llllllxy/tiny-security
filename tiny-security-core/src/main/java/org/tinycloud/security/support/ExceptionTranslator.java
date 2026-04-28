package org.tinycloud.security.support;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * tiny-security 异常翻译器接口
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
public interface ExceptionTranslator {

    /**
     * 将 tiny-security 异常翻译为 HTTP 响应。
     *
     * @param request 当前请求
     * @param response 当前响应
     * @param ex      异常信息
     */
    void translate(HttpServletRequest request, HttpServletResponse response, Exception ex);
}
