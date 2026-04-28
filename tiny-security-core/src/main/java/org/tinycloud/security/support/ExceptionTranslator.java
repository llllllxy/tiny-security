package org.tinycloud.security.support;

import jakarta.servlet.http.HttpServletRequest;
import org.tinycloud.security.exception.TinySecurityException;

import java.util.Map;

/**
 * tiny-security 异常翻译器接口
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
public interface ExceptionTranslator {

    /**
     * 将 tiny-security 异常翻译成可序列化的响应体
     *
     * @param request 当前请求
     * @param ex      异常信息
     * @return 响应体
     */
    Map<String, Object> translate(HttpServletRequest request, TinySecurityException ex);
}
