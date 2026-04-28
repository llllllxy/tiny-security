package org.tinycloud.security.support;

import jakarta.servlet.http.HttpServletRequest;
import org.tinycloud.security.consts.AuthConsts;
import org.tinycloud.security.exception.TinySecurityException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * tiny-security 默认异常翻译器
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
public class DefaultExceptionTranslator implements ExceptionTranslator {
    /**
     * 将异常翻译为统一响应体。
     *
     * @param request 当前请求
     * @param ex      安全异常
     * @return 统一响应体
     */
    @Override
    public Map<String, Object> translate(HttpServletRequest request, TinySecurityException ex) {
        Map<String, Object> body = new LinkedHashMap<>();
        int code = ex.getCode() > 0 ? ex.getCode() : AuthConsts.CODE_OTHER_ERROR;
        body.put("code", code);
        body.put("message", ex.getMessage());
        if (request != null) {
            body.put("path", request.getRequestURI());
        }
        return body;
    }
}
