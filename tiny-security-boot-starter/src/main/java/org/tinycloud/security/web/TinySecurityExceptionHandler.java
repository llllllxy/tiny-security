package org.tinycloud.security.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.tinycloud.security.consts.AuthConsts;
import org.tinycloud.security.exception.TinySecurityException;
import org.tinycloud.security.support.ExceptionTranslator;

import java.util.Map;

/**
 * tiny-security 默认异常处理器
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
@RestControllerAdvice
public class TinySecurityExceptionHandler {
    private final ExceptionTranslator exceptionTranslator;

    /**
     * 构造异常处理器。
     *
     * @param exceptionTranslator 异常翻译器
     */
    public TinySecurityExceptionHandler(ExceptionTranslator exceptionTranslator) {
        this.exceptionTranslator = exceptionTranslator;
    }

    /**
     * 处理 tiny-security 体系异常。
     *
     * @param request 当前请求
     * @param ex      安全异常
     * @return 标准响应
     */
    @ExceptionHandler(TinySecurityException.class)
    public ResponseEntity<Map<String, Object>> handleTinySecurityException(HttpServletRequest request, TinySecurityException ex) {
        Map<String, Object> body = exceptionTranslator.translate(request, ex);
        return ResponseEntity.status(resolveStatus(ex.getCode())).body(body);
    }

    /**
     * 根据业务错误码映射 HTTP 状态码。
     *
     * @param code 业务错误码
     * @return HTTP 状态码
     */
    private HttpStatus resolveStatus(int code) {
        if (code == AuthConsts.CODE_UNAUTHORIZED) {
            return HttpStatus.UNAUTHORIZED;
        }
        if (code == AuthConsts.CODE_NO_PERMISSION) {
            return HttpStatus.FORBIDDEN;
        }
        if (code == AuthConsts.CODE_CONCURRENT_LOGIN_OVER_LIMIT) {
            return HttpStatus.CONFLICT;
        }
        return HttpStatus.INTERNAL_SERVER_ERROR;
    }
}
