package org.tinycloud.security.support;

import org.springframework.util.StringUtils;
import org.tinycloud.security.consts.AuthConsts;
import org.tinycloud.security.exception.ConcurrentLoginOverLimitException;
import org.tinycloud.security.exception.NoPermissionException;
import org.tinycloud.security.exception.TinySecurityException;
import org.tinycloud.security.exception.UnAuthorizedException;
import org.tinycloud.security.util.JsonUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
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
     * 将异常翻译为统一 HTTP JSON 响应。
     *
     * @param request 当前请求
     * @param response 当前响应
     * @param ex      安全异常
     */
    @Override
    public void translate(HttpServletRequest request, HttpServletResponse response, Exception ex) {
        if (response == null || response.isCommitted()) {
            return;
        }

        int status = resolveStatus(ex);
        int code = resolveCode(ex, status);
        String message = resolveMessage(ex, status);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("code", code);
        payload.put("message", message);
        payload.put("path", request == null ? null : request.getRequestURI());
        payload.put("timestamp", System.currentTimeMillis());

        response.setStatus(status);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType("application/json;charset=UTF-8");
        try {
            response.getWriter().write(JsonUtil.writeValueAsString(payload));
            response.flushBuffer();
        } catch (IOException ignored) {
            // 渲染异常响应失败时不再抛出次级异常
        }
    }

    private int resolveStatus(Exception ex) {
        if (ex instanceof UnAuthorizedException) {
            return HttpServletResponse.SC_UNAUTHORIZED;
        }
        if (ex instanceof NoPermissionException) {
            return HttpServletResponse.SC_FORBIDDEN;
        }
        if (ex instanceof ConcurrentLoginOverLimitException) {
            return HttpServletResponse.SC_CONFLICT;
        }
        return HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
    }

    private int resolveCode(Exception ex, int status) {
        if (ex instanceof TinySecurityException) {
            TinySecurityException tinySecurityException = (TinySecurityException) ex;
            if (tinySecurityException.getCode() > 0) {
                return tinySecurityException.getCode();
            }
        }
        if (status == HttpServletResponse.SC_UNAUTHORIZED) {
            return AuthConsts.CODE_UNAUTHORIZED;
        }
        if (status == HttpServletResponse.SC_FORBIDDEN) {
            return AuthConsts.CODE_NO_PERMISSION;
        }
        if (status == HttpServletResponse.SC_CONFLICT) {
            return AuthConsts.CODE_CONCURRENT_LOGIN_OVER_LIMIT;
        }
        return AuthConsts.CODE_OTHER_ERROR;
    }

    private String resolveMessage(Exception ex, int status) {
        if (StringUtils.hasText(ex.getMessage())) {
            return ex.getMessage();
        }
        if (status == HttpServletResponse.SC_UNAUTHORIZED) {
            return "Unauthorized";
        }
        if (status == HttpServletResponse.SC_FORBIDDEN) {
            return "Forbidden";
        }
        if (status == HttpServletResponse.SC_CONFLICT) {
            return "Concurrent login limit exceeded";
        }
        return "Internal server error";
    }
}
