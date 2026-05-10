package org.tinycloud.security.context;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 安全上下文仓储接口定义，默认实现为 ThreadLocalSecurityContextRepository
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
public interface SecurityContextRepository {

    /**
     * 读取当前请求的安全上下文
     *
     * @param request 请求
     * @return 安全上下文
     */
    SecurityContext loadContext(HttpServletRequest request);

    /**
     * 保存当前请求的安全上下文
     *
     * @param context  安全上下文
     * @param request  请求
     * @param response 响应
     */
    void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response);

    /**
     * 清理当前请求的安全上下文
     *
     * @param request  请求
     * @param response 响应
     */
    void clearContext(HttpServletRequest request, HttpServletResponse response);
}
