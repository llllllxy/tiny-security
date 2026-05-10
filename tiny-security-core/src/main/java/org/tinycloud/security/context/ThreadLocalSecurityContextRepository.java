package org.tinycloud.security.context;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 基于 ThreadLocal 的安全上下文仓储实现
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
public class ThreadLocalSecurityContextRepository implements SecurityContextRepository {
    /**
     * 从当前线程读取安全上下文。
     *
     * @param request 当前请求
     * @return 安全上下文
     */
    @Override
    public SecurityContext loadContext(HttpServletRequest request) {
        return ThreadLocalSecurityContextHolder.getContext();
    }

    /**
     * 将安全上下文保存到当前线程。
     *
     * @param context  安全上下文
     * @param request  当前请求
     * @param response 当前响应
     */
    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        ThreadLocalSecurityContextHolder.setContext(context);
    }

    /**
     * 清理当前线程安全上下文。
     *
     * @param request  当前请求
     * @param response 当前响应
     */
    @Override
    public void clearContext(HttpServletRequest request, HttpServletResponse response) {
        ThreadLocalSecurityContextHolder.clearContext();
    }
}
