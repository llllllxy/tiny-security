package org.tinycloud.security.context;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 基于 ThreadLocal 的安全上下文仓储实现。
 *
 * <p>ThreadLocal 直接内联在本类中（原独立的 {@code ThreadLocalSecurityContextHolder}
 * 纯转发壳类已移除），通过静态方法提供对当前线程上下文的读写清理。
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
public class ThreadLocalSecurityContextRepository implements SecurityContextRepository {

    private static final ThreadLocal<SecurityContext> CONTEXT_HOLDER = new ThreadLocal<>();

    /**
     * 读取当前线程的安全上下文。
     *
     * @return 安全上下文，可能为 null
     */
    public static SecurityContext getContext() {
        return CONTEXT_HOLDER.get();
    }

    /**
     * 设置当前线程的安全上下文。
     *
     * @param context 安全上下文
     */
    public static void setContext(SecurityContext context) {
        CONTEXT_HOLDER.set(context);
    }

    /**
     * 清理当前线程的安全上下文。
     */
    public static void clearContext() {
        CONTEXT_HOLDER.remove();
    }

    /**
     * 从当前线程读取安全上下文。
     *
     * @param request 当前请求
     * @return 安全上下文
     */
    @Override
    public SecurityContext loadContext(HttpServletRequest request) {
        return getContext();
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
        setContext(context);
    }

    /**
     * 清理当前线程安全上下文。
     *
     * @param request  当前请求
     * @param response 当前响应
     */
    @Override
    public void clearContext(HttpServletRequest request, HttpServletResponse response) {
        clearContext();
    }
}
