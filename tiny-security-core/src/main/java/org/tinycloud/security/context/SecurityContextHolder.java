package org.tinycloud.security.context;

/**
 * 本地线程变量-缓存当前请求安全上下文
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
public class SecurityContextHolder {
    private static final ThreadLocal<SecurityContext> CONTEXT_HOLDER = new ThreadLocal<>();

    private SecurityContextHolder() {
    }

    /**
     * 获取当前线程的安全上下文。
     *
     * @return 安全上下文
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
}
