package org.tinycloud.security.context;

import org.tinycloud.security.util.AuthUtil;

import java.util.Set;

/**
 * 安全上下文工具类。
 *
 * <p>delegate 到 {@link AuthUtil}（静态外观 → {@link org.tinycloud.security.TinySecurityFacade}）。
 *
 * @author liuxingyu01
 * @since 2026-05-26
 */
public final class SecurityContextUtils {

    /**
     * 禁止实例化安全上下文工具类。
     */
    private SecurityContextUtils() {
    }

    /**
     * 获取当前请求的安全上下文。
     *
     * @return 安全上下文
     */
    public static SecurityContext getSecurityContext() {
        return AuthUtil.getSecurityContext();
    }

    /**
     * 获取当前登录主体。
     *
     * @return 登录主体
     */
    public static LoginSubject getLoginSubject() {
        return AuthUtil.getLoginSubject();
    }

    /**
     * 获取当前角色集合。
     *
     * @return 角色集合
     */
    public static Set<String> getRoleSet() {
        return AuthUtil.getRoleSet();
    }

    /**
     * 获取当前权限集合。
     *
     * @return 权限集合
     */
    public static Set<String> getPermissionSet() {
        return AuthUtil.getPermissionSet();
    }
}
