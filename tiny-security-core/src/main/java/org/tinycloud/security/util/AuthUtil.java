package org.tinycloud.security.util;

import org.tinycloud.security.TinySecurityFacade;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.context.SecurityContext;

import java.util.Set;

/**
 * 常用对外会话便捷工具类。
 *
 * <p>静态外观模式：delegate 到 {@link TinySecurityFacade}（Spring Bean），
 * 用户调用方式不变，但内部依赖可通过注入替换，便于测试。
 *
 * @author liuxingyu01
 * @version 2023-01-06-9:33
 **/
public class AuthUtil {

    private static volatile TinySecurityFacade facade;

    /**
     * 注册门面实例（由 AuthAutoConfiguration 在启动时调用）。
     *
     * @param facade 安全门面
     */
    public static void setFacade(TinySecurityFacade facade) {
        AuthUtil.facade = facade;
    }

    /**
     * 获取门面实例。
     *
     * @return 安全门面
     */
    public static TinySecurityFacade getFacade() {
        if (facade == null) {
            throw new IllegalStateException("TinySecurityFacade not initialized. " +
                    "Please ensure tiny-security is properly configured.");
        }
        return facade;
    }

    public static Object getLoginId() {
        return getFacade().getLoginId();
    }

    public static String getLoginIdAsString() {
        return getFacade().getLoginIdAsString();
    }

    public static Integer getLoginIdAsInt() {
        return getFacade().getLoginIdAsInt();
    }

    public static Long getLoginIdAsLong() {
        return getFacade().getLoginIdAsLong();
    }

    public static SecurityContext getSecurityContext() {
        return getFacade().getSecurityContext();
    }

    public static LoginSubject getLoginSubject() {
        return getFacade().getLoginSubject();
    }

    public static Set<String> getRoleSet() {
        return getFacade().getRoleSet();
    }

    public static Set<String> getPermissionSet() {
        return getFacade().getPermissionSet();
    }

    public static boolean hasRole(String role) {
        return getFacade().hasRole(role);
    }

    public static boolean hasAllRole(String... roles) {
        return getFacade().hasAllRole(roles);
    }

    public static boolean hasAnyRole(String... roles) {
        return getFacade().hasAnyRole(roles);
    }

    public static boolean hasPermission(String permission) {
        return getFacade().hasPermission(permission);
    }

    public static boolean hasAllPermission(String... permissions) {
        return getFacade().hasAllPermission(permissions);
    }

    public static boolean hasAnyPermission(String... permissions) {
        return getFacade().hasAnyPermission(permissions);
    }
}
