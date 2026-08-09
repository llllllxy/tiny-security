package org.tinycloud.security.util;

import org.tinycloud.security.authorization.AuthorizationEvaluator;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.context.SecurityContext;
import org.tinycloud.security.context.SecurityContextUtils;

/**
 * 常用对外会话便捷工具类。
 *
 * @author liuxingyu01
 * @version 2023-01-06-9:33
 **/
public class AuthUtil {

    /**
     * 获取当前登录用户的loginId。
     *
     * @return 登录账号ID
     */
    public static Object getLoginId() {
        LoginSubject subject = getLoginSubject();
        return subject == null ? null : subject.getLoginId();
    }

    /**
     * 获取当前登录用户的loginId，并转换为String类型。
     *
     * @return 字符串账号ID
     */
    public static String getLoginIdAsString() {
        Object loginId = getLoginId();
        return loginId == null ? null : String.valueOf(loginId);
    }

    /**
     * 获取当前登录用户的loginId，并转换为Integer类型。
     *
     * @return 整数账号ID
     */
    public static Integer getLoginIdAsInt() {
        Object loginId = getLoginId();
        return loginId == null ? null : Integer.parseInt(String.valueOf(loginId));
    }

    /**
     * 获取当前登录用户的loginId，并转换为Long类型。
     *
     * @return 长整数账号ID
     */
    public static Long getLoginIdAsLong() {
        Object loginId = getLoginId();
        return loginId == null ? null : Long.parseLong(String.valueOf(loginId));
    }

    /**
     * 获取当前请求安全上下文。
     *
     * @return 安全上下文
     */
    public static SecurityContext getSecurityContext() {
        return SecurityContextUtils.getSecurityContext();
    }

    /**
     * 获取当前登录主体。
     *
     * @return 登录主体
     */
    public static LoginSubject getLoginSubject() {
        return SecurityContextUtils.getLoginSubject();
    }

    /**
     * 判断当前账号是否拥有指定角色。
     *
     * @param role 角色标识
     * @return true-拥有，false-未拥有
     */
    public static boolean hasRole(String role) {
        return AuthorizationEvaluator.hasRole(SecurityContextUtils.getRoleSet(), role);
    }

    /**
     * 判断当前账号是否同时拥有全部指定角色。
     *
     * @param roles 角色列表
     * @return true-全部拥有，false-未全部拥有
     */
    public static boolean hasAllRole(String... roles) {
        return AuthorizationEvaluator.hasAllRole(SecurityContextUtils.getRoleSet(), roles);
    }

    /**
     * 判断当前账号是否拥有任意指定角色。
     *
     * @param roles 角色列表
     * @return true-拥有任意一个，false-全部未拥有
     */
    public static boolean hasAnyRole(String... roles) {
        return AuthorizationEvaluator.hasAnyRole(SecurityContextUtils.getRoleSet(), roles);
    }

    /**
     * 判断当前账号是否拥有指定权限。
     *
     * @param permission 权限标识
     * @return true-拥有，false-未拥有
     */
    public static boolean hasPermission(String permission) {
        return AuthorizationEvaluator.hasPermission(SecurityContextUtils.getPermissionSet(), permission);
    }

    /**
     * 判断当前账号是否同时拥有全部指定权限。
     *
     * @param permissions 权限列表
     * @return true-全部拥有，false-未全部拥有
     */
    public static boolean hasAllPermission(String... permissions) {
        return AuthorizationEvaluator.hasAllPermission(SecurityContextUtils.getPermissionSet(), permissions);
    }

    /**
     * 判断当前账号是否拥有任意指定权限。
     *
     * @param permissions 权限列表
     * @return true-拥有任意一个，false-全部未拥有
     */
    public static boolean hasAnyPermission(String... permissions) {
        return AuthorizationEvaluator.hasAnyPermission(SecurityContextUtils.getPermissionSet(), permissions);
    }
}
